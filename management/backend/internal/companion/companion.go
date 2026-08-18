// Copyright (C) 2026 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package companion implements appsec-agent-sync, the small process that runs
// alongside an open-appsec agent on hosts the manager cannot reach by volume.
//
// It exists because the agent's own REST API has no authentication and refuses
// POST from anything but loopback (core/rest/rest_conn.cc:140-144). Something
// therefore has to sit on the agent's host to apply policy; this is it. The
// companion pulls the rendered policy from the manager, writes it where the
// agent looks, asks the agent to apply it, and reports the result back.
package companion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/openappsec/openappsec/management/backend/internal/fleet"
)

type Config struct {
	// ManagerURL is the agent plane of the manager, e.g. http://appsec-manager.
	ManagerURL string
	// Token is the enrolment token issued when the agent was registered.
	Token string

	// PolicyPath is where the agent reads its declarative config. In a
	// container this is the bind-mounted /ext/appsec/local_policy.yaml, which
	// the installer symlinks over /etc/cp/conf/local_policy.yaml
	// (nodes/orchestration/package/orchestration_package.sh:864-868).
	PolicyPath string
	// AgentPolicyPath is the path passed to the agent in set-apply-policy. It
	// is the agent's own view of the file, which differs from PolicyPath when
	// the companion writes through a bind mount.
	AgentPolicyPath string

	// OrchestrationURL is the agent's local REST endpoint. Loopback only.
	OrchestrationURL string

	Interval time.Duration
	// ApplyTimeout bounds how long to wait for the agent to report the new
	// policy version after an apply.
	ApplyTimeout time.Duration
}

func (c *Config) setDefaults() {
	if c.PolicyPath == "" {
		c.PolicyPath = "/ext/appsec/local_policy.yaml"
	}
	if c.AgentPolicyPath == "" {
		c.AgentPolicyPath = "/etc/cp/conf/local_policy.yaml"
	}
	if c.OrchestrationURL == "" {
		// The orchestration nano-service's primary port
		// (nodes/orchestration/main.cc:82).
		c.OrchestrationURL = "http://127.0.0.1:7777"
	}
	if c.Interval <= 0 {
		c.Interval = 30 * time.Second
	}
	if c.ApplyTimeout <= 0 {
		c.ApplyTimeout = 2 * time.Minute
	}
}

type Companion struct {
	cfg    Config
	client *http.Client
	// etag is the last policy fingerprint applied, so an unchanged policy is
	// not re-applied on every tick — each apply makes the agent reload.
	etag string
}

func New(cfg Config) *Companion {
	cfg.setDefaults()
	return &Companion{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Run polls until the context is cancelled.
func (c *Companion) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.cfg.Interval)
	defer ticker.Stop()

	// Sync immediately rather than waiting a full interval on startup.
	if err := c.Sync(ctx); err != nil {
		slog.Error("initial sync failed", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := c.Sync(ctx); err != nil {
				// Keep going: the manager may simply be restarting.
				slog.Error("sync failed", "error", err)
			}
		}
	}
}

// Sync performs one cycle: fetch, apply if changed, report status.
func (c *Companion) Sync(ctx context.Context) error {
	body, etag, revision, changed, err := c.fetchPolicy(ctx)
	if err != nil {
		return err
	}

	if !changed {
		// Still report status, so the manager sees the agent as alive and
		// keeps its policy version current.
		return c.reportStatus(ctx, 0, false, "")
	}

	slog.Info("new policy received", "revision", revision, "bytes", len(body))

	if err := c.writePolicy(body); err != nil {
		return c.reportApplyFailure(ctx, revision, fmt.Errorf("writing policy: %w", err))
	}
	if err := c.applyPolicy(ctx); err != nil {
		return c.reportApplyFailure(ctx, revision, fmt.Errorf("applying policy: %w", err))
	}

	c.etag = etag
	slog.Info("policy applied", "revision", revision)
	return c.reportStatus(ctx, revision, false, "")
}

func (c *Companion) fetchPolicy(ctx context.Context) (body []byte, etag string, revision int64, changed bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.cfg.ManagerURL+"/api/v1/fleet/policy", nil)
	if err != nil {
		return nil, "", 0, false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	if c.etag != "" {
		req.Header.Set("If-None-Match", c.etag)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, "", 0, false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, c.etag, 0, false, nil
	case http.StatusOK:
	case http.StatusUnauthorized:
		return nil, "", 0, false, fmt.Errorf("manager rejected the enrollment token")
	case http.StatusNotFound:
		return nil, "", 0, false, fmt.Errorf("no policy is assigned to this agent")
	default:
		return nil, "", 0, false, fmt.Errorf("manager returned %s", resp.Status)
	}

	body, err = io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, "", 0, false, err
	}
	if len(body) == 0 {
		return nil, "", 0, false, fmt.Errorf("manager returned an empty policy")
	}

	revision = parseInt(resp.Header.Get("X-Policy-Revision"))
	return body, resp.Header.Get("ETag"), revision, true, nil
}

// writePolicy replaces the policy file atomically, so the agent cannot read a
// partially written document and fail the load.
func (c *Companion) writePolicy(body []byte) error {
	dir := filepath.Dir(c.cfg.PolicyPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".local_policy-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.cfg.PolicyPath)
}

// applyPolicyRequest is the body of the agent's set-apply-policy endpoint
// (components/security_apps/orchestration/include/declarative_policy_utils.h:57-68).
type applyPolicyRequest struct {
	PolicyPath string `json:"policy_path"`
}

// applyPolicy asks the agent to reload. This mirrors what open-appsec-ctl
// --apply-policy does (nodes/orchestration/package/open-appsec-ctl.sh:1859).
func (c *Companion) applyPolicy(ctx context.Context) error {
	payload, err := json.Marshal(applyPolicyRequest{PolicyPath: c.cfg.AgentPolicyPath})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.OrchestrationURL+"/set-apply-policy", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("agent returned %s: %s", resp.Status, bytes.TrimSpace(detail))
	}
	return nil
}

// orchestrationStatus queries the agent's status endpoint. The response keys
// are the literal labels from get_status_rest.h:70-86.
func (c *Companion) orchestrationStatus(ctx context.Context) (fleet.StatusReport, json.RawMessage, error) {
	var report fleet.StatusReport

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.OrchestrationURL+"/show-orchestration-status", bytes.NewReader([]byte("{}")))
	if err != nil {
		return report, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return report, nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return report, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return report, nil, fmt.Errorf("agent status returned %s", resp.Status)
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return report, raw, fmt.Errorf("decoding agent status: %w", err)
	}
	return report, raw, nil
}

func (c *Companion) reportStatus(ctx context.Context, appliedRev int64, failed bool, applyErr string) error {
	report, raw, err := c.orchestrationStatus(ctx)
	if err != nil {
		// The agent may be mid-restart. Still tell the manager what happened
		// with the apply, so a failure is not lost.
		slog.Debug("could not read agent status", "error", err)
	}

	push := struct {
		Report      fleet.StatusReport `json:"report"`
		Raw         json.RawMessage    `json:"raw,omitempty"`
		AppliedRev  int64              `json:"appliedRevisionId,omitempty"`
		ApplyFailed bool               `json:"applyFailed,omitempty"`
		ApplyError  string             `json:"applyError,omitempty"`
	}{Report: report, Raw: raw, AppliedRev: appliedRev, ApplyFailed: failed, ApplyError: applyErr}

	payload, err := json.Marshal(push)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.ManagerURL+"/api/v1/fleet/status", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck // best effort drain

	if resp.StatusCode >= 300 {
		return fmt.Errorf("manager rejected the status report: %s", resp.Status)
	}
	return nil
}

// reportApplyFailure records the failure with the manager and returns it, so a
// broken apply is visible in the UI rather than only in this process's log.
func (c *Companion) reportApplyFailure(ctx context.Context, revision int64, cause error) error {
	if err := c.reportStatus(ctx, revision, true, cause.Error()); err != nil {
		slog.Error("could not report the apply failure", "error", err)
	}
	return cause
}

func parseInt(s string) int64 {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}
