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

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/openappsec/openappsec/management/backend/internal/fleet"
	"github.com/openappsec/openappsec/management/backend/internal/policy"
)

type agentCtxKey int

const enrolledAgentKey agentCtxKey = iota

// requireEnrollment authenticates the appsec-agent-sync companion.
//
// Unlike the event stream, these endpoints can change what an agent enforces,
// so they are not left open: the companion presents the enrolment token issued
// when the agent was registered.
func (s *Server) requireEnrollment(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			http.Error(w, "enrollment token required", http.StatusUnauthorized)
			return
		}
		agent, err := s.fleet.ResolveEnrollment(r.Context(), token)
		if err != nil {
			if !errors.Is(err, fleet.ErrNotFound) {
				slog.Error("enrollment lookup failed", "error", err)
			}
			http.Error(w, "unknown enrollment token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), enrolledAgentKey, agent)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func enrolledAgent(ctx context.Context) *fleet.Agent {
	a, _ := ctx.Value(enrolledAgentKey).(*fleet.Agent)
	return a
}

// handlePolicyPull serves the rendered local_policy.yaml for the calling
// agent. The ETag lets the companion skip re-applying an unchanged policy,
// which matters because every apply restarts the agent's policy load.
func (s *Server) handlePolicyPull(w http.ResponseWriter, r *http.Request) {
	agent := enrolledAgent(r.Context())
	if agent == nil {
		http.Error(w, "not enrolled", http.StatusUnauthorized)
		return
	}

	body, etag, rev, err := s.policies.Rendered(r.Context(), &agent.ID)
	if errors.Is(err, policy.ErrNotFound) {
		http.Error(w, "no policy assigned", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("rendering policy failed", "agent", agent.Name, "error", err)
		http.Error(w, "failed to render policy", http.StatusInternalServerError)
		return
	}

	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		if err := s.fleet.Touch(r.Context(), agent.ID); err != nil {
			slog.Debug("touch failed", "error", err)
		}
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("X-Policy-Revision", itoa(rev.ID))
	if _, err := w.Write(body); err != nil {
		slog.Debug("writing policy response failed", "error", err)
	}
}

// StatusPush is what the companion posts after applying a policy: the agent's
// own status response, plus the revision it just applied.
type StatusPush struct {
	Report      fleet.StatusReport `json:"report"`
	Raw         json.RawMessage    `json:"raw,omitempty"`
	AppliedRev  int64              `json:"appliedRevisionId,omitempty"`
	ApplyFailed bool               `json:"applyFailed,omitempty"`
	ApplyError  string             `json:"applyError,omitempty"`
}

func (s *Server) handleStatusPush(w http.ResponseWriter, r *http.Request) {
	agent := enrolledAgent(r.Context())
	if agent == nil {
		http.Error(w, "not enrolled", http.StatusUnauthorized)
		return
	}

	var push StatusPush
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&push); err != nil {
		badRequest(w, "malformed status body")
		return
	}

	if err := s.fleet.RecordStatus(r.Context(), agent.ID, push.Report, push.Raw); err != nil {
		slog.Error("recording status failed", "agent", agent.Name, "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	// Only record the revision as applied when the companion confirms the
	// agent accepted it, so the inventory shows real drift rather than intent.
	if push.AppliedRev > 0 && !push.ApplyFailed {
		if err := s.fleet.MarkApplied(r.Context(), agent.ID, push.AppliedRev,
			push.Report.PolicyVersion); err != nil {
			slog.Error("marking revision applied failed", "error", err)
		}
	}
	if push.ApplyFailed {
		slog.Warn("agent reported a failed policy apply",
			"agent", agent.Name, "revision", push.AppliedRev, "error", push.ApplyError)
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleTuningDecisions serves decisions.data over HTTP.
//
// The agent normally fetches this from SHARED_STORAGE_HOST rather than from
// the tuning host (TuningDecision.cc), which is why the learning service also
// writes the file into the shared-storage volume. This endpoint covers the
// deployments where SHARED_STORAGE_HOST is pointed at the manager instead, and
// it serves the identical body.
func (s *Server) handleTuningDecisions(w http.ResponseWriter, r *http.Request) {
	tenantID := chi.URLParam(r, "tenantID")
	assetID := chi.URLParam(r, "assetID")

	doc, err := s.learn.DecisionsDocumentFor(r.Context(), tenantID, assetID)
	if err != nil {
		slog.Error("loading tuning decisions failed", "asset", assetID, "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func itoa(v int64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
