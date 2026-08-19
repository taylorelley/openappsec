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

package companion

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeAgent stands in for the agent's local orchestration REST API.
type fakeAgent struct {
	mu            sync.Mutex
	applyCalls    []string
	applyStatus   int
	policyVersion string
	server        *httptest.Server
}

func newFakeAgent(t *testing.T) *fakeAgent {
	t.Helper()
	a := &fakeAgent{applyStatus: http.StatusOK, policyVersion: "7"}

	mux := http.NewServeMux()
	mux.HandleFunc("/set-apply-policy", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req applyPolicyRequest
		_ = json.Unmarshal(body, &req)

		a.mu.Lock()
		a.applyCalls = append(a.applyCalls, req.PolicyPath)
		status := a.applyStatus
		a.mu.Unlock()

		if status != http.StatusOK {
			http.Error(w, "policy load failed", status)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/show-orchestration-status", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		version := a.policyVersion
		a.mu.Unlock()
		// The literal key names the agent uses.
		_ = json.NewEncoder(w).Encode(map[string]string{
			"Last update status": "Succeeded",
			"Policy version":     version,
			"Agent ID":           "agent-abc",
			"Profile ID":         "profile-1",
			"Tenant ID":          "tenant-1",
		})
	})

	a.server = httptest.NewServer(mux)
	t.Cleanup(a.server.Close)
	return a
}

func (a *fakeAgent) applies() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.applyCalls...)
}

// fakeManager stands in for the manager's agent plane.
type fakeManager struct {
	mu       sync.Mutex
	policy   string
	etag     string
	revision string
	statuses []StatusPushRecord
	server   *httptest.Server
}

type StatusPushRecord struct {
	Report      map[string]string `json:"report"`
	AppliedRev  int64             `json:"appliedRevisionId"`
	ApplyFailed bool              `json:"applyFailed"`
	ApplyError  string            `json:"applyError"`
}

func newFakeManager(t *testing.T, token string) *fakeManager {
	t.Helper()
	m := &fakeManager{policy: "apiVersion: v1beta2\n", etag: `"v1"`, revision: "3"}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/fleet/policy", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		m.mu.Lock()
		policy, etag, revision := m.policy, m.etag, m.revision
		m.mu.Unlock()

		if r.Header.Get("If-None-Match") == etag {
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("X-Policy-Revision", revision)
		_, _ = io.WriteString(w, policy)
	})
	mux.HandleFunc("/api/v1/fleet/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		var push StatusPushRecord
		_ = json.NewDecoder(r.Body).Decode(&push)

		m.mu.Lock()
		m.statuses = append(m.statuses, push)
		m.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *fakeManager) setPolicy(body, etag, revision string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy, m.etag, m.revision = body, etag, revision
}

func (m *fakeManager) pushes() []StatusPushRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]StatusPushRecord(nil), m.statuses...)
}

func newTestCompanion(t *testing.T, mgr *fakeManager, agent *fakeAgent, token string) (*Companion, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "local_policy.yaml")

	return New(Config{
		ManagerURL:       mgr.server.URL,
		Token:            token,
		PolicyPath:       path,
		AgentPolicyPath:  "/etc/cp/conf/local_policy.yaml",
		OrchestrationURL: agent.server.URL,
	}), path
}

func TestSyncWritesPolicyAndAsksTheAgentToApply(t *testing.T) {
	const token = "test-token"
	mgr := newFakeManager(t, token)
	agent := newFakeAgent(t)
	c, path := newTestCompanion(t, mgr, agent, token)

	mgr.setPolicy("apiVersion: v1beta2\npolicies:\n  default:\n    mode: prevent\n", `"abc"`, "9")

	if err := c.Sync(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("policy was not written: %v", err)
	}
	if !strings.Contains(string(written), "mode: prevent") {
		t.Fatalf("unexpected policy contents:\n%s", written)
	}

	applies := agent.applies()
	if len(applies) != 1 {
		t.Fatalf("expected exactly 1 apply call, got %d", len(applies))
	}
	// The agent must be told its own view of the path, not the companion's.
	if applies[0] != "/etc/cp/conf/local_policy.yaml" {
		t.Fatalf("apply used the wrong path: %q", applies[0])
	}

	pushes := mgr.pushes()
	if len(pushes) != 1 {
		t.Fatalf("expected 1 status push, got %d", len(pushes))
	}
	if pushes[0].AppliedRev != 9 {
		t.Errorf("appliedRevisionId = %d, want 9", pushes[0].AppliedRev)
	}
	if pushes[0].ApplyFailed {
		t.Error("apply should not be reported as failed")
	}
	if pushes[0].Report["Policy version"] != "7" {
		t.Errorf("status report was not forwarded: %+v", pushes[0].Report)
	}
}

// Re-applying an unchanged policy reloads the agent for nothing, so the ETag
// must short-circuit it.
func TestUnchangedPolicyIsNotReapplied(t *testing.T) {
	const token = "test-token"
	mgr := newFakeManager(t, token)
	agent := newFakeAgent(t)
	c, _ := newTestCompanion(t, mgr, agent, token)

	ctx := context.Background()
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}

	if got := len(agent.applies()); got != 1 {
		t.Fatalf("expected 1 apply across 3 syncs, got %d", got)
	}
	// Liveness is still reported on every cycle.
	if got := len(mgr.pushes()); got != 3 {
		t.Fatalf("expected a status push per sync, got %d", got)
	}
}

func TestChangedPolicyTriggersANewApply(t *testing.T) {
	const token = "test-token"
	mgr := newFakeManager(t, token)
	agent := newFakeAgent(t)
	c, path := newTestCompanion(t, mgr, agent, token)

	ctx := context.Background()
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	mgr.setPolicy("apiVersion: v1beta2\n# changed\n", `"v2"`, "10")
	if err := c.Sync(ctx); err != nil {
		t.Fatal(err)
	}

	if got := len(agent.applies()); got != 2 {
		t.Fatalf("expected 2 applies, got %d", got)
	}
	written, _ := os.ReadFile(path)
	if !strings.Contains(string(written), "# changed") {
		t.Fatal("the updated policy was not written")
	}
}

// A failed apply must reach the manager, or it is only visible in this
// process's log.
func TestFailedApplyIsReportedToTheManager(t *testing.T) {
	const token = "test-token"
	mgr := newFakeManager(t, token)
	agent := newFakeAgent(t)
	agent.applyStatus = http.StatusInternalServerError

	c, _ := newTestCompanion(t, mgr, agent, token)

	err := c.Sync(context.Background())
	if err == nil {
		t.Fatal("expected sync to report the apply failure")
	}

	pushes := mgr.pushes()
	if len(pushes) != 1 {
		t.Fatalf("expected a status push despite the failure, got %d", len(pushes))
	}
	if !pushes[0].ApplyFailed {
		t.Error("the push should be marked as a failed apply")
	}
	if pushes[0].ApplyError == "" {
		t.Error("the push should carry the failure reason")
	}
}

// A failed apply must not be remembered as applied, or the next sync would
// skip retrying it.
func TestFailedApplyIsRetriedOnTheNextSync(t *testing.T) {
	const token = "test-token"
	mgr := newFakeManager(t, token)
	agent := newFakeAgent(t)
	agent.applyStatus = http.StatusInternalServerError

	c, _ := newTestCompanion(t, mgr, agent, token)
	ctx := context.Background()

	_ = c.Sync(ctx)
	agent.mu.Lock()
	agent.applyStatus = http.StatusOK
	agent.mu.Unlock()

	if err := c.Sync(ctx); err != nil {
		t.Fatalf("the retry should succeed: %v", err)
	}
	if got := len(agent.applies()); got != 2 {
		t.Fatalf("expected the apply to be retried, got %d calls", got)
	}
}

func TestBadTokenIsReported(t *testing.T) {
	mgr := newFakeManager(t, "the-real-token")
	agent := newFakeAgent(t)
	c, _ := newTestCompanion(t, mgr, agent, "a-wrong-token")

	err := c.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "enrollment token") {
		t.Fatalf("expected a clear token error, got %v", err)
	}
	if len(agent.applies()) != 0 {
		t.Fatal("nothing should be applied when the manager rejects us")
	}
}

// A truncated write would leave the agent reading a partial document, so the
// replacement must be atomic and must not leave temporary files behind.
func TestPolicyWriteIsAtomic(t *testing.T) {
	const token = "test-token"
	mgr := newFakeManager(t, token)
	agent := newFakeAgent(t)
	c, path := newTestCompanion(t, mgr, agent, token)

	if err := c.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".local_policy-") {
			t.Fatalf("a temporary file was left behind: %s", e.Name())
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("policy file mode = %v, want 0644", info.Mode().Perm())
	}
}

func TestEmptyPolicyIsRefused(t *testing.T) {
	const token = "test-token"
	mgr := newFakeManager(t, token)
	agent := newFakeAgent(t)
	mgr.setPolicy("", `"empty"`, "1")

	c, path := newTestCompanion(t, mgr, agent, token)

	if err := c.Sync(context.Background()); err == nil {
		t.Fatal("an empty policy must be refused rather than written")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("nothing should have been written")
	}
	if len(agent.applies()) != 0 {
		t.Fatal("the agent must not be asked to apply an empty policy")
	}
}

func TestDefaultsMatchTheAgentLayout(t *testing.T) {
	cfg := Config{}
	cfg.setDefaults()

	// These defaults come from the agent's own installed layout.
	if cfg.PolicyPath != "/ext/appsec/local_policy.yaml" {
		t.Errorf("PolicyPath = %q", cfg.PolicyPath)
	}
	if cfg.AgentPolicyPath != "/etc/cp/conf/local_policy.yaml" {
		t.Errorf("AgentPolicyPath = %q", cfg.AgentPolicyPath)
	}
	if cfg.OrchestrationURL != "http://127.0.0.1:7777" {
		t.Errorf("OrchestrationURL = %q; the orchestration API is loopback-only", cfg.OrchestrationURL)
	}
}
