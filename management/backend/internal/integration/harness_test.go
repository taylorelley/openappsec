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

// Package integration exercises the manager end to end: an agent posting
// events, an operator editing and enforcing policy, and the companion pulling
// and applying it.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openappsec/openappsec/management/backend/internal/api/admin"
	agentapi "github.com/openappsec/openappsec/management/backend/internal/api/agent"
	"github.com/openappsec/openappsec/management/backend/internal/audit"
	"github.com/openappsec/openappsec/management/backend/internal/auth"
	"github.com/openappsec/openappsec/management/backend/internal/events"
	"github.com/openappsec/openappsec/management/backend/internal/fleet"
	"github.com/openappsec/openappsec/management/backend/internal/ingest"
	"github.com/openappsec/openappsec/management/backend/internal/learning"
	"github.com/openappsec/openappsec/management/backend/internal/policy"
	"github.com/openappsec/openappsec/management/backend/internal/store"
	"github.com/openappsec/openappsec/management/backend/internal/store/storetest"
)

type harness struct {
	t *testing.T

	store    *store.Store
	auth     *auth.Service
	fleet    *fleet.Service
	policies *policy.Service
	learn    *learning.Service
	events   *events.Service

	admin *httptest.Server
	agent *httptest.Server

	// tmp stands in for the shared volumes the manager writes to.
	policyPath        string
	sharedStoragePath string

	sessionCookie *http.Cookie
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	ctx := context.Background()
	db := storetest.Fresh(t)

	dir := t.TempDir()
	h := &harness{
		t:                 t,
		store:             db,
		policyPath:        dir + "/appsec/local_policy.yaml",
		sharedStoragePath: dir + "/db",
	}

	h.auth = auth.NewService(db.Pool, time.Hour)
	h.fleet = fleet.NewService(db.Pool)
	h.policies = policy.NewService(db.Pool, h.policyPath)
	h.learn = learning.NewService(db.Pool, h.sharedStoragePath)
	h.events = events.NewService(db.Pool)
	auditLog := audit.New(db.Pool)
	writer := ingest.NewWriter(db.Pool)

	if _, err := h.auth.Bootstrap(ctx, "admin", "integration-test-password"); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if err := h.policies.EnsureSeedRevision(ctx); err != nil {
		t.Fatalf("seed revision: %v", err)
	}

	h.admin = httptest.NewServer(admin.NewServer(
		h.auth, auditLog, h.events, h.fleet, h.policies, h.learn, false, nil).Routes())
	h.agent = httptest.NewServer(agentapi.NewServer(
		db.Pool, writer, h.fleet, h.policies, h.learn).Routes())

	t.Cleanup(func() {
		h.admin.Close()
		h.agent.Close()
		db.Close()
	})
	return h
}

// login authenticates and remembers the session cookie for later requests.
func (h *harness) login(username, password string) {
	h.t.Helper()

	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := http.Post(h.admin.URL+"/api/login", "application/json", bytes.NewReader(body))
	if err != nil {
		h.t.Fatalf("login request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(resp.Body)
		h.t.Fatalf("login failed: %s: %s", resp.Status, detail)
	}
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookieName {
			h.sessionCookie = c
		}
	}
	if h.sessionCookie == nil {
		h.t.Fatal("login did not set a session cookie")
	}
}

// do issues an authenticated admin-plane request.
func (h *harness) do(method, path string, body any) *http.Response {
	h.t.Helper()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, h.admin.URL+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if h.sessionCookie != nil {
		req.AddCookie(h.sessionCookie)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}

	// Follow a re-issued session cookie, as a browser would. Changing your own
	// password rotates the session, so a test that keeps using the old cookie
	// would see a spurious 401.
	for _, c := range resp.Cookies() {
		if c.Name == auth.SessionCookieName && c.Value != "" {
			h.sessionCookie = c
		}
	}
	return resp
}

// decode reads a JSON response, failing on an unexpected status.
func (h *harness) decode(resp *http.Response, wantStatus int, dst any) {
	h.t.Helper()
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	if resp.StatusCode != wantStatus {
		h.t.Fatalf("expected status %d, got %d: %s", wantStatus, resp.StatusCode, raw)
	}
	if dst != nil {
		if err := json.Unmarshal(raw, dst); err != nil {
			h.t.Fatalf("decoding response: %v (body: %s)", err, raw)
		}
	}
}

// postBulk sends a bulk event payload to the agent plane, exactly as the agent
// would with the local-tuning log destination enabled.
func (h *harness) postBulk(payload string) {
	h.t.Helper()

	resp, err := http.Post(h.agent.URL+"/api/v1/agents/events/bulk",
		"application/json", bytes.NewReader([]byte(payload)))
	if err != nil {
		h.t.Fatalf("bulk post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(resp.Body)
		h.t.Fatalf("bulk ingest failed: %s: %s", resp.Status, detail)
	}
}
