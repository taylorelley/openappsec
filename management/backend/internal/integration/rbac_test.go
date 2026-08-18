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

package integration

import (
	"net/http"
	"testing"

	"github.com/openappsec/openappsec/management/backend/internal/audit"
	"github.com/openappsec/openappsec/management/backend/internal/auth"
	"github.com/openappsec/openappsec/management/backend/internal/policy"
)

// A viewer may read everything and change nothing.
func TestViewerCannotMutate(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	h.decode(h.do(http.MethodPost, "/api/users", map[string]any{
		"username": "readonly", "password": "viewer-password-1", "role": "viewer",
	}), http.StatusCreated, nil)

	var deployed policy.Revision
	h.decode(h.do(http.MethodGet, "/api/policy", nil), http.StatusOK, &deployed)

	h.login("readonly", "viewer-password-1")

	// Reads still work.
	h.decode(h.do(http.MethodGet, "/api/events", nil), http.StatusOK, nil)
	h.decode(h.do(http.MethodGet, "/api/policy", nil), http.StatusOK, nil)
	h.decode(h.do(http.MethodGet, "/api/agents", nil), http.StatusOK, nil)

	// Every mutation is refused.
	forbidden := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/policy/revisions",
			map[string]any{"body": deployed.Body, "message": "nope"}},
		{http.MethodPost, "/api/policy/enforce", map[string]any{"revisionId": deployed.ID}},
		{http.MethodPost, "/api/agents", map[string]any{"name": "nope"}},
		{http.MethodPost, "/api/learning/decisions", map[string]any{
			"assetId": "a", "eventType": "url", "eventTitle": "/x", "decision": "benign"}},
		{http.MethodPost, "/api/users", map[string]any{
			"username": "x", "password": "another-password", "role": "admin"}},
	}
	for _, c := range forbidden {
		resp := h.do(c.method, c.path, c.body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s: expected 403 for a viewer, got %s", c.method, c.path, resp.Status)
		}
	}
}

// An editor may change policy but not manage users.
func TestEditorCannotManageUsers(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	h.decode(h.do(http.MethodPost, "/api/users", map[string]any{
		"username": "editor1", "password": "editor-password-1", "role": "editor",
	}), http.StatusCreated, nil)

	var deployed policy.Revision
	h.decode(h.do(http.MethodGet, "/api/policy", nil), http.StatusOK, &deployed)

	h.login("editor1", "editor-password-1")

	// Policy work is allowed.
	var rev policy.Revision
	h.decode(h.do(http.MethodPost, "/api/policy/revisions",
		map[string]any{"body": deployed.Body, "message": "editor revision"}),
		http.StatusCreated, &rev)
	h.decode(h.do(http.MethodPost, "/api/policy/enforce",
		map[string]any{"revisionId": rev.ID}), http.StatusOK, nil)

	// User management is not.
	resp := h.do(http.MethodGet, "/api/users", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor listing users: expected 403, got %s", resp.Status)
	}
}

func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{"/api/events", "/api/policy", "/api/agents", "/api/me"} {
		resp := h.do(http.MethodGet, path, nil) // no session cookie set
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without a session: expected 401, got %s", path, resp.Status)
		}
	}
}

func TestLoginFailuresDoNotDistinguishUnknownUsers(t *testing.T) {
	h := newHarness(t)

	for _, c := range []struct{ user, pass string }{
		{"admin", "wrong-password"},
		{"no-such-user", "wrong-password"},
	} {
		resp := h.do(http.MethodPost, "/api/login",
			map[string]string{"username": c.user, "password": c.pass})
		var body map[string]string
		h.decode(resp, http.StatusUnauthorized, &body)
		if body["error"] != "invalid username or password" {
			t.Errorf("login as %q leaked detail: %q", c.user, body["error"])
		}
	}
}

// Locking every admin out of the installation must not be possible.
func TestCannotRemoveTheLastAdmin(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	var me auth.User
	h.decode(h.do(http.MethodGet, "/api/me", nil), http.StatusOK, &me)

	resp := h.do(http.MethodPatch, "/api/users/"+me.ID.String(), map[string]any{"role": "viewer"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("demoting the only admin: expected 409, got %s", resp.Status)
	}

	resp = h.do(http.MethodPatch, "/api/users/"+me.ID.String(), map[string]any{"disabled": true})
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("disabling the only admin: expected 409, got %s", resp.Status)
	}

	resp = h.do(http.MethodDelete, "/api/users/"+me.ID.String(), nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("deleting your own account: expected 409, got %s", resp.Status)
	}
}

// Every policy change must be reconstructable after the fact.
func TestMutationsAreAudited(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	var deployed policy.Revision
	h.decode(h.do(http.MethodGet, "/api/policy", nil), http.StatusOK, &deployed)

	candidate, _ := deployed.Body.Clone()
	candidate["policies"].(map[string]any)["default"].(map[string]any)["mode"] = "prevent"

	var rev policy.Revision
	h.decode(h.do(http.MethodPost, "/api/policy/revisions",
		map[string]any{"body": candidate, "message": "audited change"}),
		http.StatusCreated, &rev)
	h.decode(h.do(http.MethodPost, "/api/policy/enforce",
		map[string]any{"revisionId": rev.ID}), http.StatusOK, nil)

	var entries []audit.Entry
	h.decode(h.do(http.MethodGet, "/api/audit", nil), http.StatusOK, &entries)

	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Action] = true
		if e.Username == "" {
			t.Errorf("audit entry %q has no actor", e.Action)
		}
	}
	for _, want := range []string{"user.login", "policy.revision_created", "policy.enforced"} {
		if !seen[want] {
			t.Errorf("expected an audit entry for %q; saw %v", want, seen)
		}
	}
}

// A disabled account's live sessions must stop working immediately.
func TestDisablingAUserRevokesTheirSession(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	var created auth.User
	h.decode(h.do(http.MethodPost, "/api/users", map[string]any{
		"username": "temp", "password": "temp-password-123", "role": "editor",
	}), http.StatusCreated, &created)

	adminCookie := h.sessionCookie
	h.login("temp", "temp-password-123")
	tempCookie := h.sessionCookie

	// The temp user works.
	h.decode(h.do(http.MethodGet, "/api/me", nil), http.StatusOK, nil)

	h.sessionCookie = adminCookie
	h.decode(h.do(http.MethodPatch, "/api/users/"+created.ID.String(),
		map[string]any{"disabled": true}), http.StatusOK, nil)

	h.sessionCookie = tempCookie
	resp := h.do(http.MethodGet, "/api/me", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a disabled user's session should stop working, got %s", resp.Status)
	}
}
