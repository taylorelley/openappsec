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
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openappsec/openappsec/management/backend/internal/audit"
	"github.com/openappsec/openappsec/management/backend/internal/auth"
)

// The audit log is readable by any admin, so nothing secret may be recorded
// in it. An admin resetting another user's password must not leave that
// password sitting in the log in plaintext.
func TestAdminPasswordResetIsNotWrittenToTheAuditLog(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	const secret = "a-very-secret-new-password"

	var created auth.User
	h.decode(h.do(http.MethodPost, "/api/users", map[string]any{
		"username": "target", "password": "initial-password-1", "role": "viewer",
	}), http.StatusCreated, &created)

	h.decode(h.do(http.MethodPatch, "/api/users/"+created.ID.String(),
		map[string]any{"password": secret}), http.StatusOK, nil)

	// Check the API surface an admin actually reads.
	var entries []audit.Entry
	h.decode(h.do(http.MethodGet, "/api/audit", nil), http.StatusOK, &entries)

	for _, e := range entries {
		if strings.Contains(string(e.Detail), secret) {
			t.Fatalf("audit entry %q leaked the password: %s", e.Action, e.Detail)
		}
	}

	// And check the table directly, in case the API ever stops returning the
	// detail column.
	var raw string
	err := h.store.Pool.QueryRow(context.Background(),
		`SELECT coalesce(string_agg(detail::text, ' '), '') FROM audit_log`).Scan(&raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, secret) {
		t.Fatalf("audit_log table contains the plaintext password: %s", raw)
	}

	// The change must still be recorded — redaction, not omission.
	var found bool
	for _, e := range entries {
		if e.Action != "user.updated" {
			continue
		}
		found = true
		var detail map[string]any
		if err := json.Unmarshal(e.Detail, &detail); err != nil {
			t.Fatalf("audit detail is not an object: %s", e.Detail)
		}
		if detail["passwordChanged"] != true {
			t.Errorf("the password change should still be recorded: %s", e.Detail)
		}
	}
	if !found {
		t.Fatal("no user.updated audit entry was written")
	}

	// The new password must actually work, so redaction did not break the update.
	h.login("target", secret)
}

// The same applies to creating a user with a password.
func TestUserCreationDoesNotLeakThePassword(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	const secret = "another-secret-password-9"

	h.decode(h.do(http.MethodPost, "/api/users", map[string]any{
		"username": "created", "password": secret, "role": "editor",
	}), http.StatusCreated, nil)

	var raw string
	if err := h.store.Pool.QueryRow(context.Background(),
		`SELECT coalesce(string_agg(detail::text, ' '), '') FROM audit_log`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, secret) {
		t.Fatalf("audit_log contains the plaintext password: %s", raw)
	}
}

// Changing your own password goes through a different handler; check it too.
func TestSelfPasswordChangeDoesNotLeak(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	const secret = "my-brand-new-password-42"

	h.decode(h.do(http.MethodPost, "/api/me/password", map[string]any{
		"currentPassword": "integration-test-password",
		"newPassword":     secret,
	}), http.StatusNoContent, nil)

	var raw string
	if err := h.store.Pool.QueryRow(context.Background(),
		`SELECT coalesce(string_agg(detail::text, ' '), '') FROM audit_log`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, secret) {
		t.Fatalf("audit_log contains the plaintext password: %s", raw)
	}

	h.login("admin", secret)
}

// The enrollment token is a live credential for the agent plane; it must not
// be recorded either.
func TestEnrollmentTokenIsNotAudited(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	var enrolled struct {
		EnrollmentToken string `json:"enrollmentToken"`
	}
	h.decode(h.do(http.MethodPost, "/api/agents",
		map[string]any{"name": "audited-agent"}), http.StatusCreated, &enrolled)

	if enrolled.EnrollmentToken == "" {
		t.Fatal("no token was issued")
	}

	var raw string
	if err := h.store.Pool.QueryRow(context.Background(),
		`SELECT coalesce(string_agg(detail::text, ' '), '') FROM audit_log`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, enrolled.EnrollmentToken) {
		t.Fatalf("audit_log contains the enrollment token: %s", raw)
	}
}

// Resetting a password is how an operator responds to a compromised account.
// If existing sessions survive it, the reset does not actually evict anyone —
// the attacker keeps working until the session TTL expires.
func TestAdminPasswordResetRevokesExistingSessions(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")
	adminCookie := h.sessionCookie

	var created auth.User
	h.decode(h.do(http.MethodPost, "/api/users", map[string]any{
		"username": "compromised", "password": "original-password-1", "role": "editor",
	}), http.StatusCreated, &created)

	// The "attacker" signs in and holds a session.
	h.login("compromised", "original-password-1")
	victimCookie := h.sessionCookie

	h.decode(h.do(http.MethodGet, "/api/me", nil), http.StatusOK, nil)

	// The operator resets the password.
	h.sessionCookie = adminCookie
	h.decode(h.do(http.MethodPatch, "/api/users/"+created.ID.String(),
		map[string]any{"password": "brand-new-password-2"}), http.StatusOK, nil)

	// The held session must no longer work.
	h.sessionCookie = victimCookie
	resp := h.do(http.MethodGet, "/api/me", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the pre-reset session still works (%s); the reset evicted nobody", resp.Status)
	}

	// And the new password works.
	h.login("compromised", "brand-new-password-2")
}

// Changing your own password should not log you out of the session you are
// using to change it.
func TestSelfPasswordChangeKeepsTheCurrentSessionUsable(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	h.decode(h.do(http.MethodPost, "/api/me/password", map[string]any{
		"currentPassword": "integration-test-password",
		"newPassword":     "self-service-password-3",
	}), http.StatusNoContent, nil)

	// Still signed in, using whatever cookie the server left us with.
	h.decode(h.do(http.MethodGet, "/api/me", nil), http.StatusOK, nil)
}
