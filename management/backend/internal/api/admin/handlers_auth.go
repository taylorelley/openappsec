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

package admin

import (
	"errors"
	"net/http"

	"github.com/openappsec/openappsec/management/backend/internal/auth"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	token, user, err := s.auth.Login(r.Context(), req.Username, req.Password,
		r.UserAgent(), r.RemoteAddr)
	if err != nil {
		// Do not distinguish a bad password from an unknown user; a disabled
		// account is worth reporting so the operator is not left guessing.
		if errors.Is(err, auth.ErrUserDisabled) {
			writeError(w, http.StatusForbidden, "this account is disabled")
			return
		}
		if !errors.Is(err, auth.ErrInvalidCredentials) {
			writeStoreError(w, err, "login")
			return
		}
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	s.auth.SetSessionCookie(w, token, s.secureCookies)
	// Attributed explicitly: the session cookie is not on this request, so
	// there is no authenticated user on the context yet.
	s.audit.RecordAs(r.Context(), r, user, "user.login", "user", user.ID.String(), nil)
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(auth.SessionCookieName); err == nil {
		if err := s.auth.Logout(r.Context(), cookie.Value); err != nil {
			writeStoreError(w, err, "session")
			return
		}
	}
	auth.ClearSessionCookie(w, s.secureCookies)
	w.WriteHeader(http.StatusNoContent)
}

// handleSession lets the UI discover whether it already has a valid session
// without treating a 401 as an error condition.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(auth.SessionCookieName)
	if err != nil || cookie.Value == "" {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	user, err := s.auth.Resolve(r.Context(), cookie.Value)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": user})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, auth.MustUser(r.Context()))
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (s *Server) handleChangeOwnPassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	user := auth.MustUser(r.Context())

	// Re-authenticate before changing the password, so a borrowed session
	// cannot be used to lock the real owner out.
	if _, _, err := s.auth.Login(r.Context(), user.Username, req.CurrentPassword,
		r.UserAgent(), r.RemoteAddr); err != nil {
		writeError(w, http.StatusForbidden, "current password is incorrect")
		return
	}

	if err := s.auth.SetPassword(r.Context(), user.ID, req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// SetPassword revokes every session for the user, including this one.
	// That is what makes an admin reset effective, but it would log a user
	// out for changing their own password, so issue a fresh session here.
	token, _, err := s.auth.Login(r.Context(), user.Username, req.NewPassword,
		r.UserAgent(), r.RemoteAddr)
	if err != nil {
		// The password did change, so report success rather than an error the
		// caller cannot act on; they simply need to sign in again.
		s.audit.Record(r.Context(), r, "user.password_changed", "user", user.ID.String(), nil)
		auth.ClearSessionCookie(w, s.secureCookies)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.auth.SetSessionCookie(w, token, s.secureCookies)

	s.audit.Record(r.Context(), r, "user.password_changed", "user", user.ID.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- users

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.auth.ListUsers(r.Context())
	if err != nil {
		writeStoreError(w, err, "users")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

type createUserRequest struct {
	Username string    `json:"username"`
	Email    string    `json:"email"`
	Password string    `json:"password"`
	Role     auth.Role `json:"role"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	user, err := s.auth.CreateUser(r.Context(), req.Username, req.Email, req.Password, req.Role)
	if err != nil {
		if errors.Is(err, auth.ErrDuplicate) {
			writeError(w, http.StatusConflict, "a user with that name already exists")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit.Record(r.Context(), r, "user.created", "user", user.ID.String(),
		map[string]any{"username": user.Username, "role": user.Role})
	writeJSON(w, http.StatusCreated, user)
}

type updateUserRequest struct {
	Role     *auth.Role `json:"role,omitempty"`
	Disabled *bool      `json:"disabled,omitempty"`
	Password *string    `json:"password,omitempty"`
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuidParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	var req updateUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	target, err := s.auth.GetUser(r.Context(), id)
	if err != nil {
		writeStoreError(w, err, "user")
		return
	}

	// Refuse any change that would leave the installation with no way in.
	demoting := req.Role != nil && *req.Role != auth.RoleAdmin
	disabling := req.Disabled != nil && *req.Disabled
	if target.Role == auth.RoleAdmin && !target.Disabled && (demoting || disabling) {
		admins, err := s.auth.CountAdmins(r.Context())
		if err != nil {
			writeStoreError(w, err, "users")
			return
		}
		if admins <= 1 {
			writeError(w, http.StatusConflict,
				"this is the only active admin; promote another user before changing this one")
			return
		}
	}

	if req.Role != nil {
		if err := s.auth.UpdateUserRole(r.Context(), id, *req.Role); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.Disabled != nil {
		if err := s.auth.SetUserDisabled(r.Context(), id, *req.Disabled); err != nil {
			writeStoreError(w, err, "user")
			return
		}
	}
	if req.Password != nil {
		if err := s.auth.SetPassword(r.Context(), id, *req.Password); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Recorded field by field rather than by passing req: it carries the new
	// password, and the audit log is readable by every admin through
	// handleAudit. The fact of a password change is worth keeping; the
	// password itself is not.
	detail := map[string]any{}
	if req.Role != nil {
		detail["role"] = *req.Role
	}
	if req.Disabled != nil {
		detail["disabled"] = *req.Disabled
	}
	if req.Password != nil {
		detail["passwordChanged"] = true
	}
	s.audit.Record(r.Context(), r, "user.updated", "user", id.String(), detail)
	updated, err := s.auth.GetUser(r.Context(), id)
	if err != nil {
		writeStoreError(w, err, "user")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuidParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	actor := auth.MustUser(r.Context())
	if actor.ID == id {
		writeError(w, http.StatusConflict, "you cannot delete your own account")
		return
	}

	target, err := s.auth.GetUser(r.Context(), id)
	if err != nil {
		writeStoreError(w, err, "user")
		return
	}
	if target.Role == auth.RoleAdmin && !target.Disabled {
		admins, err := s.auth.CountAdmins(r.Context())
		if err != nil {
			writeStoreError(w, err, "users")
			return
		}
		if admins <= 1 {
			writeError(w, http.StatusConflict, "this is the only active admin")
			return
		}
	}

	if err := s.auth.DeleteUser(r.Context(), id); err != nil {
		writeStoreError(w, err, "user")
		return
	}
	s.audit.Record(r.Context(), r, "user.deleted", "user", id.String(),
		map[string]any{"username": target.Username})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries, err := s.audit.List(r.Context(), queryInt(r, "limit", 200))
	if err != nil {
		writeStoreError(w, err, "audit log")
		return
	}
	writeJSON(w, http.StatusOK, entries)
}
