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

package auth

import (
	"context"
	"encoding/json"
	"net/http"
)

type ctxKey int

const userCtxKey ctxKey = iota

// FromContext returns the authenticated user, if any.
func FromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userCtxKey).(*User)
	return u, ok
}

// MustUser returns the authenticated user. It is only safe inside handlers
// mounted behind RequireAuth.
func MustUser(ctx context.Context) *User {
	u, ok := FromContext(ctx)
	if !ok {
		panic("auth: no user in context; handler is not behind RequireAuth")
	}
	return u
}

// RequireAuth rejects unauthenticated requests.
func (s *Service) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(SessionCookieName)
		if err != nil || cookie.Value == "" {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		user, err := s.Resolve(r.Context(), cookie.Value)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "session expired or invalid")
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireEditor gates every mutating endpoint: viewers get a 403.
func (s *Service) RequireEditor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := FromContext(r.Context())
		if !ok || !user.Role.CanEdit() {
			writeErr(w, http.StatusForbidden, "this action requires the editor or admin role")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin gates user management and manager settings.
func (s *Service) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := FromContext(r.Context())
		if !ok || !user.Role.CanAdmin() {
			writeErr(w, http.StatusForbidden, "this action requires the admin role")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
