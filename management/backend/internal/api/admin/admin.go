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

// Package admin implements the authenticated admin plane: the REST API behind
// the web UI, plus serving the UI itself.
package admin

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/openappsec/openappsec/management/backend/internal/audit"
	"github.com/openappsec/openappsec/management/backend/internal/auth"
	"github.com/openappsec/openappsec/management/backend/internal/events"
	"github.com/openappsec/openappsec/management/backend/internal/fleet"
	"github.com/openappsec/openappsec/management/backend/internal/learning"
	"github.com/openappsec/openappsec/management/backend/internal/policy"
)

type Server struct {
	auth     *auth.Service
	audit    *audit.Logger
	events   *events.Service
	fleet    *fleet.Service
	policies *policy.Service
	learn    *learning.Service

	// secureCookies is true only when the admin plane actually serves TLS.
	// Setting the Secure flag on a plain-HTTP listener would make the session
	// cookie silently unusable.
	secureCookies bool

	// ui is the built frontend, embedded into the binary. Nil serves an
	// explanatory placeholder instead, so an API-only build still runs.
	ui fs.FS
}

func NewServer(
	authSvc *auth.Service,
	auditLog *audit.Logger,
	eventsSvc *events.Service,
	fleetSvc *fleet.Service,
	policySvc *policy.Service,
	learnSvc *learning.Service,
	secureCookies bool,
	ui fs.FS,
) *Server {
	return &Server{
		auth: authSvc, audit: auditLog, events: eventsSvc, fleet: fleetSvc,
		policies: policySvc, learn: learnSvc, secureCookies: secureCookies, ui: ui,
	}
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)

	r.Route("/api", func(r chi.Router) {
		// Unauthenticated: login and the session probe the UI uses on load.
		r.Post("/login", s.handleLogin)
		r.Get("/session", s.handleSession)

		r.Group(func(r chi.Router) {
			r.Use(s.auth.RequireAuth)

			r.Post("/logout", s.handleLogout)
			r.Get("/me", s.handleMe)
			r.Post("/me/password", s.handleChangeOwnPassword)

			// Read paths are open to every authenticated role.
			r.Get("/events", s.handleSearchEvents)
			r.Get("/events/fields", s.handleEventFields)
			r.Get("/events/{id}", s.handleGetEvent)
			r.Get("/dashboard/summary", s.handleDashboardSummary)
			r.Get("/dashboard/timeline", s.handleDashboardTimeline)
			r.Get("/dashboard/top", s.handleDashboardTop)

			r.Get("/agents", s.handleListAgents)
			r.Get("/agents/{id}", s.handleGetAgent)
			r.Get("/agents/{id}/metrics", s.handleAgentMetrics)

			r.Get("/policy", s.handleGetDeployedPolicy)
			r.Get("/policy/schema", s.handlePolicySchema)
			r.Get("/policy/rendered", s.handleRenderedPolicy)
			r.Get("/policy/revisions", s.handleListRevisions)
			r.Get("/policy/revisions/{id}", s.handleGetRevision)
			r.Get("/policy/revisions/{from}/diff/{to}", s.handleRevisionDiff)
			r.Post("/policy/validate", s.handleValidatePolicy)
			r.Post("/policy/diff", s.handleDiffCandidate)
			r.Post("/policy/exception-from-event", s.handleExceptionFromEvent)

			r.Get("/learning/assets", s.handleLearningAssets)
			r.Get("/learning/suggestions", s.handleSuggestions)
			r.Get("/learning/decisions", s.handleListDecisions)

			r.Get("/audit", s.handleAudit)

			// Mutations require editor or admin.
			r.Group(func(r chi.Router) {
				r.Use(s.auth.RequireEditor)

				r.Post("/policy/revisions", s.handleCreateRevision)
				r.Post("/policy/enforce", s.handleEnforce)
				r.Post("/agents", s.handleEnrollAgent)
				r.Patch("/agents/{id}", s.handleUpdateAgent)
				r.Post("/agents/{id}/revoke", s.handleRevokeAgent)
				r.Post("/learning/decisions", s.handleSetDecision)
				r.Delete("/learning/decisions/{id}", s.handleDeleteDecision)
			})

			// User management and destructive fleet changes require admin.
			r.Group(func(r chi.Router) {
				r.Use(s.auth.RequireAdmin)

				r.Get("/users", s.handleListUsers)
				r.Post("/users", s.handleCreateUser)
				r.Patch("/users/{id}", s.handleUpdateUser)
				r.Delete("/users/{id}", s.handleDeleteUser)
				r.Delete("/agents/{id}", s.handleDeleteAgent)
			})
		})
	})

	s.mountUI(r)
	return r
}

// securityHeaders applies the headers appropriate to an application that edits
// WAF policy: no framing, no sniffing, no referrer leakage, and a CSP tight
// enough that an injected script has nowhere to call home.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "+
				"form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// ------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encoding response failed", "error", err)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// writeStoreError maps the domain not-found errors onto 404 and anything else
// onto 500, without leaking internal detail to the client.
func writeStoreError(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, policy.ErrNotFound),
		errors.Is(err, fleet.ErrNotFound),
		errors.Is(err, auth.ErrNotFound):
		writeError(w, http.StatusNotFound, what+" not found")
	default:
		slog.Error("request failed", "what", what, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	const maxBody = 8 << 20 // policies can be large
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request body")
		return false
	}
	return true
}

func uuidParam(r *http.Request, name string) (uuid.UUID, error) {
	return uuid.Parse(chi.URLParam(r, name))
}

func intParam(r *http.Request, name string) (int64, error) {
	return strconv.ParseInt(chi.URLParam(r, name), 10, 64)
}

func chiParam(r *http.Request, name string) string { return chi.URLParam(r, name) }

func queryInt(r *http.Request, name string, def int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

// timeRange reads the from/to query parameters, defaulting to the last 24
// hours, which is the window the dashboards open on.
func timeRange(r *http.Request) (time.Time, time.Time) {
	to := time.Now().UTC()
	from := to.Add(-24 * time.Hour)

	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t.UTC()
		}
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t.UTC()
		}
	}
	return from, to
}

func optionalAgentID(r *http.Request) *uuid.UUID {
	v := r.URL.Query().Get("agentId")
	if v == "" {
		return nil
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return nil
	}
	return &id
}
