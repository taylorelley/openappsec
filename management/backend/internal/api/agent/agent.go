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

// Package agent implements the agent plane: the endpoints open-appsec agents
// and the appsec-agent-sync companion talk to.
//
// These paths are deliberately the fog's own paths. An agent redirected here
// by TUNING_HOST posts exactly what it would post to my.openappsec.io, so this
// surface is also the foundation for full fog emulation later.
//
// Security model: this listener is plain HTTP on port 80 because
// core/logging/k8s_svc_stream.cc hardcodes both the port and UNSECURE_CONN
// when posting to the tuning host. It must therefore be treated as an
// untrusted, internal-network-only surface. Event submissions carry no
// credentials at all (the agent sends only X-Tenant-Id), so they are bounded
// by body size and rate rather than authenticated; the companion endpoints,
// which can change policy, do require an enrolment token.
package agent

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openappsec/openappsec/management/backend/internal/fleet"
	"github.com/openappsec/openappsec/management/backend/internal/ingest"
	"github.com/openappsec/openappsec/management/backend/internal/learning"
	"github.com/openappsec/openappsec/management/backend/internal/policy"
)

// maxBodyBytes caps a single ingest request. The agent's bulk size defaults to
// 100 logs ("Sent log bulk size", core/logging/logging.cc:166) and extended
// logging can attach request bodies, so this is generous but finite.
const maxBodyBytes = 32 << 20 // 32 MiB

type Server struct {
	pool     *pgxpool.Pool
	writer   *ingest.Writer
	fleet    *fleet.Service
	policies *policy.Service
	learn    *learning.Service
}

func NewServer(
	pool *pgxpool.Pool,
	writer *ingest.Writer,
	fleetSvc *fleet.Service,
	policySvc *policy.Service,
	learnSvc *learning.Service,
) *Server {
	return &Server{pool: pool, writer: writer, fleet: fleetSvc, policies: policySvc, learn: learnSvc}
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	// Fog-shaped ingest. Unauthenticated by necessity; see the package comment.
	r.Post("/api/v1/agents/events", s.handleEvent)
	r.Post("/api/v1/agents/events/bulk", s.handleBulk)

	// Tuning decisions, polled by the agent every 30 minutes
	// (components/security_apps/waap/waap_clib/TuningDecision.cc:36-41).
	r.Get("/api/{tenantID}/{assetID}/tuning/decisions.data", s.handleTuningDecisions)
	r.Get("/api/{tenantID}/{assetID}/tuning/decisions", s.handleTuningDecisions)

	// appsec-agent-sync companion endpoints; these require an enrolment token.
	r.Route("/api/v1/fleet", func(r chi.Router) {
		r.Use(s.requireEnrollment)
		r.Get("/policy", s.handlePolicyPull)
		r.Post("/status", s.handleStatusPush)
	})

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.pool.Ping(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})

	return r
}

// handleEvent accepts the single-log body: {"log": {...}}.
func (s *Server) handleEvent(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var env ingest.LogEnvelope
	if err := json.NewDecoder(body).Decode(&env); err != nil {
		badRequest(w, "malformed log body")
		return
	}
	if len(env.Log) == 0 {
		badRequest(w, "missing log field")
		return
	}

	report, err := ingest.ParseReport(env.Log)
	if err != nil {
		badRequest(w, "malformed report")
		return
	}

	if err := s.writer.Write(r.Context(), []*ingest.Event{ingest.Normalize(report)}); err != nil {
		slog.Error("failed to persist event", "error", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleBulk accepts the bulk body: {"logs":[{"id":1,"log":{...}}, ...]}.
//
// A malformed individual report is skipped rather than failing the batch: the
// agent does not retry per-log, so rejecting the whole bulk would discard the
// good records alongside the bad one.
func (s *Server) handleBulk(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var env ingest.BulkEnvelope
	if err := json.NewDecoder(body).Decode(&env); err != nil {
		badRequest(w, "malformed bulk body")
		return
	}

	events := make([]*ingest.Event, 0, len(env.Logs))
	skipped := 0
	for _, item := range env.Logs {
		report, err := ingest.ParseReport(item.Log)
		if err != nil {
			skipped++
			continue
		}
		events = append(events, ingest.Normalize(report))
	}
	if skipped > 0 {
		slog.Warn("skipped malformed reports in bulk", "skipped", skipped, "accepted", len(events))
	}

	if err := s.writer.Write(r.Context(), events); err != nil {
		slog.Error("failed to persist bulk events", "error", err, "count", len(events))
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func badRequest(w http.ResponseWriter, msg string) {
	http.Error(w, msg, http.StatusBadRequest)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}
