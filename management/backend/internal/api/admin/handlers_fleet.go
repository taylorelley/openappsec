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
	"net/http"
)

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.fleet.List(r.Context())
	if err != nil {
		writeStoreError(w, err, "agents")
		return
	}
	writeJSON(w, http.StatusOK, agents)
}

func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	id, err := uuidParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent id")
		return
	}
	agent, err := s.fleet.Get(r.Context(), id)
	if err != nil {
		writeStoreError(w, err, "agent")
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (s *Server) handleAgentMetrics(w http.ResponseWriter, r *http.Request) {
	id, err := uuidParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent id")
		return
	}
	samples, err := s.fleet.LatestMetrics(r.Context(), id)
	if err != nil {
		writeStoreError(w, err, "metrics")
		return
	}
	writeJSON(w, http.StatusOK, samples)
}

type enrollAgentRequest struct {
	Name      string `json:"name"`
	AgentUUID string `json:"agentUuid"`
}

// handleEnrollAgent issues a companion token. The token is returned exactly
// once — only its hash is stored — so the response is the operator's only
// chance to copy it.
func (s *Server) handleEnrollAgent(w http.ResponseWriter, r *http.Request) {
	var req enrollAgentRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	agent, token, err := s.fleet.Enroll(r.Context(), req.Name, req.AgentUUID)
	if err != nil {
		writeStoreError(w, err, "agent")
		return
	}
	s.audit.Record(r.Context(), r, "agent.enrolled", "agent", agent.ID.String(),
		map[string]any{"name": agent.Name})

	writeJSON(w, http.StatusCreated, map[string]any{
		"agent":           agent,
		"enrollmentToken": token,
		"note":            "This token is shown only once. Store it in the companion's configuration now.",
	})
}

type updateAgentRequest struct {
	Name            *string `json:"name,omitempty"`
	MetricsEndpoint *string `json:"metricsEndpoint,omitempty"`
}

func (s *Server) handleUpdateAgent(w http.ResponseWriter, r *http.Request) {
	id, err := uuidParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent id")
		return
	}
	var req updateAgentRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.Name != nil {
		if err := s.fleet.Rename(r.Context(), id, *req.Name); err != nil {
			writeStoreError(w, err, "agent")
			return
		}
	}
	if req.MetricsEndpoint != nil {
		if err := s.fleet.SetMetricsEndpoint(r.Context(), id, *req.MetricsEndpoint); err != nil {
			writeStoreError(w, err, "agent")
			return
		}
	}

	s.audit.Record(r.Context(), r, "agent.updated", "agent", id.String(), req)
	agent, err := s.fleet.Get(r.Context(), id)
	if err != nil {
		writeStoreError(w, err, "agent")
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (s *Server) handleRevokeAgent(w http.ResponseWriter, r *http.Request) {
	id, err := uuidParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent id")
		return
	}
	if err := s.fleet.RevokeEnrollment(r.Context(), id); err != nil {
		writeStoreError(w, err, "agent")
		return
	}
	s.audit.Record(r.Context(), r, "agent.enrollment_revoked", "agent", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	id, err := uuidParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent id")
		return
	}
	if err := s.fleet.Delete(r.Context(), id); err != nil {
		writeStoreError(w, err, "agent")
		return
	}
	s.audit.Record(r.Context(), r, "agent.deleted", "agent", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}
