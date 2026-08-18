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
	"strconv"

	"github.com/openappsec/openappsec/management/backend/internal/auth"
)

func (s *Server) handleLearningAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := s.learn.AssetsLearning(r.Context())
	if err != nil {
		writeStoreError(w, err, "learning")
		return
	}
	writeJSON(w, http.StatusOK, assets)
}

func (s *Server) handleSuggestions(w http.ResponseWriter, r *http.Request) {
	assetID := r.URL.Query().Get("assetId")
	if assetID == "" {
		writeError(w, http.StatusBadRequest, "assetId is required")
		return
	}
	suggestions, err := s.learn.Suggestions(r.Context(),
		r.URL.Query().Get("tenantId"), assetID, queryInt(r, "limit", 50))
	if err != nil {
		writeStoreError(w, err, "suggestions")
		return
	}
	writeJSON(w, http.StatusOK, suggestions)
}

func (s *Server) handleListDecisions(w http.ResponseWriter, r *http.Request) {
	decisions, err := s.learn.ListDecisions(r.Context(),
		r.URL.Query().Get("tenantId"), r.URL.Query().Get("assetId"))
	if err != nil {
		writeStoreError(w, err, "decisions")
		return
	}
	writeJSON(w, http.StatusOK, decisions)
}

type setDecisionRequest struct {
	TenantID   string `json:"tenantId"`
	AssetID    string `json:"assetId"`
	EventType  string `json:"eventType"`
	EventTitle string `json:"eventTitle"`
	Decision   string `json:"decision"`
}

// handleSetDecision records a benign/malicious/dismiss verdict and republishes
// decisions.data. The agent picks the change up on its next 30-minute poll.
func (s *Server) handleSetDecision(w http.ResponseWriter, r *http.Request) {
	var req setDecisionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	user := auth.MustUser(r.Context())

	decision, err := s.learn.SetDecision(r.Context(), req.TenantID, req.AssetID,
		req.EventType, req.EventTitle, req.Decision, &user.ID)
	if err != nil {
		if decision == nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		// The decision was stored but publishing failed; report it rather than
		// letting the operator believe the agent will act on it.
		s.audit.Record(r.Context(), r, "learning.decision_set", "asset", req.AssetID, req)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"decision": decision,
			"warning":  err.Error(),
		})
		return
	}

	s.audit.Record(r.Context(), r, "learning.decision_set", "asset", req.AssetID, req)
	writeJSON(w, http.StatusOK, decision)
}

func (s *Server) handleDeleteDecision(w http.ResponseWriter, r *http.Request) {
	id, err := intParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid decision id")
		return
	}
	if err := s.learn.DeleteDecision(r.Context(), id); err != nil {
		writeStoreError(w, err, "decision")
		return
	}
	s.audit.Record(r.Context(), r, "learning.decision_deleted", "decision",
		strconv.FormatInt(id, 10), nil)
	w.WriteHeader(http.StatusNoContent)
}
