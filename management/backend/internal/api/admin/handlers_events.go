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
	"sort"
	"strings"

	"github.com/openappsec/openappsec/management/backend/internal/events"
)

func (s *Server) searchParams(r *http.Request) events.SearchParams {
	from, to := timeRange(r)
	return events.SearchParams{
		Query:   r.URL.Query().Get("q"),
		From:    from,
		To:      to,
		AgentID: optionalAgentID(r),
		Limit:   queryInt(r, "limit", 100),
		Offset:  queryInt(r, "offset", 0),
	}
}

func (s *Server) handleSearchEvents(w http.ResponseWriter, r *http.Request) {
	result, err := s.events.Search(r.Context(), s.searchParams(r))
	if err != nil {
		// A bad query is the user's typo, not a server fault, and the message
		// is what tells them which field they got wrong.
		if strings.HasPrefix(err.Error(), "invalid query") {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeStoreError(w, err, "events")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id, err := intParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid event id")
		return
	}
	raw, err := s.events.Get(r.Context(), id)
	if err != nil {
		writeStoreError(w, err, "event")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(raw); err != nil {
		return
	}
}

// handleEventFields powers query-bar autocomplete.
func (s *Server) handleEventFields(w http.ResponseWriter, r *http.Request) {
	fields := events.KnownFields()
	sort.Strings(fields)
	writeJSON(w, http.StatusOK, fields)
}

func (s *Server) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.events.Summary(r.Context(), s.searchParams(r))
	if err != nil {
		if strings.HasPrefix(err.Error(), "invalid query") {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeStoreError(w, err, "summary")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleDashboardTimeline(w http.ResponseWriter, r *http.Request) {
	groupBy := r.URL.Query().Get("groupBy")
	if groupBy == "" {
		groupBy = "securityaction"
	}
	buckets, err := s.events.Timeline(r.Context(), s.searchParams(r), groupBy, queryInt(r, "buckets", 48))
	if err != nil {
		if strings.HasPrefix(err.Error(), "invalid query") {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeStoreError(w, err, "timeline")
		return
	}
	writeJSON(w, http.StatusOK, buckets)
}

func (s *Server) handleDashboardTop(w http.ResponseWriter, r *http.Request) {
	field := r.URL.Query().Get("field")
	if field == "" {
		writeError(w, http.StatusBadRequest, "field is required")
		return
	}
	entries, err := s.events.Top(r.Context(), s.searchParams(r), field, queryInt(r, "limit", 10))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entries)
}
