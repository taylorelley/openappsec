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
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/openappsec/openappsec/management/backend/internal/auth"
	"github.com/openappsec/openappsec/management/backend/internal/policy"
)

// handleGetDeployedPolicy returns the policy currently assigned to the fleet,
// which is what the editor opens on.
func (s *Server) handleGetDeployedPolicy(w http.ResponseWriter, r *http.Request) {
	rev, err := s.policies.DeployedRevision(r.Context(), optionalAgentID(r))
	if err != nil {
		writeStoreError(w, err, "policy")
		return
	}
	writeJSON(w, http.StatusOK, rev)
}

// handlePolicySchema serves the schema the manager validates against, so the
// UI's forms and this server cannot disagree about what is legal.
func (s *Server) handlePolicySchema(w http.ResponseWriter, r *http.Request) {
	raw, err := policy.SchemaJSON()
	if err != nil {
		writeStoreError(w, err, "schema")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(raw); err != nil {
		return
	}
}

// handleRenderedPolicy shows the exact local_policy.yaml an agent will receive.
func (s *Server) handleRenderedPolicy(w http.ResponseWriter, r *http.Request) {
	body, etag, _, err := s.policies.Rendered(r.Context(), optionalAgentID(r))
	if err != nil {
		writeStoreError(w, err, "policy")
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("ETag", etag)
	if _, err := w.Write(body); err != nil {
		return
	}
}

func (s *Server) handleListRevisions(w http.ResponseWriter, r *http.Request) {
	revisions, err := s.policies.ListRevisions(r.Context(), queryInt(r, "limit", 50))
	if err != nil {
		writeStoreError(w, err, "revisions")
		return
	}
	writeJSON(w, http.StatusOK, revisions)
}

func (s *Server) handleGetRevision(w http.ResponseWriter, r *http.Request) {
	id, err := intParam(r, "id")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid revision id")
		return
	}
	rev, err := s.policies.GetRevision(r.Context(), id)
	if err != nil {
		writeStoreError(w, err, "revision")
		return
	}
	writeJSON(w, http.StatusOK, rev)
}

func (s *Server) handleRevisionDiff(w http.ResponseWriter, r *http.Request) {
	from, err := strconv.ParseInt(chiParam(r, "from"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid from revision")
		return
	}
	to, err := strconv.ParseInt(chiParam(r, "to"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid to revision")
		return
	}

	diff, err := s.policies.Diff(r.Context(), from, to)
	if err != nil {
		writeStoreError(w, err, "revision")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"diff": diff})
}

type policyBodyRequest struct {
	Body    policy.Document `json:"body"`
	Message string          `json:"message"`
}

// handleValidatePolicy checks a candidate without storing it. The editor calls
// this on every change: a policy that fails to load leaves almost no trace on
// the agent, so it must never reach one.
func (s *Server) handleValidatePolicy(w http.ResponseWriter, r *http.Request) {
	var req policyBodyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	result, err := policy.Validate(req.Body)
	if err != nil {
		writeStoreError(w, err, "policy")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDiffCandidate(w http.ResponseWriter, r *http.Request) {
	var req policyBodyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	diff, err := s.policies.DiffAgainstDeployed(r.Context(), req.Body)
	if err != nil {
		writeStoreError(w, err, "policy")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"diff": diff})
}

func (s *Server) handleCreateRevision(w http.ResponseWriter, r *http.Request) {
	var req policyBodyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	user := auth.MustUser(r.Context())

	rev, err := s.policies.CreateRevision(r.Context(), req.Body, req.Message, &user.ID)
	if err != nil {
		// Validation failures are the caller's problem, not the server's.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit.Record(r.Context(), r, "policy.revision_created", "revision",
		strconv.FormatInt(rev.ID, 10), map[string]any{"message": req.Message, "checksum": rev.Checksum})
	writeJSON(w, http.StatusCreated, rev)
}

type enforceRequest struct {
	RevisionID int64      `json:"revisionId"`
	AgentID    *uuid.UUID `json:"agentId,omitempty"`
}

// handleEnforce assigns a revision, which both writes the shared-volume
// artefact and changes what the pull companion will fetch.
func (s *Server) handleEnforce(w http.ResponseWriter, r *http.Request) {
	var req enforceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RevisionID <= 0 {
		writeError(w, http.StatusBadRequest, "revisionId is required")
		return
	}
	user := auth.MustUser(r.Context())

	if err := s.policies.Assign(r.Context(), req.AgentID, req.RevisionID, &user.ID); err != nil {
		writeStoreError(w, err, "revision")
		return
	}

	target := "fleet"
	if req.AgentID != nil {
		target = req.AgentID.String()
	}
	s.audit.Record(r.Context(), r, "policy.enforced", "revision",
		strconv.FormatInt(req.RevisionID, 10), map[string]any{"target": target})

	writeJSON(w, http.StatusOK, map[string]any{
		"revisionId": req.RevisionID,
		"target":     target,
	})
}

// exceptionFromEventRequest builds an exception from a security event, which
// is the "this was a false positive" action on an event row.
type exceptionFromEventRequest struct {
	EventID int64    `json:"eventId"`
	Name    string   `json:"name"`
	Action  string   `json:"action"`
	Keys    []string `json:"keys"`
}

// handleExceptionFromEvent returns a candidate policy with the exception
// added. It deliberately does not enforce: the operator reviews the diff and
// presses Enforce, so a false positive never silently widens the policy.
func (s *Server) handleExceptionFromEvent(w http.ResponseWriter, r *http.Request) {
	var req exceptionFromEventRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Action == "" {
		req.Action = "accept"
	}
	switch req.Action {
	case "skip", "accept", "drop", "suppressLog":
	default:
		writeError(w, http.StatusBadRequest,
			"action must be one of skip, accept, drop or suppressLog")
		return
	}

	raw, err := s.events.Get(r.Context(), req.EventID)
	if err != nil {
		writeStoreError(w, err, "event")
		return
	}

	conditions, err := conditionsFromEvent(raw, req.Keys)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(conditions) == 0 {
		writeError(w, http.StatusBadRequest,
			"none of the requested keys are present on that event")
		return
	}

	rev, err := s.policies.DeployedRevision(r.Context(), nil)
	if err != nil {
		writeStoreError(w, err, "policy")
		return
	}
	candidate, err := rev.Body.Clone()
	if err != nil {
		writeStoreError(w, err, "policy")
		return
	}

	name := req.Name
	if name == "" {
		name = fmt.Sprintf("exception-from-event-%d", req.EventID)
	}
	exception := map[string]any{
		"name":      name,
		"action":    req.Action,
		"condition": conditions,
	}

	// Checked rather than asserted: a silent fallback here would replace the
	// policy's existing exceptions with a list containing only the new one,
	// and the operator would review a candidate that had quietly lost them.
	existing := []any{}
	if raw, present := candidate["exceptions"]; present && raw != nil {
		list, ok := raw.([]any)
		if !ok {
			writeError(w, http.StatusConflict,
				"the deployed policy's exceptions field is not a list; fix it in the policy editor first")
			return
		}
		existing = list
	}
	candidate["exceptions"] = append(existing, exception)

	// Attach it to the default rule. An exception that is defined but never
	// referenced has no effect, which is a particularly bad failure here: the
	// operator would believe the false positive was handled.
	policies, ok := candidate["policies"].(map[string]any)
	if !ok {
		writeError(w, http.StatusConflict, "the deployed policy has no policies section")
		return
	}
	def, ok := policies["default"].(map[string]any)
	if !ok {
		writeError(w, http.StatusConflict,
			"the deployed policy has no default rule to attach the exception to")
		return
	}
	refs, _ := def["exceptions"].([]any)
	def["exceptions"] = append(refs, name)

	result, err := policy.Validate(candidate)
	if err != nil {
		writeStoreError(w, err, "policy")
		return
	}
	diff, err := s.policies.DiffAgainstDeployed(r.Context(), candidate)
	if err != nil {
		writeStoreError(w, err, "policy")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"body":       candidate,
		"validation": result,
		"diff":       diff,
		"exception":  exception,
	})
}

// eventConditionKeys maps the exception condition keys the agent understands
// (components/security_apps/local_policy_mgmt_gen/new_exceptions.cc:85+) onto
// the event fields they are derived from.
var eventConditionKeys = map[string]string{
	"sourceIp":         "sourceIP",
	"url":              "httpUriPath",
	"hostName":         "httpHostName",
	"paramName":        "matchedParameter",
	"paramValue":       "matchedSample",
	"protectionName":   "protectionId",
	"countryCode":      "sourceCountryCode",
	"countryName":      "sourceCountryName",
	"sourceIdentifier": "httpSourceId",
}

// conditionsFromEvent reads the requested keys out of the stored raw event.
func conditionsFromEvent(raw json.RawMessage, keys []string) ([]any, error) {
	if len(keys) == 0 {
		// A sensible default: narrow enough to be safe, broad enough to be
		// useful for the common "this URL and parameter are fine" case.
		keys = []string{"hostName", "url", "paramName"}
	}

	var doc struct {
		EventSource map[string]any `json:"eventSource"`
		EventData   map[string]any `json:"eventData"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("stored event is not decodable")
	}

	lookup := func(field string) string {
		for _, section := range []map[string]any{doc.EventData, doc.EventSource} {
			for k, v := range section {
				if !equalFold(k, field) {
					continue
				}
				if s, ok := v.(string); ok {
					return s
				}
			}
		}
		return ""
	}

	conditions := []any{}
	for _, key := range keys {
		field, ok := eventConditionKeys[key]
		if !ok {
			return nil, fmt.Errorf("unsupported exception key %q", key)
		}
		if value := lookup(field); value != "" {
			conditions = append(conditions, map[string]any{"key": key, "value": value})
		}
	}
	return conditions, nil
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
