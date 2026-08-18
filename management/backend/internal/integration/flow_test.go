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
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openappsec/openappsec/management/backend/internal/events"
	"github.com/openappsec/openappsec/management/backend/internal/fleet"
	"github.com/openappsec/openappsec/management/backend/internal/learning"
	"github.com/openappsec/openappsec/management/backend/internal/policy"
)

// bulkPayload builds a bulk body in the agent's wire format.
func bulkPayload(entries ...string) string {
	items := make([]string, 0, len(entries))
	for i, e := range entries {
		items = append(items, fmt.Sprintf(`{"id":%d,"log":%s}`, i+1, e))
	}
	return `{"logs":[` + strings.Join(items, ",") + `]}`
}

func waapLog(sourceIP, action, incident, uri, severity string, when time.Time) string {
	return fmt.Sprintf(`{
		"eventTime": %q,
		"eventName": "Web Request",
		"eventSeverity": %q,
		"eventPriority": "High",
		"eventType": "Event Driven",
		"eventLevel": "Incident",
		"eventAudience": "Security",
		"eventAudienceTeam": "WAAP",
		"eventTags": ["Web Application & API Protection"],
		"eventSource": {
			"agentId": "agent-integration-1",
			"eventTenantId": "tenant-int",
			"serviceName": "http-transaction-handler"
		},
		"eventData": {
			"agentId": "agent-integration-1",
			"tenantId": "tenant-int",
			"assetId": "asset-int-1",
			"assetName": "juice-shop",
			"sourceIP": %q,
			"sourcePort": 44444,
			"httpHostName": "juice.example.com",
			"httpMethod": "GET",
			"httpUriPath": %q,
			"httpResponseCode": 403,
			"practiceType": "Threat Prevention",
			"securityAction": %q,
			"waapIncidentType": %q,
			"matchedLocation": "url parameter",
			"matchedParameter": "q",
			"matchedSample": "' OR 1=1--",
			"eventConfidence": "Very High"
		}
	}`, when.UTC().Format("2006-01-02T15:04:05.000"), severity, sourceIP, uri, action, incident)
}

// The whole point of the manager: an agent posts to the fog's own event path,
// and the operator can find those events in the UI.
func TestIngestThenSearch(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	now := time.Now().UTC()
	h.postBulk(bulkPayload(
		waapLog("203.0.113.9", "Prevent", "SQL Injection", "/rest/products/search", "Critical", now),
		waapLog("203.0.113.9", "Prevent", "SQL Injection", "/rest/products/search", "Critical", now),
		waapLog("198.51.100.4", "Detect", "Cross Site Scripting", "/rest/feedback", "High", now),
	))

	var result events.SearchResult
	h.decode(h.do(http.MethodGet, "/api/events?limit=50", nil), http.StatusOK, &result)

	if result.Total != 3 {
		t.Fatalf("expected 3 ingested events, got %d", result.Total)
	}
	if result.Rows[0].AssetName != "juice-shop" {
		t.Errorf("assetName not normalized: %q", result.Rows[0].AssetName)
	}
	if result.Rows[0].AgentID == nil {
		t.Error("event was not linked to a discovered agent")
	}

	// An agent that has only ever sent events must still appear in the fleet.
	var agents []fleet.Agent
	h.decode(h.do(http.MethodGet, "/api/agents", nil), http.StatusOK, &agents)
	if len(agents) != 1 || agents[0].AgentUUID != "agent-integration-1" {
		t.Fatalf("expected the agent to be discovered from its events, got %+v", agents)
	}
}

func TestSearchWithEventQueryLanguage(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	now := time.Now().UTC()
	h.postBulk(bulkPayload(
		waapLog("203.0.113.9", "Prevent", "SQL Injection", "/rest/products/search", "Critical", now),
		waapLog("198.51.100.4", "Detect", "Cross Site Scripting", "/rest/feedback", "High", now),
		waapLog("203.0.113.77", "Detect", "SQL Injection", "/rest/admin", "High", now),
	))

	cases := []struct {
		query string
		want  int64
	}{
		{`securityaction:Prevent`, 1},
		{`securityaction:prevent`, 1},           // case-insensitive
		{`waapincidenttype:"SQL Injection"`, 2}, // quoted phrase
		{`waapincidenttype:"SQL Injection" AND securityaction:Detect`, 1},
		{`sourceip:203.0.113.0/24`, 2},                // CIDR
		{`sourceip:198.51.*`, 1},                      // wildcard
		{`sourceip:(203.0.113.9 OR 198.51.100.4)`, 2}, // value list
		{`NOT securityaction:Prevent`, 2},
		{`assetname:juice-shop`, 3},
		{`httpuripath:/rest/admin`, 1},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			var result events.SearchResult
			h.decode(h.do(http.MethodGet, "/api/events?q="+urlEncode(c.query), nil),
				http.StatusOK, &result)
			if result.Total != c.want {
				t.Errorf("query %q returned %d events, want %d", c.query, result.Total, c.want)
			}
		})
	}
}

func TestInvalidQueryIsRejectedWithAMessage(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	resp := h.do(http.MethodGet, "/api/events?q="+urlEncode("nosuchfield:x"), nil)
	var body map[string]string
	h.decode(resp, http.StatusBadRequest, &body)

	if !strings.Contains(body["error"], "nosuchfield") {
		t.Fatalf("error should name the offending field, got %q", body["error"])
	}
}

// The core operator loop: edit, review, enforce, and see it on disk.
func TestPolicyEditAndEnforce(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	var deployed policy.Revision
	h.decode(h.do(http.MethodGet, "/api/policy", nil), http.StatusOK, &deployed)

	if got := deployed.Body["apiVersion"]; got != "v1beta2" {
		t.Fatalf("seed revision apiVersion = %v", got)
	}

	// Switch the default rule from detect-learn to prevent-learn.
	candidate, err := deployed.Body.Clone()
	if err != nil {
		t.Fatal(err)
	}
	candidate["policies"].(map[string]any)["default"].(map[string]any)["mode"] = "prevent-learn"

	var validation policy.ValidationResult
	h.decode(h.do(http.MethodPost, "/api/policy/validate",
		map[string]any{"body": candidate}), http.StatusOK, &validation)
	if len(validation.Errors) != 0 {
		t.Fatalf("candidate should validate: %+v", validation.Errors)
	}

	var diffResp map[string]string
	h.decode(h.do(http.MethodPost, "/api/policy/diff",
		map[string]any{"body": candidate}), http.StatusOK, &diffResp)
	if !strings.Contains(diffResp["diff"], "prevent-learn") {
		t.Fatalf("diff should show the mode change:\n%s", diffResp["diff"])
	}

	var rev policy.Revision
	h.decode(h.do(http.MethodPost, "/api/policy/revisions",
		map[string]any{"body": candidate, "message": "move to prevent"}),
		http.StatusCreated, &rev)
	if rev.ID <= deployed.ID {
		t.Fatalf("new revision id %d should exceed %d", rev.ID, deployed.ID)
	}

	h.decode(h.do(http.MethodPost, "/api/policy/enforce",
		map[string]any{"revisionId": rev.ID}), http.StatusOK, nil)

	// Enforcing must write the artefact the co-located agent reads.
	written, err := os.ReadFile(h.policyPath)
	if err != nil {
		t.Fatalf("enforce did not write %s: %v", h.policyPath, err)
	}
	if !strings.Contains(string(written), "mode: prevent-learn") {
		t.Fatalf("written policy does not carry the change:\n%s", written)
	}
	// The renderer must emit the singular key the agent actually reads.
	if strings.Contains(string(written), "customResponses:") &&
		!strings.Contains(string(written), "customResponse:") {
		t.Fatal("written policy uses the plural key the agent ignores")
	}
}

func TestInvalidPolicyIsRejectedAndNothingIsWritten(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	var deployed policy.Revision
	h.decode(h.do(http.MethodGet, "/api/policy", nil), http.StatusOK, &deployed)

	// Capture what is on disk before the bad attempt.
	h.decode(h.do(http.MethodPost, "/api/policy/enforce",
		map[string]any{"revisionId": deployed.ID}), http.StatusOK, nil)
	before, err := os.ReadFile(h.policyPath)
	if err != nil {
		t.Fatal(err)
	}

	bad, err := deployed.Body.Clone()
	if err != nil {
		t.Fatal(err)
	}
	bad["policies"].(map[string]any)["default"].(map[string]any)["mode"] = "turbo"

	resp := h.do(http.MethodPost, "/api/policy/revisions",
		map[string]any{"body": bad, "message": "should not be stored"})
	var errBody map[string]string
	h.decode(resp, http.StatusBadRequest, &errBody)

	// The rendered artefact must be untouched by the rejected attempt.
	after, err := os.ReadFile(h.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("a rejected policy changed the artefact on disk")
	}

	var revisions []policy.Revision
	h.decode(h.do(http.MethodGet, "/api/policy/revisions", nil), http.StatusOK, &revisions)
	for _, r := range revisions {
		if r.Message == "should not be stored" {
			t.Fatal("an invalid policy was stored as a revision")
		}
	}
}

func TestRollbackRestoresThePreviousPolicy(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	var original policy.Revision
	h.decode(h.do(http.MethodGet, "/api/policy", nil), http.StatusOK, &original)

	candidate, _ := original.Body.Clone()
	candidate["policies"].(map[string]any)["default"].(map[string]any)["mode"] = "prevent"

	var rev policy.Revision
	h.decode(h.do(http.MethodPost, "/api/policy/revisions",
		map[string]any{"body": candidate, "message": "to prevent"}), http.StatusCreated, &rev)
	h.decode(h.do(http.MethodPost, "/api/policy/enforce",
		map[string]any{"revisionId": rev.ID}), http.StatusOK, nil)

	written, _ := os.ReadFile(h.policyPath)
	if !strings.Contains(string(written), "mode: prevent") {
		t.Fatal("the change was not applied before rollback")
	}

	// Rolling back is re-assignment of the earlier revision, not an edit.
	h.decode(h.do(http.MethodPost, "/api/policy/enforce",
		map[string]any{"revisionId": original.ID}), http.StatusOK, nil)

	written, _ = os.ReadFile(h.policyPath)
	if !strings.Contains(string(written), "mode: detect-learn") {
		t.Fatalf("rollback did not restore the original mode:\n%s", written)
	}
}

// The companion path: enrol an agent, pull its policy, confirm the ETag stops
// a redundant re-apply, and report status back.
func TestCompanionPullAndStatusRoundTrip(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	var enrolled struct {
		Agent           fleet.Agent `json:"agent"`
		EnrollmentToken string      `json:"enrollmentToken"`
	}
	h.decode(h.do(http.MethodPost, "/api/agents",
		map[string]any{"name": "edge-1", "agentUuid": "agent-remote-1"}),
		http.StatusCreated, &enrolled)

	if enrolled.EnrollmentToken == "" {
		t.Fatal("enrollment did not return a token")
	}

	pull := func(etag string) *http.Response {
		req, err := http.NewRequest(http.MethodGet, h.agent.URL+"/api/v1/fleet/policy", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+enrolled.EnrollmentToken)
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	resp := pull("")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("policy pull returned %s", resp.Status)
	}
	etag := resp.Header.Get("ETag")
	body := make([]byte, 64*1024)
	n, _ := resp.Body.Read(body)
	resp.Body.Close()

	if etag == "" {
		t.Fatal("policy pull did not return an ETag")
	}
	if !strings.Contains(string(body[:n]), "apiVersion: v1beta2") {
		t.Fatalf("pulled policy does not look like local_policy.yaml:\n%s", body[:n])
	}

	// An unchanged policy must not be re-applied: every apply reloads the agent.
	resp = pull(etag)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("expected 304 for an unchanged policy, got %s", resp.Status)
	}

	// A wrong token must be refused.
	req, _ := http.NewRequest(http.MethodGet, h.agent.URL+"/api/v1/fleet/policy", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a bad token, got %s", resp.Status)
	}

	// Status push updates the inventory.
	status := map[string]any{
		"report": map[string]string{
			"Last update status": "Succeeded",
			"Policy version":     "42",
			"Agent ID":           "agent-remote-1",
			"Profile ID":         "profile-1",
			"Tenant ID":          "tenant-int",
		},
		"appliedRevisionId": 1,
	}
	raw, _ := json.Marshal(status)
	req, _ = http.NewRequest(http.MethodPost, h.agent.URL+"/api/v1/fleet/status",
		strings.NewReader(string(raw)))
	req.Header.Set("Authorization", "Bearer "+enrolled.EnrollmentToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status push returned %s", resp.Status)
	}

	var agent fleet.Agent
	h.decode(h.do(http.MethodGet, "/api/agents/"+enrolled.Agent.ID.String(), nil),
		http.StatusOK, &agent)
	if agent.PolicyVersion != "42" {
		t.Errorf("policy version = %q, want 42", agent.PolicyVersion)
	}
	if agent.Health != fleet.HealthHealthy {
		t.Errorf("health = %q, want healthy", agent.Health)
	}
}

// Tuning decisions must reach the agent, which means both the HTTP endpoint
// and the shared-storage file.
func TestTuningDecisionIsPublishedInBothPlaces(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	h.decode(h.do(http.MethodPost, "/api/learning/decisions", map[string]any{
		"tenantId":   "tenant-int",
		"assetId":    "asset-int-1",
		"eventType":  "url",
		"eventTitle": "/rest/products/search",
		"decision":   "benign",
	}), http.StatusOK, nil)

	// (1) The file the agent actually fetches, via SHARED_STORAGE_HOST.
	path := filepath.Join(h.sharedStoragePath, "tenant-int", "asset-int-1", "tuning", "decisions.data")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("decisions.data was not written to the shared storage volume: %v", err)
	}

	var doc learning.DecisionsDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decisions.data is not valid JSON: %v", err)
	}
	if len(doc.Decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(doc.Decisions))
	}
	// These three field names are exactly what the agent's TuningEvent expects.
	d := doc.Decisions[0]
	if d.Decision != "benign" || d.EventType != "url" || d.EventTitle != "/rest/products/search" {
		t.Fatalf("decision does not match the agent's expected schema: %+v", d)
	}

	// (2) The HTTP endpoint, for deployments that point SHARED_STORAGE_HOST
	// at the manager. The path is the one TuningDecision.cc builds.
	resp, err := http.Get(h.agent.URL + "/api/tenant-int/asset-int-1/tuning/decisions.data")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("decisions endpoint returned %s", resp.Status)
	}

	var served learning.DecisionsDocument
	if err := json.NewDecoder(resp.Body).Decode(&served); err != nil {
		t.Fatal(err)
	}
	if len(served.Decisions) != 1 || served.Decisions[0] != d {
		t.Fatalf("HTTP and file bodies disagree: %+v vs %+v", served.Decisions, doc.Decisions)
	}
}

func TestInvalidTuningDecisionIsRejected(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	for _, bad := range []map[string]any{
		{"assetId": "a", "eventType": "nonsense", "eventTitle": "x", "decision": "benign"},
		{"assetId": "a", "eventType": "url", "eventTitle": "x", "decision": "maybe"},
		{"assetId": "a", "eventType": "url", "eventTitle": "", "decision": "benign"},
	} {
		resp := h.do(http.MethodPost, "/api/learning/decisions", bad)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("expected 400 for %+v, got %s", bad, resp.Status)
		}
	}
}

// Turning a false positive into an exception is the most common corrective
// action, and it must never widen policy without review.
func TestExceptionFromEventProducesAReviewableCandidate(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	h.postBulk(bulkPayload(waapLog("203.0.113.9", "Prevent", "SQL Injection",
		"/rest/products/search", "Critical", time.Now().UTC())))

	var result events.SearchResult
	h.decode(h.do(http.MethodGet, "/api/events", nil), http.StatusOK, &result)
	if len(result.Rows) == 0 {
		t.Fatal("no events to build an exception from")
	}

	var out struct {
		Body       policy.Document         `json:"body"`
		Validation policy.ValidationResult `json:"validation"`
		Diff       string                  `json:"diff"`
		Exception  map[string]any          `json:"exception"`
	}
	h.decode(h.do(http.MethodPost, "/api/policy/exception-from-event", map[string]any{
		"eventId": result.Rows[0].ID,
		"keys":    []string{"hostName", "url", "paramName"},
	}), http.StatusOK, &out)

	if len(out.Validation.Errors) != 0 {
		t.Fatalf("the generated candidate must validate: %+v", out.Validation.Errors)
	}
	conditions, _ := out.Exception["condition"].([]any)
	if len(conditions) != 3 {
		t.Fatalf("expected 3 conditions from the event, got %+v", conditions)
	}
	if !strings.Contains(out.Diff, "exception") {
		t.Fatalf("diff should show the new exception:\n%s", out.Diff)
	}

	// The exception must be referenced by the default rule, not merely defined.
	def := out.Body["policies"].(map[string]any)["default"].(map[string]any)
	refs, _ := def["exceptions"].([]any)
	if len(refs) == 0 {
		t.Fatal("the exception was defined but never referenced, so it would have no effect")
	}

	// Crucially, nothing is enforced until the operator says so.
	deployedNow, err := os.ReadFile(h.policyPath)
	if err == nil && strings.Contains(string(deployedNow), "exception-from-event") {
		t.Fatal("generating an exception must not enforce it")
	}
}

func TestLearningProgressIsDerivedFromEvents(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	now := time.Now().UTC()
	logs := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		logs = append(logs, waapLog(fmt.Sprintf("203.0.113.%d", i), "Detect",
			"SQL Injection", fmt.Sprintf("/rest/item/%d", i), "Low", now))
	}
	h.postBulk(bulkPayload(logs...))

	var assets []learning.AssetLearning
	h.decode(h.do(http.MethodGet, "/api/learning/assets", nil), http.StatusOK, &assets)

	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	a := assets[0]
	if a.TotalEvents != 12 {
		t.Errorf("totalEvents = %d, want 12", a.TotalEvents)
	}
	if a.UniqueSources != 12 {
		t.Errorf("uniqueSources = %d, want 12", a.UniqueSources)
	}
	// Far below the thresholds, so it must not claim readiness.
	if a.Readiness == learning.ReadinessReady {
		t.Error("an asset with 12 events must not be reported ready for prevent")
	}
	if a.Recommendation == "" {
		t.Error("a recommendation should always explain the readiness verdict")
	}

	var suggestions []learning.Suggestion
	h.decode(h.do(http.MethodGet, "/api/learning/suggestions?assetId=asset-int-1&tenantId=tenant-int",
		nil), http.StatusOK, &suggestions)
	if len(suggestions) == 0 {
		t.Fatal("expected tuning suggestions to be derived from the event stream")
	}
}

func TestDashboardAggregates(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	now := time.Now().UTC()
	h.postBulk(bulkPayload(
		waapLog("203.0.113.9", "Prevent", "SQL Injection", "/a", "Critical", now),
		waapLog("203.0.113.9", "Prevent", "SQL Injection", "/a", "Critical", now),
		waapLog("198.51.100.4", "Detect", "Cross Site Scripting", "/b", "High", now),
	))

	var summary events.Summary
	h.decode(h.do(http.MethodGet, "/api/dashboard/summary", nil), http.StatusOK, &summary)
	if summary.Total != 3 || summary.Prevented != 2 || summary.Detected != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	if summary.UniqueIPs != 2 {
		t.Errorf("uniqueSources = %d, want 2", summary.UniqueIPs)
	}
	if summary.BySeverity["Critical"] != 2 {
		t.Errorf("bySeverity = %+v", summary.BySeverity)
	}

	var top []events.TopEntry
	h.decode(h.do(http.MethodGet, "/api/dashboard/top?field=waapincidenttype", nil),
		http.StatusOK, &top)
	if len(top) != 2 || top[0].Key != "SQL Injection" || top[0].Count != 2 {
		t.Fatalf("top attack types = %+v", top)
	}

	var timeline []events.TimeBucket
	h.decode(h.do(http.MethodGet, "/api/dashboard/timeline?groupBy=securityaction", nil),
		http.StatusOK, &timeline)
	if len(timeline) == 0 {
		t.Fatal("timeline should not be empty")
	}
}

// A malformed record in a bulk must not cost the good records: the agent does
// not retry individual logs.
func TestMalformedRecordInBulkDoesNotDiscardTheBatch(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	now := time.Now().UTC()
	payload := `{"logs":[
		{"id":1,"log":` + waapLog("203.0.113.9", "Prevent", "SQL Injection", "/a", "Critical", now) + `},
		{"id":2,"log":"this is not an object"},
		{"id":3,"log":` + waapLog("203.0.113.10", "Detect", "XSS", "/b", "High", now) + `}
	]}`
	h.postBulk(payload)

	var result events.SearchResult
	h.decode(h.do(http.MethodGet, "/api/events", nil), http.StatusOK, &result)
	if result.Total != 2 {
		t.Fatalf("expected the 2 valid records to survive, got %d", result.Total)
	}
}

func TestSingleEventEndpoint(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	single := `{"log":` + waapLog("203.0.113.9", "Prevent", "SQL Injection",
		"/single", "Critical", time.Now().UTC()) + `}`
	resp, err := http.Post(h.agent.URL+"/api/v1/agents/events",
		"application/json", strings.NewReader(single))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("single event ingest returned %s", resp.Status)
	}

	var result events.SearchResult
	h.decode(h.do(http.MethodGet, "/api/events", nil), http.StatusOK, &result)
	if result.Total != 1 {
		t.Fatalf("expected 1 event, got %d", result.Total)
	}
}

func TestSyncLearningNotificationRecordsAWindow(t *testing.T) {
	h := newHarness(t)
	h.login("admin", "integration-test-password")

	body := `{"log":{
		"eventTime": "` + time.Now().UTC().Format("2006-01-02T15:04:05.000") + `",
		"eventName": "Sync learning",
		"eventSeverity": "Info",
		"eventAudienceTeam": "WAAP",
		"eventSource": {"agentId":"agent-integration-1","notificationId":"b9b9ab04-2e2a-4cd1-b7e5-2c956861fb69"},
		"eventData": {
			"agentId": "agent-integration-1",
			"tenantId": "tenant-int",
			"assetId": "asset-int-1",
			"notificationId": "b9b9ab04-2e2a-4cd1-b7e5-2c956861fb69",
			"notificationConsumerData": {
				"syncLearnNotificationConsumers": {
					"assetId": "asset-int-1", "type": "Indicators", "windowId": "17"
				}
			}
		}
	}}`
	resp, err := http.Post(h.agent.URL+"/api/v1/agents/events",
		"application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	var count int
	err = h.store.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM learning_windows WHERE asset_id = 'asset-int-1'
		   AND window_type = 'Indicators' AND window_id = '17'`).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected the learning window to be recorded, found %d", count)
	}
}

func urlEncode(s string) string {
	var sb strings.Builder
	for _, b := range []byte(s) {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9',
			b == '-', b == '_', b == '.', b == '~', b == '/':
			sb.WriteByte(b)
		default:
			sb.WriteString(fmt.Sprintf("%%%02X", b))
		}
	}
	return sb.String()
}
