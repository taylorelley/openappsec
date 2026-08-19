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

package ingest

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// The bulk body shape is defined by LogBulkRest::genJson in
// core/include/services_sdk/resources/report/log_rest.h:82-95.
func TestParseBulkEnvelope(t *testing.T) {
	var env BulkEnvelope
	if err := json.Unmarshal(loadFixture(t, "waap_bulk.json"), &env); err != nil {
		t.Fatalf("decode bulk: %v", err)
	}
	if len(env.Logs) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(env.Logs))
	}
	// Fog ids start at 1, not 0.
	if env.Logs[0].ID != 1 {
		t.Fatalf("expected first id 1, got %d", env.Logs[0].ID)
	}
}

func TestNormalizeWAAPEvent(t *testing.T) {
	var env BulkEnvelope
	if err := json.Unmarshal(loadFixture(t, "waap_bulk.json"), &env); err != nil {
		t.Fatal(err)
	}
	report, err := ParseReport(env.Logs[0].Log)
	if err != nil {
		t.Fatalf("parse report: %v", err)
	}
	e := Normalize(report)

	checks := map[string]struct{ got, want string }{
		"eventName":        {e.EventName, "Web Request"},
		"eventSeverity":    {e.EventSeverity, "Critical"},
		"agentId":          {e.AgentID, "5f9c2b1e-0000-4a1b-9d3e-77aa11bb22cc"},
		"tenantId":         {e.TenantID, "tenant-001"},
		"assetName":        {e.AssetName, "juice-shop"},
		"securityAction":   {e.SecurityAction, "Prevent"},
		"waapIncidentType": {e.WaapIncidentType, "SQL Injection"},
		"sourceIp":         {e.SourceIP, "203.0.113.9"},
		"httpHostName":     {e.HTTPHostName, "juice.example.com"},
		"httpMethod":       {e.HTTPMethod, "GET"},
		"httpUriPath":      {e.HTTPURIPath, "/rest/products/search"},
		"matchedLocation":  {e.MatchedLocation, "url parameter"},
		"matchedParameter": {e.MatchedParameter, "q"},
		"matchedSample":    {e.MatchedSample, "' OR 1=1--"},
		"practiceType":     {e.PracticeType, "Threat Prevention"},
		"eventConfidence":  {e.EventConfidence, "Very High"},
		"serviceName":      {e.ServiceName, "http-transaction-handler"},
	}
	for name, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", name, c.got, c.want)
		}
	}

	if e.SourcePort == nil || *e.SourcePort != 51514 {
		t.Errorf("sourcePort not captured: %v", e.SourcePort)
	}
	if e.HTTPResponseCode == nil || *e.HTTPResponseCode != 403 {
		t.Errorf("httpResponseCode not captured: %v", e.HTTPResponseCode)
	}
	if e.WaapFinalScore == nil || *e.WaapFinalScore != 9.5 {
		t.Errorf("waapFinalScore not captured: %v", e.WaapFinalScore)
	}
	if len(e.EventTags) != 2 {
		t.Errorf("expected 2 event tags, got %v", e.EventTags)
	}

	// A parseable address must populate the inet column, which is what makes
	// CIDR filtering work.
	if e.SourceIPAddr == nil || *e.SourceIPAddr != "203.0.113.9" {
		t.Errorf("source_ip_addr not populated: %v", e.SourceIPAddr)
	}

	want := time.Date(2026, 8, 18, 10, 15, 30, 123000000, time.UTC)
	if !e.EventTime.Equal(want) {
		t.Errorf("eventTime = %v, want %v", e.EventTime, want)
	}
	if e.EventTime.Location() != time.UTC {
		t.Errorf("eventTime must be UTC, got %v", e.EventTime.Location())
	}
}

// The agent's timestamps carry no zone but are produced from gmtime, so they
// must be read as UTC. Reading them as local time would shift every event.
func TestEventTimeIsUTCWithoutZoneSuffix(t *testing.T) {
	got := ParseEventTime("2026-08-18T10:15:30.123")
	want := time.Date(2026, 8, 18, 10, 15, 30, 123000000, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestEventTimeFallsBackToNow(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	got := ParseEventTime("not a timestamp")
	if got.Before(before) {
		t.Fatalf("expected a fallback near now, got %v", got)
	}
}

// Only FogStream obfuscates, so a local-tuning deployment sees plaintext. A
// manager acting as a fog sees the encoded form, and both must decode.
func TestDeobfuscateRoundTrip(t *testing.T) {
	original := "' OR 1=1-- <script>alert(1)</script>"
	encoded := Obfuscate(original)

	if encoded == original {
		t.Fatal("Obfuscate returned the input unchanged")
	}
	if got := Deobfuscate(encoded); got != original {
		t.Fatalf("round trip failed: got %q, want %q", got, original)
	}
}

func TestDeobfuscatePassesThroughPlaintext(t *testing.T) {
	plain := "no marker here"
	if got := Deobfuscate(plain); got != plain {
		t.Fatalf("plaintext altered: %q", got)
	}
}

func TestDeobfuscateKeepsUndecodableValue(t *testing.T) {
	// Better to surface the raw value than to silently drop the field.
	bad := xorLabel + "!!!not base64!!!"
	if got := Deobfuscate(bad); got != bad {
		t.Fatalf("expected the value to be preserved, got %q", got)
	}
}

func TestObfuscatedFieldsAreDecodedDuringNormalize(t *testing.T) {
	raw := `{
		"eventTime": "2026-08-18T10:00:00.000",
		"eventName": "Web Request",
		"eventSource": {"agentId": "a-1"},
		"eventData": {"agentId": "a-1", "matchedSample": ` +
		mustJSONString(Obfuscate("' OR 1=1--")) + `}
	}`
	report, err := ParseReport([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	e := Normalize(report)
	if e.MatchedSample != "' OR 1=1--" {
		t.Fatalf("obfuscated field not decoded: %q", e.MatchedSample)
	}
}

// Nested objects are flattened by leaf name, which is how the SYNC_LEARNING
// payload's assetId/type/windowId become reachable.
func TestNestedFieldsAreFlattened(t *testing.T) {
	var env LogEnvelope
	if err := json.Unmarshal(loadFixture(t, "sync_learning.json"), &env); err != nil {
		t.Fatal(err)
	}
	report, err := ParseReport(env.Log)
	if err != nil {
		t.Fatal(err)
	}
	if got := report.String("windowId"); got != "17" {
		t.Errorf("windowId = %q, want 17", got)
	}
	if got := report.String("type"); got != "Indicators" {
		t.Errorf("type = %q, want Indicators", got)
	}
	if got := Normalize(report).NotificationID; got != SyncLearningNotificationID {
		t.Errorf("notificationId = %q, want the SYNC_LEARNING id", got)
	}
}

// The C++ emits camelCase names while the query language documents lower case;
// both must resolve to the same value.
func TestFieldLookupIsCaseInsensitive(t *testing.T) {
	report, err := ParseReport([]byte(
		`{"eventData":{"sourceIP":"1.2.3.4","waapIncidentType":"SQL Injection"}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sourceIP", "sourceip", "SOURCEIP"} {
		if got := report.String(name); got != "1.2.3.4" {
			t.Errorf("String(%q) = %q, want 1.2.3.4", name, got)
		}
	}
	if got := report.String("waapincidenttype"); got != "SQL Injection" {
		t.Errorf("lower-cased lookup failed: %q", got)
	}
}

func TestMissingFieldsYieldZeroValues(t *testing.T) {
	report, err := ParseReport([]byte(`{"eventName":"Bare"}`))
	if err != nil {
		t.Fatal(err)
	}
	e := Normalize(report)
	if e.AssetName != "" || e.SourceIP != "" {
		t.Fatal("absent fields should normalize to empty strings")
	}
	if e.SourcePort != nil || e.HTTPResponseCode != nil || e.WaapFinalScore != nil {
		t.Fatal("absent numeric fields should stay nil, not zero")
	}
	if e.EventTags == nil {
		t.Fatal("EventTags must be non-nil for the text[] column")
	}
}

func TestRawDocumentIsPreserved(t *testing.T) {
	report, err := ParseReport([]byte(`{"eventName":"X","eventData":{"futureField":"keep me"}}`))
	if err != nil {
		t.Fatal(err)
	}
	e := Normalize(report)
	var round map[string]any
	if err := json.Unmarshal(e.Raw, &round); err != nil {
		t.Fatalf("raw is not valid JSON: %v", err)
	}
	data := round["eventData"].(map[string]any)
	if data["futureField"] != "keep me" {
		t.Fatal("unindexed fields must survive in the raw document")
	}
}

func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
