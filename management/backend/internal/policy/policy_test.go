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

package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoFile locates a file in the open-appsec checkout this package lives in.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "..", rel)
}

// The embedded schema must not drift from the repository's canonical copy —
// the agent validates against the latter, so a divergence would mean the
// manager accepts policies the agent rejects.
func TestEmbeddedSchemaMatchesRepository(t *testing.T) {
	embedded, err := schemaFS.ReadFile("schema/schema_v1beta2.yaml")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := os.ReadFile(repoFile(t, "config/linux/v1beta2/schema/schema_v1beta2.yaml"))
	if err != nil {
		t.Skipf("canonical schema not reachable from the test working directory: %v", err)
	}
	if string(embedded) != string(canonical) {
		t.Fatal("internal/policy/schema/schema_v1beta2.yaml has drifted from " +
			"config/linux/v1beta2/schema/schema_v1beta2.yaml; re-copy it")
	}
}

func TestEmbeddedDefaultPolicyMatchesRepository(t *testing.T) {
	embedded, err := schemaFS.ReadFile("schema/default_policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := os.ReadFile(repoFile(t, "config/linux/v1beta2/default/local_policy.yaml"))
	if err != nil {
		t.Skipf("canonical default policy not reachable: %v", err)
	}
	if string(embedded) != string(canonical) {
		t.Fatal("internal/policy/schema/default_policy.yaml has drifted from " +
			"config/linux/v1beta2/default/local_policy.yaml; re-copy it")
	}
}

// Every policy file shipped in the repository must validate. If one does not,
// either the manager's validator is wrong or the shipped file is.
func TestShippedPoliciesValidate(t *testing.T) {
	for _, rel := range []string{
		"config/linux/v1beta2/default/local_policy.yaml",
		"config/linux/v1beta2/prevent/local_policy.yaml",
		"config/linux/v1beta2/example/local_policy.yaml",
	} {
		t.Run(rel, func(t *testing.T) {
			raw, err := os.ReadFile(repoFile(t, rel))
			if err != nil {
				t.Skipf("not reachable: %v", err)
			}
			doc, err := ParseYAML(raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			result, err := Validate(doc)
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			if !result.OK() {
				t.Fatalf("shipped policy failed validation: %s", result.Error())
			}
		})
	}
}

// Discrepancy (2): the shipped default policy writes `customResponses`
// (plural) under policies.default, but the agent's NewParsedRule reads
// `customResponse`. The plural is silently ignored, so the manager warns.
func TestPluralCustomResponseIsWarned(t *testing.T) {
	raw, err := os.ReadFile(repoFile(t, "config/linux/v1beta2/default/local_policy.yaml"))
	if err != nil {
		t.Skipf("not reachable: %v", err)
	}
	doc, err := ParseYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := doc["policies"].(map[string]any)["default"].(map[string]any)["customResponses"]; !has {
		t.Skip("upstream default policy no longer uses the plural spelling")
	}

	result, err := Validate(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() {
		t.Fatalf("the plural spelling must warn, not fail: %s", result.Error())
	}
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w.Path, "customResponses") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a warning about the plural spelling, got %+v", result.Warnings)
	}
}

// ...and the renderer must fold it into the singular form so the agent
// actually honours the custom response.
func TestRendererFoldsPluralCustomResponseToSingular(t *testing.T) {
	doc := Document{
		"apiVersion": "v1beta2",
		"policies": map[string]any{
			"default": map[string]any{
				"mode":                      "detect-learn",
				"threatPreventionPractices": []any{"p"},
				"accessControlPractices":    []any{},
				"customResponses":           "my-response",
			},
		},
		"threatPreventionPractices": []any{map[string]any{"name": "p"}},
		"customResponses":           []any{map[string]any{"name": "my-response"}},
	}

	out, err := LocalPolicyYAML{}.Render(doc)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := ParseYAML(out)
	if err != nil {
		t.Fatalf("rendered output does not parse: %v", err)
	}
	def := rendered["policies"].(map[string]any)["default"].(map[string]any)

	if _, stillPlural := def["customResponses"]; stillPlural {
		t.Error("the plural key must not survive rendering; the agent ignores it")
	}
	if def["customResponse"] != "my-response" {
		t.Errorf("customResponse = %v, want my-response", def["customResponse"])
	}
}

// Discrepancy (1): autoUpgrade is parsed by the agent but missing from the
// shipped schema. With additionalProperties:false it would otherwise fail.
func TestAutoUpgradeIsAccepted(t *testing.T) {
	doc := minimalDoc()
	doc["autoUpgrade"] = []any{map[string]any{
		"name": "nightly",
		"mode": "scheduled",
		"schedule": map[string]any{
			"days":                      []any{"Monday"},
			"upgradeWindowStartHourUTC": "0:00",
			"upgradeWindowDuration":     4,
		},
	}}

	result, err := Validate(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() {
		t.Fatalf("autoUpgrade must be accepted (the agent parses it): %s", result.Error())
	}
}

// Discrepancy (3): rate-limit action/condition are in the schema but are not
// implemented by the agent's loader, so they warn rather than pass silently.
func TestRateLimitActionAndConditionWarn(t *testing.T) {
	doc := minimalDoc()
	doc["accessControlPractices"] = []any{map[string]any{
		"name": "ac",
		"rateLimit": map[string]any{
			"overrideMode": "inherited",
			"rules": []any{map[string]any{
				"limit":     100,
				"unit":      "minute",
				"uri":       "/api",
				"action":    "prevent",
				"condition": []any{map[string]any{"key": "sourceIP", "value": "10.0.0.0/8"}},
			}},
		},
	}}
	doc["policies"].(map[string]any)["default"].(map[string]any)["accessControlPractices"] = []any{"ac"}

	result, err := Validate(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() {
		t.Fatalf("unexpected errors: %s", result.Error())
	}

	var sawAction, sawCondition bool
	for _, w := range result.Warnings {
		if strings.HasSuffix(w.Path, "/action") {
			sawAction = true
		}
		if strings.HasSuffix(w.Path, "/condition") {
			sawCondition = true
		}
	}
	if !sawAction || !sawCondition {
		t.Fatalf("expected warnings for both unimplemented fields, got %+v", result.Warnings)
	}
}

// A rule naming a practice that does not exist yields a policy the agent will
// not load, and the agent reports that failure only at debug level — so the
// manager must catch it before apply.
func TestDanglingReferenceIsAnError(t *testing.T) {
	doc := minimalDoc()
	doc["policies"].(map[string]any)["default"].(map[string]any)["triggers"] = []any{"no-such-trigger"}

	result, err := Validate(doc)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK() {
		t.Fatal("expected a dangling trigger reference to be rejected")
	}
	if !strings.Contains(result.Error(), "no-such-trigger") {
		t.Fatalf("error should name the missing reference: %s", result.Error())
	}
}

func TestWrongAPIVersionIsRejected(t *testing.T) {
	doc := minimalDoc()
	doc["apiVersion"] = "v1beta1"

	result, err := Validate(doc)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK() {
		t.Fatal("v1beta1 must be rejected by the v1beta2 authoring path")
	}
}

func TestInvalidEnumIsRejected(t *testing.T) {
	doc := minimalDoc()
	doc["policies"].(map[string]any)["default"].(map[string]any)["mode"] = "turbo"

	result, err := Validate(doc)
	if err != nil {
		t.Fatal(err)
	}
	if result.OK() {
		t.Fatal("an invalid mode enum must be rejected")
	}
}

// Rendering then re-parsing must reproduce the document exactly, or the editor
// would lose data across a save.
func TestRenderRoundTripsShippedPolicies(t *testing.T) {
	for _, rel := range []string{
		"config/linux/v1beta2/default/local_policy.yaml",
		"config/linux/v1beta2/prevent/local_policy.yaml",
		"config/linux/v1beta2/example/local_policy.yaml",
	} {
		t.Run(rel, func(t *testing.T) {
			raw, err := os.ReadFile(repoFile(t, rel))
			if err != nil {
				t.Skipf("not reachable: %v", err)
			}
			doc, err := ParseYAML(raw)
			if err != nil {
				t.Fatal(err)
			}
			// The renderer intentionally rewrites the plural spelling, so
			// compare against the prepared form.
			expected, err := prepareForAgent(doc)
			if err != nil {
				t.Fatal(err)
			}

			out, err := LocalPolicyYAML{}.Render(doc)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseYAML(out)
			if err != nil {
				t.Fatalf("rendered output does not re-parse: %v\n%s", err, out)
			}
			assertSameJSON(t, expected, got)
		})
	}
}

// Key order follows the schema, not Go's map iteration, so that a rendered
// policy diffs cleanly between revisions.
func TestRenderKeyOrderIsSchemaDrivenAndStable(t *testing.T) {
	doc, err := DefaultDocument()
	if err != nil {
		t.Fatal(err)
	}
	first, err := LocalPolicyYAML{}.Render(doc)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := LocalPolicyYAML{}.Render(doc)
		if err != nil {
			t.Fatal(err)
		}
		if string(first) != string(again) {
			t.Fatal("rendering is not deterministic across runs")
		}
	}

	body := string(first)
	apiIdx := strings.Index(body, "apiVersion:")
	polIdx := strings.Index(body, "\npolicies:")
	tppIdx := strings.Index(body, "\nthreatPreventionPractices:")
	if apiIdx < 0 || polIdx < 0 || tppIdx < 0 {
		t.Fatalf("expected top-level sections in the output:\n%s", body)
	}
	if !(apiIdx < polIdx && polIdx < tppIdx) {
		t.Fatal("top-level keys should follow schema declaration order")
	}
}

// Empty arrays must render as `[]`. A bare key would become null after the
// agent's yq conversion, where it expects a list.
func TestEmptyArraysRenderAsFlowSequences(t *testing.T) {
	doc := minimalDoc()
	doc["policies"].(map[string]any)["specificRules"] = []any{}

	out, err := LocalPolicyYAML{}.Render(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "specificRules: []") {
		t.Fatalf("expected an explicit empty list, got:\n%s", out)
	}
}

func TestDefaultDocumentIsValid(t *testing.T) {
	doc, err := DefaultDocument()
	if err != nil {
		t.Fatal(err)
	}
	result, err := Validate(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() {
		t.Fatalf("the seed revision must validate: %s", result.Error())
	}
}

func TestChecksumIsOrderIndependent(t *testing.T) {
	a := Document{"apiVersion": "v1beta2", "policies": map[string]any{"x": 1, "y": 2}}
	b := Document{"policies": map[string]any{"y": 2, "x": 1}, "apiVersion": "v1beta2"}

	ca, err := a.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	cb, err := b.Checksum()
	if err != nil {
		t.Fatal(err)
	}
	if ca != cb {
		t.Fatal("checksum must not depend on key order")
	}

	c := Document{"apiVersion": "v1beta2", "policies": map[string]any{"x": 2, "y": 2}}
	cc, _ := c.Checksum()
	if ca == cc {
		t.Fatal("different content must produce different checksums")
	}
}

func TestCloneIsDeep(t *testing.T) {
	doc := minimalDoc()
	clone, err := doc.Clone()
	if err != nil {
		t.Fatal(err)
	}
	clone["policies"].(map[string]any)["default"].(map[string]any)["mode"] = "prevent"

	original := doc["policies"].(map[string]any)["default"].(map[string]any)["mode"]
	if original != "detect-learn" {
		t.Fatal("mutating a clone changed the original")
	}
}

// minimalDoc is the smallest document that satisfies the schema's required
// fields, used as a base for targeted negative tests.
func minimalDoc() Document {
	return Document{
		"apiVersion": "v1beta2",
		"policies": map[string]any{
			"default": map[string]any{
				"mode":                      "detect-learn",
				"threatPreventionPractices": []any{"tp"},
				"accessControlPractices":    []any{},
				"triggers":                  []any{},
				"exceptions":                []any{},
			},
			"specificRules": []any{},
		},
		"threatPreventionPractices": []any{
			map[string]any{
				"name":         "tp",
				"practiceMode": "inherited",
				"webAttacks":   map[string]any{"overrideMode": "inherited", "minimumConfidence": "high"},
				// The schema marks these three as required on every practice.
				"intrusionPrevention": map[string]any{"overrideMode": "inherited"},
				"fileSecurity":        map[string]any{"overrideMode": "inherited"},
				"snortSignatures":     map[string]any{"overrideMode": "inherited"},
			},
		},
	}
}

// assertSameJSON compares two documents by their JSON encoding. Go type
// identity is the wrong equality here: a document loaded from JSONB holds
// float64 where a freshly parsed YAML document holds int, yet the two describe
// the same policy.
func assertSameJSON(t *testing.T, want, got Document) {
	t.Helper()
	wb, err := want.JSON()
	if err != nil {
		t.Fatal(err)
	}
	gb, err := got.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(wb) != string(gb) {
		t.Fatalf("round trip changed the document\nwant: %s\ngot:  %s", wb, gb)
	}
}

// A whole-valued float must render as an integer. JSONB turns every integer
// into a float64, and yaml.v3 would otherwise write large values in scientific
// notation, which the agent cannot parse into its integer fields.
func TestIntegralFloatsRenderAsIntegers(t *testing.T) {
	doc := minimalDoc()
	practice := doc["threatPreventionPractices"].([]any)[0].(map[string]any)
	practice["webAttacks"] = map[string]any{
		"overrideMode":      "inherited",
		"minimumConfidence": "high",
		// These arrive as float64 after a database round trip.
		"maxBodySizeKb":      float64(1000000),
		"maxUrlSizeBytes":    float64(32768),
		"maxHeaderSizeBytes": float64(102400),
	}

	out, err := LocalPolicyYAML{}.Render(doc)
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)

	if strings.Contains(body, "e+") || strings.Contains(body, "E+") {
		t.Fatalf("scientific notation would break the agent's integer parsing:\n%s", body)
	}
	for _, want := range []string{"maxBodySizeKb: 1000000", "maxUrlSizeBytes: 32768", "maxHeaderSizeBytes: 102400"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in rendered output:\n%s", want, body)
		}
	}

	// The rendered output must still validate, since the schema types these
	// fields as integers.
	reparsed, err := ParseYAML(out)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Validate(reparsed)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() {
		t.Fatalf("rendered output no longer validates: %s", result.Error())
	}
}

// Genuine fractions must survive; only whole values are converted.
func TestFractionalValuesArePreserved(t *testing.T) {
	doc := minimalDoc()
	doc["threatPreventionPractices"].([]any)[0].(map[string]any)["someScore"] = float64(9.5)

	out, err := LocalPolicyYAML{}.Render(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "9.5") {
		t.Fatalf("fractional value was altered:\n%s", out)
	}
}

// A nil slice marshals to JSON null, which the UI cannot treat as an array.
// Both fields must always serialise as arrays, even when empty.
func TestValidationResultSerialisesEmptySlicesAsArrays(t *testing.T) {
	result, err := Validate(minimalDoc())
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() {
		t.Fatalf("fixture should validate: %s", result.Error())
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("null")) {
		t.Fatalf("validation result must not contain null arrays: %s", encoded)
	}

	var round struct {
		Errors   []Problem `json:"errors"`
		Warnings []Problem `json:"warnings"`
	}
	if err := json.Unmarshal(encoded, &round); err != nil {
		t.Fatal(err)
	}
	if round.Errors == nil || round.Warnings == nil {
		t.Fatalf("both fields must decode as arrays: %s", encoded)
	}
}

// The seed revision must route events to the manager. The upstream default
// sends them to the open-appsec cloud with no local destination, which would
// leave a fresh install with an empty dashboard and telemetry going off-site.
func TestSeedPolicyRoutesLoggingToTheManager(t *testing.T) {
	doc, err := DefaultDocument()
	if err != nil {
		t.Fatal(err)
	}

	triggers, _ := doc["logTriggers"].([]any)
	if len(triggers) == 0 {
		t.Fatal("the seed policy has no log triggers")
	}

	for i, item := range triggers {
		trigger := item.(map[string]any)
		destination, ok := trigger["logDestination"].(map[string]any)
		if !ok {
			t.Fatalf("trigger %d has no logDestination", i)
		}
		if destination["local-tuning"] != true {
			t.Errorf("trigger %d: local-tuning = %v, want true — without it no events reach the manager",
				i, destination["local-tuning"])
		}
		if destination["cloud"] != false {
			t.Errorf("trigger %d: cloud = %v, want false for a self-hosted deployment",
				i, destination["cloud"])
		}
		if destination["logToAgent"] != true {
			t.Errorf("trigger %d: logToAgent = %v, want true as a local fallback",
				i, destination["logToAgent"])
		}
	}

	result, err := Validate(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK() {
		t.Fatalf("the seed revision must still validate: %s", result.Error())
	}
}

// The embedded copy stays byte-identical to upstream; only the seed document
// built from it is adjusted.
func TestRoutingDoesNotMutateTheEmbeddedFile(t *testing.T) {
	raw, err := schemaFS.ReadFile("schema/default_policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "cloud: true") {
		t.Fatal("the embedded default should remain the unmodified upstream copy")
	}
}
