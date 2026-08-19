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
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

// Problem is one validation finding. Warnings do not block an apply; errors do.
type Problem struct {
	Path     string `json:"path"`
	Message  string `json:"message"`
	Severity string `json:"severity"` // "error" or "warning"
}

type ValidationResult struct {
	Errors   []Problem `json:"errors"`
	Warnings []Problem `json:"warnings"`
}

func (v ValidationResult) OK() bool { return len(v.Errors) == 0 }

func (v ValidationResult) Error() string {
	if v.OK() {
		return ""
	}
	parts := make([]string, 0, len(v.Errors))
	for _, e := range v.Errors {
		parts = append(parts, e.Path+": "+e.Message)
	}
	return strings.Join(parts, "; ")
}

var (
	compiledSchema *jsonschema.Schema
	compileOnce    sync.Once
	compileErr     error
)

// schemaJSON converts the shipped YAML schema to JSON and applies the
// corrections the agent's own parsers require. See adjustSchema.
func schemaJSON() ([]byte, error) {
	raw, err := schemaFS.ReadFile("schema/schema_v1beta2.yaml")
	if err != nil {
		return nil, err
	}
	var node any
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return nil, fmt.Errorf("parse schema yaml: %w", err)
	}
	normalized, err := normalizeYAML(node)
	if err != nil {
		return nil, err
	}
	root, ok := normalized.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("schema root must be a mapping")
	}
	adjustSchema(root)
	return json.Marshal(root)
}

// adjustSchema reconciles the shipped JSON Schema with what the agent's C++
// loaders actually accept. Three divergences were found by reading the
// parsers, and validating against the unmodified schema would be wrong in
// both directions.
func adjustSchema(root map[string]any) {
	props, _ := root["properties"].(map[string]any)
	if props == nil {
		return
	}

	// (1) autoUpgrade is parsed by the agent
	// (components/security_apps/local_policy_mgmt_gen/new_auto_upgrade.cc:72)
	// but is absent from the shipped schema. With additionalProperties:false
	// at the root, validating unmodified would reject a document the agent
	// accepts, so declare it.
	if _, exists := props["autoUpgrade"]; !exists {
		props["autoUpgrade"] = map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":            map[string]any{"type": "string"},
					"appsecClassName": map[string]any{"type": "string"},
					"mode":            map[string]any{"type": "string"},
					"schedule": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"days":                      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
							"upgradeWindowStartHourUTC": map[string]any{"type": "string"},
							"upgradeWindowDuration":     map[string]any{"type": "integer"},
						},
					},
				},
			},
		}
	}

	// (2) The shipped default policy writes `customResponses` (plural) under
	// policies.default, but NewParsedRule parses `customResponse` (singular)
	// — new_appsec_policy_crd_parser.cc:24-41. The plural is silently ignored
	// by the agent. Allow both through the schema so an imported document
	// does not hard-fail, and flag the plural as a warning in lint().
	allowPluralCustomResponse(props)
}

func allowPluralCustomResponse(props map[string]any) {
	policies, _ := props["policies"].(map[string]any)
	if policies == nil {
		return
	}
	policyProps, _ := policies["properties"].(map[string]any)
	if policyProps == nil {
		return
	}
	for _, key := range []string{"default", "specificRules"} {
		target, _ := policyProps[key].(map[string]any)
		if target == nil {
			continue
		}
		if key == "specificRules" {
			target, _ = target["items"].(map[string]any)
			if target == nil {
				continue
			}
		}
		fields, _ := target["properties"].(map[string]any)
		if fields == nil {
			continue
		}
		if _, exists := fields["customResponses"]; !exists {
			fields["customResponses"] = map[string]any{"type": "string"}
		}
	}
}

func schema() (*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		raw, err := schemaJSON()
		if err != nil {
			compileErr = err
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource("schema_v1beta2.json", bytes.NewReader(raw)); err != nil {
			compileErr = err
			return
		}
		compiledSchema, compileErr = c.Compile("schema_v1beta2.json")
	})
	return compiledSchema, compileErr
}

// Validate checks a document against the v1beta2 schema and the additional
// rules that come from reading the agent's parsers.
//
// The slices are always non-nil: a nil slice marshals to JSON null, and the
// UI reads these as arrays.
func Validate(doc Document) (ValidationResult, error) {
	result := ValidationResult{Errors: []Problem{}, Warnings: []Problem{}}

	s, err := schema()
	if err != nil {
		return result, fmt.Errorf("load schema: %w", err)
	}

	// The validator needs plain JSON types, which a round trip guarantees.
	raw, err := doc.JSON()
	if err != nil {
		return result, err
	}
	var instance any
	if err := json.Unmarshal(raw, &instance); err != nil {
		return result, err
	}

	if err := s.Validate(instance); err != nil {
		var ve *jsonschema.ValidationError
		if ok := asValidationError(err, &ve); ok {
			result.Errors = append(result.Errors, flattenSchemaErrors(ve)...)
		} else {
			result.Errors = append(result.Errors, Problem{
				Path: "/", Message: err.Error(), Severity: "error",
			})
		}
	}

	result.Errors = append(result.Errors, lintErrors(doc)...)
	result.Warnings = append(result.Warnings, lintWarnings(doc)...)

	sort.SliceStable(result.Errors, func(i, j int) bool { return result.Errors[i].Path < result.Errors[j].Path })
	sort.SliceStable(result.Warnings, func(i, j int) bool { return result.Warnings[i].Path < result.Warnings[j].Path })
	return result, nil
}

func asValidationError(err error, target **jsonschema.ValidationError) bool {
	ve, ok := err.(*jsonschema.ValidationError)
	if ok {
		*target = ve
	}
	return ok
}

// flattenSchemaErrors turns the validator's error tree into a flat list of
// leaf problems, which is what a form UI can attach to individual fields.
func flattenSchemaErrors(ve *jsonschema.ValidationError) []Problem {
	if ve == nil {
		return nil
	}
	if len(ve.Causes) == 0 {
		path := ve.InstanceLocation
		if path == "" {
			path = "/"
		}
		return []Problem{{Path: path, Message: ve.Message, Severity: "error"}}
	}
	var out []Problem
	for _, cause := range ve.Causes {
		out = append(out, flattenSchemaErrors(cause)...)
	}
	return out
}

// lintErrors covers referential integrity, which the JSON Schema cannot
// express: a rule naming a practice that does not exist produces a policy the
// agent will not load.
func lintErrors(doc Document) []Problem {
	var problems []Problem

	if v := doc.APIVersion(); v != APIVersion {
		problems = append(problems, Problem{
			Path:     "/apiVersion",
			Message:  fmt.Sprintf("must be %q, got %q", APIVersion, v),
			Severity: "error",
		})
	}

	defined := map[string]map[string]bool{
		"threatPreventionPractices": namesIn(doc, "threatPreventionPractices"),
		"accessControlPractices":    namesIn(doc, "accessControlPractices"),
		"logTriggers":               namesIn(doc, "logTriggers"),
		"customResponses":           namesIn(doc, "customResponses"),
		"exceptions":                namesIn(doc, "exceptions"),
		"trustedSources":            namesIn(doc, "trustedSources"),
		"sourcesIdentifiers":        namesIn(doc, "sourcesIdentifiers"),
	}

	checkRule := func(rule map[string]any, path string) {
		refList := func(field, section string) {
			items, _ := rule[field].([]any)
			for i, item := range items {
				name, _ := item.(string)
				if name == "" {
					continue
				}
				if !defined[section][name] {
					problems = append(problems, Problem{
						Path: fmt.Sprintf("%s/%s/%d", path, field, i),
						Message: fmt.Sprintf("references %s %q, which is not defined in this policy",
							section, name),
						Severity: "error",
					})
				}
			}
		}
		refOne := func(field, section string) {
			name, _ := rule[field].(string)
			if name == "" {
				return
			}
			if !defined[section][name] {
				problems = append(problems, Problem{
					Path: path + "/" + field,
					Message: fmt.Sprintf("references %s %q, which is not defined in this policy",
						section, name),
					Severity: "error",
				})
			}
		}

		refList("threatPreventionPractices", "threatPreventionPractices")
		refList("accessControlPractices", "accessControlPractices")
		refList("triggers", "logTriggers")
		refList("exceptions", "exceptions")
		refOne("customResponse", "customResponses")
		refOne("trustedSources", "trustedSources")
		refOne("sourceIdentifiers", "sourcesIdentifiers")
	}

	policies, _ := doc["policies"].(map[string]any)
	if policies == nil {
		return problems
	}
	if def, ok := policies["default"].(map[string]any); ok {
		checkRule(def, "/policies/default")
	}
	if rules, ok := policies["specificRules"].([]any); ok {
		for i, r := range rules {
			if rule, ok := r.(map[string]any); ok {
				checkRule(rule, fmt.Sprintf("/policies/specificRules/%d", i))
			}
		}
	}
	return problems
}

// lintWarnings flags constructs the agent accepts but silently ignores. These
// are the failure modes worth surfacing loudly, because the agent gives no
// feedback at all when it drops them.
func lintWarnings(doc Document) []Problem {
	var problems []Problem

	// (2) `customResponses` (plural) under a rule is ignored by the parser,
	// which reads `customResponse`. The shipped default policy has this bug
	// (nodes/orchestration/package/local-default-policy-v1beta2.yaml:12), so
	// imported documents commonly carry it.
	checkPlural := func(rule map[string]any, path string) {
		if _, has := rule["customResponses"]; has {
			msg := "`customResponses` is ignored by the agent, which reads `customResponse` " +
				"(singular); the manager renders the singular form on apply"
			problems = append(problems, Problem{
				Path: path + "/customResponses", Message: msg, Severity: "warning",
			})
		}
	}

	// (3) Rate-limit rules carry `action` and `condition` in the schema, but
	// AccessControlPracticeSpec does not parse them
	// (components/security_apps/local_policy_mgmt_gen/access_control_practice.cc:145-158).
	// Offering them in the UI would be offering dead fields.
	practices, _ := doc["accessControlPractices"].([]any)
	for i, p := range practices {
		practice, ok := p.(map[string]any)
		if !ok {
			continue
		}
		rateLimit, _ := practice["rateLimit"].(map[string]any)
		if rateLimit == nil {
			continue
		}
		rules, _ := rateLimit["rules"].([]any)
		for j, r := range rules {
			rule, ok := r.(map[string]any)
			if !ok {
				continue
			}
			for _, field := range []string{"action", "condition"} {
				if _, has := rule[field]; has {
					problems = append(problems, Problem{
						Path: fmt.Sprintf("/accessControlPractices/%d/rateLimit/rules/%d/%s", i, j, field),
						Message: "rate-limit `" + field + "` is accepted by the schema but not " +
							"implemented by the agent's access-control loader; it will have no effect",
						Severity: "warning",
					})
				}
			}
		}
	}

	policies, _ := doc["policies"].(map[string]any)
	if policies != nil {
		if def, ok := policies["default"].(map[string]any); ok {
			checkPlural(def, "/policies/default")
		}
		if rules, ok := policies["specificRules"].([]any); ok {
			for i, r := range rules {
				if rule, ok := r.(map[string]any); ok {
					checkPlural(rule, fmt.Sprintf("/policies/specificRules/%d", i))
				}
			}
		}
	}
	return problems
}

// namesIn collects the `name` of every entry in a top-level array section.
func namesIn(doc Document, section string) map[string]bool {
	out := map[string]bool{}
	items, _ := doc[section].([]any)
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if name, ok := entry["name"].(string); ok && name != "" {
			out[name] = true
		}
	}
	return out
}

// SchemaJSON exposes the adjusted schema so the UI can drive its forms from
// exactly the contract the manager validates against.
func SchemaJSON() ([]byte, error) { return schemaJSON() }
