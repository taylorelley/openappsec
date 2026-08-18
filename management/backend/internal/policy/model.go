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

// Package policy owns the canonical open-appsec policy: its schema, its
// validation rules, and the renderers that turn it into artefacts an agent
// consumes.
//
// The canonical model is the v1beta2 declarative document itself, held as a
// generic map rather than a Go struct. That choice is deliberate: the agent's
// schema grows between versions, and a generic model round-trips fields this
// manager does not yet know about instead of silently dropping them on save.
package policy

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed schema/schema_v1beta2.yaml schema/default_policy.yaml
var schemaFS embed.FS

// APIVersion is the only declarative version this manager authors.
//
// v1beta1 documents are still parsed by the agent, but they use a different
// (kebab-case) vocabulary; authoring only v1beta2 keeps one editor, one
// validator and one renderer.
const APIVersion = "v1beta2"

// Document is a canonical policy. Key order is not significant here — the
// renderer imposes a deterministic order on output.
type Document map[string]any

// DefaultDocument returns the shipped default policy, which is the seed
// revision for a fresh install. It mirrors
// config/linux/v1beta2/default/local_policy.yaml.
func DefaultDocument() (Document, error) {
	raw, err := schemaFS.ReadFile("schema/default_policy.yaml")
	if err != nil {
		return nil, err
	}
	return ParseYAML(raw)
}

// ParseYAML decodes a policy document from YAML into the canonical form.
func ParseYAML(raw []byte) (Document, error) {
	var node any
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return nil, fmt.Errorf("parse policy yaml: %w", err)
	}
	normalized, err := normalizeYAML(node)
	if err != nil {
		return nil, err
	}
	doc, ok := normalized.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("policy must be a mapping at the top level")
	}
	return Document(doc), nil
}

// normalizeYAML converts a decoded YAML tree into JSON-compatible types.
//
// yaml.v3 already produces map[string]any for string-keyed mappings, but a
// non-string key would yield map[any]any, which neither the JSON Schema
// validator nor JSONB can consume. Rejecting those explicitly gives a clear
// error rather than an opaque failure further down.
func normalizeYAML(v any) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			nv, err := normalizeYAML(val)
			if err != nil {
				return nil, err
			}
			out[k] = nv
		}
		return out, nil

	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("policy keys must be strings, found %T", k)
			}
			nv, err := normalizeYAML(val)
			if err != nil {
				return nil, err
			}
			out[ks] = nv
		}
		return out, nil

	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			nv, err := normalizeYAML(val)
			if err != nil {
				return nil, err
			}
			out[i] = nv
		}
		return out, nil

	default:
		return v, nil
	}
}

// ParseJSON decodes a policy document from JSON, as stored in the database and
// submitted by the UI.
func ParseJSON(raw []byte) (Document, error) {
	var doc Document
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse policy json: %w", err)
	}
	return doc, nil
}

func (d Document) JSON() ([]byte, error) { return json.Marshal(map[string]any(d)) }

// Checksum identifies a revision's content. It is computed over the canonical
// JSON encoding so that two documents differing only in key order hash alike.
func (d Document) Checksum() (string, error) {
	canonical, err := canonicalJSON(map[string]any(d))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// canonicalJSON marshals with sorted keys. encoding/json already sorts map
// keys, so this is just a marshal — the helper exists to make the intent
// explicit and to give one place to change if that ever stops being true.
func canonicalJSON(v any) ([]byte, error) { return json.Marshal(v) }

func (d Document) APIVersion() string {
	if v, ok := d["apiVersion"].(string); ok {
		return v
	}
	return ""
}

// Clone returns a deep copy, so that editing a loaded revision cannot mutate
// cached state.
func (d Document) Clone() (Document, error) {
	raw, err := d.JSON()
	if err != nil {
		return nil, err
	}
	return ParseJSON(raw)
}
