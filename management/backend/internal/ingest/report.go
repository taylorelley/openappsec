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

// Package ingest decodes the agent's Report documents and writes them to the
// event store.
//
// The wire format is the fog's, not a manager-specific one. The agent posts
// the identical payload to this manager (via the local-tuning log destination,
// core/logging/k8s_svc_stream.cc) that it would post to my.openappsec.io
// (core/logging/fog_stream.cc), so these types are shaped by
// core/include/services_sdk/resources/report/log_rest.h.
package ingest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// obfuscation markers from core/report/report.cc:97-98.
const (
	xorLabel = "{XORANDB64}:"
	xorKey   = "ChkPoint"
)

// LogEnvelope is the single-log body: {"log": {...}}.
type LogEnvelope struct {
	Log json.RawMessage `json:"log"`
}

// BulkEnvelope is the bulk body: {"logs":[{"id":1,"log":{...}}, ...]}.
type BulkEnvelope struct {
	Logs []BulkItem `json:"logs"`
}

type BulkItem struct {
	ID  int             `json:"id"`
	Log json.RawMessage `json:"log"`
}

// Report is one decoded agent report. Envelope fields are typed; eventSource
// and eventData stay generic because their contents differ per security engine
// (WAAP, IPS, geo filter, nginx reader) and grow between agent versions.
type Report struct {
	EventTime         string   `json:"eventTime"`
	EventName         string   `json:"eventName"`
	EventSeverity     string   `json:"eventSeverity"`
	EventPriority     string   `json:"eventPriority"`
	EventType         string   `json:"eventType"`
	EventLevel        string   `json:"eventLevel"`
	EventLogLevel     string   `json:"eventLogLevel"`
	EventAudience     string   `json:"eventAudience"`
	EventAudienceTeam string   `json:"eventAudienceTeam"`
	EventFrequency    int      `json:"eventFrequency"`
	EventTags         []string `json:"eventTags"`

	EventSource map[string]any `json:"eventSource"`
	EventData   map[string]any `json:"eventData"`

	// Raw is the document exactly as received, preserved so the UI can show
	// fields this manager version does not yet know about.
	Raw json.RawMessage `json:"-"`

	// fields is a case-insensitive, flattened view of eventSource + eventData,
	// built once by index().
	fields map[string]any
}

// ParseReport decodes one report document.
func ParseReport(raw []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}
	r.Raw = append(json.RawMessage(nil), raw...)
	r.index()
	return &r, nil
}

// index flattens eventSource and eventData into a single lower-cased map.
//
// Lower-casing matters: the C++ emits camelCase LogField names ("sourceIP",
// "waapIncidentType") while the documented Event Query Language refers to the
// same fields in lower case ("sourceip"). Indexing on the lower-cased name
// lets both spellings resolve. Nested objects are flattened by leaf name,
// since the agent's field names are unique across nesting levels.
func (r *Report) index() {
	r.fields = make(map[string]any, len(r.EventSource)+len(r.EventData))
	flatten(r.EventSource, r.fields)
	flatten(r.EventData, r.fields)
}

func flatten(src map[string]any, dst map[string]any) {
	for k, v := range src {
		key := strings.ToLower(k)
		if nested, ok := v.(map[string]any); ok {
			flatten(nested, dst)
			continue
		}
		// First writer wins: eventSource is flattened before eventData, but a
		// field carried in both holds the same value in practice.
		if _, exists := dst[key]; !exists {
			dst[key] = v
		}
	}
}

// String returns a field by (case-insensitive) name, de-obfuscated if needed.
func (r *Report) String(name string) string {
	v, ok := r.fields[strings.ToLower(name)]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return Deobfuscate(t)
	case float64:
		// JSON numbers arrive as float64; render integers without a decimal.
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// Int returns a numeric field, and whether it was present and numeric.
func (r *Report) Int(name string) (int, bool) {
	v, ok := r.fields[strings.ToLower(name)]
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case float64:
		return int(t), true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(Deobfuscate(t)))
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

// Float returns a floating-point field, and whether it was present.
func (r *Report) Float(name string) (float64, bool) {
	v, ok := r.fields[strings.ToLower(name)]
	if !ok {
		return 0, false
	}
	switch t := v.(type) {
	case float64:
		return t, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(Deobfuscate(t)), 64)
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// Has reports whether a field is present.
func (r *Report) Has(name string) bool {
	_, ok := r.fields[strings.ToLower(name)]
	return ok
}

// Time parses the report's eventTime.
//
// The agent formats it as "%FT%T" plus a fractional part and no timezone
// suffix (core/time_proxy/time_proxy.cc:118-130), built from gmtime, so the
// value is UTC despite carrying no zone. Report::serialize truncates the
// microsecond field to milliseconds.
func (r *Report) Time() time.Time {
	return ParseEventTime(r.EventTime)
}

var eventTimeLayouts = []string{
	"2006-01-02T15:04:05.000",
	"2006-01-02T15:04:05.000000",
	"2006-01-02T15:04:05",
	time.RFC3339Nano,
	time.RFC3339,
}

// ParseEventTime parses an agent timestamp, falling back to the current time
// when the value is missing or unparseable — an event with a bad clock is
// still worth keeping.
func ParseEventTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Now().UTC()
	}
	for _, layout := range eventTimeLayouts {
		// The zone-less layouts must be read as UTC, not local time.
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

// Deobfuscate reverses the agent's "{XORANDB64}:" encoding: base64-decode,
// then XOR with the repeating key "ChkPoint" (core/report/report.cc:97-112).
//
// In a local-tuning deployment nothing is obfuscated — only FogStream sets the
// flag that turns it on (core/logging/fog_stream.cc:37-38) — but a manager
// acting as a fog receives the encoded form, and a mixed fleet can produce
// both.
func Deobfuscate(s string) string {
	if !strings.HasPrefix(s, xorLabel) {
		return s
	}
	payload := strings.TrimPrefix(s, xorLabel)

	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		// Leave the value as received rather than dropping data.
		return s
	}
	out := make([]byte, len(decoded))
	for i, b := range decoded {
		out[i] = b ^ xorKey[i%len(xorKey)]
	}
	return string(out)
}

// Obfuscate applies the agent's encoding. Used by tests to build fixtures that
// match what a fog-mode agent sends.
func Obfuscate(s string) string {
	buf := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		buf[i] = s[i] ^ xorKey[i%len(xorKey)]
	}
	return xorLabel + base64.StdEncoding.EncodeToString(buf)
}
