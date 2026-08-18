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

package events

import (
	"fmt"
	"net/netip"
	"strings"
)

// fieldColumns maps Event Query Language field names to event columns.
//
// Keys are the lower-case names used by the documented schema
// (https://docs.openappsec.io/references/events-logs-schema); the agent's own
// camelCase spellings are accepted too because lookup lower-cases the input.
var fieldColumns = map[string]string{
	// envelope
	"eventname":         "event_name",
	"eventseverity":     "event_severity",
	"eventpriority":     "event_priority",
	"eventtype":         "event_type",
	"eventlevel":        "event_level",
	"eventloglevel":     "event_log_level",
	"eventaudience":     "event_audience",
	"eventaudienceteam": "event_audience_team",
	"eventconfidence":   "event_confidence",
	"eventreferenceid":  "event_reference_id",

	// source
	"agentid":              "agent_id",
	"tenantid":             "tenant_id",
	"servicename":          "service_name",
	"issuingengineversion": "issuing_engine_version",
	"eventtraceid":         "event_trace_id",
	"notificationid":       "notification_id",

	// asset and practice
	"assetid":         "asset_id",
	"assetname":       "asset_name",
	"practicetype":    "practice_type",
	"practicesubtype": "practice_sub_type",
	"practicename":    "practice_name",
	"rulename":        "rule_name",
	"securityaction":  "security_action",

	// network
	"sourceip":          "source_ip",
	"sourceport":        "source_port",
	"sourcecountryname": "source_country_name",
	"sourcecountrycode": "source_country_code",
	"destinationip":     "destination_ip",
	"destinationport":   "destination_port",
	"ipprotocol":        "ip_protocol",
	"httpsourceid":      "http_source_id",

	// http
	"httphostname":     "http_host_name",
	"hostname":         "http_host_name",
	"httpmethod":       "http_method",
	"httpuripath":      "http_uri_path",
	"httpuriquery":     "http_uri_query",
	"httpresponsecode": "http_response_code",

	// waap verdict
	"waapincidenttype":          "waap_incident_type",
	"waapincidentdetails":       "waap_incident_details",
	"waapfoundindicators":       "waap_found_indicators",
	"waapuserreputation":        "waap_user_reputation",
	"waapfinalscore":            "waap_final_score",
	"waapcalculatedthreatlevel": "waap_calculated_threat_level",
	"matchedlocation":           "matched_location",
	"matchedparameter":          "matched_parameter",
	"matchedsample":             "matched_sample",
	"matchreason":               "match_reason",
	"protectionid":              "protection_id",
	"incidenttype":              "incident_type",
}

// freeTextColumns are searched when a criterion has no field.
var freeTextColumns = []string{
	"event_name", "asset_name", "source_ip", "http_host_name", "http_uri_path",
	"waap_incident_type", "matched_sample", "matched_parameter", "security_action",
}

// numericColumns take a numeric comparison rather than a text match.
var numericColumns = map[string]bool{
	"source_port":        true,
	"destination_port":   true,
	"http_response_code": true,
	"waap_final_score":   true,
}

// ipTextColumns have a companion inet column supporting CIDR containment.
var ipInetColumn = map[string]string{
	"source_ip": "source_ip_addr",
}

// Compiler turns a parsed query into a SQL predicate with bound arguments.
// Values are always parameterised — no user input is interpolated into SQL.
type Compiler struct {
	args []any
}

// Compile returns a SQL boolean expression and its arguments. The argument
// placeholders start at $(offset+1) so the caller can prepend its own.
func Compile(n Node, offset int) (string, []any, error) {
	if n == nil {
		return "TRUE", nil, nil
	}
	c := &Compiler{}
	sql, err := c.compile(n, offset)
	if err != nil {
		return "", nil, err
	}
	return sql, c.args, nil
}

func (c *Compiler) placeholder(offset int, v any) string {
	c.args = append(c.args, v)
	return fmt.Sprintf("$%d", offset+len(c.args))
}

func (c *Compiler) compile(n Node, offset int) (string, error) {
	switch t := n.(type) {
	case *AndNode:
		return c.join(t.Children, "AND", offset)
	case *OrNode:
		return c.join(t.Children, "OR", offset)
	case *NotNode:
		inner, err := c.compile(t.Child, offset)
		if err != nil {
			return "", err
		}
		return "(NOT " + inner + ")", nil
	case *TermNode:
		return c.compileTerm(t, offset)
	default:
		return "", fmt.Errorf("unsupported query node")
	}
}

func (c *Compiler) join(children []Node, op string, offset int) (string, error) {
	parts := make([]string, 0, len(children))
	for _, child := range children {
		s, err := c.compile(child, offset)
		if err != nil {
			return "", err
		}
		parts = append(parts, s)
	}
	return "(" + strings.Join(parts, " "+op+" ") + ")", nil
}

func (c *Compiler) compileTerm(t *TermNode, offset int) (string, error) {
	if t.Field == "" {
		parts := make([]string, 0, len(freeTextColumns))
		for _, col := range freeTextColumns {
			parts = append(parts, c.textMatch(col, t.Value, offset))
		}
		return "(" + strings.Join(parts, " OR ") + ")", nil
	}

	col, ok := fieldColumns[strings.ToLower(t.Field)]
	if !ok {
		return "", fmt.Errorf("unknown query field %q", t.Field)
	}

	if numericColumns[col] {
		return c.numericMatch(col, t.Value, offset)
	}
	if inetCol, ok := ipInetColumn[col]; ok {
		if sql, matched := c.ipMatch(col, inetCol, t.Value, offset); matched {
			return sql, nil
		}
	}
	return c.textMatch(col, t.Value, offset), nil
}

// textMatch produces an exact, case-insensitive comparison, or a LIKE when the
// value carries the documented wildcards (* for any string, ? for one char).
func (c *Compiler) textMatch(col, value string, offset int) string {
	if !strings.ContainsAny(value, "*?") {
		return fmt.Sprintf("lower(%s) = lower(%s)", col, c.placeholder(offset, value))
	}
	return fmt.Sprintf("%s ILIKE %s", col, c.placeholder(offset, wildcardToLike(value)))
}

func (c *Compiler) numericMatch(col, value string, offset int) (string, error) {
	// Wildcards are meaningless on a numeric column; compare as text instead
	// of failing the whole query.
	if strings.ContainsAny(value, "*?") {
		return fmt.Sprintf("%s::text ILIKE %s", col, c.placeholder(offset, wildcardToLike(value))), nil
	}
	return fmt.Sprintf("%s::text = %s", col, c.placeholder(offset, value)), nil
}

// ipMatch handles the documented IP forms: CIDR notation (192.168.0.0/16) via
// inet containment, and wildcards (192.168.*) via a text LIKE.
func (c *Compiler) ipMatch(textCol, inetCol, value string, offset int) (string, bool) {
	if strings.Contains(value, "/") {
		if _, err := netip.ParsePrefix(value); err == nil {
			return fmt.Sprintf("%s <<= %s::inet", inetCol, c.placeholder(offset, value)), true
		}
	}
	if strings.ContainsAny(value, "*?") {
		return fmt.Sprintf("%s ILIKE %s", textCol, c.placeholder(offset, wildcardToLike(value))), true
	}
	return "", false
}

// wildcardToLike converts the query language's wildcards to LIKE syntax,
// escaping the LIKE metacharacters that may occur literally in a value.
func wildcardToLike(value string) string {
	var sb strings.Builder
	for _, r := range value {
		switch r {
		case '*':
			sb.WriteRune('%')
		case '?':
			sb.WriteRune('_')
		case '%', '_', '\\':
			sb.WriteRune('\\')
			sb.WriteRune(r)
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// KnownFields returns the queryable field names, for UI autocomplete.
func KnownFields() []string {
	out := make([]string, 0, len(fieldColumns))
	for k := range fieldColumns {
		out = append(out, k)
	}
	return out
}
