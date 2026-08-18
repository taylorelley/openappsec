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
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// Event is one normalized report, shaped for the events table. Fields the
// manager indexes get their own column; everything else survives in Raw.
type Event struct {
	EventTime      time.Time
	ManagerAgentID *uuid.UUID

	EventName         string
	EventSeverity     string
	EventPriority     string
	EventType         string
	EventLevel        string
	EventLogLevel     string
	EventAudience     string
	EventAudienceTeam string
	EventTags         []string

	AgentID              string
	TenantID             string
	ServiceName          string
	IssuingEngineVersion string
	EventTraceID         string
	NotificationID       string

	AssetID         string
	AssetName       string
	PracticeType    string
	PracticeSubType string
	PracticeName    string
	RuleName        string
	SecurityAction  string

	SourceIP          string
	SourceIPAddr      *string
	SourcePort        *int
	SourceCountryName string
	SourceCountryCode string
	DestinationIP     string
	DestinationPort   *int
	IPProtocol        string
	HTTPSourceID      string

	HTTPHostName     string
	HTTPMethod       string
	HTTPURIPath      string
	HTTPURIQuery     string
	HTTPResponseCode *int

	WaapIncidentType          string
	WaapIncidentDetails       string
	WaapFoundIndicators       string
	WaapUserReputation        string
	WaapFinalScore            *float64
	WaapCalculatedThreatLevel string
	EventConfidence           string
	EventReferenceID          string
	MatchedLocation           string
	MatchedParameter          string
	MatchedSample             string
	MatchReason               string
	ProtectionID              string
	IncidentType              string

	Raw json.RawMessage
}

// Normalize projects a decoded report onto the event columns.
func Normalize(r *Report) *Event {
	e := &Event{
		EventTime:         r.Time(),
		EventName:         r.EventName,
		EventSeverity:     r.EventSeverity,
		EventPriority:     r.EventPriority,
		EventType:         r.EventType,
		EventLevel:        r.EventLevel,
		EventLogLevel:     r.EventLogLevel,
		EventAudience:     r.EventAudience,
		EventAudienceTeam: r.EventAudienceTeam,
		EventTags:         r.EventTags,

		AgentID:              r.String("agentId"),
		TenantID:             r.String("tenantId"),
		ServiceName:          r.String("serviceName"),
		IssuingEngineVersion: r.String("issuingEngineVersion"),
		EventTraceID:         r.String("eventTraceId"),
		NotificationID:       r.String("notificationId"),

		AssetID:         r.String("assetId"),
		AssetName:       r.String("assetName"),
		PracticeType:    r.String("practiceType"),
		PracticeSubType: r.String("practiceSubType"),
		PracticeName:    r.String("practiceName"),
		RuleName:        r.String("ruleName"),
		SecurityAction:  r.String("securityAction"),

		SourceIP:          r.String("sourceIP"),
		SourceCountryName: r.String("sourceCountryName"),
		SourceCountryCode: r.String("sourceCountryCode"),
		DestinationIP:     firstNonEmpty(r.String("destinationIp"), r.String("destinationIP")),
		IPProtocol:        r.String("ipProtocol"),
		HTTPSourceID:      r.String("httpSourceId"),

		HTTPHostName: firstNonEmpty(r.String("httpHostName"), r.String("hostName")),
		HTTPMethod:   r.String("httpMethod"),
		HTTPURIPath:  r.String("httpUriPath"),
		HTTPURIQuery: r.String("httpUriQuery"),

		WaapIncidentType:          r.String("waapIncidentType"),
		WaapIncidentDetails:       r.String("waapIncidentDetails"),
		WaapFoundIndicators:       r.String("waapFoundIndicators"),
		WaapUserReputation:        r.String("waapUserReputation"),
		WaapCalculatedThreatLevel: r.String("waapCalculatedThreatLevel"),
		EventConfidence:           r.String("eventConfidence"),
		EventReferenceID:          r.String("eventReferenceId"),
		MatchedLocation:           r.String("matchedLocation"),
		MatchedParameter:          r.String("matchedParameter"),
		MatchedSample:             r.String("matchedSample"),
		// nginx_message_reader spells this "matchreason"; the lower-cased
		// index resolves both spellings to the same column.
		MatchReason:  firstNonEmpty(r.String("matchReason"), r.String("matchreason")),
		ProtectionID: r.String("protectionId"),
		IncidentType: r.String("incidentType"),

		Raw: r.Raw,
	}

	if e.EventTags == nil {
		e.EventTags = []string{}
	}
	if v, ok := r.Int("sourcePort"); ok {
		e.SourcePort = &v
	}
	if v, ok := r.Int("destinationPort"); ok {
		e.DestinationPort = &v
	}
	if v, ok := r.Int("httpResponseCode"); ok {
		e.HTTPResponseCode = &v
	}
	if v, ok := r.Float("waapFinalScore"); ok {
		e.WaapFinalScore = &v
	}

	// A parseable address also populates the inet column, which is what makes
	// CIDR filters in the query language possible. Non-address values (an
	// XFF chain, a placeholder) keep the text column only.
	if addr, err := netip.ParseAddr(e.SourceIP); err == nil {
		s := addr.String()
		e.SourceIPAddr = &s
	}

	return e
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
