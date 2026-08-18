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

package learning

import (
	"context"
	"time"
)

// AssetLearning summarises how much an asset has learned and whether it looks
// ready to move from detect to prevent.
//
// The SaaS presents a Kindergarten-to-PhD ladder, but that grading is computed
// cloud-side and is not reproducible from anything the agent exposes locally.
// Rather than invent labels that imply the same meaning, this reports the
// observable evidence — traffic volume, breadth of sources, elapsed time and
// completed learning windows — and a recommendation derived from it.
type AssetLearning struct {
	TenantID      string     `json:"tenantId"`
	AssetID       string     `json:"assetId"`
	AssetName     string     `json:"assetName"`
	FirstSeenAt   time.Time  `json:"firstSeenAt"`
	LastSeenAt    time.Time  `json:"lastSeenAt"`
	TotalEvents   int64      `json:"totalEvents"`
	UniqueSources int64      `json:"uniqueSources"`
	UniqueURIs    int64      `json:"uniqueUris"`
	LearningHours float64    `json:"learningHours"`
	Windows       int64      `json:"completedLearningWindows"`
	LastWindowAt  *time.Time `json:"lastWindowAt,omitempty"`

	CriticalLast48h int64 `json:"criticalLast48h"`
	HighLast48h     int64 `json:"highLast48h"`
	PreventLast48h  int64 `json:"preventLast48h"`
	DetectLast48h   int64 `json:"detectLast48h"`

	OpenSuggestions int64 `json:"openSuggestions"`
	Decisions       int64 `json:"decisions"`

	Readiness      string `json:"readiness"`
	Recommendation string `json:"recommendation"`
}

// Readiness levels, ordered.
const (
	ReadinessInsufficient = "insufficient-data"
	ReadinessLearning     = "learning"
	ReadinessNearlyReady  = "nearly-ready"
	ReadinessReady        = "ready-for-prevent"
)

// Thresholds for the readiness heuristic. These are deliberately conservative
// and are stated here rather than buried in the query so an operator can see
// exactly what the recommendation is based on.
const (
	minEventsForPrevent  = 10000
	minSourcesForPrevent = 50
	minHoursForPrevent   = 24 * 7
)

func (s *Service) AssetsLearning(ctx context.Context) ([]AssetLearning, error) {
	rows, err := s.pool.Query(ctx, `
		WITH stats AS (
			SELECT tenant_id, asset_id,
			       max(asset_name)                                    AS asset_name,
			       count(*)                                           AS total_events,
			       count(DISTINCT NULLIF(source_ip, ''))              AS unique_sources,
			       count(DISTINCT NULLIF(http_uri_path, ''))          AS unique_uris,
			       min(event_time)                                    AS first_event,
			       max(event_time)                                    AS last_event,
			       count(*) FILTER (WHERE event_severity = 'Critical'
			                          AND event_time > now() - interval '48 hours') AS critical_48h,
			       count(*) FILTER (WHERE event_severity = 'High'
			                          AND event_time > now() - interval '48 hours') AS high_48h,
			       count(*) FILTER (WHERE lower(security_action) = 'prevent'
			                          AND event_time > now() - interval '48 hours') AS prevent_48h,
			       count(*) FILTER (WHERE lower(security_action) = 'detect'
			                          AND event_time > now() - interval '48 hours') AS detect_48h
			  FROM events
			 WHERE asset_id <> ''
			 GROUP BY tenant_id, asset_id
		),
		windows AS (
			SELECT tenant_id, asset_id, count(*) AS window_count, max(observed_at) AS last_window
			  FROM learning_windows GROUP BY tenant_id, asset_id
		),
		decisions AS (
			SELECT tenant_id, asset_id, count(*) AS decision_count
			  FROM tuning_decisions GROUP BY tenant_id, asset_id
		)
		SELECT s.tenant_id, s.asset_id, s.asset_name, s.total_events, s.unique_sources,
		       s.unique_uris, s.first_event, s.last_event,
		       s.critical_48h, s.high_48h, s.prevent_48h, s.detect_48h,
		       COALESCE(w.window_count, 0), w.last_window,
		       COALESCE(d.decision_count, 0)
		  FROM stats s
		  LEFT JOIN windows   w ON w.tenant_id = s.tenant_id AND w.asset_id = s.asset_id
		  LEFT JOIN decisions d ON d.tenant_id = s.tenant_id AND d.asset_id = s.asset_id
		 ORDER BY s.total_events DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AssetLearning{}
	for rows.Next() {
		var a AssetLearning
		if err := rows.Scan(&a.TenantID, &a.AssetID, &a.AssetName, &a.TotalEvents,
			&a.UniqueSources, &a.UniqueURIs, &a.FirstSeenAt, &a.LastSeenAt,
			&a.CriticalLast48h, &a.HighLast48h, &a.PreventLast48h, &a.DetectLast48h,
			&a.Windows, &a.LastWindowAt, &a.Decisions); err != nil {
			return nil, err
		}
		a.LearningHours = a.LastSeenAt.Sub(a.FirstSeenAt).Hours()
		a.Readiness, a.Recommendation = assessReadiness(&a)
		out = append(out, a)
	}
	return out, rows.Err()
}

// assessReadiness turns the observable evidence into a recommendation. It is
// intentionally explicit about what is missing, because "not ready" is only
// actionable if the operator knows which threshold is short.
func assessReadiness(a *AssetLearning) (string, string) {
	switch {
	case a.TotalEvents < minEventsForPrevent/10:
		return ReadinessInsufficient,
			"Too little traffic has been observed to judge accuracy. Keep the asset in " +
				"detect-learn and revisit once it has handled meaningfully more requests."

	case a.TotalEvents < minEventsForPrevent || a.UniqueSources < minSourcesForPrevent ||
		a.LearningHours < minHoursForPrevent:
		return ReadinessLearning, describeShortfall(a)

	case a.CriticalLast48h > 0:
		return ReadinessNearlyReady,
			"Volume and duration thresholds are met, but critical-severity events were " +
				"seen in the last 48 hours. Review them and add exceptions for any false " +
				"positives before switching to prevent."

	case a.HighLast48h > 0:
		return ReadinessNearlyReady,
			"Thresholds are met and no critical events were seen in the last 48 hours, " +
				"though high-severity events remain. Review them, then consider prevent " +
				"with the sensitivity set to critical only."

	default:
		return ReadinessReady,
			"Traffic volume, source diversity and learning duration thresholds are met, " +
				"and no high or critical events were seen in the last 48 hours. This asset " +
				"looks safe to move to prevent."
	}
}

func describeShortfall(a *AssetLearning) string {
	msg := "Still learning."
	if a.TotalEvents < minEventsForPrevent {
		msg += " Requests observed are below the volume threshold."
	}
	if a.UniqueSources < minSourcesForPrevent {
		msg += " Traffic has come from few distinct sources, so the model has seen a narrow slice of real use."
	}
	if a.LearningHours < minHoursForPrevent {
		msg += " Less than a week of traffic has been observed."
	}
	return msg
}

// -------------------------------------------------------------- suggestions

// Suggestion is a candidate tuning decision inferred from the event stream:
// something the agent flagged repeatedly that an operator should classify.
type Suggestion struct {
	TenantID    string    `json:"tenantId"`
	AssetID     string    `json:"assetId"`
	AssetName   string    `json:"assetName"`
	EventType   string    `json:"eventType"`
	EventTitle  string    `json:"eventTitle"`
	Events      int64     `json:"events"`
	Sources     int64     `json:"sources"`
	TopAttack   string    `json:"topAttackType"`
	MaxSeverity string    `json:"maxSeverity"`
	FirstSeen   time.Time `json:"firstSeen"`
	LastSeen    time.Time `json:"lastSeen"`
	Decision    string    `json:"decision,omitempty"`
}

// Suggestions ranks candidates for an asset, excluding anything already
// decided. Grouping mirrors the four decision types the agent understands.
func (s *Service) Suggestions(ctx context.Context, tenantID, assetID string, limit int) ([]Suggestion, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	// Only events that actually matched something are useful candidates; a
	// clean request tells the operator nothing to classify.
	rows, err := s.pool.Query(ctx, `
		WITH candidates AS (
			SELECT tenant_id, asset_id, max(asset_name) AS asset_name,
			       'url'::text AS event_type, http_uri_path AS event_title,
			       count(*) AS events, count(DISTINCT source_ip) AS sources,
			       mode() WITHIN GROUP (ORDER BY waap_incident_type) AS top_attack,
			       -- Ranked explicitly: event_severity is text, so max() would
			       -- return the alphabetically last value ("Medium" beats
			       -- "Critical") and understate the risk of a suggestion.
			       (ARRAY['', 'Info', 'Low', 'Medium', 'High', 'Critical'])[
			           max(CASE lower(event_severity)
			                 WHEN 'critical' THEN 6 WHEN 'high' THEN 5
			                 WHEN 'medium' THEN 4 WHEN 'low' THEN 3
			                 WHEN 'info' THEN 2 ELSE 1 END)] AS max_severity,
			       min(event_time) AS first_seen, max(event_time) AS last_seen
			  FROM events
			 WHERE asset_id = $2 AND ($1 = '' OR tenant_id = $1)
			   AND http_uri_path <> '' AND waap_incident_type <> ''
			 GROUP BY tenant_id, asset_id, http_uri_path

			UNION ALL

			SELECT tenant_id, asset_id, max(asset_name),
			       'parameterName', matched_parameter,
			       count(*), count(DISTINCT source_ip),
			       mode() WITHIN GROUP (ORDER BY waap_incident_type),
			       (ARRAY['', 'Info', 'Low', 'Medium', 'High', 'Critical'])[
			           max(CASE lower(event_severity)
			                 WHEN 'critical' THEN 6 WHEN 'high' THEN 5
			                 WHEN 'medium' THEN 4 WHEN 'low' THEN 3
			                 WHEN 'info' THEN 2 ELSE 1 END)], min(event_time), max(event_time)
			  FROM events
			 WHERE asset_id = $2 AND ($1 = '' OR tenant_id = $1)
			   AND matched_parameter <> '' AND waap_incident_type <> ''
			 GROUP BY tenant_id, asset_id, matched_parameter

			UNION ALL

			SELECT tenant_id, asset_id, max(asset_name),
			       'source', source_ip,
			       count(*), count(DISTINCT source_ip),
			       mode() WITHIN GROUP (ORDER BY waap_incident_type),
			       (ARRAY['', 'Info', 'Low', 'Medium', 'High', 'Critical'])[
			           max(CASE lower(event_severity)
			                 WHEN 'critical' THEN 6 WHEN 'high' THEN 5
			                 WHEN 'medium' THEN 4 WHEN 'low' THEN 3
			                 WHEN 'info' THEN 2 ELSE 1 END)], min(event_time), max(event_time)
			  FROM events
			 WHERE asset_id = $2 AND ($1 = '' OR tenant_id = $1)
			   AND source_ip <> '' AND waap_incident_type <> ''
			 GROUP BY tenant_id, asset_id, source_ip
		)
		SELECT c.tenant_id, c.asset_id, c.asset_name, c.event_type, c.event_title,
		       c.events, c.sources, COALESCE(c.top_attack, ''), COALESCE(c.max_severity, ''),
		       c.first_seen, c.last_seen, COALESCE(d.decision, '')
		  FROM candidates c
		  LEFT JOIN tuning_decisions d
		         ON d.tenant_id = c.tenant_id AND d.asset_id = c.asset_id
		        AND d.event_type = c.event_type AND d.event_title = c.event_title
		 WHERE d.decision IS NULL
		 ORDER BY c.events DESC
		 LIMIT $3`, tenantID, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Suggestion{}
	for rows.Next() {
		var s Suggestion
		if err := rows.Scan(&s.TenantID, &s.AssetID, &s.AssetName, &s.EventType, &s.EventTitle,
			&s.Events, &s.Sources, &s.TopAttack, &s.MaxSeverity,
			&s.FirstSeen, &s.LastSeen, &s.Decision); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
