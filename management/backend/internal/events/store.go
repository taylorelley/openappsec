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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct{ pool *pgxpool.Pool }

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// Row is the projection shown in the events table.
type Row struct {
	ID                int64      `json:"id"`
	EventTime         time.Time  `json:"eventTime"`
	AgentID           *uuid.UUID `json:"agentId,omitempty"`
	EventName         string     `json:"eventName"`
	EventSeverity     string     `json:"eventSeverity"`
	EventConfidence   string     `json:"eventConfidence"`
	AssetName         string     `json:"assetName"`
	SecurityAction    string     `json:"securityAction"`
	WaapIncidentType  string     `json:"waapIncidentType"`
	SourceIP          string     `json:"sourceIp"`
	SourceCountryName string     `json:"sourceCountryName"`
	HTTPHostName      string     `json:"httpHostName"`
	HTTPMethod        string     `json:"httpMethod"`
	HTTPURIPath       string     `json:"httpUriPath"`
	HTTPResponseCode  *int       `json:"httpResponseCode,omitempty"`
	MatchedLocation   string     `json:"matchedLocation"`
	MatchedParameter  string     `json:"matchedParameter"`
	MatchedSample     string     `json:"matchedSample"`
	PracticeType      string     `json:"practiceType"`
	WaapFinalScore    *float64   `json:"waapFinalScore,omitempty"`
}

type SearchParams struct {
	Query   string
	From    time.Time
	To      time.Time
	AgentID *uuid.UUID
	Limit   int
	Offset  int
}

type SearchResult struct {
	Rows      []Row `json:"rows"`
	Total     int64 `json:"total"`
	Limit     int   `json:"limit"`
	Offset    int   `json:"offset"`
	Truncated bool  `json:"truncated"`
}

const rowColumns = `id, event_time, manager_agent_id, event_name, event_severity, event_confidence,
	asset_name, security_action, waap_incident_type, source_ip, source_country_name,
	http_host_name, http_method, http_uri_path, http_response_code,
	matched_location, matched_parameter, matched_sample, practice_type, waap_final_score`

// buildWhere assembles the time/agent filters plus the compiled query.
// Arguments are positional: $1 = from, $2 = to, then optionally the agent,
// then whatever the query compiler binds.
func buildWhere(p SearchParams) (string, []any, error) {
	args := []any{p.From, p.To}
	where := []string{"event_time >= $1", "event_time < $2"}

	if p.AgentID != nil {
		args = append(args, *p.AgentID)
		where = append(where, fmt.Sprintf("manager_agent_id = $%d", len(args)))
	}

	node, err := Parse(p.Query)
	if err != nil {
		return "", nil, fmt.Errorf("invalid query: %w", err)
	}
	sql, qargs, err := Compile(node, len(args))
	if err != nil {
		return "", nil, fmt.Errorf("invalid query: %w", err)
	}
	where = append(where, sql)
	args = append(args, qargs...)

	return strings.Join(where, " AND "), args, nil
}

func (s *Service) Search(ctx context.Context, p SearchParams) (*SearchResult, error) {
	if p.Limit <= 0 || p.Limit > 1000 {
		p.Limit = 100
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	if p.To.IsZero() {
		p.To = time.Now().UTC().Add(time.Minute)
	}
	if p.From.IsZero() {
		p.From = p.To.Add(-24 * time.Hour)
	}

	where, args, err := buildWhere(p)
	if err != nil {
		return nil, err
	}

	// Counting every matching row gets expensive on a large window, so the
	// count is capped and the UI is told the total was truncated.
	const countCap = 10000
	var total int64
	countSQL := fmt.Sprintf(
		`SELECT count(*) FROM (SELECT 1 FROM events WHERE %s LIMIT %d) t`, where, countCap)
	if err := s.pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, err
	}

	querySQL := fmt.Sprintf(
		`SELECT %s FROM events WHERE %s ORDER BY event_time DESC, id DESC LIMIT %d OFFSET %d`,
		rowColumns, where, p.Limit, p.Offset)

	rows, err := s.pool.Query(ctx, querySQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := &SearchResult{Rows: []Row{}, Total: total, Limit: p.Limit, Offset: p.Offset,
		Truncated: total >= countCap}
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.ID, &r.EventTime, &r.AgentID, &r.EventName, &r.EventSeverity,
			&r.EventConfidence, &r.AssetName, &r.SecurityAction, &r.WaapIncidentType,
			&r.SourceIP, &r.SourceCountryName, &r.HTTPHostName, &r.HTTPMethod, &r.HTTPURIPath,
			&r.HTTPResponseCode, &r.MatchedLocation, &r.MatchedParameter, &r.MatchedSample,
			&r.PracticeType, &r.WaapFinalScore); err != nil {
			return nil, err
		}
		result.Rows = append(result.Rows, r)
	}
	return result, rows.Err()
}

// Get returns the full raw document for one event, which is what the detail
// drawer shows — including fields this manager version does not index.
func (s *Service) Get(ctx context.Context, id int64) (json.RawMessage, error) {
	var raw json.RawMessage
	err := s.pool.QueryRow(ctx, `SELECT raw FROM events WHERE id = $1 LIMIT 1`, id).Scan(&raw)
	return raw, err
}

// ---------------------------------------------------------------- analytics

type TimeBucket struct {
	Bucket time.Time        `json:"bucket"`
	Counts map[string]int64 `json:"counts"`
}

// Timeline returns counts bucketed over time, split by a grouping column.
func (s *Service) Timeline(ctx context.Context, p SearchParams, groupBy string, buckets int) ([]TimeBucket, error) {
	col, ok := fieldColumns[strings.ToLower(groupBy)]
	if !ok {
		col = "security_action"
	}
	if buckets <= 0 || buckets > 500 {
		buckets = 48
	}
	if p.To.IsZero() {
		p.To = time.Now().UTC()
	}
	if p.From.IsZero() {
		p.From = p.To.Add(-24 * time.Hour)
	}

	where, args, err := buildWhere(p)
	if err != nil {
		return nil, err
	}

	interval := p.To.Sub(p.From) / time.Duration(buckets)
	if interval < time.Minute {
		interval = time.Minute
	}

	// Numeric columns must be cast before being compared with '' — Postgres
	// rejects `integer <> ''` with an invalid-input-syntax error, which would
	// fail the request for a field the API advertises as groupable.
	groupExpr := col
	if numericColumns[col] {
		groupExpr = col + "::text"
	}

	// The bucket width is derived from the caller's range, never from input
	// text, so formatting it into the statement is safe.
	sql := fmt.Sprintf(`
		SELECT to_timestamp(floor(extract(epoch FROM event_time) / %d) * %d) AS bucket,
		       COALESCE(NULLIF(%s, ''), 'unknown') AS grp,
		       count(*)
		  FROM events WHERE %s
		 GROUP BY bucket, grp ORDER BY bucket`,
		int(interval.Seconds()), int(interval.Seconds()), groupExpr, where)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byBucket := map[time.Time]map[string]int64{}
	var order []time.Time
	for rows.Next() {
		var (
			bucket time.Time
			grp    string
			n      int64
		)
		if err := rows.Scan(&bucket, &grp, &n); err != nil {
			return nil, err
		}
		if _, ok := byBucket[bucket]; !ok {
			byBucket[bucket] = map[string]int64{}
			order = append(order, bucket)
		}
		byBucket[bucket][grp] = n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]TimeBucket, 0, len(order))
	for _, b := range order {
		out = append(out, TimeBucket{Bucket: b, Counts: byBucket[b]})
	}
	return out, nil
}

type TopEntry struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// Top returns the highest-volume values of a column, for the dashboard's
// "top attacks / sources / assets" panels.
func (s *Service) Top(ctx context.Context, p SearchParams, field string, limit int) ([]TopEntry, error) {
	col, ok := fieldColumns[strings.ToLower(field)]
	if !ok {
		return nil, fmt.Errorf("unknown field %q", field)
	}
	if limit <= 0 || limit > 100 {
		limit = 10
	}

	where, args, err := buildWhere(p)
	if err != nil {
		return nil, err
	}

	// As above: an empty-string test is invalid on a numeric column, so those
	// are filtered on NULL instead.
	selectExpr, presenceExpr := col, col+" <> ''"
	if numericColumns[col] {
		selectExpr, presenceExpr = col+"::text", col+" IS NOT NULL"
	}

	sql := fmt.Sprintf(`
		SELECT %s AS k, count(*) AS n FROM events
		 WHERE %s AND %s
		 GROUP BY k ORDER BY n DESC LIMIT %d`, selectExpr, where, presenceExpr, limit)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []TopEntry{}
	for rows.Next() {
		var e TopEntry
		if err := rows.Scan(&e.Key, &e.Count); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type Summary struct {
	Total       int64            `json:"total"`
	Prevented   int64            `json:"prevented"`
	Detected    int64            `json:"detected"`
	UniqueHosts int64            `json:"uniqueHosts"`
	UniqueIPs   int64            `json:"uniqueSources"`
	BySeverity  map[string]int64 `json:"bySeverity"`
}

// Summary powers the dashboard's stat tiles.
func (s *Service) Summary(ctx context.Context, p SearchParams) (*Summary, error) {
	where, args, err := buildWhere(p)
	if err != nil {
		return nil, err
	}

	sum := &Summary{BySeverity: map[string]int64{}}
	sql := fmt.Sprintf(`
		SELECT count(*),
		       count(*) FILTER (WHERE lower(security_action) = 'prevent'),
		       count(*) FILTER (WHERE lower(security_action) = 'detect'),
		       count(DISTINCT NULLIF(http_host_name, '')),
		       count(DISTINCT NULLIF(source_ip, ''))
		  FROM events WHERE %s`, where)
	if err := s.pool.QueryRow(ctx, sql, args...).Scan(
		&sum.Total, &sum.Prevented, &sum.Detected, &sum.UniqueHosts, &sum.UniqueIPs); err != nil {
		return nil, err
	}

	sevSQL := fmt.Sprintf(`
		SELECT COALESCE(NULLIF(event_severity, ''), 'Unknown'), count(*)
		  FROM events WHERE %s GROUP BY 1`, where)
	rows, err := s.pool.Query(ctx, sevSQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			k string
			n int64
		)
		if err := rows.Scan(&k, &n); err != nil {
			return nil, err
		}
		sum.BySeverity[k] = n
	}
	return sum, rows.Err()
}

// Rollup refreshes event_daily_rollups for the recent window. Dashboards over
// long ranges read the rollups instead of scanning the events table.
func (s *Service) Rollup(ctx context.Context, since time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO event_daily_rollups
		     (day, manager_agent_id, asset_name, security_action, waap_incident_type, event_severity, event_count)
		SELECT date_trunc('day', event_time)::date,
		       COALESCE(manager_agent_id, '00000000-0000-0000-0000-000000000000'::uuid),
		       asset_name, security_action, waap_incident_type, event_severity, count(*)
		  FROM events
		 -- Truncated to a day boundary: the conflict target is the whole day,
		 -- so aggregating only part of one would replace a complete total with
		 -- the count of the trailing window.
		 WHERE event_time >= date_trunc('day', $1::timestamptz)
		 GROUP BY 1, 2, 3, 4, 5, 6
		ON CONFLICT (day, manager_agent_id, asset_name, security_action, waap_incident_type, event_severity)
		DO UPDATE SET event_count = EXCLUDED.event_count`, since)
	return err
}
