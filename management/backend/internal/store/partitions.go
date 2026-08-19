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

package store

import (
	"context"
	"fmt"
	"time"
)

// EnsureEventPartitions creates the monthly partitions covering the current
// month plus the next `ahead` months. Ingest fails outright if no partition
// covers the incoming timestamp, so this must run before the first insert and
// periodically thereafter.
func (s *Store) EnsureEventPartitions(ctx context.Context, now time.Time, ahead int) error {
	start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	// One month back too, so events that arrive with a slightly stale clock
	// (or a backlog flushed from the agent's event buffer) still land.
	start = start.AddDate(0, -1, 0)

	for i := 0; i <= ahead+1; i++ {
		from := start.AddDate(0, i, 0)
		to := from.AddDate(0, 1, 0)
		name := fmt.Sprintf("events_%04d_%02d", from.Year(), int(from.Month()))

		// Unqualified names resolve through search_path, which is what keeps
		// this correct whichever schema the manager is deployed into.
		stmt := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s PARTITION OF events FOR VALUES FROM ('%s') TO ('%s')`,
			name, from.Format(time.RFC3339), to.Format(time.RFC3339),
		)
		if _, err := s.Pool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("create partition %s: %w", name, err)
		}
	}
	return nil
}

// DropExpiredEventPartitions removes whole partitions that end before the
// retention horizon. Dropping partitions is what keeps the events table
// bounded; a DELETE-based retention job would not reclaim space usefully.
func (s *Store) DropExpiredEventPartitions(ctx context.Context, retentionDays int) ([]string, error) {
	if retentionDays <= 0 {
		return nil, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)

	// Scoped to the current schema on both sides. Matching on relname alone
	// would also find the partitions of an `events` table in some other
	// schema of the same database, and then drop them by unqualified name.
	rows, err := s.Pool.Query(ctx, `
		SELECT c.relname,
		       pg_get_expr(c.relpartbound, c.oid)
		  FROM pg_class c
		  JOIN pg_inherits i ON i.inhrelid = c.oid
		  JOIN pg_class p ON p.oid = i.inhparent
		 WHERE p.relname = 'events'
		   AND p.relnamespace = current_schema()::regnamespace
		   AND c.relnamespace = current_schema()::regnamespace`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type partition struct{ name, bound string }
	var parts []partition
	for rows.Next() {
		var p partition
		if err := rows.Scan(&p.name, &p.bound); err != nil {
			return nil, err
		}
		parts = append(parts, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var dropped []string
	for _, p := range parts {
		// Partition names are events_YYYY_MM; derive the upper bound from the
		// name rather than parsing the bound expression.
		var year, month int
		if _, err := fmt.Sscanf(p.name, "events_%04d_%02d", &year, &month); err != nil {
			continue
		}
		end := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
		if end.After(cutoff) {
			continue
		}
		if _, err := s.Pool.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS %s`, p.name)); err != nil {
			return dropped, fmt.Errorf("drop partition %s: %w", p.name, err)
		}
		dropped = append(dropped, p.name)
	}
	return dropped, nil
}
