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
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// Fresh is defined in the storetest subpackage, but this package cannot
// import it without a cycle, so the same isolation is set up locally.
func Fresh(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()

	dsn := os.Getenv("MANAGER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("MANAGER_TEST_DATABASE_URL not set; skipping database test")
	}

	admin, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	schema := "test_" + hex.EncodeToString(buf)

	if _, err := admin.Pool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	s, err := OpenWithSchema(ctx, dsn, schema)
	if err != nil {
		t.Fatalf("open scoped: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := s.EnsureEventPartitions(ctx, time.Now().UTC(), 2); err != nil {
		t.Fatalf("partitions: %v", err)
	}

	t.Cleanup(func() {
		s.Close()
		_, _ = admin.Pool.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		admin.Close()
	})
	return s
}

func TestMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := Fresh(t)

	// Running again must be a no-op rather than an error.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	var tables int
	err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.tables
		 WHERE table_schema = current_schema() AND table_name IN
		       ('users','sessions','agents','policy_revisions','policy_assignments',
		        'events','event_daily_rollups','assets','learning_windows',
		        'tuning_decisions','agent_metrics','audit_log','manager_settings')`).Scan(&tables)
	if err != nil {
		t.Fatalf("count tables: %v", err)
	}
	if tables != 13 {
		t.Fatalf("expected 13 core tables, got %d", tables)
	}
}

func TestEventPartitionsCoverNow(t *testing.T) {
	ctx := context.Background()
	s := Fresh(t)

	// An insert only succeeds if a partition covers the timestamp, so this
	// doubles as the partition-coverage assertion.
	_, err := s.Pool.Exec(ctx,
		`INSERT INTO events (event_time, event_name, raw) VALUES ($1, $2, '{}'::jsonb)`,
		time.Now().UTC(), "Web Request")
	if err != nil {
		t.Fatalf("insert into current partition: %v", err)
	}

	// And a month back, which EnsureEventPartitions also provisions so that a
	// flushed agent event buffer does not get rejected.
	_, err = s.Pool.Exec(ctx,
		`INSERT INTO events (event_time, event_name, raw) VALUES ($1, $2, '{}'::jsonb)`,
		time.Now().UTC().AddDate(0, 0, -20), "Web Request")
	if err != nil {
		t.Fatalf("insert into previous partition: %v", err)
	}
}

func TestDropExpiredEventPartitions(t *testing.T) {
	ctx := context.Background()
	s := Fresh(t)

	// Provision a partition well in the past, then prove retention drops it.
	old := time.Now().UTC().AddDate(0, -14, 0)
	name := "events_" + old.Format("2006_01")
	from := time.Date(old.Year(), old.Month(), 1, 0, 0, 0, 0, time.UTC)
	_, err := s.Pool.Exec(ctx,
		`CREATE TABLE `+name+` PARTITION OF events FOR VALUES FROM ('`+
			from.Format(time.RFC3339)+`') TO ('`+from.AddDate(0, 1, 0).Format(time.RFC3339)+`')`)
	if err != nil {
		t.Fatalf("create old partition: %v", err)
	}

	dropped, err := s.DropExpiredEventPartitions(ctx, 30)
	if err != nil {
		t.Fatalf("drop: %v", err)
	}
	found := false
	for _, d := range dropped {
		if d == name {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %s to be dropped, got %v", name, dropped)
	}

	// The current partition must survive.
	var exists bool
	cur := "events_" + time.Now().UTC().Format("2006_01")
	if err := s.Pool.QueryRow(ctx,
		`SELECT to_regclass($1) IS NOT NULL`, cur).Scan(&exists); err != nil {
		t.Fatalf("check current: %v", err)
	}
	if !exists {
		t.Fatalf("current partition %s was dropped", cur)
	}
}

// Partition maintenance must not reach outside its own schema. A manager
// deployed alongside another schema that also has an `events` partitioned
// table would otherwise drop that schema's partitions.
func TestRetentionIsScopedToItsOwnSchema(t *testing.T) {
	ctx := context.Background()
	mine := Fresh(t)
	theirs := Fresh(t)

	// Give the other schema an old partition that retention would match on
	// name alone.
	old := time.Now().UTC().AddDate(0, -14, 0)
	name := "events_" + old.Format("2006_01")
	from := time.Date(old.Year(), old.Month(), 1, 0, 0, 0, 0, time.UTC)
	_, err := theirs.Pool.Exec(ctx,
		`CREATE TABLE `+name+` PARTITION OF events FOR VALUES FROM ('`+
			from.Format(time.RFC3339)+`') TO ('`+from.AddDate(0, 1, 0).Format(time.RFC3339)+`')`)
	if err != nil {
		t.Fatalf("create partition in the other schema: %v", err)
	}

	dropped, err := mine.DropExpiredEventPartitions(ctx, 30)
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if len(dropped) != 0 {
		t.Fatalf("retention dropped partitions belonging to another schema: %v", dropped)
	}

	var exists bool
	if err := theirs.Pool.QueryRow(ctx,
		`SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("the other schema's partition was dropped")
	}
}
