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

// Package storetest provides a migrated, isolated database for tests.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/openappsec/openappsec/management/backend/internal/store"
)

// DSN returns the test database DSN, skipping the test when the suite is run
// without a Postgres available.
func DSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("MANAGER_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("MANAGER_TEST_DATABASE_URL not set; skipping database test")
	}
	return dsn
}

// Fresh returns a migrated store in a schema of its own.
//
// Each caller gets a uniquely named schema rather than a wiped `public`.
// `go test` runs packages in parallel, so a shared schema means one package's
// setup can drop the tables another is midway through using — which is
// exactly the kind of failure that looks like flakiness.
func Fresh(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	dsn := DSN(t)

	// The schema has to exist before a pool can pin its search_path to it.
	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}

	schema := uniqueSchemaName(t)
	if _, err := admin.Pool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatalf("create schema %s: %v", schema, err)
	}

	scoped, err := store.OpenWithSchema(ctx, dsn, schema)
	if err != nil {
		admin.Close()
		t.Fatalf("open scoped pool: %v", err)
	}

	if err := scoped.Migrate(ctx); err != nil {
		scoped.Close()
		admin.Close()
		t.Fatalf("migrate: %v", err)
	}
	if err := scoped.EnsureEventPartitions(ctx, time.Now().UTC(), 2); err != nil {
		scoped.Close()
		admin.Close()
		t.Fatalf("provision partitions: %v", err)
	}

	t.Cleanup(func() {
		scoped.Close()
		dropCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := admin.Pool.Exec(dropCtx, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Logf("could not drop test schema %s: %v", schema, err)
		}
		admin.Close()
	})

	return scoped
}

func uniqueSchemaName(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generate schema name: %v", err)
	}
	return fmt.Sprintf("test_%s", hex.EncodeToString(buf))
}
