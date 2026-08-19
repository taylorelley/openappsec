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

package storetest

import (
	"strings"
	"testing"
)

// The redacted DSN goes into a t.Fatalf that CI keeps, so a password reaching
// it is a credential in a log.
func TestRedactDSNNeverPrintsAPassword(t *testing.T) {
	const secret = "hunter2-do-not-print"
	for _, dsn := range []string{
		"postgres://manager:" + secret + "@db:5432/appsec_manager?sslmode=disable",
		"postgresql://manager:" + secret + "@db/appsec_manager",
		// The libpq keyword/value form parses as a URL without error.
		"host=db user=manager password=" + secret + " dbname=appsec_manager",
		"  host=db password=" + secret,
		"://not-a-dsn",
	} {
		t.Run(dsn, func(t *testing.T) {
			if got := redactDSN(dsn); strings.Contains(got, secret) {
				t.Fatalf("redactDSN leaked the password: %q", got)
			}
		})
	}
}
