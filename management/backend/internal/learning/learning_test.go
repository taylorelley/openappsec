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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openappsec/openappsec/management/backend/internal/store/storetest"
)

func newService(t *testing.T) (*Service, string) {
	t.Helper()
	db := storetest.Fresh(t)
	root := t.TempDir()
	return NewService(db.Pool, root), root
}

// The asset and tenant identifiers become path segments under the
// shared-storage root. filepath.Join resolves ".." rather than rejecting it,
// so without validation an identifier can escape the root entirely and the
// manager will create directories and write a file wherever it lands.
func TestPublishDecisionsRejectsTraversal(t *testing.T) {
	ctx := context.Background()
	svc, root := newService(t)

	// A sentinel outside the root that must remain untouched.
	outside := filepath.Dir(root)

	for _, assetID := range []string{
		"../escape",
		"../../escape",
		"../../../etc/cron.d",
		"a/../../escape",
		"..",
		"nested/path",
		`back\slash`,
		"trailing/",
		"with space",
		strings.Repeat("x", 300),
	} {
		t.Run(assetID, func(t *testing.T) {
			err := svc.PublishDecisions(ctx, "tenant", assetID)
			if err == nil {
				t.Fatalf("PublishDecisions accepted a dangerous asset id %q", assetID)
			}
		})
	}

	// Nothing may have been created outside the root.
	entries, err := os.ReadDir(outside)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == "escape" || e.Name() == "tuning" {
			t.Fatalf("a file was created outside the shared-storage root: %s", e.Name())
		}
	}
}

func TestPublishDecisionsRejectsTraversalInTenant(t *testing.T) {
	ctx := context.Background()
	svc, _ := newService(t)

	for _, tenantID := range []string{"../escape", "..", "a/b"} {
		if err := svc.PublishDecisions(ctx, tenantID, "good-asset"); err == nil {
			t.Errorf("PublishDecisions accepted a dangerous tenant id %q", tenantID)
		}
	}
}

// A bad identifier must be refused before the row is written, or the decision
// is stored but can never be published.
func TestSetDecisionRejectsTraversal(t *testing.T) {
	ctx := context.Background()
	svc, _ := newService(t)

	_, err := svc.SetDecision(ctx, "tenant", "../../escape", TypeURL, "/x", DecisionBenign, nil)
	if err == nil {
		t.Fatal("SetDecision accepted a traversing asset id")
	}

	decisions, err := svc.ListDecisions(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 0 {
		t.Fatalf("a rejected decision was still stored: %+v", decisions)
	}
}

// Realistic identifiers must keep working: the agent uses UUIDs, and the
// deployments in this repository use names like "asset-demo-1".
func TestPublishDecisionsAcceptsRealIdentifiers(t *testing.T) {
	ctx := context.Background()
	svc, root := newService(t)

	cases := []struct{ tenant, asset string }{
		{"aaaa1111-2222-3333-4444-555566667777", "bbbb1111-2222-3333-4444-555566667777"},
		{"tenant-demo", "asset-demo-1"},
		{"", "asset-with-no-tenant"},
		{"tenant.with.dots", "asset_with_underscores"},
	}
	for _, c := range cases {
		if _, err := svc.SetDecision(ctx, c.tenant, c.asset,
			TypeURL, "/rest/products/search", DecisionBenign, nil); err != nil {
			t.Fatalf("SetDecision(%q, %q) failed: %v", c.tenant, c.asset, err)
		}

		parts := []string{root}
		if c.tenant != "" {
			parts = append(parts, c.tenant)
		}
		parts = append(parts, c.asset, "tuning", "decisions.data")
		if _, err := os.Stat(filepath.Join(parts...)); err != nil {
			t.Fatalf("decisions.data was not written for (%q, %q): %v", c.tenant, c.asset, err)
		}
	}
}

func TestValidEventTypeAndDecision(t *testing.T) {
	for _, v := range []string{TypeSource, TypeURL, TypeParameterName, TypeParameterValue} {
		if !ValidEventType(v) {
			t.Errorf("ValidEventType(%q) = false", v)
		}
	}
	for _, v := range []string{"", "URL", "cookie", "../"} {
		if ValidEventType(v) {
			t.Errorf("ValidEventType(%q) = true", v)
		}
	}
	for _, v := range []string{DecisionBenign, DecisionMalicious, DecisionDismiss} {
		if !ValidDecision(v) {
			t.Errorf("ValidDecision(%q) = false", v)
		}
	}
	for _, v := range []string{"", "Benign", "allow"} {
		if ValidDecision(v) {
			t.Errorf("ValidDecision(%q) = true", v)
		}
	}
}
