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

package config

import (
	"strings"
	"testing"
)

// A non-positive retention window is not "keep everything": the partition
// dropper treats it as nothing to do, so the events table grows without bound
// and nothing ever says so.
func TestLoadRejectsANonPositiveRetentionWindow(t *testing.T) {
	for _, value := range []string{"0", "-1"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("MANAGER_EVENT_RETENTION_DAYS", value)
			if _, err := Load(); err == nil {
				t.Fatal("accepted a retention window that retains nothing")
			} else if !strings.Contains(err.Error(), "MANAGER_EVENT_RETENTION_DAYS") {
				t.Fatalf("the error should name the variable: %v", err)
			}
		})
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("MANAGER_EVENT_RETENTION_DAYS", "")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.EventRetentionDays != 30 {
		t.Fatalf("retention default = %d, want 30", c.EventRetentionDays)
	}
	// Agents normally live on a private network, so the scraper must reach
	// them without extra configuration.
	if !c.AllowPrivateScrapeTargets {
		t.Fatal("private scrape targets should be allowed by default")
	}
	if !strings.Contains(c.DatabaseURL, "sslmode=prefer") {
		t.Fatalf("assembled DSN should default to sslmode=prefer: %q", c.DatabaseURL)
	}
}

func TestLoadRejectsANonBooleanScrapeSwitch(t *testing.T) {
	t.Setenv("MANAGER_ALLOW_PRIVATE_SCRAPE_TARGETS", "sometimes")
	if _, err := Load(); err == nil {
		t.Fatal("accepted a non-boolean value")
	}
}
