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

package fleet

import (
	"strings"
	"testing"
	"time"
)

// A representative sample of what the agent's prometheus node serves: the
// metric names come from components/security_apps/prometheus/prometheus_metric_names.h
// and the labels from core/metric/generic_metric.cc:158-178.
const exposition = `# HELP total_requests_counter Total requests
# TYPE total_requests_counter counter
total_requests_counter{id="1",agent="5f9c2b1e",process="cp-nano-http-transaction-handler",assetId="aaaa1111",metricName="WAAP telemetry"} 1523
# TYPE requests_blocked_by_waf_counter counter
requests_blocked_by_waf_counter{id="1",agent="5f9c2b1e",assetId="aaaa1111",metricName="WAAP telemetry"} 42
sql_injection_attacks_type_counter{agent="5f9c2b1e",assetId="aaaa1111"} 7
cpu_usage_percentage_max{agent="5f9c2b1e",process="cp-nano-orchestration"} 12.5
no_labels_metric 99
requests_time_latency_average{agent="5f9c2b1e"} 3.75

service_physical_memory_size_kb_max{agent="5f9c2b1e"} 1.048576e+06
`

func TestParsePrometheusText(t *testing.T) {
	samples, err := ParsePrometheusText(strings.NewReader(exposition))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(samples) != 7 {
		t.Fatalf("expected 7 samples, got %d: %+v", len(samples), samples)
	}

	byName := map[string]Sample{}
	for _, s := range samples {
		byName[s.Name] = s
	}

	first := byName["total_requests_counter"]
	if first.Value != 1523 {
		t.Errorf("value = %v, want 1523", first.Value)
	}
	if first.Labels["assetId"] != "aaaa1111" {
		t.Errorf("assetId label missing: %+v", first.Labels)
	}
	if first.Labels["metricName"] != "WAAP telemetry" {
		t.Errorf("label value with a space was mishandled: %q", first.Labels["metricName"])
	}
	if first.Labels["process"] != "cp-nano-http-transaction-handler" {
		t.Errorf("process label missing: %+v", first.Labels)
	}

	if got := byName["cpu_usage_percentage_max"].Value; got != 12.5 {
		t.Errorf("float value = %v, want 12.5", got)
	}
	if got := byName["service_physical_memory_size_kb_max"].Value; got != 1048576 {
		t.Errorf("scientific notation value = %v, want 1048576", got)
	}

	bare := byName["no_labels_metric"]
	if bare.Value != 99 {
		t.Errorf("unlabelled metric value = %v, want 99", bare.Value)
	}
	if bare.Labels == nil {
		t.Error("labels map should be non-nil even with no labels")
	}
}

// HELP and TYPE lines must not become samples.
func TestParseSkipsMetadataAndBlankLines(t *testing.T) {
	samples, err := ParsePrometheusText(strings.NewReader(
		"# HELP x help\n# TYPE x counter\n\n   \nx 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].Name != "x" {
		t.Fatalf("expected exactly the one real sample, got %+v", samples)
	}
}

// One malformed line must not discard the rest of the scrape.
func TestParseSkipsMalformedLines(t *testing.T) {
	samples, err := ParsePrometheusText(strings.NewReader(
		"good_one 1\nbroken{unbalanced 2\nnot_a_number xyz\ngood_two 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("expected the 2 good samples to survive, got %+v", samples)
	}
}

func TestParseHandlesNonFiniteValues(t *testing.T) {
	samples, err := ParsePrometheusText(strings.NewReader("a +Inf\nb NaN\nc -Inf\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 3 {
		t.Fatalf("expected 3 samples, got %d", len(samples))
	}
}

func TestParseIgnoresTrailingTimestamp(t *testing.T) {
	samples, err := ParsePrometheusText(strings.NewReader(`m{a="b"} 5 1699999999000` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].Value != 5 {
		t.Fatalf("timestamp handling wrong: %+v", samples)
	}
}

func TestHealthFromStatus(t *testing.T) {
	cases := []struct {
		name   string
		report StatusReport
		want   Health
	}{
		{"success", StatusReport{LastUpdateStatus: "Succeeded", PolicyVersion: "12"}, HealthHealthy},
		{"up to date", StatusReport{LastUpdateStatus: "Policy is up to date", PolicyVersion: "12"}, HealthHealthy},
		{"failure", StatusReport{LastUpdateStatus: "Failed to download policy", PolicyVersion: "12"}, HealthUnhealthy},
		{"error", StatusReport{LastUpdateStatus: "Error contacting fog", PolicyVersion: "3"}, HealthUnhealthy},
		{"no policy yet", StatusReport{LastUpdateStatus: "Succeeded"}, HealthDegraded},
		{"silent", StatusReport{}, HealthDegraded},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := healthFromStatus(c.report); got != c.want {
				t.Errorf("healthFromStatus = %v, want %v", got, c.want)
			}
		})
	}
}

// An agent that stopped reporting is unknown, whatever its last stored health.
func TestDeriveHealthMarksStaleAgentsUnknown(t *testing.T) {
	recent := time.Now().Add(-time.Minute)
	stale := time.Now().Add(-time.Hour)

	if got := deriveHealth(&Agent{Health: HealthHealthy, LastSeenAt: &recent}); got != HealthHealthy {
		t.Errorf("recent agent = %v, want healthy", got)
	}
	if got := deriveHealth(&Agent{Health: HealthHealthy, LastSeenAt: &stale}); got != HealthUnknown {
		t.Errorf("stale agent = %v, want unknown", got)
	}
	if got := deriveHealth(&Agent{Health: HealthHealthy}); got != HealthUnknown {
		t.Errorf("never-seen agent = %v, want unknown", got)
	}
}
