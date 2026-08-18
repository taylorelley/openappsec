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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Sample is one parsed Prometheus time series point.
type Sample struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	Value  float64           `json:"value"`
}

// ParsePrometheusText parses the exposition format served by the agent's
// prometheus nano-service at :7465/metrics
// (components/security_apps/prometheus/prometheus_comp.cc:98-101).
//
// This is a deliberately small parser: the agent emits plain counters and
// gauges with simple labels, so pulling in a full Prometheus client library
// for it would be disproportionate.
func ParsePrometheusText(r io.Reader) ([]Sample, error) {
	var (
		samples []Sample
		scanner = newLineScanner(r)
	)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // HELP/TYPE metadata and blank lines
		}

		name, labels, rest, err := splitSeries(line)
		if err != nil {
			continue // skip a malformed line rather than losing the scrape
		}

		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		value, err := parseValue(fields[0])
		if err != nil {
			continue
		}
		samples = append(samples, Sample{Name: name, Labels: labels, Value: value})
	}
	return samples, scanner.Err()
}

func parseValue(s string) (float64, error) {
	switch s {
	case "+Inf":
		return math.Inf(1), nil
	case "-Inf":
		return math.Inf(-1), nil
	case "NaN":
		return math.NaN(), nil
	}
	return strconv.ParseFloat(s, 64)
}

// splitSeries breaks `name{label="v",...} value [timestamp]` into its parts.
func splitSeries(line string) (name string, labels map[string]string, rest string, err error) {
	labels = map[string]string{}

	open := strings.IndexByte(line, '{')
	if open < 0 {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			return "", nil, "", fmt.Errorf("malformed series line")
		}
		return parts[0], labels, parts[1], nil
	}

	name = strings.TrimSpace(line[:open])
	close := strings.LastIndexByte(line, '}')
	if close < open {
		return "", nil, "", fmt.Errorf("unbalanced label braces")
	}

	for _, pair := range splitLabels(line[open+1 : close]) {
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(pair[:eq])
		val := strings.TrimSpace(pair[eq+1:])
		val = strings.Trim(val, `"`)
		val = strings.ReplaceAll(val, `\"`, `"`)
		labels[key] = val
	}
	return name, labels, strings.TrimSpace(line[close+1:]), nil
}

// splitLabels splits on commas that are not inside a quoted value.
func splitLabels(s string) []string {
	var (
		out     []string
		current strings.Builder
		inQuote bool
	)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' && (i == 0 || s[i-1] != '\\'):
			inQuote = !inQuote
			current.WriteByte(c)
		case c == ',' && !inQuote:
			out = append(out, current.String())
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}

// Scraper polls each agent's Prometheus endpoint.
type Scraper struct {
	svc    *Service
	client *http.Client
}

func NewScraper(svc *Service) *Scraper {
	return &Scraper{
		svc:    svc,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// DefaultMetricsPort is the prometheus nano-service's primary port
// (nodes/prometheus/main.cc:10). That service also sets "Nano service API
// Allow Get From External IP", which is what makes this the one agent
// endpoint reachable from off-box.
const DefaultMetricsPort = 7465

// ScrapeAll polls every agent that has a metrics endpoint configured.
func (s *Scraper) ScrapeAll(ctx context.Context) {
	agents, err := s.svc.List(ctx)
	if err != nil {
		slog.Error("metrics scrape: listing agents failed", "error", err)
		return
	}
	for i := range agents {
		agent := agents[i]
		if agent.MetricsEndpoint == "" {
			continue
		}
		if err := s.scrapeOne(ctx, &agent); err != nil {
			// A single unreachable agent is normal (restart, network blip) and
			// must not stop the rest of the sweep.
			slog.Debug("metrics scrape failed", "agent", agent.Name, "error", err)
		}
	}
}

func (s *Scraper) scrapeOne(ctx context.Context, agent *Agent) error {
	endpoint := agent.MetricsEndpoint
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = fmt.Sprintf("http://%s:%d/metrics", endpoint, DefaultMetricsPort)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metrics endpoint returned %s", resp.Status)
	}

	samples, err := ParsePrometheusText(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	return s.Store(ctx, agent.ID, samples)
}

func (s *Scraper) Store(ctx context.Context, agentID uuid.UUID, samples []Sample) error {
	if len(samples) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, sample := range samples {
		// Non-finite values cannot be stored as double precision and carry no
		// useful meaning here.
		if math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) {
			continue
		}
		labels, err := json.Marshal(sample.Labels)
		if err != nil {
			continue
		}
		batch.Queue(
			`INSERT INTO agent_metrics (agent_id, metric_name, labels, value) VALUES ($1, $2, $3, $4)`,
			agentID, sample.Name, labels, sample.Value)
	}
	if batch.Len() == 0 {
		return nil
	}

	results := s.svc.pool.SendBatch(ctx, batch)
	for i := 0; i < batch.Len(); i++ {
		if _, err := results.Exec(); err != nil {
			results.Close()
			return err
		}
	}
	if err := results.Close(); err != nil {
		return err
	}
	return s.svc.Touch(ctx, agentID)
}

// LatestMetrics returns the most recent value of each metric for an agent.
func (s *Service) LatestMetrics(ctx context.Context, agentID uuid.UUID) ([]Sample, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (metric_name, labels) metric_name, labels, value
		  FROM agent_metrics
		 WHERE agent_id = $1 AND scraped_at > now() - interval '1 hour'
		 ORDER BY metric_name, labels, scraped_at DESC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Sample{}
	for rows.Next() {
		var (
			s      Sample
			labels []byte
		)
		if err := rows.Scan(&s.Name, &labels, &s.Value); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(labels, &s.Labels); err != nil {
			s.Labels = map[string]string{}
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PurgeMetrics trims the rolling metrics window.
func (s *Service) PurgeMetrics(ctx context.Context, keep time.Duration) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM agent_metrics WHERE scraped_at < now() - $1::interval`, keep.String())
	return err
}
