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

// Package fleet maintains the agent inventory: identity, liveness, reported
// status and scraped metrics.
package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openappsec/openappsec/management/backend/internal/auth"
)

var ErrNotFound = errors.New("fleet: agent not found")

type Health string

const (
	HealthHealthy   Health = "healthy"
	HealthDegraded  Health = "degraded"
	HealthUnhealthy Health = "unhealthy"
	HealthUnknown   Health = "unknown"
)

type Agent struct {
	ID                uuid.UUID       `json:"id"`
	Name              string          `json:"name"`
	AgentUUID         string          `json:"agentUuid"`
	TenantID          string          `json:"tenantId"`
	ProfileID         string          `json:"profileId"`
	Mode              string          `json:"mode"`
	Version           string          `json:"version"`
	PolicyVersion     string          `json:"policyVersion"`
	AppliedRevisionID *int64          `json:"appliedRevisionId,omitempty"`
	Health            Health          `json:"health"`
	Status            json.RawMessage `json:"status"`
	Labels            json.RawMessage `json:"labels"`
	MetricsEndpoint   string          `json:"metricsEndpoint"`
	Enrolled          bool            `json:"enrolled"`
	FirstSeenAt       time.Time       `json:"firstSeenAt"`
	LastSeenAt        *time.Time      `json:"lastSeenAt,omitempty"`
	LastStatusAt      *time.Time      `json:"lastStatusAt,omitempty"`
}

// StatusReport is what the companion posts back. The field names mirror the
// literal JSON keys of the agent's own show-orchestration-status response
// (components/security_apps/orchestration/include/get_status_rest.h:70-86), so
// the companion can forward that response almost verbatim.
type StatusReport struct {
	LastUpdateAttempt  string `json:"Last update attempt"`
	LastUpdate         string `json:"Last update"`
	LastUpdateStatus   string `json:"Last update status"`
	PolicyVersion      string `json:"Policy version"`
	LastPolicyUpdate   string `json:"Last policy update"`
	LastManifestUpdate string `json:"Last manifest update"`
	LastSettingsUpdate string `json:"Last settings update"`
	RegistrationStatus string `json:"Registration status"`
	ManifestStatus     string `json:"Manifest status"`
	UpgradeMode        string `json:"Upgrade mode"`
	FogAddress         string `json:"Fog address"`
	AgentID            string `json:"Agent ID"`
	ProfileID          string `json:"Profile ID"`
	TenantID           string `json:"Tenant ID"`

	// Supplied by the companion rather than by the agent's status call.
	AgentVersion      string          `json:"agentVersion,omitempty"`
	OrchestrationMode string          `json:"orchestrationMode,omitempty"`
	HealthCheck       json.RawMessage `json:"healthCheck,omitempty"`
	MetricsEndpoint   string          `json:"metricsEndpoint,omitempty"`
}

type Service struct{ pool *pgxpool.Pool }

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

const agentColumns = `id, name, COALESCE(agent_uuid, ''), tenant_id, profile_id, mode, version,
	policy_version, applied_revision_id, health, status, labels, metrics_endpoint,
	enrollment_token_hash IS NOT NULL, first_seen_at, last_seen_at, last_status_at`

func scanAgent(row pgx.Row) (*Agent, error) {
	var a Agent
	err := row.Scan(&a.ID, &a.Name, &a.AgentUUID, &a.TenantID, &a.ProfileID, &a.Mode, &a.Version,
		&a.PolicyVersion, &a.AppliedRevisionID, &a.Health, &a.Status, &a.Labels,
		&a.MetricsEndpoint, &a.Enrolled, &a.FirstSeenAt, &a.LastSeenAt, &a.LastStatusAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &a, err
}

func (s *Service) List(ctx context.Context) ([]Agent, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+agentColumns+` FROM agents ORDER BY last_seen_at DESC NULLS LAST, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	agents := []Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Liveness is derived on read rather than written by a sweeper: an agent
	// that has stopped reporting is stale even though nothing updated its row.
	for i := range agents {
		agents[i].Health = deriveHealth(&agents[i])
	}
	return agents, nil
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (*Agent, error) {
	a, err := scanAgent(s.pool.QueryRow(ctx, `SELECT `+agentColumns+` FROM agents WHERE id = $1`, id))
	if err != nil {
		return nil, err
	}
	a.Health = deriveHealth(a)
	return a, nil
}

// staleAfter is how long an agent may go without contact before its health is
// reported as unknown. The agent's own health check runs every 30s by default
// and bulk logs flush every 2s, so several minutes of silence is meaningful.
const staleAfter = 5 * time.Minute

func deriveHealth(a *Agent) Health {
	if a.LastSeenAt == nil || time.Since(*a.LastSeenAt) > staleAfter {
		return HealthUnknown
	}
	return a.Health
}

// Enroll registers an agent for the pull companion and returns its token. The
// token is shown once; only its hash is stored.
func (s *Service) Enroll(ctx context.Context, name, agentUUID string) (*Agent, string, error) {
	token, err := auth.NewToken()
	if err != nil {
		return nil, "", err
	}

	var id uuid.UUID
	// An agent may already exist because it started sending events before
	// anyone enrolled it; in that case attach the token to the existing row
	// rather than creating a duplicate.
	if agentUUID != "" {
		err = s.pool.QueryRow(ctx, `
			INSERT INTO agents (id, name, agent_uuid, enrollment_token_hash)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (agent_uuid) DO UPDATE
			   SET enrollment_token_hash = EXCLUDED.enrollment_token_hash,
			       name = CASE WHEN EXCLUDED.name <> '' THEN EXCLUDED.name ELSE agents.name END,
			       updated_at = now()
			RETURNING id`,
			uuid.New(), name, agentUUID, auth.HashToken(token)).Scan(&id)
	} else {
		err = s.pool.QueryRow(ctx, `
			INSERT INTO agents (id, name, enrollment_token_hash)
			VALUES ($1, $2, $3) RETURNING id`,
			uuid.New(), name, auth.HashToken(token)).Scan(&id)
	}
	if err != nil {
		return nil, "", err
	}

	agent, err := s.Get(ctx, id)
	if err != nil {
		return nil, "", err
	}
	return agent, token, nil
}

// ResolveEnrollment authenticates a companion request.
func (s *Service) ResolveEnrollment(ctx context.Context, token string) (*Agent, error) {
	a, err := scanAgent(s.pool.QueryRow(ctx,
		`SELECT `+agentColumns+` FROM agents WHERE enrollment_token_hash = $1`,
		auth.HashToken(token)))
	if err != nil {
		return nil, err
	}
	return a, nil
}

// RevokeEnrollment invalidates an agent's companion token.
func (s *Service) RevokeEnrollment(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE agents SET enrollment_token_hash = NULL, updated_at = now() WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Service) Rename(ctx context.Context, id uuid.UUID, name string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE agents SET name = $2, updated_at = now() WHERE id = $1`, id, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordStatus stores a status report and updates the derived columns.
func (s *Service) RecordStatus(ctx context.Context, id uuid.UUID, report StatusReport, raw json.RawMessage) error {
	if len(raw) == 0 {
		var err error
		if raw, err = json.Marshal(report); err != nil {
			return err
		}
	}

	// The endpoint in a status push is chosen by the agent, so it decides what
	// the manager will connect to. Drop anything that does not validate rather
	// than storing a target the scraper would later refuse anyway.
	metricsEndpoint := report.MetricsEndpoint
	if metricsEndpoint != "" {
		if _, err := ParseMetricsEndpoint(metricsEndpoint); err != nil {
			slog.Warn("ignoring an invalid metrics endpoint reported by an agent",
				"agent", id, "endpoint", metricsEndpoint, "error", err)
			metricsEndpoint = ""
		}
	}

	_, err := s.pool.Exec(ctx, `
		UPDATE agents SET
			status          = $2,
			policy_version  = COALESCE(NULLIF($3, ''), policy_version),
			profile_id      = COALESCE(NULLIF($4, ''), profile_id),
			tenant_id       = COALESCE(NULLIF($5, ''), tenant_id),
			agent_uuid      = COALESCE(agent_uuid, NULLIF($6, '')),
			version         = COALESCE(NULLIF($7, ''), version),
			mode            = COALESCE(NULLIF($8, ''), mode),
			metrics_endpoint= COALESCE(NULLIF($9, ''), metrics_endpoint),
			health          = $10,
			last_status_at  = now(),
			last_seen_at    = now(),
			updated_at      = now()
		WHERE id = $1`,
		id, raw, report.PolicyVersion, report.ProfileID, report.TenantID, report.AgentID,
		report.AgentVersion, report.OrchestrationMode, metricsEndpoint,
		string(healthFromStatus(report)))
	return err
}

// healthFromStatus interprets the agent's own status wording.
//
// The status strings are free text produced by the orchestrator, so this
// matches loosely and treats anything unrecognised as unknown rather than
// claiming a health it cannot support.
func healthFromStatus(r StatusReport) Health {
	status := strings.ToLower(r.LastUpdateStatus)
	switch {
	case strings.Contains(status, "fail"), strings.Contains(status, "error"):
		return HealthUnhealthy
	case r.PolicyVersion == "":
		// Running, in contact, but nothing enforced yet.
		return HealthDegraded
	case strings.Contains(status, "succe"), strings.Contains(status, "up to date"):
		return HealthHealthy
	case status == "":
		return HealthUnknown
	default:
		return HealthDegraded
	}
}

// MarkApplied records which revision an agent last confirmed applying, which
// is what surfaces policy drift in the inventory.
func (s *Service) MarkApplied(ctx context.Context, id uuid.UUID, revisionID int64, policyVersion string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE agents SET applied_revision_id = $2,
		                  policy_version = COALESCE(NULLIF($3, ''), policy_version),
		                  last_seen_at = now(), updated_at = now()
		 WHERE id = $1`, id, revisionID, policyVersion)
	return err
}

// Touch refreshes liveness without a full status report.
func (s *Service) Touch(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `UPDATE agents SET last_seen_at = now() WHERE id = $1`, id)
	return err
}

// SetMetricsEndpoint configures where the agent's Prometheus node is reachable.
// A bare host is expanded to http://<host>:7465/metrics by the scraper.
func (s *Service) SetMetricsEndpoint(ctx context.Context, id uuid.UUID, endpoint string) error {
	// An empty value clears the endpoint and disables scraping for the agent.
	if endpoint != "" {
		if _, err := ParseMetricsEndpoint(endpoint); err != nil {
			return err
		}
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE agents SET metrics_endpoint = $2, updated_at = now() WHERE id = $1`, id, endpoint)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
