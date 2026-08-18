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

package ingest

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SyncLearningNotificationID marks a closed learning window
// (core/report/tag_and_enum_management.cc:262).
const SyncLearningNotificationID = "b9b9ab04-2e2a-4cd1-b7e5-2c956861fb69"

// Writer persists normalized events and maintains the derived agent and asset
// registries.
type Writer struct {
	pool *pgxpool.Pool

	// agentCache maps an agent's self-reported ID to our row ID, so the common
	// path does not hit the database for every event in a bulk.
	mu         sync.RWMutex
	agentCache map[string]uuid.UUID
}

func NewWriter(pool *pgxpool.Pool) *Writer {
	return &Writer{pool: pool, agentCache: map[string]uuid.UUID{}}
}

// Write persists a batch of events. Agents and assets referenced by the batch
// are registered on first sight: an agent that starts sending events should
// appear in the fleet inventory without any manual enrolment step.
func (w *Writer) Write(ctx context.Context, events []*Event) error {
	if len(events) == 0 {
		return nil
	}

	for _, e := range events {
		if e.AgentID == "" {
			continue
		}
		id, err := w.resolveAgent(ctx, e.AgentID, e.TenantID)
		if err != nil {
			return err
		}
		e.ManagerAgentID = &id
	}

	batch := &pgx.Batch{}
	for _, e := range events {
		batch.Queue(insertEventSQL,
			e.EventTime, e.ManagerAgentID,
			e.EventName, e.EventSeverity, e.EventPriority, e.EventType,
			e.EventLevel, e.EventLogLevel, e.EventAudience, e.EventAudienceTeam, e.EventTags,
			e.AgentID, e.TenantID, e.ServiceName, e.IssuingEngineVersion,
			e.EventTraceID, e.NotificationID,
			e.AssetID, e.AssetName, e.PracticeType, e.PracticeSubType,
			e.PracticeName, e.RuleName, e.SecurityAction,
			e.SourceIP, e.SourceIPAddr, e.SourcePort, e.SourceCountryName, e.SourceCountryCode,
			e.DestinationIP, e.DestinationPort, e.IPProtocol, e.HTTPSourceID,
			e.HTTPHostName, e.HTTPMethod, e.HTTPURIPath, e.HTTPURIQuery, e.HTTPResponseCode,
			e.WaapIncidentType, e.WaapIncidentDetails, e.WaapFoundIndicators,
			e.WaapUserReputation, e.WaapFinalScore, e.WaapCalculatedThreatLevel,
			e.EventConfidence, e.EventReferenceID,
			e.MatchedLocation, e.MatchedParameter, e.MatchedSample, e.MatchReason,
			e.ProtectionID, e.IncidentType,
			e.Raw,
		)
	}

	results := w.pool.SendBatch(ctx, batch)
	for range events {
		if _, err := results.Exec(); err != nil {
			results.Close()
			return err
		}
	}
	if err := results.Close(); err != nil {
		return err
	}

	return w.updateDerived(ctx, events)
}

const insertEventSQL = `
INSERT INTO events (
	event_time, manager_agent_id,
	event_name, event_severity, event_priority, event_type,
	event_level, event_log_level, event_audience, event_audience_team, event_tags,
	agent_id, tenant_id, service_name, issuing_engine_version,
	event_trace_id, notification_id,
	asset_id, asset_name, practice_type, practice_sub_type,
	practice_name, rule_name, security_action,
	source_ip, source_ip_addr, source_port, source_country_name, source_country_code,
	destination_ip, destination_port, ip_protocol, http_source_id,
	http_host_name, http_method, http_uri_path, http_uri_query, http_response_code,
	waap_incident_type, waap_incident_details, waap_found_indicators,
	waap_user_reputation, waap_final_score, waap_calculated_threat_level,
	event_confidence, event_reference_id,
	matched_location, matched_parameter, matched_sample, match_reason,
	protection_id, incident_type,
	raw
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
	$11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
	$21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
	$31, $32, $33, $34, $35, $36, $37, $38, $39, $40,
	$41, $42, $43, $44, $45, $46, $47, $48, $49, $50,
	$51, $52, $53
)`

// resolveAgent maps an agent's self-reported ID to a row in agents, creating
// the row on first sight.
func (w *Writer) resolveAgent(ctx context.Context, agentUUID, tenantID string) (uuid.UUID, error) {
	w.mu.RLock()
	if id, ok := w.agentCache[agentUUID]; ok {
		w.mu.RUnlock()
		return id, nil
	}
	w.mu.RUnlock()

	var id uuid.UUID
	err := w.pool.QueryRow(ctx, `
		INSERT INTO agents (id, agent_uuid, tenant_id, name, last_seen_at)
		VALUES ($1, $2, $3, $2, now())
		ON CONFLICT (agent_uuid) DO UPDATE
		   SET last_seen_at = now(),
		       tenant_id = CASE WHEN agents.tenant_id = '' THEN EXCLUDED.tenant_id
		                        ELSE agents.tenant_id END
		RETURNING id`,
		uuid.New(), agentUUID, tenantID,
	).Scan(&id)
	if err != nil {
		return uuid.Nil, err
	}

	w.mu.Lock()
	w.agentCache[agentUUID] = id
	w.mu.Unlock()
	return id, nil
}

// updateDerived maintains the asset registry, agent liveness, and the
// learning-window log that the learning view is built from.
func (w *Writer) updateDerived(ctx context.Context, events []*Event) error {
	type assetKey struct{ tenant, id, name string }
	assets := map[assetKey]int{}
	seenAgents := map[uuid.UUID]bool{}

	batch := &pgx.Batch{}

	for _, e := range events {
		if e.AssetID != "" || e.AssetName != "" {
			assets[assetKey{e.TenantID, e.AssetID, e.AssetName}]++
		}
		if e.ManagerAgentID != nil {
			seenAgents[*e.ManagerAgentID] = true
		}
		if e.NotificationID == SyncLearningNotificationID {
			batch.Queue(`
				INSERT INTO learning_windows (tenant_id, asset_id, window_type, window_id)
				VALUES ($1, $2, $3, $4)
				ON CONFLICT (tenant_id, asset_id, window_type, window_id) DO NOTHING`,
				e.TenantID, learningAssetID(e), learningType(e), learningWindowID(e))
		}
	}

	for k, n := range assets {
		batch.Queue(`
			INSERT INTO assets (id, tenant_id, asset_id, asset_name, event_count)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, asset_id) DO UPDATE
			   SET last_seen_at = now(),
			       event_count  = assets.event_count + EXCLUDED.event_count,
			       asset_name   = CASE WHEN EXCLUDED.asset_name <> '' THEN EXCLUDED.asset_name
			                           ELSE assets.asset_name END`,
			uuid.New(), k.tenant, k.id, k.name, n)
	}

	for id := range seenAgents {
		batch.Queue(`UPDATE agents SET last_seen_at = now() WHERE id = $1`, id)
	}

	if batch.Len() == 0 {
		return nil
	}
	results := w.pool.SendBatch(ctx, batch)
	for i := 0; i < batch.Len(); i++ {
		if _, err := results.Exec(); err != nil {
			results.Close()
			return err
		}
	}
	return results.Close()
}

// The SYNC_LEARNING payload nests assetId/type/windowId under
// notificationConsumerData.syncLearnNotificationConsumers; the report index
// flattens them by leaf name.
func learningAssetID(e *Event) string { return e.AssetID }

func learningType(e *Event) string {
	if v, ok := rawLookup(e, "type"); ok {
		return v
	}
	return ""
}

func learningWindowID(e *Event) string {
	if v, ok := rawLookup(e, "windowid"); ok {
		return v
	}
	return ""
}

// rawLookup re-reads a field from the preserved raw document. Learning windows
// are rare enough that re-parsing beats widening the Event struct for them.
func rawLookup(e *Event, field string) (string, bool) {
	r, err := ParseReport(e.Raw)
	if err != nil {
		return "", false
	}
	if !r.Has(field) {
		return "", false
	}
	return r.String(field), true
}

// PurgeOldMetrics trims the rolling metrics window.
func (w *Writer) PurgeOldMetrics(ctx context.Context, keep time.Duration) error {
	_, err := w.pool.Exec(ctx,
		`DELETE FROM agent_metrics WHERE scraped_at < now() - $1::interval`,
		keep.String())
	return err
}
