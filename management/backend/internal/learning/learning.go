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

// Package learning covers the detect-to-prevent workflow: per-asset learning
// progress, tuning suggestions computed from the event stream, and the
// decisions fed back to the agent.
//
// The suggestion engine that the SaaS uses (smartsync-tuning) lives in a
// different repository and is not reimplemented here. Instead, suggestions are
// derived from the events this manager already ingests, and the operator's
// decisions are published in the exact shape the agent polls for.
package learning

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Decision values accepted by the agent
// (components/security_apps/waap/waap_clib/TuningDecision.cc:79-93).
const (
	DecisionBenign    = "benign"
	DecisionMalicious = "malicious"
	DecisionDismiss   = "dismiss"
)

// Event types accepted by the agent (TuningDecision.cc:95-115).
const (
	TypeSource         = "source"
	TypeURL            = "url"
	TypeParameterName  = "parameterName"
	TypeParameterValue = "parameterValue"
)

func ValidDecision(d string) bool {
	switch d {
	case DecisionBenign, DecisionMalicious, DecisionDismiss:
		return true
	}
	return false
}

// identifierPattern bounds what may become a path segment under the
// shared-storage root. Agent tenant and asset IDs are UUIDs in practice, and
// the deployments in this repository use names like "asset-demo-1", so this
// charset is generous for real input while excluding every path separator.
var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ValidIdentifier reports whether a tenant or asset ID is safe to use as a
// path segment.
//
// This matters because PublishDecisions builds a filesystem path from these
// values, and filepath.Join *resolves* ".." rather than rejecting it — an
// asset ID of "../../../etc/cron.d" would otherwise escape the root entirely
// and have a file written at the result.
func ValidIdentifier(s string) bool {
	if s == "." || s == ".." {
		return false
	}
	return identifierPattern.MatchString(s)
}

func ValidEventType(t string) bool {
	switch t {
	case TypeSource, TypeURL, TypeParameterName, TypeParameterValue:
		return true
	}
	return false
}

// TuningEvent is one decision, serialized exactly as the agent's TuningEvent
// struct expects (TuningDecision.cc:48-60).
type TuningEvent struct {
	Decision   string `json:"decision"`
	EventType  string `json:"eventType"`
	EventTitle string `json:"eventTitle"`
}

// DecisionsDocument is the body of decisions.data.
type DecisionsDocument struct {
	Decisions []TuningEvent `json:"decisions"`
}

type Decision struct {
	ID         int64     `json:"id"`
	TenantID   string    `json:"tenantId"`
	AssetID    string    `json:"assetId"`
	EventType  string    `json:"eventType"`
	EventTitle string    `json:"eventTitle"`
	Decision   string    `json:"decision"`
	DecidedBy  string    `json:"decidedBy"`
	DecidedAt  time.Time `json:"decidedAt"`
}

type Service struct {
	pool *pgxpool.Pool
	// sharedStoragePath is the root of the volume that the
	// appsec-shared-storage service serves. See PublishDecisions.
	sharedStoragePath string
}

func NewService(pool *pgxpool.Pool, sharedStoragePath string) *Service {
	return &Service{pool: pool, sharedStoragePath: sharedStoragePath}
}

// ------------------------------------------------------------- decisions

func (s *Service) SetDecision(ctx context.Context, tenantID, assetID, eventType, eventTitle, decision string, by *uuid.UUID) (*Decision, error) {
	// Validated before the insert, not just before the write: a row that
	// cannot be published is worse than a rejected request, because it stays
	// in the table and fails again on every republish.
	if !ValidIdentifier(assetID) {
		return nil, fmt.Errorf("learning: invalid asset id %q", assetID)
	}
	if tenantID != "" && !ValidIdentifier(tenantID) {
		return nil, fmt.Errorf("learning: invalid tenant id %q", tenantID)
	}
	if !ValidEventType(eventType) {
		return nil, fmt.Errorf("learning: invalid event type %q", eventType)
	}
	if !ValidDecision(decision) {
		return nil, fmt.Errorf("learning: invalid decision %q", decision)
	}
	if eventTitle == "" {
		return nil, fmt.Errorf("learning: event title is required")
	}

	var d Decision
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tuning_decisions (tenant_id, asset_id, event_type, event_title, decision, decided_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, asset_id, event_type, event_title)
		DO UPDATE SET decision = EXCLUDED.decision,
		              decided_by = EXCLUDED.decided_by,
		              decided_at = now()
		RETURNING id, tenant_id, asset_id, event_type, event_title, decision, decided_at`,
		tenantID, assetID, eventType, eventTitle, decision, by,
	).Scan(&d.ID, &d.TenantID, &d.AssetID, &d.EventType, &d.EventTitle, &d.Decision, &d.DecidedAt)
	if err != nil {
		return nil, err
	}

	// Republish immediately so the agent picks the change up on its next poll
	// rather than after the following manager restart.
	if err := s.PublishDecisions(ctx, tenantID, assetID); err != nil {
		return &d, fmt.Errorf("decision saved, but publishing decisions.data failed: %w", err)
	}
	return &d, nil
}

func (s *Service) DeleteDecision(ctx context.Context, id int64) error {
	var tenantID, assetID string
	err := s.pool.QueryRow(ctx,
		`DELETE FROM tuning_decisions WHERE id = $1 RETURNING tenant_id, asset_id`, id,
	).Scan(&tenantID, &assetID)
	if err != nil {
		return err
	}
	return s.PublishDecisions(ctx, tenantID, assetID)
}

func (s *Service) ListDecisions(ctx context.Context, tenantID, assetID string) ([]Decision, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT d.id, d.tenant_id, d.asset_id, d.event_type, d.event_title, d.decision,
		       COALESCE(u.username, ''), d.decided_at
		  FROM tuning_decisions d
		  LEFT JOIN users u ON u.id = d.decided_by
		 WHERE ($1 = '' OR d.tenant_id = $1) AND ($2 = '' OR d.asset_id = $2)
		 ORDER BY d.decided_at DESC`, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Decision{}
	for rows.Next() {
		var d Decision
		if err := rows.Scan(&d.ID, &d.TenantID, &d.AssetID, &d.EventType, &d.EventTitle,
			&d.Decision, &d.DecidedBy, &d.DecidedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DecisionsDocumentFor builds the decisions.data body for one asset.
func (s *Service) DecisionsDocumentFor(ctx context.Context, tenantID, assetID string) (*DecisionsDocument, error) {
	decisions, err := s.ListDecisions(ctx, tenantID, assetID)
	if err != nil {
		return nil, err
	}
	doc := &DecisionsDocument{Decisions: make([]TuningEvent, 0, len(decisions))}
	for _, d := range decisions {
		doc.Decisions = append(doc.Decisions, TuningEvent{
			Decision:   d.Decision,
			EventType:  d.EventType,
			EventTitle: d.EventTitle,
		})
	}
	return doc, nil
}

// PublishDecisions writes decisions.data into the shared-storage volume.
//
// This is the delivery path that actually works with a stock agent. The agent
// fetches tuning decisions from SHARED_STORAGE_HOST, not from TUNING_HOST:
// TuningDecision::sendObject targets getSharedStorageHost() on port 80 for any
// non-ONLINE orchestration mode (TuningDecision.cc), while only the event
// stream goes to the tuning host. Rather than reimplement the shared-storage
// service's API, the manager writes the file into the same volume that
// appsec-shared-storage serves, at the path the agent will request:
//
//	<shared storage>/<tenantId>/<assetId>/tuning/decisions.data
//
// which the agent asks for as GET /api/<tenantId>/<assetId>/tuning/decisions.data.
//
// The manager also serves that URL itself, so a deployment that points
// SHARED_STORAGE_HOST at the manager works too; see the agent API package.
func (s *Service) PublishDecisions(ctx context.Context, tenantID, assetID string) error {
	if s.sharedStoragePath == "" || assetID == "" {
		return nil
	}
	if !ValidIdentifier(assetID) {
		return fmt.Errorf("learning: refusing to publish for invalid asset id %q", assetID)
	}
	if tenantID != "" && !ValidIdentifier(tenantID) {
		return fmt.Errorf("learning: refusing to publish for invalid tenant id %q", tenantID)
	}

	doc, err := s.DecisionsDocumentFor(ctx, tenantID, assetID)
	if err != nil {
		return err
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	// The agent collapses "//" in the remote path, so an empty tenant yields
	// <asset>/tuning/... rather than a leading empty segment.
	parts := []string{s.sharedStoragePath}
	if tenantID != "" {
		parts = append(parts, tenantID)
	}
	parts = append(parts, assetID, "tuning")
	dir := filepath.Join(parts...)

	// Belt and braces: the identifiers are already validated, but confirm the
	// joined path really is inside the root before creating anything. This
	// keeps the guarantee if a future caller reaches here by another route.
	if err := ensureWithin(s.sharedStoragePath, dir); err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Written atomically: the agent may be reading while we write.
	target := filepath.Join(dir, "decisions.data")
	tmp, err := os.CreateTemp(dir, ".decisions-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), target)
}

// RepublishAll rewrites every asset's decisions file, used at startup so the
// volume reflects the database even after the volume was recreated.
func (s *Service) RepublishAll(ctx context.Context) error {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT tenant_id, asset_id FROM tuning_decisions`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type key struct{ tenant, asset string }
	var keys []key
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.tenant, &k.asset); err != nil {
			return err
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, k := range keys {
		if err := s.PublishDecisions(ctx, k.tenant, k.asset); err != nil {
			return err
		}
	}
	return nil
}

// TitleForEventType extracts the value a decision applies to from an event's
// fields, matching how the agent looks decisions up: by URI for URL decisions,
// by parameter name or value, or by source identifier
// (KeywordIndicatorFilter.cc:131-132, TypeIndicatorsFilter.cc:113).
func TitleForEventType(eventType, uri, paramName, paramValue, source string) string {
	switch eventType {
	case TypeURL:
		return uri
	case TypeParameterName:
		return paramName
	case TypeParameterValue:
		return paramValue
	case TypeSource:
		return source
	}
	return ""
}

// NormalizeTenant maps an empty tenant to the agent's own convention so that
// lookups from the UI and from the agent agree.
func NormalizeTenant(tenantID string) string { return strings.TrimSpace(tenantID) }

// ensureWithin reports an error unless path is the root or sits beneath it.
func ensureWithin(root, path string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return fmt.Errorf("learning: %q is not under %q", path, root)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("learning: refusing to write outside %q", root)
	}
	return nil
}
