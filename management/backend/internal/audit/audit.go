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

// Package audit records every state-changing action taken through the admin
// plane. Policy changes on a WAF are exactly the kind of thing an operator
// needs to be able to reconstruct after the fact.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openappsec/openappsec/management/backend/internal/auth"
)

type Entry struct {
	ID         int64           `json:"id"`
	OccurredAt time.Time       `json:"occurredAt"`
	Username   string          `json:"username"`
	Action     string          `json:"action"`
	TargetType string          `json:"targetType"`
	TargetID   string          `json:"targetId"`
	Detail     json.RawMessage `json:"detail"`
	RemoteAddr string          `json:"remoteAddr"`
}

type Logger struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Logger { return &Logger{pool: pool} }

// Record writes an audit entry attributed to the authenticated user, if any.
// A failure to audit must never fail the operation that was already
// performed, so errors are logged, not returned.
func (l *Logger) Record(ctx context.Context, r *http.Request, action, targetType, targetID string, detail any) {
	var (
		userID   *uuid.UUID
		username string
	)
	if u, ok := auth.FromContext(ctx); ok {
		userID = &u.ID
		username = u.Username
	}
	l.record(ctx, r, userID, username, action, targetType, targetID, detail)
}

// RecordAs writes an audit entry for an explicitly named actor. Login is the
// case that needs it: the session does not exist yet when it is recorded, so
// there is no user on the request context to attribute it to.
func (l *Logger) RecordAs(ctx context.Context, r *http.Request, actor *auth.User, action, targetType, targetID string, detail any) {
	var (
		userID   *uuid.UUID
		username string
	)
	if actor != nil {
		userID = &actor.ID
		username = actor.Username
	}
	l.record(ctx, r, userID, username, action, targetType, targetID, detail)
}

func (l *Logger) record(ctx context.Context, r *http.Request, userID *uuid.UUID, username, action, targetType, targetID string, detail any) {
	body := json.RawMessage("{}")
	if detail != nil {
		if b, err := json.Marshal(detail); err == nil {
			body = b
		}
	}

	remote := ""
	if r != nil {
		remote = clientIP(r)
	}

	_, err := l.pool.Exec(ctx, `
		INSERT INTO audit_log (user_id, username, action, target_type, target_id, detail, remote_addr)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		userID, username, action, targetType, targetID, body, remote)
	if err != nil {
		slog.Error("failed to write audit entry", "action", action, "error", err)
	}
}

func (l *Logger) List(ctx context.Context, limit int) ([]Entry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := l.pool.Query(ctx, `
		SELECT id, occurred_at, username, action, target_type, target_id, detail, remote_addr
		  FROM audit_log ORDER BY occurred_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.Username, &e.Action,
			&e.TargetType, &e.TargetID, &e.Detail, &e.RemoteAddr); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func clientIP(r *http.Request) string {
	// The manager is expected to sit behind a proxy in most deployments, but
	// XFF is attacker-controlled when it is not, so record RemoteAddr and let
	// the operator correlate.
	return r.RemoteAddr
}
