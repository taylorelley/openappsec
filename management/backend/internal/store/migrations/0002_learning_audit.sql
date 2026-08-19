-- Copyright (C) 2026 Check Point Software Technologies Ltd. All rights reserved.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Assets are not configured; they are discovered from the event stream.
CREATE TABLE assets (
    id            uuid        PRIMARY KEY,
    tenant_id     text        NOT NULL DEFAULT '',
    asset_id      text        NOT NULL DEFAULT '',
    asset_name    text        NOT NULL DEFAULT '',
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    event_count   bigint      NOT NULL DEFAULT 0,
    UNIQUE (tenant_id, asset_id)
);
CREATE INDEX assets_name_idx ON assets (asset_name);

-- Emitted by the agent as Notification::SYNC_LEARNING; each row marks a
-- learning window that closed for an asset.
CREATE TABLE learning_windows (
    id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id     text        NOT NULL DEFAULT '',
    asset_id      text        NOT NULL DEFAULT '',
    window_type   text        NOT NULL DEFAULT '',
    window_id     text        NOT NULL DEFAULT '',
    observed_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, asset_id, window_type, window_id)
);
CREATE INDEX learning_windows_asset_idx ON learning_windows (asset_id, observed_at DESC);

-- Operator decisions, served back to the agent as decisions.data.
-- decision/event_type values are exactly those TuningDecision.cc accepts.
CREATE TABLE tuning_decisions (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id   text        NOT NULL DEFAULT '',
    asset_id    text        NOT NULL DEFAULT '',
    event_type  text        NOT NULL
                            CHECK (event_type IN ('source', 'url', 'parameterName', 'parameterValue')),
    event_title text        NOT NULL,
    decision    text        NOT NULL
                            CHECK (decision IN ('benign', 'malicious', 'dismiss')),
    decided_by  uuid        REFERENCES users (id) ON DELETE SET NULL,
    decided_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, asset_id, event_type, event_title)
);
CREATE INDEX tuning_decisions_asset_idx ON tuning_decisions (tenant_id, asset_id);

-- Rolling window of Prometheus samples scraped from agents.
CREATE TABLE agent_metrics (
    id           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_id     uuid        NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    scraped_at   timestamptz NOT NULL DEFAULT now(),
    metric_name  text        NOT NULL,
    labels       jsonb       NOT NULL DEFAULT '{}'::jsonb,
    value        double precision NOT NULL
);
CREATE INDEX agent_metrics_lookup_idx ON agent_metrics (agent_id, metric_name, scraped_at DESC);
CREATE INDEX agent_metrics_scraped_idx ON agent_metrics (scraped_at);

CREATE TABLE audit_log (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    user_id     uuid        REFERENCES users (id) ON DELETE SET NULL,
    username    text        NOT NULL DEFAULT '',
    action      text        NOT NULL,
    target_type text        NOT NULL DEFAULT '',
    target_id   text        NOT NULL DEFAULT '',
    detail      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    remote_addr text        NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_time_idx ON audit_log (occurred_at DESC);
CREATE INDEX audit_log_user_idx ON audit_log (user_id, occurred_at DESC);

-- Single-row table for manager-wide settings (first-run state, retention).
CREATE TABLE manager_settings (
    id                   integer     PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    initialized          boolean     NOT NULL DEFAULT false,
    event_retention_days integer     NOT NULL DEFAULT 30,
    updated_at           timestamptz NOT NULL DEFAULT now()
);
INSERT INTO manager_settings (id) VALUES (1);
