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

-- ---------------------------------------------------------------- identity

CREATE TABLE users (
    id            uuid        PRIMARY KEY,
    username      text        NOT NULL UNIQUE,
    email         text        NOT NULL DEFAULT '',
    password_hash text        NOT NULL DEFAULT '',
    role          text        NOT NULL CHECK (role IN ('admin', 'editor', 'viewer')),
    disabled      boolean     NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
);

-- Seam for the OIDC provider: a user may be backed by an external subject
-- instead of (or in addition to) a local password.
CREATE TABLE user_identities (
    id         uuid        PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider   text        NOT NULL,
    subject    text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, subject)
);

CREATE TABLE sessions (
    token_hash   bytea       PRIMARY KEY,
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    user_agent   text        NOT NULL DEFAULT '',
    remote_addr  text        NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user_idx    ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

-- ------------------------------------------------------------------ fleet

CREATE TABLE agents (
    id                    uuid        PRIMARY KEY,
    name                  text        NOT NULL DEFAULT '',
    -- The agent's own identity, as reported by show-orchestration-status.
    agent_uuid            text        UNIQUE,
    tenant_id             text        NOT NULL DEFAULT '',
    profile_id            text        NOT NULL DEFAULT '',
    -- Fog-emulation seam: populated only when this manager acts as a fog.
    client_id             text,
    shared_secret_hash    bytea,
    resource_checksums    jsonb       NOT NULL DEFAULT '{}'::jsonb,
    -- Agent-plane credential for the appsec-agent-sync companion.
    enrollment_token_hash bytea       UNIQUE,
    mode                  text        NOT NULL DEFAULT '',
    version               text        NOT NULL DEFAULT '',
    policy_version        text        NOT NULL DEFAULT '',
    -- Revision the manager last rendered for this agent, for drift detection.
    applied_revision_id   bigint,
    health                text        NOT NULL DEFAULT 'unknown'
                                      CHECK (health IN ('healthy', 'degraded', 'unhealthy', 'unknown')),
    status                jsonb       NOT NULL DEFAULT '{}'::jsonb,
    labels                jsonb       NOT NULL DEFAULT '{}'::jsonb,
    metrics_endpoint      text        NOT NULL DEFAULT '',
    first_seen_at         timestamptz NOT NULL DEFAULT now(),
    last_seen_at          timestamptz,
    last_status_at        timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agents_last_seen_idx ON agents (last_seen_at DESC NULLS LAST);

-- ----------------------------------------------------------------- policy

CREATE TABLE policy_revisions (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    api_version text        NOT NULL DEFAULT 'v1beta2',
    body        jsonb       NOT NULL,
    checksum    text        NOT NULL,
    message     text        NOT NULL DEFAULT '',
    author_id   uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX policy_revisions_created_idx ON policy_revisions (created_at DESC);

-- A NULL agent_id row is the fleet-wide default assignment.
CREATE TABLE policy_assignments (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_id    uuid        REFERENCES agents (id) ON DELETE CASCADE,
    revision_id bigint      NOT NULL REFERENCES policy_revisions (id),
    assigned_at timestamptz NOT NULL DEFAULT now(),
    assigned_by uuid        REFERENCES users (id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX policy_assignments_agent_uniq
    ON policy_assignments (COALESCE(agent_id, '00000000-0000-0000-0000-000000000000'::uuid));

-- ----------------------------------------------------------------- events

CREATE TABLE events (
    id                      bigint      GENERATED ALWAYS AS IDENTITY,
    event_time              timestamptz NOT NULL,
    received_at             timestamptz NOT NULL DEFAULT now(),
    manager_agent_id        uuid,

    -- Report envelope (core/report/report.cc).
    event_name              text        NOT NULL DEFAULT '',
    event_severity          text        NOT NULL DEFAULT '',
    event_priority          text        NOT NULL DEFAULT '',
    event_type              text        NOT NULL DEFAULT '',
    event_level             text        NOT NULL DEFAULT '',
    event_log_level         text        NOT NULL DEFAULT '',
    event_audience          text        NOT NULL DEFAULT '',
    event_audience_team     text        NOT NULL DEFAULT '',
    event_tags              text[]      NOT NULL DEFAULT '{}',

    -- eventSource.
    agent_id                text        NOT NULL DEFAULT '',
    tenant_id               text        NOT NULL DEFAULT '',
    service_name            text        NOT NULL DEFAULT '',
    issuing_engine_version  text        NOT NULL DEFAULT '',
    event_trace_id          text        NOT NULL DEFAULT '',
    notification_id         text        NOT NULL DEFAULT '',

    -- eventData: asset and practice.
    asset_id                text        NOT NULL DEFAULT '',
    asset_name              text        NOT NULL DEFAULT '',
    practice_type           text        NOT NULL DEFAULT '',
    practice_sub_type       text        NOT NULL DEFAULT '',
    practice_name           text        NOT NULL DEFAULT '',
    rule_name               text        NOT NULL DEFAULT '',
    security_action         text        NOT NULL DEFAULT '',

    -- eventData: network.
    source_ip               text        NOT NULL DEFAULT '',
    source_ip_addr          inet,
    source_port             integer,
    source_country_name     text        NOT NULL DEFAULT '',
    source_country_code     text        NOT NULL DEFAULT '',
    destination_ip          text        NOT NULL DEFAULT '',
    destination_port        integer,
    ip_protocol             text        NOT NULL DEFAULT '',
    http_source_id          text        NOT NULL DEFAULT '',

    -- eventData: HTTP.
    http_host_name          text        NOT NULL DEFAULT '',
    http_method             text        NOT NULL DEFAULT '',
    http_uri_path           text        NOT NULL DEFAULT '',
    http_uri_query          text        NOT NULL DEFAULT '',
    http_response_code      integer,

    -- eventData: WAAP verdict detail.
    waap_incident_type      text        NOT NULL DEFAULT '',
    waap_incident_details   text        NOT NULL DEFAULT '',
    waap_found_indicators   text        NOT NULL DEFAULT '',
    waap_user_reputation    text        NOT NULL DEFAULT '',
    waap_final_score        double precision,
    waap_calculated_threat_level text   NOT NULL DEFAULT '',
    event_confidence        text        NOT NULL DEFAULT '',
    event_reference_id      text        NOT NULL DEFAULT '',
    matched_location        text        NOT NULL DEFAULT '',
    matched_parameter       text        NOT NULL DEFAULT '',
    matched_sample          text        NOT NULL DEFAULT '',
    match_reason            text        NOT NULL DEFAULT '',
    protection_id           text        NOT NULL DEFAULT '',
    incident_type           text        NOT NULL DEFAULT '',

    raw                     jsonb       NOT NULL,

    PRIMARY KEY (id, event_time)
) PARTITION BY RANGE (event_time);

CREATE INDEX events_time_idx        ON events (event_time DESC);
CREATE INDEX events_agent_idx       ON events (manager_agent_id, event_time DESC);
CREATE INDEX events_asset_idx       ON events (asset_name, event_time DESC);
CREATE INDEX events_source_ip_idx   ON events (source_ip, event_time DESC);
CREATE INDEX events_source_cidr_idx ON events USING gist (source_ip_addr inet_ops);
CREATE INDEX events_action_idx      ON events (security_action, event_time DESC);
CREATE INDEX events_incident_idx    ON events (waap_incident_type, event_time DESC);
CREATE INDEX events_severity_idx    ON events (event_severity, event_time DESC);
CREATE INDEX events_host_idx        ON events (http_host_name, event_time DESC);

CREATE TABLE event_daily_rollups (
    day                date    NOT NULL,
    manager_agent_id   uuid    NOT NULL,
    asset_name         text    NOT NULL DEFAULT '',
    security_action    text    NOT NULL DEFAULT '',
    waap_incident_type text    NOT NULL DEFAULT '',
    event_severity     text    NOT NULL DEFAULT '',
    event_count        bigint  NOT NULL DEFAULT 0,
    PRIMARY KEY (day, manager_agent_id, asset_name, security_action, waap_incident_type, event_severity)
);
