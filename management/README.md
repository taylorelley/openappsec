# open-appsec Manager

A self-hosted management and monitoring web UI for open-appsec — an
alternative to the SaaS portal at my.openappsec.io for deployments that need
to keep policy and telemetry on their own infrastructure.

It manages policy across a fleet of agents, ingests their security events,
tracks agent health, and drives the learning/tuning loop. **No changes to the
agent are required**: everything here uses interfaces a stock agent already
speaks.

## How it connects to agents

```
                    ┌──────────────────────────────────────┐
   browser ────────▶│  appsec-manager  (single Go binary)  │
                    │                                      │
                    │  :8080  admin UI + admin API         │
                    │  :80    agent ingest + policy pull   │
                    └───┬──────────────────┬───────────────┘
                        │                  │
              ┌─────────▼────────┐   ┌─────▼──────────┐
              │  Postgres        │   │ shared volumes │
              └──────────────────┘   └─────┬──────────┘
                                           │
   ┌───────────────────────────────────────▼───────────────┐
   │ agent host                                            │
   │   appsec-agent (hybrid / standalone mode)             │
   │     POST /api/v1/agents/events[/bulk]  ──▶ manager    │
   │     GET  :7465/metrics                 ◀── scraped    │
   │   appsec-agent-sync (remote hosts only)               │
   │     GET  /api/v1/fleet/policy          ──▶ manager    │
   │     POST 127.0.0.1:7777/set-apply-policy              │
   └───────────────────────────────────────────────────────┘
```

Three integration points, all of them existing agent behaviour:

| What | How |
|---|---|
| **Events** | The agent's `local-tuning` log destination posts the same payload to `$TUNING_HOST` that it would post to the cloud. Point `TUNING_HOST` at the manager and the full event stream arrives. |
| **Policy** | The manager renders `local_policy.yaml`. Co-located agents read it from a shared volume; remote agents pull it via the `appsec-agent-sync` companion, which then calls the agent's own `set-apply-policy`. |
| **Tuning** | Operator decisions are published as `decisions.data` into the shared-storage volume, in the exact three-field schema the agent polls for every 30 minutes. |

### Two listeners, two trust levels

The **admin plane** (`:8080`) is authenticated and should serve TLS. The
**agent plane** (`:80`) is plain HTTP and unauthenticated for event
submission — not by choice: `core/logging/k8s_svc_stream.cc` hardcodes port 80
and marks the connection unsecured when posting to the tuning host. Keep the
agent plane on an internal network. The companion endpoints on that plane,
which can change policy, do require a per-agent enrolment token.

## Quick start with docker compose

From `deployment/docker-compose/nginx/`:

1. In `.env`, set:
   ```
   COMPOSE_PROFILES=standalone,manager
   APPSEC_TUNING_HOST=appsec-manager
   ```
2. `docker compose up -d`
3. Read the generated admin password:
   `docker compose logs appsec-manager | grep password`
4. Browse to `http://<host>:8080` and sign in. Change the password under
   Settings.
5. In **Policy → Editor → Log triggers**, enable **"Send to this manager"**
   (`logDestination.local-tuning`) and press **Save and enforce**.

Events start arriving within a couple of seconds — the agent flushes log
bulks every 2s by default.

To collect agent metrics, set `PROMETHEUS=true` on the agent container and
enter the agent's hostname under **Fleet → Details → Metrics endpoint**.

## Managing agents on other hosts

Agents the manager cannot reach by shared volume are managed by the
`appsec-agent-sync` companion. It must run with loopback access to the
agent's orchestration API, which refuses connections from anywhere else.

1. **Fleet → Enroll an agent** and copy the token (shown only once).
2. Run the companion alongside the agent:
   ```yaml
   appsec-agent-sync:
     image: ghcr.io/openappsec/agent-sync:latest
     network_mode: service:appsec-agent
     environment:
       - MANAGER_URL=http://manager.internal
       - MANAGER_ENROLLMENT_TOKEN=<token>
     volumes:
       - ./appsec-localconfig:/ext/appsec
   ```
3. Set `APPSEC_AUTO_POLICY_LOAD=false` on the agent, so the manager controls
   when policy is applied rather than a 30-second poll.

## Layout

```
management/
  backend/
    cmd/appsec-manager/       the server
    cmd/appsec-agent-sync/    the pull companion
    internal/
      api/admin/              authenticated REST API behind the UI
      api/agent/              agent plane (fog-shaped paths)
      auth/                   users, sessions, RBAC, provider seam
      policy/                 canonical model, validation, renderers
      ingest/                 Report decoding
      events/                 search, Event Query Language, analytics
      fleet/                  agent registry, status, Prometheus scraping
      learning/               readiness, suggestions, tuning decisions
      store/                  Postgres access and migrations
  frontend/                   React + TypeScript, embedded into the binary
  docker/                     container images
```

## Development

```bash
# Backend, with a database for the integration tests
createdb appsec_manager_test
cd backend
MANAGER_TEST_DATABASE_URL="postgres://postgres:pass@127.0.0.1:5432/appsec_manager_test?sslmode=disable" \
  go test ./...

# Run the server
MANAGER_DATABASE_URL="postgres://postgres:pass@127.0.0.1:5432/appsec_manager?sslmode=disable" \
  MANAGER_ADMIN_LISTEN=:8080 MANAGER_AGENT_LISTEN=:8081 \
  go run ./cmd/appsec-manager

# Frontend, proxying /api to the server above
cd frontend && npm install && npm run dev
```

`backend/web/dist` holds only a placeholder in git; `npm run build` produces
the real assets, which are embedded at compile time. A binary built without
them still runs and serves the API.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `MANAGER_DATABASE_URL` | built from the parts below | Postgres DSN |
| `MANAGER_DB_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_NAME` | `appsec-db` / `5432` / `postgres` / — / `appsec_manager` | DSN parts |
| `MANAGER_ADMIN_LISTEN` | `:8080` | admin UI and API |
| `MANAGER_AGENT_LISTEN` | `:80` | agent plane; must be 80 for agents |
| `MANAGER_TLS_CERT` / `MANAGER_TLS_KEY` | — | serve the admin plane over TLS |
| `MANAGER_POLICY_OUTPUT` | `/ext/appsec/local_policy.yaml` | rendered policy for co-located agents |
| `MANAGER_SHARED_STORAGE_PATH` | `/db` | where `decisions.data` is published |
| `MANAGER_ADMIN_USER` / `MANAGER_ADMIN_PASSWORD` | `admin` / generated | first-run account |
| `MANAGER_EVENT_RETENTION_DAYS` | `30` | events older than this are dropped by partition |
| `MANAGER_SESSION_TTL` | `12h` | browser session lifetime |
| `MANAGER_METRICS_SCRAPE_INTERVAL` | `1m` | Prometheus scrape cadence |
| `MANAGER_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

## Known limitations

- **The agent plane is plain HTTP and unauthenticated for event submission.**
  This is forced by the agent, not a design choice. Keep it internal, or put a
  TLS terminator in front of it.
- **Learning progress is inferred, not read from the agent.** The agent
  exposes no query API for learning state, so readiness is derived from event
  volume, source diversity, elapsed time and `SYNC_LEARNING` notifications.
  It deliberately does not reproduce the SaaS's Kindergarten-to-PhD labels,
  which are computed cloud-side and cannot be reproduced faithfully here.
- **Tuning suggestions are computed from the event stream.** The SaaS
  suggestion engine (`smartsync-tuning`) lives in another repository and is
  not reimplemented; candidates are ranked from ingested events instead.
- **Fog emulation is not implemented.** Agents are managed in hybrid mode. The
  internal seams for a fog-mode transport exist — the ingest paths, the agent
  registry columns and the renderer interface — but registration, token auth
  and `/api/v2/agents/resources` are not built.

## Notes on the policy schema

The editor validates against `config/linux/v1beta2/schema/schema_v1beta2.yaml`
from this repository, with three corrections that come from reading the
agent's own parsers:

1. `autoUpgrade` is parsed by the agent but absent from the shipped schema, so
   it is permitted rather than rejected.
2. `policies.default.customResponse` is **singular** in the parser, while the
   shipped default policy writes the plural. The plural is silently ignored by
   the agent; the manager warns about it and renders the singular form.
3. Rate-limit `action` and `condition` appear in the schema but are not
   implemented by the agent's access-control loader, so they warn rather than
   pass silently.

A policy that fails to load leaves almost no trace on the agent — it logs at
debug level and keeps the old policy — which is why validation happens before
anything is written.
