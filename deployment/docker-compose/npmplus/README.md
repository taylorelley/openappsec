# NPMplus + open-appsec + open-appsec Manager

A complete stack: [NPMplus](https://github.com/ZoeyVid/NPMplus) as the reverse
proxy, the open-appsec agent enforcing WAF policy inside its nginx, and the
self-hosted [open-appsec Manager](../../../management/README.md) as the
management UI — no dependency on the SaaS portal at my.openappsec.io.

It is NPMplus's own open-appsec block with `smartsync-tuning` replaced by the
manager, which becomes the agent's `TUNING_HOST`:

```
   browser ─── :81 ──▶ npmplus  (host network, nginx + open-appsec attachment)
                          │ shared memory (/dev/shm/check-point)
                          ▼
                    openappsec-agent ──── events ────▶ openappsec-manager :80
                          ▲                                    │  :8080 UI
                          └── local_policy.yaml ◀──────────────┘
                                (shared /ext/appsec volume)
```

| Service | Role |
|---|---|
| `npmplus` | Reverse proxy and its own web UI on `:81`. Loads the open-appsec attachment. |
| `openappsec-agent` | Enforces policy in the nginx workers, posts events to the manager. |
| `openappsec-manager` | Policy editor, event search, fleet and tuning UI on `:8080`. |
| `openappsec-smartsync` + `openappsec-shared-storage` | Share learning between the agent's processes. |
| `openappsec-db` | Postgres, used only by the manager. |
| `juiceshop-backend` | Optional vulnerable backend for testing (`juiceshop` profile). |

## Before you deploy: the NPMplus pin

`.env` pins `docker.io/zoeyvid/npmplus:2026-07-24-r1`, and that is deliberate.

NPMplus removed the open-appsec attachment module in commit
[`d70bcd71`](https://github.com/ZoeyVid/NPMplus/commit/d70bcd71) — *"breaking:
drop openappsec attachment support"*, 24 July 2026. That change is on `develop`
and is therefore already in the `:develop` image; `2026-07-24-r1` is the last
tagged release that still ships the module. Moving this stack to a later
NPMplus release will fail nginx with a `load_module` error for the attachment,
and there is no `NGINX_LOAD_OPENAPPSEC_ATTACHMENT_MODULE` to set any more.

If you need a newer proxy, use one of the attachment images this repository
publishes instead — `deployment/docker-compose/nginx-proxy-manager/` runs the
same manager profile against upstream nginx-proxy-manager.

## Deploy

```bash
cd deployment/docker-compose/npmplus
# Set TZ in .env — NPMplus will not start without it.
docker compose up -d          # builds the manager image on first run
```

The manager image is built from `management/` in this repository, because no
registry publishes it yet. Set `APPSEC_MANAGER_IMAGE` in `.env` to a registry
tag once one exists.

Then:

```bash
docker compose logs openappsec-manager | grep password
```

| UI | Address | Credentials |
|---|---|---|
| NPMplus | `https://<host>:81` | `admin@example.org` and the password NPMplus prints on first start (`docker compose logs npmplus`) |
| open-appsec Manager | `http://127.0.0.1:8080` | `admin` and the generated password above |

Both prompt for a change on first sign-in. Do it.

You do **not** need to download a starter `local_policy.yaml` first, which
upstream NPMplus instructions ask for: the manager seeds a policy revision and
renders it to `appsec-localconfig/local_policy.yaml` when it starts.

## Turn on the event stream

The agent only posts events to the manager if the deployed policy says so:

1. In the manager, go to **Policy → Editor → Log triggers**.
2. Enable **"Send to this manager"** (`logDestination.local-tuning`).
3. **Save and enforce**.

Events start arriving within a couple of seconds — the agent flushes log bulks
every 2s.

## Turn on agent metrics

`PROMETHEUS=true` is already set on the agent. In the manager, go to **Fleet →
Details → Metrics endpoint** and enter `openappsec-agent`; the scraper expands
a bare host to `http://<host>:7465/metrics`. Samples appear within one
`MANAGER_METRICS_SCRAPE_INTERVAL` (1 minute by default).

The scraper resolves the endpoint and checks the resulting address at dial
time. `openappsec-agent` resolves to the compose bridge network, which is
RFC1918 and allowed by `MANAGER_ALLOW_PRIVATE_SCRAPE_TARGETS` (default true).
Loopback addresses are always refused, so pointing this at `127.0.0.1` will
not work regardless of network mode.

## Testing it end to end

```bash
# In .env: COMPOSE_PROFILES=juiceshop
docker compose up -d
```

Add a proxy host in NPMplus forwarding to `127.0.0.1:3000` — NPMplus runs on
the host network namespace and cannot resolve container names. Then send
something the WAF should notice, and watch it land under **Events**:

```bash
curl "http://<your-proxy-host>/rest/products/search?q=%27%20OR%201=1--"
```

## Notes and constraints

- **The manager's agent plane is plain HTTP and unauthenticated for event
  ingest.** This is forced by the agent, which hardcodes port 80 and an
  unsecured connection when posting to its tuning host. Port 80 of the manager
  is not published by this compose file; keep it that way.
- **The admin plane is plain HTTP too**, and is published on `127.0.0.1` only.
  To reach it from elsewhere, add an NPMplus proxy host with a certificate
  forwarding to `127.0.0.1:8080`, rather than changing `APPSEC_MANAGER_BIND`.
- **Do not set an `AGENT_TOKEN`.** A profile token puts the agent under central
  SaaS management, which is mutually exclusive with the manager here.
- **Do not add `no-new-privileges:true` to `openappsec-manager`.** It binds
  port 80 unprivileged through a file capability, which `no_new_privs`
  disables.
- **Volume ownership.** The manager container starts as root, takes ownership
  of `/ext/appsec` and `/db`, and then runs the server as uid 10001. If you
  make `openappsec-shared-storage` run as `appuser` instead of root, set
  matching `PUID`/`PGID` on `openappsec-manager` so both agree on the owner.
- **Managing agents on other hosts** — including a second NPMplus — uses the
  `appsec-agent-sync` companion. See
  [`management/README.md`](../../../management/README.md).
