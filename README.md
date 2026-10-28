<img width="2968" height="841" alt="NetGoat" src="assets/netgoat-banner.png" />

# NetGoat telemetry server

The telemetry server receives runtime and application snapshots from NetGoat
agents and exposes an authenticated browser dashboard. It keeps a bounded,
in-memory view of agents and recent events, so it can run without a database and
restart cleanly.

The repository also contains an independent software-error monitor in
[`software-errors/`](software-errors/).

## Architecture

```text
agents ──POST /api/telemetry──► telemetry server ──► in-memory ring buffer
                                      │                    (5k events,
                                      │                     10k agents)
                                      └──► dashboard (embedded HTML, JWT session)

apps ──POST /api/errors──► software-errors (separate process, port 9092)
```

Both processes are single-binary, dependency-free, and keep all state in
memory. Nothing is persisted, so a restart clears history by design.

## Stack

| Layer | Choice |
| --- | --- |
| Language | Go 1.24 (stdlib only for the server) |
| Dashboard | Embedded HTML/CSS/JS served from `static/` |
| Sessions | HMAC-signed JWT, 24 hours |
| Error monitor | Node.js 22, no dependencies |
| Container | distroless static (Go) and distroless Node 22, both non-root |

## Prerequisites

- Go 1.24 or newer
- Node.js 22 or newer (only for the software-error monitor and the simulator tests)

## Run locally

```bash
cp .env.example .env
set -a; . ./.env; set +a
go run .
```

The server listens on `127.0.0.1:9091` by default. Open
<http://127.0.0.1:9091> and sign in with the configured administrator
credentials. If no credentials are configured, the local-development fallback
is `admin` / `admin` and the server logs a warning.

CAS is optional here too. Leave `CAS_ENABLED` (or `TELEMETRY_CAS_ENABLED`)
unset to run the dashboard as a standalone telemetry viewer; set it to `true`
when the dashboard should advertise a central administrative service
integration.

A positional port continues to work and stays loopback-only:

```bash
go run . 9191
```

Use `TELEMETRY_ADDR=0.0.0.0:9091` only when the service must be reachable from
another host. Set strong administrator, JWT, and ingestion secrets before
exposing it, and terminate TLS at a trusted reverse proxy.

## Agent ingestion

NetGoat currently posts telemetry to the legacy-compatible `POST /api`
endpoint. `POST /api/telemetry` is the canonical endpoint; `POST /` remains
available for older clients. All three accept the same JSON payload.

Set the same shared key on the server and each agent:

```bash
export TELEMETRY_INGEST_KEY='replace-with-a-long-random-value'
```

Clients send it in the `X-Telemetry-Key` header:

```bash
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -H "X-Telemetry-Key: $TELEMETRY_INGEST_KEY" \
  --data '{"instance_id":"agent-1","event_type":"heartbeat"}' \
  http://127.0.0.1:9091/api/telemetry
```

Leaving `TELEMETRY_INGEST_KEY` unset preserves compatibility with unconfigured
local agents, but ingestion is then unauthenticated and the server emits a
warning. Payloads are limited to 128 KiB and validated before they affect
server state.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `TELEMETRY_ADDR` | `127.0.0.1:9091` | HTTP listen address |
| `TELEMETRY_ADMIN_USERNAME` | `admin` | Dashboard administrator |
| `TELEMETRY_ADMIN_PASSWORD` | `admin` | Dashboard password; always override outside local development |
| `TELEMETRY_JWT_SECRET` | random per process | HMAC key for 24-hour dashboard sessions; set it to preserve sessions across restarts |
| `TELEMETRY_INGEST_KEY` | empty | Optional shared key required in `X-Telemetry-Key` for ingestion |
| `CAS_ENABLED` / `TELEMETRY_CAS_ENABLED` | `false` | Marks the dashboard as CAS-aware and surfaces the standalone/connected state in the UI |
| `NO_COLOR` | empty | Disable ANSI colors in logs when set |

## HTTP API

| Method and path | Authentication | Description |
| --- | --- | --- |
| `GET /health`, `GET /api/health` | none | Liveness and uptime |
| `POST /api`, `POST /api/telemetry` | `X-Telemetry-Key` when configured | Receive an agent snapshot |
| `POST /api/login` | administrator credentials | Create a dashboard bearer token |
| `GET /api/stats` | bearer token | Server totals and uptime |
| `GET /api/agents` | bearer token | Sorted agent snapshots |
| `GET /api/agents/{id}` | bearer token | Agent details and up to 1,000 recent events |
| `GET /api/events?limit=200` | bearer token | Newest events; limit must be 1–1,000 |

The server retains the newest 5,000 events in a fixed-size ring and the latest
snapshot for at most 10,000 agent IDs. Aggregate event totals continue
increasing while the process is running. All state is intentionally in memory
and is cleared on restart or with the REPL `clear` command.

## Docker

```bash
# telemetry server
docker build -t netgoat-telemetry .
docker run --rm -p 9091:9091 \
  -e TELEMETRY_ADMIN_PASSWORD=change-me \
  -e TELEMETRY_JWT_SECRET="$(openssl rand -hex 32)" \
  netgoat-telemetry

# software error monitor
docker build -t netgoat-software-errors ./software-errors
docker run --rm -p 9092:9092 \
  -e ERROR_MONITOR_INGEST_KEY="$(openssl rand -hex 32)" \
  netgoat-software-errors
```

Published images: `ghcr.io/netgoat-xyz/telemetry`. The Go server runs on
distroless static as `nonroot` with a bundled busybox for the `/health`
healthcheck. The error monitor has its own Dockerfile under `software-errors/`
and is documented in [its README](software-errors/README.md).

## Deployment

Both services are stateless and safe to restart. Terminate TLS at a reverse
proxy, keep the listeners on the agent network, and set every secret from the
environment. Because the event ring and agent map are in memory, horizontal
scaling gives each replica a partial view — run one replica unless agents are
pinned to a replica.

## Security

- Admin sign-in is rate limited per source address: 5 failures trigger a
  15-minute lockout, with a bounded tracking map.
- Dashboard sessions are HMAC-signed and expire after 24 hours.
- Ingestion payloads are size-limited and validated before touching state.
- The dashboard escapes stored telemetry so agent-supplied strings cannot
  inject script.
- Report vulnerabilities per [SECURITY.md](SECURITY.md); do not open a public issue.

## Verification

```bash
go vet ./...
go test ./...
go test -race ./...
node --test scripts/dashboard.test.mjs
node --test software-errors/server.test.mjs
```

`go test` covers the ingestion contract, auth, retention bounds and the
dashboard embedding. The Node suites cover the dashboard rendering and the
software-error monitor.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[GNU Affero General Public License v3.0](LICENSE).
