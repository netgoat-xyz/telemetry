# NetGoat Telemetry Server

The telemetry server receives runtime and application snapshots from NetGoat agents and exposes an authenticated browser dashboard. It keeps a bounded, in-memory view of agents and recent events, so it can run without a database and restart cleanly.

The repository also contains an independent software-error monitor in [`software-errors/`](software-errors/).

## Run locally

Go 1.24 or newer is required.

```bash
cp .env.example .env
set -a; . ./.env; set +a
go run .
```

The server listens on `127.0.0.1:9091` by default. Open <http://127.0.0.1:9091> and sign in with the configured administrator credentials. If no credentials are configured, the local-development fallback is `admin` / `admin` and the server logs a warning.

A positional port continues to work and stays loopback-only:

```bash
go run . 9191
```

Use `TELEMETRY_ADDR=0.0.0.0:9091` only when the service must be reachable from another host. Set strong administrator, JWT, and ingestion secrets before exposing it, and terminate TLS at a trusted reverse proxy.

## Agent ingestion

NetGoat currently posts telemetry to the legacy-compatible `POST /api` endpoint. `POST /api/telemetry` is the canonical endpoint; `POST /` remains available for older clients. All three accept the same JSON payload.

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

Leaving `TELEMETRY_INGEST_KEY` unset preserves compatibility with unconfigured local agents, but ingestion is then unauthenticated and the server emits a warning. Payloads are limited to 128 KiB and validated before they affect server state.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `TELEMETRY_ADDR` | `127.0.0.1:9091` | HTTP listen address |
| `TELEMETRY_ADMIN_USERNAME` | `admin` | Dashboard administrator |
| `TELEMETRY_ADMIN_PASSWORD` | `admin` | Dashboard password; always override outside local development |
| `TELEMETRY_JWT_SECRET` | random per process | HMAC key for 24-hour dashboard sessions; set it to preserve sessions across restarts |
| `TELEMETRY_INGEST_KEY` | empty | Optional shared key required in `X-Telemetry-Key` for ingestion |
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

The server retains the newest 5,000 events in a fixed-size ring and the latest snapshot for at most 10,000 agent IDs. Aggregate event totals continue increasing while the process is running. All state is intentionally in memory and is cleared on restart or with the REPL `clear` command.

## Verification

```bash
go test ./...
go test -race ./...
go vet ./...
node scripts/fake-clients.mjs --clients 20 --rounds 3
```
