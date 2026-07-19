# Software Error Monitor

This zero-dependency Node.js service groups application error events into issues and provides a Sentry-style local dashboard. It is independent from the Go agent telemetry server and listens on `127.0.0.1:9092` by default.

## Run

Node.js 20 or newer is recommended.

```bash
cd software-errors
cp .env.example .env
set -a; . ./.env; set +a
node server.mjs
```

Open <http://127.0.0.1:9092>. Generate sample issues from the repository root with:

```bash
node software-errors/scripts/fake-errors.mjs --events 120
```

## Authentication and exposure

Set `ERROR_MONITOR_INGEST_KEY` on the server and producers. Producers send the value in `X-Error-Monitor-Key`:

```bash
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -H "X-Error-Monitor-Key: $ERROR_MONITOR_INGEST_KEY" \
  --data '{"type":"TypeError","message":"example","service":"edge-proxy"}' \
  http://127.0.0.1:9092/api/errors
```

When the ingestion key is empty, local compatibility mode accepts events without a key and logs a warning. The destructive `POST /api/clear` endpoint is disabled unless `ERROR_MONITOR_ADMIN_KEY` is configured; once enabled, it requires that key in the same `X-Error-Monitor-Key` header.

Dashboard reads and issue status transitions do not have a login flow. Keep the service on loopback or place an authenticated TLS reverse proxy in front of it before exposing it. CORS is denied by default and can be enabled for one exact origin with `ERROR_MONITOR_CORS_ORIGIN`.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | HTTP listen host |
| `PORT` | `9092` | HTTP listen port |
| `ERROR_MONITOR_INGEST_KEY` | empty | Optional shared ingestion key |
| `ERROR_MONITOR_ADMIN_KEY` | empty | Enables and protects `POST /api/clear` |
| `ERROR_MONITOR_CORS_ORIGIN` | empty | One exact browser origin allowed to call the API |
| `MAX_BODY_BYTES` | `262144` | Maximum JSON event body, 1 KiB–1 MiB |
| `MAX_EVENTS` | `10000` | Global retained-event ring, 1–100,000 |
| `MAX_ISSUES` | `5000` | Maximum live issue groups, 1–50,000 |
| `MAX_EVENTS_PER_ISSUE` | `80` | Recent events retained per issue, 1–1,000 |
| `NO_COLOR` | empty | Disable ANSI log colors when set |

Nested context is sanitized to three levels, 64 keys per object, 40 values per array, and 2,000 characters per context string. Stack traces retain at most 16,000 characters and each issue retains bounded user, service, environment, and release sets.

## API

| Method and path | Description |
| --- | --- |
| `GET /health` | Liveness and uptime |
| `POST /api/errors`, `POST /api/events` | Ingest and group an error event |
| `GET /api/stats` | Retained and lifetime process statistics |
| `GET /api/issues` | Issue summaries with `status`, `level`, `environment`, `service`, and `q` filters |
| `GET /api/issues/{id}` | Issue summary and recent events |
| `PATCH /api/issues/{id}` | Set status to `open` or `resolved` |
| `POST /api/clear` | Clear in-memory state when administrator-key access is enabled |

All data is held in memory. Restarting the process clears it.

## Verification

```bash
node --check server.mjs
node --test server.test.mjs
```
