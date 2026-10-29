#!/usr/bin/env node
const defaults = {
  endpoint: "http://localhost:9092/api/errors",
  events: 120,
  interval: 35,
  seed: Date.now(),
  ingestKey: process.env.ERROR_MONITOR_INGEST_KEY || "",
};

const services = ["dashboard-web", "billing-api", "edge-proxy", "worker-sync", "auth-gateway", "checkout"];
const environments = ["production", "staging", "canary"];
const releases = ["2026.7.13-1", "2026.7.13-2", "2026.7.12-5", "0.9.4-beta"];
const users = [
  { id: "usr_1029", email: "mara@acme.test", ip_address: "203.0.113.41" },
  { id: "usr_8801", email: "lin@forge.test", ip_address: "198.51.100.24" },
  { id: "usr_4410", email: "ops@netgoat.local", ip_address: "192.0.2.19" },
  { id: "usr_5122", email: "noor@example.test", ip_address: "203.0.113.87" },
];

const templates = [
  {
    level: "fatal",
    type: "TypeError",
    message: "Cannot read properties of undefined (reading 'teamId')",
    service: "dashboard-web",
    stack: [
      "TypeError: Cannot read properties of undefined (reading 'teamId')",
      "    at TeamSwitcher (/app/.next/server/app/dashboard/page.js:221:18)",
      "    at renderWithHooks (/app/node_modules/react-dom/cjs/react-dom-server.edge.production.js:4189:12)",
      "    at async DashboardPage (/app/.next/server/app/dashboard/page.js:94:9)",
    ].join("\n"),
    tags: { framework: "nextjs", route: "/dashboard/[team]" },
  },
  {
    level: "error",
    type: "MongoServerSelectionError",
    message: "Server selection timed out after 30000 ms",
    service: "billing-api",
    stack: [
      "MongoServerSelectionError: Server selection timed out after 30000 ms",
      "    at Topology.selectServer (/srv/app/node_modules/mongodb/lib/sdam/topology.js:327:38)",
      "    at async InvoiceRepository.findDueInvoices (/srv/app/src/invoices.ts:88:14)",
      "    at async POST (/srv/app/src/routes/billing.ts:142:22)",
    ].join("\n"),
    tags: { subsystem: "billing", dependency: "mongodb" },
  },
  {
    level: "warning",
    type: "UpstreamTimeout",
    message: "Proxy upstream did not return headers before timeout",
    service: "edge-proxy",
    stack: [
      "UpstreamTimeout: Proxy upstream did not return headers before timeout",
      "    at reverseProxy (/opt/netgoat/internal/proxy/proxy.go:177:16)",
      "    at ServeHTTP (/opt/netgoat/internal/proxy/router.go:74:9)",
    ].join("\n"),
    tags: { upstream: "payments.internal", status: "504" },
  },
  {
    level: "error",
    type: "ValueError",
    message: "Expected 6 features, got 4",
    service: "worker-sync",
    stack: [
      "ValueError: Expected 6 features, got 4",
      "  File \"/srv/ai/model_server.py\", line 42, in predict",
      "  File \"/srv/worker/jobs/anomaly.py\", line 116, in run_batch",
    ].join("\n"),
    tags: { job: "anomaly-batch", model: "koda-2" },
  },
  {
    level: "error",
    type: "AuthTokenError",
    message: "JWT signature verification failed",
    service: "auth-gateway",
    stack: [
      "AuthTokenError: JWT signature verification failed",
      "    at verifyToken (/srv/auth/src/session.ts:51:11)",
      "    at requireSession (/srv/auth/src/middleware.ts:29:18)",
    ].join("\n"),
    tags: { auth_mode: "jwt", route: "/api/account" },
  },
];

function parseArgs(argv) {
  const opts = { ...defaults };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      console.log(`Generate fake software error events.

Usage:
  node telemetry-server/software-errors/scripts/fake-errors.mjs [options]

Options:
  --endpoint <url>  Default: ${defaults.endpoint}
  --events <n>      Default: ${defaults.events}
  --interval <ms>   Default: ${defaults.interval}
  --seed <n>        Default: current timestamp
  --ingest-key <v>  Shared key. Defaults to ERROR_MONITOR_INGEST_KEY.
`);
      process.exit(0);
    }
    if (!arg.startsWith("--")) throw new Error(`Unexpected argument: ${arg}`);
    const [key, inline] = arg.slice(2).split("=", 2);
    const value = inline ?? argv[++i];
    if (key === "endpoint") opts.endpoint = value;
    else if (key === "events") opts.events = value;
    else if (key === "interval") opts.interval = value;
    else if (key === "seed") opts.seed = Number(value);
    else if (key === "ingest-key") opts.ingestKey = value;
    else throw new Error(`Unknown option: --${key}`);
  }
  opts.events = boundedInteger(opts.events, 1, 100000, "events");
  opts.interval = boundedInteger(opts.interval, 0, 60000, "interval");
  if (!Number.isFinite(opts.seed)) throw new Error("seed must be a finite number");
  if (opts.ingestKey == null) throw new Error("ingest-key requires a value");
  opts.ingestKey = String(opts.ingestKey);
  const endpoint = new URL(opts.endpoint);
  if (endpoint.protocol !== "http:" && endpoint.protocol !== "https:") throw new Error("endpoint must use HTTP or HTTPS");
  return opts;
}

function boundedInteger(value, min, max, label) {
  const number = Number(String(value).trim());
  if (!Number.isSafeInteger(number) || number < min || number > max) {
    throw new Error(`${label} must be between ${min} and ${max}`);
  }
  return number;
}

function rng(seed) {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let n = Math.imul(t ^ (t >>> 15), t | 1);
    n ^= n + Math.imul(n ^ (n >>> 7), n | 61);
    return ((n ^ (n >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = (r, xs) => xs[Math.floor(r() * xs.length)];
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function eventFor(r, index) {
  const template = pick(r, templates);
  const service = r() < 0.78 ? template.service : pick(r, services);
  const route = template.tags.route || pick(r, ["/api/domains", "/api/billing", "/dashboard", "/login", "/api/proxy"]);
  const user = pick(r, users);
  const release = pick(r, releases);
  return {
    level: template.level,
    type: template.type,
    message: template.message,
    stack: template.stack,
    service,
    environment: pick(r, environments),
    release,
    url: `https://${service}.netgoat.local${route}`,
    transaction: route,
    user,
    tags: {
      ...template.tags,
      region: pick(r, ["iad1", "sfo1", "fra1", "sin1"]),
      browser: pick(r, ["Chrome 126", "Firefox 128", "Safari 18", "curl/8.6"]),
    },
    runtime: {
      name: pick(r, ["node", "go", "python"]),
      version: pick(r, ["22.3.0", "1.24.0", "3.12.4"]),
    },
    breadcrumbs: [
      { timestamp: new Date(Date.now() - 8000).toISOString(), category: "navigation", message: `GET ${route}` },
      { timestamp: new Date(Date.now() - 4200).toISOString(), category: "http", message: `POST ${route}` },
      { timestamp: new Date(Date.now() - 900).toISOString(), category: "log", message: `request_id=req_${index.toString(16).padStart(4, "0")}` },
    ],
    request: {
      method: pick(r, ["GET", "POST", "PATCH"]),
      url: `https://${service}.netgoat.local${route}`,
      headers: {
        "user-agent": pick(r, ["Mozilla/5.0", "NetGoatAgent/0.1", "curl/8.6"]),
        "x-request-id": `req_${index.toString(16).padStart(4, "0")}`,
      },
    },
    timestamp: new Date(Date.now() - Math.floor(r() * 6 * 60 * 60 * 1000)).toISOString(),
  };
}

async function post(endpoint, event, ingestKey) {
  const headers = { "Content-Type": "application/json" };
  if (ingestKey) headers["X-Error-Monitor-Key"] = ingestKey;
  const res = await fetch(endpoint, {
    method: "POST",
    headers,
    body: JSON.stringify(event),
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const r = rng(opts.seed);
  console.log(`fake-errors endpoint=${opts.endpoint} events=${opts.events} interval=${opts.interval}ms`);
  for (let i = 1; i <= opts.events; i++) {
    const event = eventFor(r, i);
    await post(opts.endpoint, event, opts.ingestKey);
    if (i % 10 === 0 || i === opts.events) {
      console.log(`posted ${i}/${opts.events}`);
    }
    if (opts.interval > 0) await sleep(opts.interval);
  }
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
