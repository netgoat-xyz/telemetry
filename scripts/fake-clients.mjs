#!/usr/bin/env node
import { randomUUID } from "node:crypto";

const defaults = {
  endpoint: "http://localhost:9091/api/telemetry",
  clients: 100, // Increased default
  rounds: 16,
  interval: 400,
  errorRate: 0.38,
  seed: Date.now(),
  shutdown: false,
};

const colors = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  amber: "\x1b[33m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
  magenta: "\x1b[35m",
};

const osProfiles = [
  { os: "linux", arch: "amd64", kernel: "6.8.12", go: "go1.24.0" },
  { os: "linux", arch: "arm64", kernel: "6.6.31", go: "go1.24.0" },
  { os: "linux", arch: "amd64", kernel: "5.15.0", go: "go1.22.1" },
  { os: "darwin", arch: "arm64", kernel: "23.5.0", go: "go1.23.6" },
  { os: "darwin", arch: "arm64", kernel: "24.0.0", go: "go1.24.0" },
  { os: "freebsd", arch: "amd64", kernel: "14.1", go: "go1.24.0" },
  { os: "windows", arch: "amd64", kernel: "10.0.22631", go: "go1.23.5" },
];

const cpuModels = [
  "AMD EPYC 7B13 64-Core",
  "AMD Ryzen 9 7950X",
  "Intel Xeon Platinum 8370C",
  "Intel Core i9-14900K",
  "Intel Core i7-12700K",
  "Apple M3 Pro",
  "Apple M2 Max",
  "Ampere Altra Q80-30",
  "ARM Neoverse-N1",
  "Intel Xeon Gold 6348",
];

const hostPrefixes = ["edge", "waf", "proxy", "gateway", "lab", "api", "worker", "canary", "db", "auth", "cache", "event"];

const errorTemplates = [
  { kind: "proxy", message: "dial tcp 10.0.4.18:443: connect: connection refused" },
  { kind: "proxy", message: "upstream response header timeout after 30s" },
  { kind: "proxy", message: "tls: failed to verify certificate: x509 unknown authority" },
  { kind: "proxy", message: "http2: stream closed by peer" },
  { kind: "proxy", message: "proxy: connection reset by peer" },
  { kind: "proxy", message: "io: read/write on closed pipe" },
  { kind: "http", message: "429 Too Many Requests" },
  { kind: "http", message: "403 Forbidden" },
  { kind: "http", message: "502 Bad Gateway" },
  { kind: "http", message: "503 Service Unavailable" },
  { kind: "http", message: "504 Gateway Timeout" },
  { kind: "http", message: "408 Request Timeout" },
  { kind: "http", message: "401 Unauthorized" },
];

const blockReasons = [
  "rate-limit",
  "request-queue",
  "zero-trust",
  "waf:sql-injection",
  "waf:xss-script",
  "koda-waf",
  "goatai",
  "geo-block",
  "bot-detection",
  "auth-failure",
];

function parseArgs(argv) {
  const opts = { ...defaults };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
    if (!arg.startsWith("--")) continue;
    const [rawKey, inlineValue] = arg.slice(2).split("=", 2);
    const key = rawKey.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    if (key === "shutdown") {
      const value = inlineValue;
      opts.shutdown = value === undefined ? true : value !== "false";
    } else if (key in opts) {
      const value = inlineValue ?? argv[++i];
      opts[key] = value;
    } else {
      fail(`Unknown option: --${rawKey}`);
    }
  }

  // Removed upper limit on clients for scalability
  opts.clients = clampInt(opts.clients, 1, 100000, "clients");
  opts.rounds = clampInt(opts.rounds, 0, 10000, "rounds");
  opts.interval = clampInt(opts.interval, 0, 60000, "interval");
  opts.errorRate = clampFloat(opts.errorRate, 0, 1, "error-rate");
  opts.seed = Number(opts.seed) || Date.now();
  return opts;
}

function printHelp() {
  console.log(`Generate fake NetGoat telemetry clients.

Usage:
  node telemetry-server/scripts/fake-clients.mjs [options]

Options:
  --endpoint <url>       Telemetry endpoint. Default: ${defaults.endpoint}
  --clients <n>          Number of fake clients.
  --rounds <n>           Heartbeat rounds after startup.
  --interval <ms>        Delay between rounds.
  --error-rate <0..1>    Chance each client emits new errors per round.
  --seed <n>             Reproducible random seed.
  --shutdown             Send shutdown events at the end
`);
}

function clampInt(value, min, max, label) {
  const n = Number.parseInt(String(value), 10);
  if (!Number.isFinite(n) || n < min) {
    fail(`${label} must be at least ${min}`);
  }
  return n;
}

function clampFloat(value, min, max, label) {
  const n = Number.parseFloat(String(value));
  if (!Number.isFinite(n) || n < min || n > max) {
    fail(`${label} must be between ${min} and ${max}`);
  }
  return n;
}

function fail(message) {
  console.error(color("red", `error ${message}`));
  process.exit(1);
}

function mulberry32(seed) {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let n = Math.imul(t ^ (t >>> 15), t | 1);
    n ^= n + Math.imul(n ^ (n >>> 7), n | 61);
    return ((n ^ (n >>> 14)) >>> 0) / 4294967296;
  };
}

function choice(rng, items) {
  return items[Math.floor(rng() * items.length)];
}

function int(rng, min, max) {
  return Math.floor(rng() * (max - min + 1)) + min;
}

function color(name, value) {
  if (process.env.NO_COLOR) return value;
  return `${colors[name] || ""}${value}${colors.reset}`;
}

function log(level, message) {
  const ts = new Date().toISOString().slice(11, 19);
  const tone = level === "error" ? "red" : level === "warn" ? "amber" : "green";
  console.log(`${color("dim", ts)} ${color("magenta", "fake-telemetry")} ${color(tone, level.toUpperCase().padEnd(5))} ${message}`);
}

function makeClient(rng, index) {
  const profile = choice(rng, osProfiles);
  const diskTotal = int(rng, 80, 1800) * 1024;
  const ramTotal = choice(rng, [2048, 4096, 8192, 16384, 32768, 65536, 131072]);
  const routes = int(rng, 2, 80);
  const users = int(rng, 0, 250);

  return {
    instanceID: randomUUID(),
    hostname: `${choice(rng, hostPrefixes)}-${String(index + 1).padStart(2, "0")}.netgoat.local`,
    goVersion: profile.go,
    os: profile.os,
    arch: profile.arch,
    kernel: profile.kernel,
    cpuModel: choice(rng, cpuModels),
    cpuCores: int(rng, 2, 64),
    ramTotalMB: ramTotal,
    diskTotalMB: diskTotal,
    diskFreeMB: int(rng, Math.floor(diskTotal * 0.12), Math.floor(diskTotal * 0.82)),
    startedAt: new Date(Date.now() - int(rng, 30, 7200) * 1000),
    app: {
      routes,
      users,
      requests: int(rng, 100, 20000),
      blocked: int(rng, 0, 200),
      proxy_errors: int(rng, 0, 40),
      total_errors: 0,
      avg_latency_ms: Number((20 + rng() * 260).toFixed(2)),
      status_codes: { "200": int(rng, 100, 14000), "301": int(rng, 0, 400), "404": int(rng, 0, 80) },
      block_reasons: {},
      error_status_codes: {},
      recent_errors: [],
    },
  };
}

function mutateClient(rng, client, opts, eventType) {
  const requests = int(rng, 10, 900);
  const blocked = rng() < opts.errorRate ? int(rng, 1, 40) : int(rng, 0, 3);
  const proxyErrors = rng() < opts.errorRate ? int(rng, 1, 12) : 0;
  const statusErrors = rng() < opts.errorRate ? int(rng, 1, 30) : 0;
  const ok = Math.max(0, requests - blocked - proxyErrors - statusErrors);

  client.app.requests += requests;
  client.app.blocked += blocked;
  client.app.proxy_errors += proxyErrors;
  client.app.avg_latency_ms = Number(Math.max(8, client.app.avg_latency_ms + (rng() - 0.45) * 30).toFixed(2));
  client.app.status_codes["200"] = (client.app.status_codes["200"] || 0) + ok;

  if (blocked > 0) {
    const reason = choice(rng, blockReasons);
    client.app.block_reasons[reason] = (client.app.block_reasons[reason] || 0) + blocked;
  }

  if (statusErrors > 0) {
    const code = choice(rng, ["400", "401", "403", "404", "429", "500", "502", "503", "504", "408"]);
    client.app.status_codes[code] = (client.app.status_codes[code] || 0) + statusErrors;
    client.app.error_status_codes[code] = (client.app.error_status_codes[code] || 0) + statusErrors;
    rememberError(client.app, "http", code, statusErrors);
  }

  if (proxyErrors > 0) {
    const err = choice(rng, errorTemplates.filter((item) => item.kind === "proxy"));
    rememberError(client.app, err.kind, err.message, proxyErrors);
  }

  client.app.total_errors = client.app.blocked + client.app.proxy_errors;
  client.diskFreeMB = Math.max(512, client.diskFreeMB - int(rng, 0, 24));

  return payloadFor(client, eventType);
}

function rememberError(app, kind, message, count) {
  const existing = app.recent_errors.find((item) => item.kind === kind && item.message === message);
  if (existing) {
    existing.count += count;
    existing.last_seen = new Date().toISOString();
  } else {
    app.recent_errors.unshift({
      kind,
      message,
      count,
      last_seen: new Date().toISOString(),
    });
  }
  app.recent_errors = app.recent_errors
    .sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen))
    .slice(0, 8);
}

function payloadFor(client, eventType) {
  return {
    instance_id: client.instanceID,
    hostname: client.hostname,
    go_version: client.goVersion,
    os: client.os,
    arch: client.arch,
    kernel: client.kernel,
    cpu_model: client.cpuModel,
    cpu_cores: client.cpuCores,
    ram_total_mb: client.ramTotalMB,
    disk_total_mb: client.diskTotalMB,
    disk_free_mb: client.diskFreeMB,
    uptime: formatUptime(Date.now() - client.startedAt.getTime()),
    event_type: eventType,
    timestamp: new Date().toISOString(),
    app: client.app,
  };
}

function formatUptime(ms) {
  const total = Math.max(0, Math.floor(ms / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (hours > 0) return `${hours}h${minutes}m${seconds}s`;
  if (minutes > 0) return `${minutes}m${seconds}s`;
  return `${seconds}s`;
}

async function postTelemetry(endpoint, payload) {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}${text ? `: ${text}` : ""}`);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function sendRound(endpoint, clients, rng, opts, eventType) {
  let errors = 0;
  // Note: For massive client counts, you might want to chunk this
  await Promise.all(
    clients.map(async (client) => {
      try {
        await postTelemetry(endpoint, mutateClient(rng, client, opts, eventType));
      } catch (err) {
        errors++;
      }
    }),
  );
  return errors;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const rng = mulberry32(opts.seed);
  const clients = Array.from({ length: opts.clients }, (_, i) => makeClient(rng, i));

  log("info", `endpoint=${opts.endpoint} clients=${opts.clients} rounds=${opts.rounds} interval=${opts.interval}ms error_rate=${opts.errorRate}`);

  let failed = await sendRound(opts.endpoint, clients, rng, opts, "startup");
  log(failed ? "warn" : "info", `startup sent (${opts.clients - failed}/${opts.clients})`);

  for (let round = 1; round <= opts.rounds; round++) {
    if (opts.interval > 0) await sleep(opts.interval);
    failed = await sendRound(opts.endpoint, clients, rng, opts, "heartbeat");
    const totalErrors = clients.reduce((sum, client) => sum + client.app.total_errors, 0);
    log(failed ? "warn" : "info", `round=${round}/${opts.rounds} posted=${opts.clients - failed}/${opts.clients} dashboard_errors=${totalErrors.toLocaleString()}`);
  }

  if (opts.shutdown) {
    if (opts.interval > 0) await sleep(opts.interval);
    failed = await sendRound(opts.endpoint, clients, rng, opts, "shutdown");
    log(failed ? "warn" : "info", `shutdown sent (${opts.clients - failed}/${opts.clients})`);
  }
}

main().catch((err) => {
  log("error", err.message);
  process.exit(1);
});