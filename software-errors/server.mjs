#!/usr/bin/env node
import http from "node:http";
import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const staticDir = join(__dirname, "static");
const host = process.env.HOST || "0.0.0.0";
const port = Number.parseInt(process.env.PORT || process.argv[2] || "9092", 10);
const maxEvents = Number.parseInt(process.env.MAX_EVENTS || "10000", 10);
const maxEventsPerIssue = Number.parseInt(process.env.MAX_EVENTS_PER_ISSUE || "80", 10);

const issues = new Map();
const events = [];
const startedAt = new Date();

const colors = {
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  amber: "\x1b[33m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
  magenta: "\x1b[35m",
};

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

const severityRank = { debug: 0, info: 1, warning: 2, error: 3, fatal: 4 };

function json(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "GET,POST,PATCH,OPTIONS",
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
      if (data.length > 1024 * 1024) {
        req.destroy();
        reject(new Error("request body too large"));
      }
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function normalizeLevel(value) {
  const level = String(value || "error").toLowerCase();
  return ["debug", "info", "warning", "error", "fatal"].includes(level) ? level : "error";
}

function compact(value, max = 240) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function firstStackFrame(stack) {
  if (!stack) return "";
  return String(stack)
    .split("\n")
    .map((line) => line.trim())
    .find((line) => line.startsWith("at ") || line.includes(".js:") || line.includes(".ts:") || line.includes(".go:") || line.includes(".py:")) || "";
}

function culpritFromStack(stack, fallback) {
  const frame = firstStackFrame(stack);
  if (!frame) return fallback || "unknown";
  return compact(frame.replace(/^at\s+/, ""), 120);
}

function fingerprintFor(event) {
  if (Array.isArray(event.fingerprint) && event.fingerprint.length > 0) {
    return createHash("sha1").update(event.fingerprint.join("|")).digest("hex").slice(0, 16);
  }
  if (event.fingerprint) {
    return createHash("sha1").update(String(event.fingerprint)).digest("hex").slice(0, 16);
  }
  const basis = [
    event.service,
    event.environment,
    event.type,
    event.message,
    firstStackFrame(event.stack),
  ].join("|");
  return createHash("sha1").update(basis).digest("hex").slice(0, 16);
}

function normalizeUser(user) {
  if (!user || typeof user !== "object") return null;
  const id = compact(user.id || user.email || user.username || user.ip_address || user.ip, 120);
  if (!id) return null;
  return {
    id,
    email: compact(user.email, 160),
    username: compact(user.username, 120),
    ip_address: compact(user.ip_address || user.ip, 80),
  };
}

function normalizeError(input) {
  const now = new Date();
  const exception = Array.isArray(input.exception?.values) ? input.exception.values[0] : input.exception;
  const type = compact(input.type || exception?.type || input.name || "Error", 160);
  const message = compact(input.message || exception?.value || input.error || "Unhandled software error", 300);
  const stack = String(input.stack || exception?.stacktrace || exception?.stack || "");
  const service = compact(input.service || input.project || input.app || "unknown-service", 120);
  const environment = compact(input.environment || input.env || "production", 80);
  const release = compact(input.release || input.version || "unreleased", 120);

  const event = {
    id: randomUUID(),
    timestamp: input.timestamp ? new Date(input.timestamp).toISOString() : now.toISOString(),
    received_at: now.toISOString(),
    level: normalizeLevel(input.level || input.severity),
    type,
    message,
    title: compact(`${type}: ${message}`, 220),
    culprit: culpritFromStack(stack, input.culprit || input.transaction),
    stack,
    service,
    environment,
    release,
    dist: compact(input.dist, 80),
    url: compact(input.url || input.request?.url, 220),
    transaction: compact(input.transaction || input.route, 180),
    runtime: input.runtime && typeof input.runtime === "object" ? input.runtime : {},
    sdk: input.sdk && typeof input.sdk === "object" ? input.sdk : {},
    request: input.request && typeof input.request === "object" ? input.request : {},
    user: normalizeUser(input.user),
    tags: input.tags && typeof input.tags === "object" ? input.tags : {},
    contexts: input.contexts && typeof input.contexts === "object" ? input.contexts : {},
    breadcrumbs: Array.isArray(input.breadcrumbs) ? input.breadcrumbs.slice(-20) : [],
  };
  event.fingerprint = fingerprintFor({ ...input, ...event });
  return event;
}

function issueSummary(issue) {
  return {
    id: issue.id,
    fingerprint: issue.fingerprint,
    title: issue.title,
    message: issue.message,
    type: issue.type,
    culprit: issue.culprit,
    level: issue.level,
    status: issue.status,
    service: issue.service,
    environment: issue.environment,
    release: issue.release,
    count: issue.count,
    user_count: issue.users.size,
    first_seen: issue.first_seen,
    last_seen: issue.last_seen,
    environments: [...issue.environments].sort(),
    releases: [...issue.releases].sort().slice(-8),
    services: [...issue.services].sort(),
  };
}

function ingest(input) {
  const event = normalizeError(input);
  events.unshift(event);
  if (events.length > maxEvents) events.length = maxEvents;

  let issue = issues.get(event.fingerprint);
  if (!issue) {
    issue = {
      id: `ISSUE-${String(issues.size + 1).padStart(4, "0")}`,
      fingerprint: event.fingerprint,
      title: event.title,
      message: event.message,
      type: event.type,
      culprit: event.culprit,
      level: event.level,
      status: "open",
      service: event.service,
      environment: event.environment,
      release: event.release,
      count: 0,
      users: new Set(),
      services: new Set(),
      environments: new Set(),
      releases: new Set(),
      first_seen: event.timestamp,
      last_seen: event.timestamp,
      events: [],
    };
    issues.set(event.fingerprint, issue);
  }

  issue.count++;
  issue.last_seen = event.timestamp;
  issue.title = event.title;
  issue.message = event.message;
  issue.culprit = event.culprit;
  issue.service = event.service;
  issue.environment = event.environment;
  issue.release = event.release;
  issue.services.add(event.service);
  issue.environments.add(event.environment);
  issue.releases.add(event.release);
  if (event.user?.id) issue.users.add(event.user.id);
  if (severityRank[event.level] > severityRank[issue.level]) issue.level = event.level;
  issue.events.unshift(event);
  if (issue.events.length > maxEventsPerIssue) issue.events.length = maxEventsPerIssue;

  log(event.level === "fatal" ? "error" : "info", `${event.service} ${event.level.toUpperCase()} ${event.title}`);
  return { issue: issueSummary(issue), event };
}

function allIssueSummaries(filters = {}) {
  let rows = [...issues.values()].map(issueSummary);
  if (filters.status && filters.status !== "all") rows = rows.filter((row) => row.status === filters.status);
  if (filters.level && filters.level !== "all") rows = rows.filter((row) => row.level === filters.level);
  if (filters.environment && filters.environment !== "all") rows = rows.filter((row) => row.environments.includes(filters.environment));
  if (filters.service && filters.service !== "all") rows = rows.filter((row) => row.services.includes(filters.service));
  if (filters.q) {
    const q = filters.q.toLowerCase();
    rows = rows.filter((row) => [row.title, row.culprit, row.service, row.release].join(" ").toLowerCase().includes(q));
  }
  return rows.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));
}

function stats() {
  const issueRows = [...issues.values()];
  const open = issueRows.filter((issue) => issue.status === "open").length;
  const resolved = issueRows.length - open;
  const users = new Set();
  const services = new Set();
  const environments = new Set();
  const levels = { debug: 0, info: 0, warning: 0, error: 0, fatal: 0 };
  const last24h = Date.now() - 24 * 60 * 60 * 1000;

  for (const event of events) {
    if (event.user?.id) users.add(event.user.id);
    services.add(event.service);
    environments.add(event.environment);
    levels[event.level] = (levels[event.level] || 0) + 1;
  }

  return {
    uptime_seconds: Math.floor((Date.now() - startedAt.getTime()) / 1000),
    total_events: events.length,
    total_issues: issueRows.length,
    open_issues: open,
    resolved_issues: resolved,
    affected_users: users.size,
    events_24h: events.filter((event) => new Date(event.timestamp).getTime() >= last24h).length,
    levels,
    services: [...services].sort(),
    environments: [...environments].sort(),
  };
}

async function serveStatic(req, res) {
  const rawPath = req.url === "/" ? "/index.html" : new URL(req.url, "http://local").pathname;
  const safePath = normalize(rawPath).replace(/^(\.\.[/\\])+/, "");
  const filePath = join(staticDir, safePath);
  if (!filePath.startsWith(staticDir)) {
    res.writeHead(403);
    res.end("forbidden");
    return;
  }
  try {
    const body = await readFile(filePath);
    res.writeHead(200, { "Content-Type": mimeTypes[extname(filePath)] || "application/octet-stream" });
    res.end(body);
  } catch {
    const body = await readFile(join(staticDir, "index.html"));
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(body);
  }
}

async function handleApi(req, res) {
  if (req.method === "OPTIONS") return json(res, 204, {});
  const url = new URL(req.url, "http://local");

  try {
    if (req.method === "POST" && (url.pathname === "/api/errors" || url.pathname === "/api/events")) {
      const body = JSON.parse((await readBody(req)) || "{}");
      const result = ingest(body);
      return json(res, 202, result);
    }

    if (req.method === "GET" && url.pathname === "/api/stats") {
      return json(res, 200, stats());
    }

    if (req.method === "GET" && url.pathname === "/api/issues") {
      return json(res, 200, allIssueSummaries(Object.fromEntries(url.searchParams.entries())));
    }

    const issueMatch = url.pathname.match(/^\/api\/issues\/([^/]+)$/);
    if (issueMatch) {
      const issue = [...issues.values()].find((item) => item.id === issueMatch[1] || item.fingerprint === issueMatch[1]);
      if (!issue) return json(res, 404, { error: "issue not found" });
      if (req.method === "GET") {
        return json(res, 200, { issue: issueSummary(issue), events: issue.events });
      }
      if (req.method === "PATCH") {
        const body = JSON.parse((await readBody(req)) || "{}");
        issue.status = body.status === "resolved" ? "resolved" : "open";
        return json(res, 200, { issue: issueSummary(issue) });
      }
    }

    if (req.method === "POST" && url.pathname === "/api/clear") {
      issues.clear();
      events.length = 0;
      return json(res, 200, { ok: true });
    }

    return json(res, 404, { error: "endpoint not found" });
  } catch (err) {
    return json(res, 400, { error: err.message || "bad request" });
  }
}

function log(level, message) {
  const ts = new Date().toISOString().slice(11, 19);
  const tone = level === "error" ? "red" : level === "warn" ? "amber" : "green";
  if (process.env.NO_COLOR) {
    console[level === "error" ? "error" : "log"](`${ts} errors ${level.toUpperCase()} ${message}`);
    return;
  }
  console[level === "error" ? "error" : "log"](`${colors.dim}${ts}${colors.reset} ${colors.magenta}errors${colors.reset} ${colors[tone]}${level.toUpperCase().padEnd(5)}${colors.reset} ${message}`);
}

const server = http.createServer((req, res) => {
  if (req.url.startsWith("/api/")) {
    handleApi(req, res);
  } else {
    serveStatic(req, res);
  }
});

server.listen(port, host, () => {
  log("info", `software error monitor listening on http://localhost:${port}`);
  log("info", `ingest endpoint http://localhost:${port}/api/errors`);
});
