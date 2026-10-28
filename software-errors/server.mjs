#!/usr/bin/env node
import http from "node:http";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { extname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const staticDir = join(__dirname, "static");
const host = process.env.HOST || "127.0.0.1";
const port = boundedInteger(process.env.PORT || process.argv[2] || "9092", 1, 65535, "PORT");
const maxEvents = boundedInteger(process.env.MAX_EVENTS || "10000", 1, 100000, "MAX_EVENTS");
const maxEventsPerIssue = boundedInteger(process.env.MAX_EVENTS_PER_ISSUE || "80", 1, 1000, "MAX_EVENTS_PER_ISSUE");
const maxIssues = boundedInteger(process.env.MAX_ISSUES || "5000", 1, 50000, "MAX_ISSUES");
const maxBodyBytes = boundedInteger(process.env.MAX_BODY_BYTES || String(256 * 1024), 1024, 1024 * 1024, "MAX_BODY_BYTES");
const configuredIngestKey = process.env.ERROR_MONITOR_INGEST_KEY || "";
const configuredAdminKey = process.env.ERROR_MONITOR_ADMIN_KEY || "";
const configuredCorsOrigin = process.env.ERROR_MONITOR_CORS_ORIGIN || "";

const issues = new Map();
const issuesById = new Map();
const events = new Array(maxEvents);
let eventStart = 0;
let eventCount = 0;
let totalEvents = 0;
let nextIssueId = 1;
const startedAt = new Date();

function boundedInteger(value, min, max, name) {
  const parsed = Number(String(value).trim());
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return parsed;
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

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

function json(res, status, data, corsOrigin = "") {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  };
  if (corsOrigin) {
    headers["Access-Control-Allow-Origin"] = corsOrigin;
    headers["Vary"] = "Origin";
  }
  res.writeHead(status, headers);
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    req.on("data", (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > maxBodyBytes) {
        settled = true;
        req.resume();
        reject(new HttpError(413, `request body exceeds ${maxBodyBytes} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (!settled) resolve(Buffer.concat(chunks, size).toString("utf8"));
    });
    req.on("error", (error) => {
      if (!settled) reject(error);
    });
  });
}

function requireJSON(req) {
  const contentType = String(req.headers["content-type"] || "").toLowerCase();
  if (!contentType.startsWith("application/json")) {
    throw new HttpError(415, "content-type must be application/json");
  }
}

function secureEqual(left, right) {
  const leftHash = createHash("sha256").update(String(left)).digest();
  const rightHash = createHash("sha256").update(String(right)).digest();
  return timingSafeEqual(leftHash, rightHash);
}

function requireKey(req, expected, label) {
  if (!expected) return;
  if (!secureEqual(req.headers["x-error-monitor-key"] || "", expected)) {
    throw new HttpError(401, `invalid ${label} key`);
  }
}

async function parseJSONBody(req) {
  requireJSON(req);
  let parsed;
  try {
    parsed = JSON.parse((await readBody(req)) || "{}");
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, "invalid JSON body");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new HttpError(422, "request body must be a JSON object");
  }
  return parsed;
}

function normalizeLevel(value) {
  const level = String(value || "error").toLowerCase();
  return ["debug", "info", "warning", "error", "fatal"].includes(level) ? level : "error";
}

function compact(value, max = 240) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1)}...` : text;
}

function boundedText(value, max = 16000) {
  const text = String(value ?? "");
  return text.length > max ? `${text.slice(0, max - 3)}...` : text;
}

function sanitizeValue(value, depth = 0) {
  if (value == null || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string") return boundedText(value, 2000);
  if (depth >= 3) return boundedText(JSON.stringify(value), 2000);
  if (Array.isArray(value)) return value.slice(0, 40).map((item) => sanitizeValue(item, depth + 1));
  if (typeof value !== "object") return boundedText(value, 2000);

  const output = Object.create(null);
  for (const [key, child] of Object.entries(value).slice(0, 64)) {
    output[compact(key, 100)] = sanitizeValue(child, depth + 1);
  }
  return output;
}

function sanitizeRecord(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return Object.create(null);
  return sanitizeValue(value);
}

function addBounded(set, value, limit) {
  if (set.has(value) || set.size < limit) set.add(value);
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
    return createHash("sha1").update(event.fingerprint.slice(0, 20).map((value) => compact(value, 200)).join("|")).digest("hex").slice(0, 16);
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
  const stackValue = input.stack || exception?.stacktrace || exception?.stack || "";
  const stack = boundedText(typeof stackValue === "string" ? stackValue : JSON.stringify(stackValue), 16000);
  const service = compact(input.service || input.project || input.app || "unknown-service", 120);
  const environment = compact(input.environment || input.env || "production", 80);
  const release = compact(input.release || input.version || "unreleased", 120);

  const event = {
    id: randomUUID(),
    timestamp: normalizeTimestamp(input.timestamp, now),
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
    runtime: sanitizeRecord(input.runtime),
    sdk: sanitizeRecord(input.sdk),
    request: sanitizeRecord(input.request),
    user: normalizeUser(input.user),
    tags: sanitizeRecord(input.tags),
    contexts: sanitizeRecord(input.contexts),
    breadcrumbs: Array.isArray(input.breadcrumbs) ? input.breadcrumbs.slice(-20).map((item) => sanitizeValue(item)) : [],
  };
  event.fingerprint = fingerprintFor({ ...input, ...event });
  return event;
}

function normalizeTimestamp(value, fallback) {
  if (!value) return fallback.toISOString();
  const timestamp = new Date(value);
  if (!Number.isFinite(timestamp.getTime())) throw new HttpError(422, "timestamp must be a valid date");
  return timestamp.toISOString();
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

function appendEvent(event) {
  const index = (eventStart + eventCount) % maxEvents;
  if (eventCount < maxEvents) {
    events[index] = event;
    eventCount++;
  } else {
    events[eventStart] = event;
    eventStart = (eventStart + 1) % maxEvents;
  }
  totalEvents++;
}

function retainedEvents() {
  const rows = new Array(eventCount);
  for (let offset = 0; offset < eventCount; offset++) {
    rows[offset] = events[(eventStart + offset) % maxEvents];
  }
  return rows;
}

function evictOldestIssue() {
  let oldest = null;
  for (const issue of issues.values()) {
    if (!oldest || issue.last_received_at < oldest.last_received_at) oldest = issue;
  }
  if (!oldest) return;
  issues.delete(oldest.fingerprint);
  issuesById.delete(oldest.id);
}

function ingest(input) {
  const event = normalizeError(input);
  appendEvent(event);

  let issue = issues.get(event.fingerprint);
  if (!issue) {
    if (issues.size >= maxIssues) evictOldestIssue();
    issue = {
      id: `ISSUE-${String(nextIssueId++).padStart(4, "0")}`,
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
      last_received_at: event.received_at,
      events: [],
    };
    issues.set(event.fingerprint, issue);
    issuesById.set(issue.id, issue);
  }

  issue.count++;
  issue.last_received_at = event.received_at;
  if (new Date(event.timestamp).getTime() < new Date(issue.first_seen).getTime()) issue.first_seen = event.timestamp;
  if (new Date(event.timestamp).getTime() > new Date(issue.last_seen).getTime()) issue.last_seen = event.timestamp;
  issue.title = event.title;
  issue.message = event.message;
  issue.culprit = event.culprit;
  issue.service = event.service;
  issue.environment = event.environment;
  issue.release = event.release;
  addBounded(issue.services, event.service, 128);
  addBounded(issue.environments, event.environment, 128);
  addBounded(issue.releases, event.release, 512);
  if (event.user?.id) addBounded(issue.users, event.user.id, 10000);
  if (severityRank[event.level] > severityRank[issue.level]) issue.level = event.level;
  issue.events.unshift(event);
  if (issue.events.length > maxEventsPerIssue) issue.events.length = maxEventsPerIssue;

  log(event.level === "fatal" ? "error" : "info", `${event.service} ${event.level.toUpperCase()} ${event.title}`);
  return { issue: issueSummary(issue), event };
}

function clearState() {
  issues.clear();
  issuesById.clear();
  events.fill(undefined);
  eventStart = 0;
  eventCount = 0;
  totalEvents = 0;
  nextIssueId = 1;
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
  const eventRows = retainedEvents();
  const open = issueRows.filter((issue) => issue.status === "open").length;
  const resolved = issueRows.length - open;
  const users = new Set();
  const services = new Set();
  const environments = new Set();
  const levels = { debug: 0, info: 0, warning: 0, error: 0, fatal: 0 };
  const now = Date.now();
  const last24h = now - 24 * 60 * 60 * 1000;

  for (const event of eventRows) {
    if (event.user?.id) users.add(event.user.id);
    services.add(event.service);
    environments.add(event.environment);
    levels[event.level] = (levels[event.level] || 0) + 1;
  }

  return {
    uptime_seconds: Math.floor((Date.now() - startedAt.getTime()) / 1000),
    total_events: totalEvents,
    retained_events: eventCount,
    total_issues: issueRows.length,
    open_issues: open,
    resolved_issues: resolved,
    affected_users: users.size,
    events_24h: eventRows.filter((event) => {
      const timestamp = new Date(event.timestamp).getTime();
      return timestamp >= last24h && timestamp <= now;
    }).length,
    levels,
    services: [...services].sort(),
    environments: [...environments].sort(),
  };
}

async function serveStatic(req, res) {
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, "http://local").pathname);
  } catch {
    throw new HttpError(400, "invalid URL path");
  }
  const requestedPath = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const filePath = resolve(staticDir, requestedPath);
  const relativePath = relative(staticDir, filePath);
  if (relativePath === ".." || relativePath.startsWith(`..${sep}`)) {
    res.writeHead(403);
    res.end("forbidden");
    return;
  }
  try {
    const body = await readFile(filePath);
    res.writeHead(200, { "Content-Type": mimeTypes[extname(filePath)] || "application/octet-stream" });
    res.end(req.method === "HEAD" ? undefined : body);
  } catch (error) {
    if (error.code !== "ENOENT" && error.code !== "EISDIR") throw error;
    const body = await readFile(join(staticDir, "index.html"));
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(req.method === "HEAD" ? undefined : body);
  }
}

async function handleApi(req, res, options) {
  const requestOrigin = req.headers.origin || "";
  const corsOrigin = options.corsOrigin && requestOrigin === options.corsOrigin ? options.corsOrigin : "";
  if (req.method === "OPTIONS") {
    if (!corsOrigin) return json(res, 403, { error: "cross-origin access denied" });
    res.writeHead(204, {
      "Access-Control-Allow-Origin": corsOrigin,
      "Access-Control-Allow-Headers": "content-type,x-error-monitor-key",
      "Access-Control-Allow-Methods": "GET,POST,PATCH,OPTIONS",
      "Access-Control-Max-Age": "600",
      "Vary": "Origin",
    });
    return res.end();
  }
  const url = new URL(req.url, "http://local");

  try {
    if (req.method === "POST" && (url.pathname === "/api/errors" || url.pathname === "/api/events")) {
      requireKey(req, options.ingestKey, "ingestion");
      const body = await parseJSONBody(req);
      const result = ingest(body);
      return json(res, 202, result, corsOrigin);
    }

    if (req.method === "GET" && url.pathname === "/api/stats") {
      return json(res, 200, stats(), corsOrigin);
    }

    if (req.method === "GET" && url.pathname === "/api/issues") {
      return json(res, 200, allIssueSummaries(Object.fromEntries(url.searchParams.entries())), corsOrigin);
    }

    const issueMatch = url.pathname.match(/^\/api\/issues\/([^/]+)$/);
    if (issueMatch) {
      const identifier = decodeURIComponent(issueMatch[1]);
      const issue = issuesById.get(identifier) || issues.get(identifier);
      if (!issue) return json(res, 404, { error: "issue not found" }, corsOrigin);
      if (req.method === "GET") {
        return json(res, 200, { issue: issueSummary(issue), events: issue.events }, corsOrigin);
      }
      if (req.method === "PATCH") {
        const body = await parseJSONBody(req);
        if (body.status !== "resolved" && body.status !== "open") {
          throw new HttpError(422, "status must be open or resolved");
        }
        issue.status = body.status;
        return json(res, 200, { issue: issueSummary(issue) }, corsOrigin);
      }
    }

    if (req.method === "POST" && url.pathname === "/api/clear") {
      if (!options.adminKey) throw new HttpError(403, "clear endpoint is disabled");
      requireKey(req, options.adminKey, "administrator");
      clearState();
      return json(res, 200, { ok: true }, corsOrigin);
    }

    return json(res, 404, { error: "endpoint not found" }, corsOrigin);
  } catch (err) {
    if (err instanceof HttpError) return json(res, err.status, { error: err.message }, corsOrigin);
    log("error", err.stack || err.message);
    return json(res, 500, { error: "internal server error" }, corsOrigin);
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

function createServer(options = {}) {
  const serverOptions = {
    ingestKey: options.ingestKey ?? configuredIngestKey,
    adminKey: options.adminKey ?? configuredAdminKey,
    corsOrigin: options.corsOrigin ?? configuredCorsOrigin,
  };
  const server = http.createServer((req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    let operation;
    if (req.url === "/health") {
      return json(res, 200, { status: "ok", uptime_seconds: Math.floor((Date.now() - startedAt.getTime()) / 1000) });
    }
    if (req.url?.startsWith("/api/")) {
      operation = handleApi(req, res, serverOptions);
    } else if (req.method === "GET" || req.method === "HEAD") {
      operation = serveStatic(req, res);
    } else {
      return json(res, 405, { error: "method not allowed" });
    }
    operation.catch((error) => {
      log("error", error.stack || error.message);
      if (!res.headersSent) return json(res, error.status || 500, { error: error.status ? error.message : "internal server error" });
      res.destroy();
    });
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 64;
  return server;
}

async function startServer() {
  const server = createServer();
  server.on("error", (error) => {
    log("error", error.message);
    process.exitCode = 1;
  });
  server.listen(port, host, () => {
    log("info", `software error monitor listening on http://${host}:${port}`);
    log("info", `ingest endpoint http://${host}:${port}/api/errors`);
    if (!configuredIngestKey) log("warn", "ingestion is unauthenticated; set ERROR_MONITOR_INGEST_KEY");
    if (!configuredAdminKey) log("warn", "clear endpoint is disabled; set ERROR_MONITOR_ADMIN_KEY to enable it");
  });

  let stopping = false;
  const stop = (signal) => {
    if (stopping) return;
    stopping = true;
    log("info", `received ${signal}; shutting down`);
    const force = setTimeout(() => {
      log("error", "graceful shutdown timed out");
      process.exit(1);
    }, 10000);
    force.unref();
    server.close((error) => {
      clearTimeout(force);
      if (error) {
        log("error", error.message);
        process.exitCode = 1;
      }
    });
  };
  process.once("SIGINT", () => stop("SIGINT"));
  process.once("SIGTERM", () => stop("SIGTERM"));
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) startServer().catch((error) => {
  log("error", error.stack || error.message);
  process.exit(1);
});

export {
  clearState,
  createServer,
  fingerprintFor,
  ingest,
  normalizeError,
  stats,
};
