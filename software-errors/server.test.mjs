import assert from "node:assert/strict";
import test from "node:test";

import {
  clearState,
  createServer,
  ingest,
  normalizeError,
  stats,
} from "./server.mjs";

const ingestKey = "test-ingestion-key";
const adminKey = "test-administrator-key";

async function withServer(options, callback) {
  const server = createServer(options);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  try {
    await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

function errorEvent(overrides = {}) {
  return {
    type: "TypeError",
    message: "Cannot read property from undefined",
    service: "dashboard-web",
    environment: "test",
    release: "1.0.0",
    stack: "TypeError: failure\n    at render (/srv/app.js:10:2)",
    timestamp: "2026-07-20T10:00:00.000Z",
    ...overrides,
  };
}

async function postJSON(url, body, headers = {}) {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

test("HTTP API hardening", async (t) => {
  await t.test("requires the configured ingestion key before mutating state", async () => {
    clearState();
    await withServer({ ingestKey, adminKey }, async (baseURL) => {
      const missing = await postJSON(`${baseURL}/api/errors`, errorEvent());
      assert.equal(missing.status, 401);
      assert.equal(stats().total_events, 0);

      const wrong = await postJSON(`${baseURL}/api/errors`, errorEvent(), { "X-Error-Monitor-Key": "wrong" });
      assert.equal(wrong.status, 401);
      assert.equal(stats().total_events, 0);

      const accepted = await postJSON(`${baseURL}/api/errors`, errorEvent(), { "X-Error-Monitor-Key": ingestKey });
      assert.equal(accepted.status, 202);
      assert.equal(stats().total_events, 1);
    });
  });

  await t.test("enforces JSON content type, body limits, and timestamp validation", async () => {
    clearState();
    await withServer({ ingestKey }, async (baseURL) => {
      const wrongType = await fetch(`${baseURL}/api/errors`, {
        method: "POST",
        headers: { "Content-Type": "text/plain", "X-Error-Monitor-Key": ingestKey },
        body: "{}",
      });
      assert.equal(wrongType.status, 415);

      const invalidTimestamp = await postJSON(
        `${baseURL}/api/errors`,
        errorEvent({ timestamp: "not-a-date" }),
        { "X-Error-Monitor-Key": ingestKey },
      );
      assert.equal(invalidTimestamp.status, 422);

      const oversized = await postJSON(
        `${baseURL}/api/errors`,
        errorEvent({ message: "x".repeat(300000) }),
        { "X-Error-Monitor-Key": ingestKey },
      );
      assert.equal(oversized.status, 413);
      assert.equal(stats().total_events, 0);
    });
  });

  await t.test("validates issue transitions and protects destructive clearing", async () => {
    clearState();
    await withServer({ ingestKey, adminKey }, async (baseURL) => {
      const accepted = await postJSON(`${baseURL}/api/errors`, errorEvent(), { "X-Error-Monitor-Key": ingestKey });
      const { issue } = await accepted.json();

      const invalidStatus = await fetch(`${baseURL}/api/issues/${issue.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "deleted" }),
      });
      assert.equal(invalidStatus.status, 422);

      const resolved = await fetch(`${baseURL}/api/issues/${issue.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "resolved" }),
      });
      assert.equal(resolved.status, 200);
      assert.equal((await resolved.json()).issue.status, "resolved");

      const missingKey = await fetch(`${baseURL}/api/clear`, { method: "POST" });
      assert.equal(missingKey.status, 401);
      assert.equal(stats().total_events, 1);

      const cleared = await fetch(`${baseURL}/api/clear`, {
        method: "POST",
        headers: { "X-Error-Monitor-Key": adminKey },
      });
      assert.equal(cleared.status, 200);
      assert.equal(stats().total_events, 0);
    });
  });

  await t.test("denies arbitrary CORS preflights and allows only the configured origin", async () => {
    clearState();
    await withServer({ corsOrigin: "https://console.example.test" }, async (baseURL) => {
      const denied = await fetch(`${baseURL}/api/issues`, {
        method: "OPTIONS",
        headers: { Origin: "https://evil.example.test" },
      });
      assert.equal(denied.status, 403);
      assert.equal(denied.headers.get("access-control-allow-origin"), null);

      const allowed = await fetch(`${baseURL}/api/issues`, {
        method: "OPTIONS",
        headers: { Origin: "https://console.example.test" },
      });
      assert.equal(allowed.status, 204);
      assert.equal(allowed.headers.get("access-control-allow-origin"), "https://console.example.test");
    });
  });

  await t.test("serves health and static content without accepting stray mutations", async () => {
    clearState();
    await withServer({}, async (baseURL) => {
      const health = await fetch(`${baseURL}/health`);
      assert.equal(health.status, 200);
      assert.equal((await health.json()).status, "ok");

      const dashboard = await fetch(`${baseURL}/`);
      assert.equal(dashboard.status, 200);
      assert.match(await dashboard.text(), /Software Error Monitor/);
      assert.equal(dashboard.headers.get("x-frame-options"), "DENY");

      const strayPost = await fetch(`${baseURL}/`, { method: "POST" });
      assert.equal(strayPost.status, 405);

      const traversal = await fetch(`${baseURL}/..%2f..%2fetc%2fpasswd`);
      assert.equal(traversal.status, 403);
    });
  });
});

test("normalization bounds nested error data", () => {
  const tags = Object.fromEntries(Array.from({ length: 100 }, (_, index) => [`tag-${index}`, "x".repeat(3000)]));
  const normalized = normalizeError(errorEvent({
    stack: "s".repeat(20000),
    tags,
    breadcrumbs: Array.from({ length: 30 }, (_, index) => ({ message: "m".repeat(3000), index })),
  }));

  assert.ok(normalized.stack.length <= 16000);
  assert.equal(Object.keys(normalized.tags).length, 64);
  assert.ok(Object.values(normalized.tags).every((value) => value.length <= 2000));
  assert.equal(normalized.breadcrumbs.length, 20);
});

test("issue windows preserve chronological first and last occurrence", () => {
  clearState();
  ingest(errorEvent({ timestamp: "2026-07-20T10:00:00.000Z" }));
  const result = ingest(errorEvent({ timestamp: "2026-07-19T10:00:00.000Z" }));

  assert.equal(result.issue.first_seen, "2026-07-19T10:00:00.000Z");
  assert.equal(result.issue.last_seen, "2026-07-20T10:00:00.000Z");
  assert.equal(result.issue.count, 2);
});
