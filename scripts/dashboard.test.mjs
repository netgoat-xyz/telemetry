#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const html = await readFile(new URL("../static/index.html", import.meta.url), "utf8");
const scripts = [...html.matchAll(/<script(?: [^>]*)?>([\s\S]*?)<\/script>/g)];
const dashboardSource = scripts.at(-1)?.[1];

if (!dashboardSource) throw new Error("dashboard script not found");

const context = vm.createContext({
  console,
  URLSearchParams,
  localStorage: {
    getItem: () => null,
    removeItem: () => {},
    setItem: () => {},
  },
  window: {
    addEventListener: () => {},
    innerWidth: 1280,
    location: { pathname: "/" },
  },
  fetch: async () => { throw new Error("unexpected fetch"); },
});

const sourceWithoutInit = dashboardSource.split("// INIT")[0];
new vm.Script(`${sourceWithoutInit}
globalThis.dashboard = {
  aggregateAppStats,
  agentRoute,
  api,
  escHtml,
  renderAgentsTable,
  renderEventsTable,
};`).runInContext(context);

const dashboard = context.dashboard;

test("escapes every HTML attribute delimiter", () => {
  assert.equal(
    dashboard.escHtml(`<img src=x onerror="alert('x')">&`),
    "&lt;img src=x onerror=&quot;alert(&#39;x&#39;)&quot;&gt;&amp;",
  );
});

test("agent rows do not turn telemetry fields into markup or handlers", () => {
  const rendered = dashboard.renderAgentsTable([{
    instance_id: `agent');globalThis.pwned=true;//<svg/onload=alert(1)>`,
    hostname: `<img src=x onerror=alert(1)>`,
    os: `<script>alert(1)</script>`,
    arch: "amd64",
    go_version: `go1.26"><iframe srcdoc=x>`,
    status: "online",
    heartbeats: 1,
    last_seen: new Date().toISOString(),
  }]);

  assert.doesNotMatch(rendered, /<img src=x|<script>|<svg\/onload|<iframe/);
  assert.doesNotMatch(rendered, /onclick=/);
  assert.match(rendered, /data-copy=/);
  assert.match(rendered, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

test("event rows escape untrusted event and host labels", () => {
  const rendered = dashboard.renderEventsTable([{
    event_type: `<img src=x onerror=alert(1)>`,
    instance_id: `<agent>`,
    hostname: `host<script>alert(1)</script>`,
    timestamp: new Date().toISOString(),
  }]);

  assert.doesNotMatch(rendered, /<img src=x|<script>/);
  assert.match(rendered, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(rendered, /host&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
});

test("aggregates latency by request volume without prototype pollution", () => {
  const hostileMap = JSON.parse(`{"__proto__":4,"500":2}`);
  const aggregate = dashboard.aggregateAppStats([
    { app: { requests: 100, avg_latency_ms: 10, status_codes: hostileMap } },
    { app: { requests: 1, avg_latency_ms: 100, status_codes: { "200": 1 } } },
  ]);

  assert.equal(Object.getPrototypeOf(aggregate.status_codes), null);
  assert.equal(aggregate.status_codes.__proto__, 4);
  assert.equal(aggregate.status_codes["500"], 2);
  assert.ok(Math.abs(aggregate.avg_latency_ms - (1100 / 101)) < 0.0001);
});

test("encodes agent identifiers used in route attributes", () => {
  const route = dashboard.agentRoute(`team/a"><script>alert(1)</script>`);
  assert.equal(route, "/agents/team%2Fa%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E");
});

test("surfaces invalid login responses instead of treating them as expired sessions", async () => {
  context.fetch = async () => ({
    status: 401,
    statusText: "Unauthorized",
    ok: false,
    json: async () => ({ error: "invalid username or password" }),
  });

  await assert.rejects(
    dashboard.api("/api/login", { method: "POST", body: "{}" }),
    /invalid username or password/,
  );
});
