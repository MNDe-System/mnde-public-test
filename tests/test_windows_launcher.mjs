#!/usr/bin/env node
// Launcher test for installer/windows/mnde-launch.mjs (the one-click "MNDe" shortcut target).
//
// Uses a throwaway MNDE_HOME and a free port, launches from an unrelated working
// directory, and proves: cold start serves the dashboard, a repeat launch reuses
// the running sidecar (no second process), concurrent launches start exactly one,
// the sidecar binds loopback only, and a foreign listener on the port fails
// cleanly instead of hanging.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const launcher = join(repoRoot, "installer", "windows", "mnde-launch.mjs");
const home = mkdtempSync(join(tmpdir(), "mnde-launch-"));
const elsewhere = mkdtempSync(join(tmpdir(), "mnde-cwd-"));

async function freePort() {
  return await new Promise((ok, bad) => {
    const s = createServer();
    s.once("error", bad);
    s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => ok(port)); });
  });
}
const port = await freePort();
const env = {
  ...process.env,
  MNDE_HOME: home,
  MNDE_BIND_PORT: String(port),
  MNDE_LAUNCH_NO_BROWSER: "1",
  MNDE_LAUNCH_NO_DIALOG: "1",
  MNDE_LAUNCH_TIMEOUT_MS: "30000"
};
const run = (extra = {}) =>
  new Promise((done) => {
    const c = spawn(process.execPath, [launcher], { cwd: elsewhere, env: { ...env, ...extra }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (out += d));
    c.on("close", (code) => done({ code, out }));
  });
const pids = () =>
  spawnSync("sh", ["-c", `ps -eo pid,args | grep "[m]nde-local-sidecar.mjs" | wc -l`], { encoding: "utf8", env }).stdout.trim();
const runningRuntimes = process.platform === "win32" ? null : () => Number(pids());

let sidecarPid = null;
try {
  // 1. Cold start from an unrelated cwd.
  const first = await run();
  assert.equal(first.code, 0, first.out);
  assert.match(first.out, /ready/);
  const html = await (await fetch(`http://127.0.0.1:${port}/`)).text();
  assert.match(html, /<title>MNDe/, "dashboard served at /");
  const ready = await (await fetch(`http://127.0.0.1:${port}/readyz`)).json();
  assert.equal(ready.ok, true);
  const identity = await fetch(`http://127.0.0.1:${port}/identity`).then((r) => r.json()).catch(() => null);
  sidecarPid = identity?.process_id ?? null;

  // 2. Repeat launch reuses the running sidecar.
  const second = await run();
  assert.equal(second.code, 0, second.out);
  assert.match(second.out, /already running/);
  if (runningRuntimes) assert.equal(runningRuntimes(), 1, "no duplicate sidecar after repeat launch");

  // 3. Loopback only.
  const lan = Object.values((await import("node:os")).networkInterfaces()).flat().find((i) => i && !i.internal && i.family === "IPv4");
  if (lan) {
    const reachable = await fetch(`http://${lan.address}:${port}/readyz`, { signal: AbortSignal.timeout(1500) }).then(() => true, () => false);
    assert.equal(reachable, false, "sidecar must not answer on a non-loopback address");
  }
} finally {
  if (sidecarPid) { try { process.kill(sidecarPid); } catch { /* gone */ } }
}

// 4. Concurrent cold launches start exactly one sidecar.
await new Promise((r) => setTimeout(r, 800));
const port2 = await freePort();
const results = await Promise.all([1, 2, 3].map(() => run({ MNDE_BIND_PORT: String(port2) })));
for (const r of results) assert.equal(r.code, 0, r.out);
const id2 = await (await fetch(`http://127.0.0.1:${port2}/identity`)).json();
const ps = spawnSync("sh", ["-c", `ps -eo args | grep "[m]nde-local-sidecar.mjs" | wc -l`], { encoding: "utf8" });
if (process.platform !== "win32") assert.equal(Number(ps.stdout.trim()), 1, "exactly one sidecar for concurrent launches");
try { process.kill(id2.process_id); } catch { /* gone */ }

// 5. A foreign listener on the port fails cleanly (non-zero, no hang).
await new Promise((r) => setTimeout(r, 800));
const port3 = await freePort();
const blocker = createServer((s) => s.end("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nno"));
await new Promise((r) => blocker.listen(port3, "127.0.0.1", r));
const blocked = await run({ MNDE_BIND_PORT: String(port3), MNDE_LAUNCH_TIMEOUT_MS: "5000" });
blocker.close();
assert.notEqual(blocked.code, 0, "foreign listener must fail");
assert.match(blocked.out, /did not become ready/);

rmSync(home, { recursive: true, force: true });
rmSync(elsewhere, { recursive: true, force: true });
console.log("WINDOWS LAUNCHER: PASS");
