#!/usr/bin/env node
// Graceful-shutdown behavior of the REAL sidecar process.
//
//   npm run test:sidecar-shutdown
//
// Boots mnde-local-sidecar.mjs (zero-config policy-engine default) with the test
// harness enabled, and drives shutdown through the harness stdin `stop` line —
// the SAME graceful path SIGINT/SIGTERM take — so the test is cross-platform and
// does not depend on POSIX signal delivery to a child.
//
// Synchronization is state-driven, not sleep-driven: we poll /readyz for the
// observable state we need (inflight count, draining flag) before acting, and
// hold work in-flight deterministically via harness request modes (`hang`,
// `slow`). Deadlines are generous to tolerate scheduler jitter.
//
// Covers, per the shutdown-hardening acceptance criteria:
//   A. a decision active when shutdown begins finishes (response + receipt) → exit 0
//   B. new work is refused once draining starts, incl. on a pre-existing connection
//   C. work still running after the client disconnects is accounted for (receipt persisted)
//   D. pending receipts flush before a successful exit (throughput durability)
//   E. repeated stop signals do not duplicate cleanup or raise unhandled errors
//   F. a deliberately stalled drain exits non-zero within the configured deadline
//   G. idle connections do not unnecessarily block graceful shutdown

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import net from "node:net";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
bootstrapReceiptKeys({ repoRoot });

const HOST = "127.0.0.1";
const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.stack ?? error.message}`);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function spawnSidecar(port, receiptLog, overrides = {}) {
  const env = {
    ...process.env,
    MNDE_BIND_PORT: String(port),
    MNDE_TEST_HARNESS: "1",             // enables the stdin `stop` seam + hang/slow modes
    MNDE_INLINE_REFUSAL_RECEIPTS: "1",
    MNDE_RECEIPT_LOG: receiptLog,
    MNDE_WORKER_POOL_SIZE: "1",
    // Keep the socket idle-eviction sweep from tearing down a connection during
    // the deliberate in-request delays this suite uses (a test-timing concern,
    // unrelated to shutdown). Sockets are still force-closed at drain time.
    MNDE_SOCKET_IDLE_TIMEOUT_MS: "30000",
    // The trust-root pre-flight requires an explicit profile — there is no
    // implicit default (a missing profile fails closed with ERR_PROFILE_REQUIRED).
    // This lifecycle suite exercises shutdown, not the production trust gate, so
    // it runs the documented development profile.
    MNDE_PROFILE: "local",
    MNDE_HARNESS_INSTANCE_ID: `shutdown-${port}-${Math.random()}`
  };
  // Clean engine slate → real zero-config policy-engine default. Profile is set
  // explicitly above (never deleted): the pre-flight demands one.
  for (const k of ["MNDE_DECISION_ENGINE", "MNDE_PE_POLICY", "MNDE_PE_POLICY_BUNDLE"]) delete env[k];
  for (const [k, v] of Object.entries(overrides)) { if (v === undefined) delete env[k]; else env[k] = v; }
  const child = spawn(process.execPath, ["mnde-local-sidecar.mjs"], {
    cwd: repoRoot,
    env,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true
  });
  let out = "";
  let err = "";
  child.stdout.on("data", (d) => (out += d.toString()));
  child.stderr.on("data", (d) => (err += d.toString()));
  return { child, out: () => out, err: () => err };
}

async function getReadyz(port) {
  try {
    const r = await fetch(`http://${HOST}:${port}/readyz`, { signal: AbortSignal.timeout(1000) });
    return await r.json();
  } catch {
    return null;
  }
}

async function waitFor(fn, { timeoutMs = 8000, intervalMs = 25, label = "condition" } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await fn();
    if (value) return value;
    await sleep(intervalMs);
  }
  throw new Error(`timed out waiting for ${label}`);
}

const waitReady = (s, port) => waitFor(async () => {
  if (s.child.exitCode !== null) throw new Error(`sidecar exited early (code ${s.child.exitCode}): ${s.err().slice(-400)}`);
  const b = await getReadyz(port);
  return b && b.ok === true ? b : null;
}, { label: "readyz.ok", timeoutMs: 12000 });

const waitInflight = (port, n) => waitFor(async () => {
  const b = await getReadyz(port);
  return b && typeof b.inflight === "number" && b.inflight >= n ? b : null;
}, { label: `inflight>=${n}` });

// Once server.close() runs, fresh /readyz connections are refused, so drain is
// observed via the process's own stdout marker (printed right after the latch).
const waitDrainingMarker = (s) => waitFor(
  async () => s.out().includes("mnde.sidecar.shutdown draining"),
  { label: "draining marker" }
);

function stop(s) {
  try { s.child.stdin.write("stop\n"); } catch { /* stdin may be closed */ }
}

function waitExit(s, timeoutMs = 12000) {
  return new Promise((resolveExit, reject) => {
    if (s.child.exitCode !== null) return resolveExit(s.child.exitCode);
    const timer = setTimeout(() => reject(new Error(`process did not exit within ${timeoutMs}ms`)), timeoutMs);
    s.child.once("exit", (code) => { clearTimeout(timer); resolveExit(code ?? 0); });
  });
}

function countReceipts(receiptLog) {
  if (!existsSync(receiptLog)) return 0;
  const text = readFileSync(receiptLog, "utf8").trim();
  return text === "" ? 0 : text.split(/\r?\n/).filter((l) => l.trim() !== "").length;
}

const peRequest = () => ({
  schema_version: "1.0", request_id: `sd-${Math.random().toString(36).slice(2)}`, timestamp: "2026-06-25T00:00:00.000Z",
  principal: { id: "p" }, agent: { id: "a" }, tool: { tool_name: "read_status" },
  parameters: {}, environment: {}, context: {}
});

function decisionFetch(port, { headers = {}, signal } = {}) {
  return fetch(`http://${HOST}:${port}/v1/decisions`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(peRequest()),
    signal
  });
}

// Minimal raw HTTP/1.1 request over a caller-supplied (already connected) socket,
// so we can prove that a request arriving on a connection that predates draining
// is refused at the application layer. The sidecar answers connection:close.
function openSocket(port) {
  return new Promise((resolveSock, reject) => {
    const socket = net.connect(port, HOST);
    socket.once("connect", () => resolveSock(socket));
    socket.once("error", reject);
  });
}

function rawDecision(socket, port) {
  return new Promise((resolveResp, reject) => {
    let buf = "";
    socket.on("data", (d) => (buf += d.toString()));
    socket.once("error", reject);
    socket.once("close", () => {
      const statusMatch = buf.match(/^HTTP\/1\.1 (\d{3})/);
      const bodyStart = buf.indexOf("\r\n\r\n");
      let body = null;
      if (bodyStart >= 0) { try { body = JSON.parse(buf.slice(bodyStart + 4).trim()); } catch { /* leave null */ } }
      resolveResp({ status: statusMatch ? Number(statusMatch[1]) : null, body });
    });
    const payload = Buffer.from(JSON.stringify(peRequest()));
    socket.write(
      `POST /v1/decisions HTTP/1.1\r\nHost: ${HOST}:${port}\r\nContent-Type: application/json\r\n` +
      `Content-Length: ${payload.length}\r\nConnection: close\r\n\r\n`
    );
    socket.write(payload);
  });
}

function tmpLog(tag) {
  return join(mkdtempSync(join(tmpdir(), `mnde-sd-${tag}-`)), "receipts.jsonl");
}

async function main() {
  console.log("MNDe sidecar graceful-shutdown integration tests\n");

  // A ─────────────────────────────────────────────────────────────────────────
  await test("A. decision active at shutdown finishes with response + receipt, exit 0", async () => {
    const port = 8841;
    const log = tmpLog("A");
    const s = spawnSidecar(port, log, { MNDE_SHUTDOWN_DEADLINE_MS: "10000" });
    try {
      await waitReady(s, port);
      const before = countReceipts(log);
      const pending = decisionFetch(port, { headers: { "x-mnde-shutdown-test": "slow", "x-mnde-shutdown-slow-ms": "700" } });
      await waitInflight(port, 1);           // request is admitted and mid-flight
      stop(s);                                // shutdown begins while it runs
      const res = await pending;              // the in-flight decision still completes
      assert.equal(res.status, 200, "active decision must return 200");
      const body = await res.json();
      assert.ok(body.decision === "ALLOW" || body.decision === "REFUSE", "must carry a decision");
      assert.ok(body.receipt && typeof body.receipt === "object", "must carry a receipt");
      const code = await waitExit(s);
      assert.equal(code, 0, "graceful shutdown after the request completes exits 0");
      assert.equal(countReceipts(log), before + 1, "the active decision's receipt is persisted before exit");
    } finally {
      stop(s); await waitExit(s).catch(() => {});
    }
  });

  // B ─────────────────────────────────────────────────────────────────────────
  await test("B. new work refused during draining, incl. on a pre-existing connection", async () => {
    const port = 8842;
    const log = tmpLog("B");
    const s = spawnSidecar(port, log, { MNDE_SHUTDOWN_DEADLINE_MS: "12000" });
    try {
      await waitReady(s, port);
      // A connection opened BEFORE draining — left idle. It must survive drain
      // start (we do not tear idle connections down early) and its later request
      // must be refused at the app layer, not silently dropped.
      const preSock = await openSocket(port);
      // Hold the process in the draining/quiescence window with a slow request.
      const hold = decisionFetch(port, { headers: { "x-mnde-shutdown-test": "slow", "x-mnde-shutdown-slow-ms": "3000" } }).catch(() => null);
      await waitInflight(port, 1);
      stop(s);
      await waitDrainingMarker(s);             // drain latch is set; new decision work is refused
      const onExisting = await rawDecision(preSock, port);
      assert.equal(onExisting.status, 503, "request on a pre-existing connection during draining → 503");
      assert.equal(onExisting.body?.reason_code, "ERR_SIDECAR_DRAINING", "must be the draining refusal contract");
      assert.equal(onExisting.body?.decision, "REFUSE", "draining refusal is a REFUSE envelope");
      assert.equal(onExisting.body?.receipt, null, "a liveness refusal carries no receipt");
      // A fresh connection is also not admitted (either TCP-refused or draining-refused; never a 200 decision).
      let freshStatus = "conn-refused";
      try { freshStatus = (await decisionFetch(port)).status; } catch { /* server.close refuses new connects */ }
      assert.notEqual(freshStatus, 200, "no new decision may succeed during draining");
      await hold;
      const code = await waitExit(s);
      assert.equal(code, 0, "process still exits cleanly once the held request drains");
    } finally {
      stop(s); await waitExit(s).catch(() => {});
    }
  });

  // C ─────────────────────────────────────────────────────────────────────────
  await test("C. work still running after client disconnect is accounted for (receipt persisted)", async () => {
    const port = 8843;
    const log = tmpLog("C");
    const s = spawnSidecar(port, log, { MNDE_SHUTDOWN_DEADLINE_MS: "10000" });
    try {
      await waitReady(s, port);
      const before = countReceipts(log);
      const ac = new AbortController();
      const req = decisionFetch(port, { headers: { "x-mnde-shutdown-test": "slow", "x-mnde-shutdown-slow-ms": "800" }, signal: ac.signal }).catch(() => null);
      await waitInflight(port, 1);
      ac.abort();                             // client disconnects while app work is still running
      await req;
      stop(s);                                // shutdown begins; disconnected work must still be accounted for
      const code = await waitExit(s);
      assert.equal(code, 0, "graceful exit once the disconnected-but-running work settles");
      assert.equal(countReceipts(log), before + 1, "the receipt for the disconnected request is persisted before exit");
    } finally {
      stop(s); await waitExit(s).catch(() => {});
    }
  });

  // D ─────────────────────────────────────────────────────────────────────────
  await test("D. pending receipts flush before a successful exit (throughput durability)", async () => {
    const port = 8844;
    const log = tmpLog("D");
    // Large batch thresholds so a completed decision's receipt sits UNFLUSHED in
    // the queue until the shutdown drain flushes it.
    const s = spawnSidecar(port, log, {
      MNDE_SHUTDOWN_DEADLINE_MS: "10000",
      MNDE_RECEIPT_DURABILITY_MODE: "throughput",
      MNDE_RECEIPT_BATCH_MAX_SIZE: "1000",
      MNDE_RECEIPT_BATCH_MAX_AGE_MS: "60000",
      // Disable the ledger: its per-decision flush() would persist the receipt
      // immediately, defeating the "still pending at shutdown" precondition.
      MNDE_EXECUTION_LEDGER: "off"
    });
    try {
      await waitReady(s, port);
      const res = await decisionFetch(port);
      assert.equal(res.status, 200, "decision completes");
      await res.json();
      assert.equal(countReceipts(log), 0, "precondition: receipt is still queued, not yet on disk");
      stop(s);
      const code = await waitExit(s);
      assert.equal(code, 0, "clean exit");
      assert.equal(countReceipts(log), 1, "the pending receipt is flushed to disk during drain, before exit");
    } finally {
      stop(s); await waitExit(s).catch(() => {});
    }
  });

  // E ─────────────────────────────────────────────────────────────────────────
  await test("E. repeated stop signals → single clean exit 0, no unhandled errors", async () => {
    const port = 8845;
    const log = tmpLog("E");
    const s = spawnSidecar(port, log, { MNDE_SHUTDOWN_DEADLINE_MS: "10000" });
    try {
      await waitReady(s, port);
      stop(s); stop(s); stop(s);              // three overlapping shutdown triggers
      const code = await waitExit(s);
      assert.equal(code, 0, "repeated stops still exit cleanly exactly once");
      assert.doesNotMatch(s.err(), /Unhandled|UnhandledPromiseRejection|TypeError|ReferenceError/, "no unhandled errors on repeated shutdown");
    } finally {
      stop(s); await waitExit(s).catch(() => {});
    }
  });

  // F ─────────────────────────────────────────────────────────────────────────
  await test("F. stalled drain exits non-zero within the configured deadline", async () => {
    const port = 8846;
    const log = tmpLog("F");
    const DEADLINE = 900;
    const s = spawnSidecar(port, log, { MNDE_SHUTDOWN_DEADLINE_MS: String(DEADLINE) });
    try {
      await waitReady(s, port);
      // A request that never completes → inflight never reaches zero → the drain
      // must fall back to the deadline and force termination.
      decisionFetch(port, { headers: { "x-mnde-shutdown-test": "hang" } }).catch(() => null);
      await waitInflight(port, 1);
      const startedAt = Date.now();
      stop(s);
      const code = await waitExit(s, DEADLINE + 6000);
      const elapsed = Date.now() - startedAt;
      assert.notEqual(code, 0, "a stalled drain must exit non-zero");
      assert.ok(elapsed >= DEADLINE * 0.5, `must wait for the deadline, not exit instantly (elapsed ${elapsed}ms)`);
      assert.ok(elapsed <= DEADLINE + 5000, `must terminate near the deadline (elapsed ${elapsed}ms)`);
      assert.match(s.err(), /ERR_SIDECAR_SHUTDOWN_DEADLINE/, "diagnostic names the deadline");
    } finally {
      stop(s); await waitExit(s).catch(() => {});
    }
  });

  // G ─────────────────────────────────────────────────────────────────────────
  await test("G. idle connections do not unnecessarily block graceful shutdown", async () => {
    const port = 8847;
    const log = tmpLog("G");
    const DEADLINE = 8000;
    const s = spawnSidecar(port, log, { MNDE_SHUTDOWN_DEADLINE_MS: String(DEADLINE) });
    try {
      await waitReady(s, port);
      const idle = await openSocket(port);    // connected, no request — pure idle keep-alive
      idle.on("error", () => {});
      const startedAt = Date.now();
      stop(s);
      const code = await waitExit(s);
      const elapsed = Date.now() - startedAt;
      assert.equal(code, 0, "idle-only shutdown exits cleanly");
      assert.ok(elapsed < DEADLINE - 1000, `must NOT wait for the deadline on idle connections (elapsed ${elapsed}ms)`);
    } finally {
      stop(s); await waitExit(s).catch(() => {});
    }
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL sidecar-shutdown tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS sidecar-shutdown tests (${results.length}/${results.length})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
