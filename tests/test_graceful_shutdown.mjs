#!/usr/bin/env node
// Unit tests for the sidecar graceful-shutdown lifecycle helper.
//
//   npm run test:graceful-shutdown
//
// Pure and deterministic: the clock, timers, and process.exit are all injected,
// so the deadline path is fired explicitly rather than waited on. No sleeps.
// Covers idempotency, phase ordering, the deadline path exiting non-zero, a
// persistence failure that must NOT be reported as success, forced cleanup, and
// the quiescence gate. The live end-to-end behavior is covered separately by
// test:sidecar-shutdown against the real process.

import assert from "node:assert/strict";

import {
  createGracefulShutdown,
  parseShutdownDeadlineMs,
  waitForQuiescence,
  ERR_SHUTDOWN_CONFIG,
  ERR_SIDECAR_SHUTDOWN_DEADLINE,
  ERR_SIDECAR_SHUTDOWN_PERSISTENCE
} from "../sidecar/graceful_shutdown.mjs";

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

// A manual timer registry: nothing fires until the test fires it. Lets us drive
// the deadline deterministically without wall-clock time.
function fakeTimers() {
  let seq = 1;
  const timers = new Map();
  return {
    setTimer: (fn, ms) => { const id = seq++; timers.set(id, { fn, ms }); return id; },
    clearTimer: (id) => timers.delete(id),
    fireAll: () => { for (const [id, { fn }] of [...timers]) { timers.delete(id); fn(); } },
    pending: () => timers.size
  };
}

function harness({ phases, deadlineMs = 1000 }) {
  const timers = fakeTimers();
  const log = [];
  const events = [];
  let exitCode = null;
  let forcedCleanupCalls = 0;
  let beginCalls = 0;
  const controller = createGracefulShutdown({
    deadlineMs,
    phases,
    onBegin: () => { beginCalls += 1; events.push("begin"); },
    onForcedCleanup: () => { forcedCleanupCalls += 1; events.push("forced"); },
    now: () => 0,
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer,
    exit: (code) => { if (exitCode === null) exitCode = code; events.push(`exit:${code}`); },
    log: (line) => log.push(line)
  });
  return {
    controller,
    timers,
    log,
    events,
    beginCalls: () => beginCalls,
    forcedCleanupCalls: () => forcedCleanupCalls,
    exitCode: () => exitCode
  };
}

async function main() {
  console.log("MNDe graceful-shutdown lifecycle unit tests\n");

  await test("all phases succeed in order → exit 0, no forced cleanup", async () => {
    const order = [];
    const h = harness({
      phases: [
        { name: "await-quiescence", run: () => { order.push("q"); } },
        { name: "drain-receipts", run: async () => { order.push("r"); return { ok: true }; } },
        { name: "stop-workers", run: () => { order.push("w"); } },
        { name: "cleanup-sockets", run: () => { order.push("s"); } }
      ]
    });
    await h.controller.shutdown();
    assert.deepEqual(order, ["q", "r", "w", "s"], "phases must run in declared order");
    assert.equal(h.exitCode(), 0, "clean shutdown exits 0");
    assert.equal(h.forcedCleanupCalls(), 0, "forced cleanup must NOT run on success");
    assert.equal(h.beginCalls(), 1, "onBegin runs exactly once");
  });

  await test("idempotent: repeated shutdown() shares one run", async () => {
    let runs = 0;
    const h = harness({
      phases: [{ name: "await-quiescence", run: async () => { runs += 1; } }]
    });
    const a = h.controller.shutdown();
    const b = h.controller.shutdown();
    assert.equal(a, b, "second shutdown() returns the same in-flight promise");
    await Promise.all([a, b]);
    h.controller.shutdown(); // even after completion
    assert.equal(runs, 1, "phases run exactly once across repeated calls");
    assert.equal(h.beginCalls(), 1, "onBegin runs exactly once across repeated calls");
    assert.equal(h.events.filter((e) => e.startsWith("exit")).length, 1, "exit happens exactly once");
  });

  await test("deadline fires while a phase is stuck → exit 1 + forced cleanup", async () => {
    const h = harness({
      deadlineMs: 50,
      phases: [
        { name: "await-quiescence", run: () => new Promise(() => {}) } // never resolves
      ]
    });
    h.controller.shutdown();          // begins; arms the (fake) deadline timer
    await Promise.resolve();          // let execute() reach the await
    assert.equal(h.timers.pending() >= 1, true, "a deadline timer is armed");
    h.timers.fireAll();               // fire the deadline deterministically
    assert.equal(h.exitCode(), 1, "deadline expiry must exit non-zero");
    assert.equal(h.forcedCleanupCalls(), 1, "deadline path runs forced cleanup");
    assert.equal(h.log.some((l) => l.includes(ERR_SIDECAR_SHUTDOWN_DEADLINE)), true, "diagnostic names the deadline");
  });

  await test("receipt persistence finishing fail-closed is NOT reported as success", async () => {
    const h = harness({
      phases: [
        { name: "await-quiescence", run: () => {} },
        // Mirrors the real wiring: the queue's shutdown() resolved, but metrics
        // report fail_closed, so the phase returns { ok:false }.
        { name: "drain-receipts", run: async () => ({ ok: false, reason: "ERR_RECEIPT_FLUSH_FAILED" }) },
        { name: "stop-workers", run: () => { throw new Error("must not reach stop-workers"); } }
      ]
    });
    await h.controller.shutdown();
    assert.equal(h.exitCode(), 1, "a persistence failure must exit non-zero");
    assert.equal(h.forcedCleanupCalls(), 1, "persistence failure runs forced cleanup");
    assert.equal(h.log.some((l) => l.includes(ERR_SIDECAR_SHUTDOWN_PERSISTENCE)), true, "diagnostic names persistence");
  });

  await test("a phase that throws → exit 1 + forced cleanup (no unhandled rejection)", async () => {
    const h = harness({
      phases: [
        { name: "await-quiescence", run: () => {} },
        { name: "stop-workers", run: async () => { throw new Error("boom"); } }
      ]
    });
    await h.controller.shutdown();
    assert.equal(h.exitCode(), 1, "a throwing phase exits non-zero");
    assert.equal(h.forcedCleanupCalls(), 1, "a throwing phase runs forced cleanup");
  });

  await test("waitForQuiescence resolves once inflight reaches zero", async () => {
    let calls = 0;
    const getInflight = () => (calls++ < 3 ? 2 : 0);
    await waitForQuiescence(getInflight, { aborted: false }, { intervalMs: 0, setTimer: (fn) => setImmediate(fn) });
    assert.equal(calls >= 4, true, "polls until inflight is zero");
  });

  await test("waitForQuiescence resolves when the deadline signal aborts", async () => {
    const signal = { aborted: false };
    const p = waitForQuiescence(() => 5, signal, { intervalMs: 0, setTimer: (fn) => setImmediate(fn) });
    setImmediate(() => { signal.aborted = true; });
    await p; // must resolve despite inflight never reaching zero
    assert.equal(signal.aborted, true);
  });

  await test("parseShutdownDeadlineMs: unset → default, valid → parsed, invalid → throws", () => {
    assert.equal(parseShutdownDeadlineMs({}), 5000, "unset uses the documented default");
    assert.equal(parseShutdownDeadlineMs({ MNDE_SHUTDOWN_DEADLINE_MS: "" }), 5000, "empty uses the default");
    assert.equal(parseShutdownDeadlineMs({ MNDE_SHUTDOWN_DEADLINE_MS: "1234" }), 1234, "valid is parsed");
    for (const bad of ["0", "-1", "abc", "  "]) {
      assert.throws(() => parseShutdownDeadlineMs({ MNDE_SHUTDOWN_DEADLINE_MS: bad }), new RegExp(ERR_SHUTDOWN_CONFIG), `must reject ${bad}`);
    }
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL graceful-shutdown unit tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS graceful-shutdown unit tests (${results.length}/${results.length})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
