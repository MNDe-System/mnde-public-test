import { parentPort, workerData } from "node:worker_threads";
import { performance } from "node:perf_hooks";
import { executeDeterministicPipeline } from "../audit/node_runtime.ts";

// This live per-request handler deliberately does NOT reset budget-token state
// between tasks. Budget holds/commits MUST accumulate across requests so a
// token's spending cap is tracked over its lifetime — a per-task reset here
// wiped committed spend and let the cap be bypassed (it previously called
// resetRuntimeState(); removed on purpose). The execution_id ledger was never
// reset here either.
//
// SCOPE: enforcement persists across requests handled by THIS worker process
// only. budgetTokenStore is a per-worker in-memory singleton, so durable and
// cross-worker enforcement are NOT provided here — that is the durable-ledger
// design (PR #5). resetRuntimeState() remains for replay/test isolation only
// (see sidecar/replay_engine.mjs and audit/node_runtime.ts replayReceiptStore).
parentPort.on("message", (message) => {
  const started = performance.now();
  const timings = {};
  try {
    const result = executeDeterministicPipeline(message.raw_input, { timings });
    parentPort.postMessage({
      ok: true,
      task_id: message.task_id,
      worker_id: workerData.worker_id,
      result,
      timings,
      exec_ms: Math.max(0, Math.round(performance.now() - started))
    });
  } catch (error) {
    parentPort.postMessage({
      ok: false,
      task_id: message.task_id,
      worker_id: workerData.worker_id,
      reason_code: error.message?.startsWith("ERR_") ? error.message : "ERR_RUNTIME_ERROR",
      exec_ms: Math.max(0, Math.round(performance.now() - started))
    });
  }
});
