// MNDe Executor — strict fail-closed enforcement (hostile).
//
//   npm run test:executor-fail-closed
//
// The product claim is that execution is contingent on a cryptographically
// verified, exact-request-bound ALLOW receipt — NOT merely the string "ALLOW".
// These tests attack that claim: a sidecar (or anything answering its port) that
// returns ALLOW with no receipt, an unverifiable receipt, or a genuinely valid
// receipt issued for a DIFFERENT request must never cause the wrapped function
// to run.
//
// Cases (b) and (c) reuse a REAL, signed, offline-verifiable receipt captured
// from the live sidecar and replay it against a mismatched request — proving the
// gate binds identity, not just signature validity.

import assert from "node:assert/strict";
import http from "node:http";
import { readFileSync, rmSync } from "node:fs";

import { createMndeExecutor } from "../executor/index.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";

const REAL_URL = "http://127.0.0.1:8806";
const MOCK_PORT = 8807;
const MOCK_URL = `http://127.0.0.1:${MOCK_PORT}`;
const RECEIPTS_DIR = "./mnde-receipts/executor-fail-closed-tests";
const REAL_ID = "fc-real-allow-001";

rmSync(RECEIPTS_DIR, { recursive: true, force: true });

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

// A mock "sidecar" that returns exactly the body we hand it, for any request.
function mockSidecar(bodyForRequest) {
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      let sent = {};
      try { sent = JSON.parse(raw); } catch { /* ignore */ }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(bodyForRequest(sent)));
    });
  });
  return {
    start: () => new Promise((done) => server.listen(MOCK_PORT, "127.0.0.1", done)),
    stop: () => new Promise((done) => server.close(done))
  };
}

async function executeAgainstMock(body, {
  action = "read_status",
  input = { service: "billing" },
  executionId = REAL_ID,
  executorConfig = {}
} = {}) {
  const mock = mockSidecar(() => structuredClone(body));
  await mock.start();
  try {
    const exec = createMndeExecutor({ sidecarUrl: MOCK_URL, receiptsDir: RECEIPTS_DIR, timeoutMs: 2000, ...executorConfig });
    let executorCallCount = 0;
    const result = await exec.execute({
      action,
      input,
      executionId,
      run: async () => { executorCallCount += 1; return "DANGER"; }
    });
    return { result, executorCallCount };
  } finally {
    await mock.stop();
  }
}

async function main() {
  console.log("MNDe Executor — strict fail-closed enforcement\n");

  const sidecar = await startMndeSidecar({
    url: REAL_URL,
    testerId: "EXEC-FC-001",
    env: { MNDE_INLINE_REFUSAL_RECEIPTS: "1" }
  });
  const real = createMndeExecutor({ sidecarUrl: REAL_URL, receiptsDir: RECEIPTS_DIR });

  // Capture a genuine, signed, offline-verifiable ALLOW receipt bound to a known
  // execution id + action. This is the material the replay/substitution attacks
  // below reuse.
  let capturedReceipt = null;
  let capturedRefuseReceipt = null;
  try {
    // THE CONTRACT: a valid, request-bound ALLOW receipt is evidence of a policy
    // decision. It is NOT permission to execute, and it never was — the executor
    // is the enforcement point and it refuses while execution is disabled.
    //
    // Both halves matter. The receipt must still be genuine and verifiable (that
    // is the product), and nothing must run (that is the safety property). A test
    // asserting that an ALLOW executes would be asserting the bug F-001 describes:
    // a signature can be presented twice, so treating one as a grant makes every
    // effect replayable.
    await test("positive: a valid, request-bound ALLOW receipt is evidence, not permission", async () => {
      let executorCallCount = 0;
      const r = await real.execute({ action: "read_status", input: { service: "billing" }, executionId: REAL_ID, run: async () => { executorCallCount += 1; return "ok"; } });

      // The evidence half: policy approved, and the receipt verifies offline.
      assert.ok(r.receipt, "receipt must be present");
      assert.equal(r.verified, true, "the receipt must verify offline");
      const inner = r.receipt.receipt ?? r.receipt;
      assert.equal(inner.decision_output?.decision, "ALLOW", "policy must still decide ALLOW and say so in the signed body");

      // The enforcement half: nothing ran.
      assert.equal(r.decision, "REFUSE", "an ALLOW receipt must not become an execution");
      assert.equal(r.executed, false, "no protected effect may run while execution is disabled");
      assert.equal(executorCallCount, 0, "the callback must never be entered");
      assert.equal(r.failClosed, true);

      capturedReceipt = r.receipt;
    });

    await test("valid signed REFUSE does NOT execute", async () => {
      let executorCallCount = 0;
      const r = await real.execute({
        action: "delete_backups",
        input: { path: "backups/", script: "rm -rf backups/" },
        executionId: "fc-real-refuse-001",
        run: async () => { executorCallCount += 1; return "DANGER"; }
      });
      assert.equal(r.decision, "REFUSE");
      assert.equal(r.executed, false);
      assert.equal(executorCallCount, 0, "executorCallCount must remain zero on REFUSE");
      assert.equal(r.verified, true);
      capturedRefuseReceipt = r.receipt;
    });
  } finally {
    await sidecar.stop();
  }

  assert.ok(capturedReceipt, "could not capture a real receipt; cannot run replay attacks");
  assert.ok(capturedRefuseReceipt, "could not capture a real REFUSE receipt");

  // (a) Bare ALLOW, NO receipt — the core fail-open bug.
  await test("(a) ALLOW with NO receipt does NOT execute", async () => {
    const { result: r, executorCallCount } = await executeAgainstMock({ decision: "ALLOW", reason_code: "OK_ALLOW" });
    assert.equal(executorCallCount, 0, "executorCallCount must remain zero without a receipt");
    assert.equal(r.executed, false);
    assert.equal(r.decision, "REFUSE");
    assert.equal(r.failClosed, true);
    assert.equal(r.reason, "ERR_NO_RECEIPT");
  });

  // (b) A genuinely valid receipt, but for a DIFFERENT execution id (replay).
  await test("(b) a VALID receipt replayed under a different execution id does NOT execute", async () => {
    const { result: r, executorCallCount } = await executeAgainstMock(
      { decision: "ALLOW", reason_code: "OK_ALLOW", receipt: capturedReceipt },
      { executionId: "fc-replay-999" }
    );
    assert.equal(executorCallCount, 0, "executorCallCount must remain zero for a receipt from another request");
    assert.equal(r.executed, false);
    assert.equal(r.decision, "REFUSE");
    assert.equal(r.reason, "ERR_RECEIPT_REQUEST_MISMATCH");
  });

  // (c) A valid receipt for the right execution id but the WRONG action.
  await test("(c) a VALID receipt bound to a different action does NOT execute", async () => {
    const { result: r, executorCallCount } = await executeAgainstMock(
      { decision: "ALLOW", reason_code: "OK_ALLOW", receipt: capturedReceipt },
      { action: "delete_backups", input: { path: "backups/" } }
    );
    assert.equal(executorCallCount, 0, "executorCallCount must remain zero for a different action");
    assert.equal(r.executed, false);
    assert.equal(r.decision, "REFUSE");
    assert.equal(r.reason, "ERR_RECEIPT_ACTION_MISMATCH");
  });

  // (d) ALLOW with a present but unverifiable (forged) receipt.
  const forged = JSON.parse(JSON.stringify(capturedReceipt));
  if (forged.signature) forged.signature.value = "0".repeat((forged.signature.value || "").length || 64);
  if (forged.verifiable_signature) forged.verifiable_signature.value = "0".repeat((forged.verifiable_signature.value || "").length || 128);
  await test("(d) ALLOW with an unverifiable receipt does NOT execute", async () => {
    const { result: r, executorCallCount } = await executeAgainstMock({ decision: "ALLOW", reason_code: "OK_ALLOW", receipt: forged });
    assert.equal(executorCallCount, 0, "executorCallCount must remain zero for an invalid signature");
    assert.equal(r.executed, false);
    assert.equal(r.decision, "REFUSE");
    assert.equal(r.reason, "ERR_RECEIPT_UNVERIFIED");
    // A distinct fail-closed refusal record must be written even though a
    // receipt was supplied — so audit can tell the executor refused it.
    assert.ok(r.receiptPath && /failclosed-/.test(r.receiptPath), "a fail-closed refusal record must be persisted");
    const record = JSON.parse(readFileSync(r.receiptPath, "utf8"));
    assert.equal(record.mnde_failclosed, true);
    assert.equal(record.reason, "ERR_RECEIPT_UNVERIFIED");
    assert.ok(record.supplied_receipt_path, "refusal record must reference the supplied receipt");
  });

  await test("malformed receipt does NOT execute", async () => {
    const { result: r, executorCallCount } = await executeAgainstMock({ decision: "ALLOW", receipt: {} });
    assert.equal(executorCallCount, 0);
    assert.equal(r.reason, "ERR_RECEIPT_UNVERIFIED");
  });

  await test("unknown signing key does NOT execute", async () => {
    const unknownKey = structuredClone(capturedReceipt);
    const signature = unknownKey.verifiable_signature ?? unknownKey.signature;
    signature.key_id = "unknown-receipt-key";
    const { result: r, executorCallCount } = await executeAgainstMock({ decision: "ALLOW", receipt: unknownKey });
    assert.equal(executorCallCount, 0);
    assert.equal(r.reason, "ERR_RECEIPT_UNVERIFIED");
  });

  await test("request arguments changed after authorization do NOT execute", async () => {
    const { result: r, executorCallCount } = await executeAgainstMock(
      { decision: "ALLOW", receipt: capturedReceipt },
      { input: { service: "payments" } }
    );
    assert.equal(executorCallCount, 0);
    assert.equal(r.reason, "ERR_RECEIPT_ACTION_MISMATCH");
  });

  await test("target/resource changed after authorization does NOT execute", async () => {
    const { result: r, executorCallCount } = await executeAgainstMock(
      { decision: "ALLOW", receipt: capturedReceipt },
      { input: { service: "production-control-plane" } }
    );
    assert.equal(executorCallCount, 0);
    assert.equal(r.reason, "ERR_RECEIPT_ACTION_MISMATCH");
  });

  await test("caller/subject mismatch does NOT execute", async () => {
    const { result: r, executorCallCount } = await executeAgainstMock(
      { decision: "ALLOW", receipt: capturedReceipt },
      { executorConfig: { expectedSubjectId: "different-subject" } }
    );
    assert.equal(executorCallCount, 0);
    assert.equal(r.reason, "ERR_SUBJECT_MISMATCH");
  });

  await test("required executor identity rejects a raw receipt with no executor layer", async () => {
    const { result: r, executorCallCount } = await executeAgainstMock(
      { decision: "ALLOW", receipt: capturedReceipt },
      { executorConfig: { verifyExpectedExecutorId: "executor-42" } }
    );
    assert.equal(executorCallCount, 0);
    assert.equal(r.reason, "ERR_EXECUTOR_MISMATCH");
  });

  await test("policy mismatch does NOT execute", async () => {
    const { result: r, executorCallCount } = await executeAgainstMock(
      { decision: "ALLOW", receipt: capturedReceipt },
      { executorConfig: { expectedPolicyHash: "not-the-authorized-policy" } }
    );
    assert.equal(executorCallCount, 0);
    assert.equal(r.reason, "ERR_POLICY_MISMATCH");
  });

  await test("HTTP ALLOW carrying a valid signed REFUSE does NOT execute", async () => {
    const { result: r, executorCallCount } = await executeAgainstMock(
      { decision: "ALLOW", receipt: capturedRefuseReceipt },
      {
        action: "delete_backups",
        input: { path: "backups/", script: "rm -rf backups/" },
        executionId: "fc-real-refuse-001"
      }
    );
    assert.equal(executorCallCount, 0);
    assert.equal(r.reason, "ERR_RECEIPT_DECISION_MISMATCH");
  });

  for (const decision of ["REVIEW", "INDETERMINATE", "UNKNOWN"]) {
    await test(`${decision} response does NOT execute`, async () => {
      const { result: r, executorCallCount } = await executeAgainstMock({ decision, receipt: capturedReceipt });
      assert.equal(executorCallCount, 0);
      assert.equal(r.reason, "ERR_MALFORMED_DECISION");
    });
  }

  await test("malformed canonical payload fails verification and does NOT execute", async () => {
    const malformedCanonical = structuredClone(capturedReceipt);
    malformedCanonical.canonical_request = "{not-json";
    const { result: r, executorCallCount } = await executeAgainstMock({ decision: "ALLOW", receipt: malformedCanonical });
    assert.equal(executorCallCount, 0);
    assert.equal(r.reason, "ERR_RECEIPT_UNVERIFIED");
  });

  await test("legacy verify:false cannot bypass mandatory verification", async () => {
    const { result: r, executorCallCount } = await executeAgainstMock(
      { decision: "ALLOW", receipt: forged },
      { executorConfig: { verify: false } }
    );
    assert.equal(executorCallCount, 0);
    assert.equal(r.reason, "ERR_RECEIPT_UNVERIFIED");
  });

  // (e, f) Policy-engine path — the SAME gate, a different receipt shape. The
  // MCP proxy runs the executor in PE mode, so the gate must bind PE receipts
  // (flat canonical_request with tool + parameters) just as strictly.
  const { fileURLToPath } = await import("node:url");
  const { dirname, join } = await import("node:path");
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
  const PE_URL = "http://127.0.0.1:8811";
  const pePolicy = join(repoRoot, "examples", "policy-engine", "sample-policy.json");
  const peSidecar = await startMndeSidecar({ url: PE_URL, testerId: "EXEC-FC-PE", env: { MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: pePolicy } });
  let peReceipt = null;
  const PE_ID = "fc-pe-allow-001";
  try {
    // Same contract as the legacy-engine case above, on the canonical
    // policy-engine path: the receipt is genuine and verified, and it still is not
    // permission. The receipt is captured for the replay attack in (f), which is
    // the whole reason this ALLOW needs to be real.
    await test("(e) policy-engine: a valid, request-bound ALLOW receipt is evidence, not permission", async () => {
      const exec = createMndeExecutor({ sidecarUrl: PE_URL, receiptsDir: RECEIPTS_DIR });
      let executorCallCount = 0;
      const r = await exec.execute({ action: "read_status", input: {}, executionId: PE_ID, run: async () => { executorCallCount += 1; return "ok"; } });
      assert.equal(r.verified, true);
      assert.ok(r.receipt, "receipt must be present");
      assert.equal(r.executed, false, "a valid PE receipt must not execute while execution is disabled");
      assert.equal(executorCallCount, 0);
      peReceipt = r.receipt;
    });
  } finally {
    await peSidecar.stop();
  }
  assert.ok(peReceipt, "could not capture a PE receipt; cannot run the PE replay attack");

  await test("(f) policy-engine: a VALID PE receipt replayed under a different execution id does NOT execute", async () => {
    const mock = mockSidecar(() => ({ decision: "ALLOW", reason_code: "OK_ALLOW", receipt: peReceipt }));
    await mock.start();
    try {
      const exec = createMndeExecutor({ sidecarUrl: MOCK_URL, receiptsDir: RECEIPTS_DIR, timeoutMs: 2000 });
      let executorCallCount = 0;
      const r = await exec.execute({ action: "read_status", input: {}, executionId: "fc-pe-replay-999", run: async () => { executorCallCount += 1; return "DANGER"; } });
      assert.equal(executorCallCount, 0, "a replayed PE receipt (wrong execution id) must NOT execute");
      assert.equal(r.executed, false);
      assert.equal(r.decision, "REFUSE");
      assert.equal(r.reason, "ERR_RECEIPT_REQUEST_MISMATCH");
    } finally {
      await mock.stop();
    }
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL executor fail-closed tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS executor fail-closed tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
