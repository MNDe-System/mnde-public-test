// MNDe — a decision receipt is evidence, not an execution grant.
//
//   npm run test:decision-not-execution
//
// This pins the distinction the whole deployment hold rests on:
//
//   ALLOW  means "policy approved this request."
//   ALLOW  does NOT mean "execution happened" or "execution is permitted now."
//
// Other suites prove the enforcement half (nothing runs). This one proves the
// EVIDENCE half is honest: the receipt says, in its own signed body, that MNDe
// could not have executed it — and that statement cannot be removed without
// breaking the signature.
//
// That last property is the point. An unsigned envelope field announcing
// "dispatchable: false" is worthless against anyone who can edit the response in
// transit; they simply drop it and the receipt reads like a plain ALLOW. Putting
// the marker inside the signed payload makes stripping it detectable.

import assert from "node:assert/strict";
import { rmSync } from "node:fs";

import { buildPolicyReceipt, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { EXECUTION_STATUS_DISABLED, isDispatchEnabled, receiptExecutionStatus } from "../src/execution-availability/index.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { createMndeExecutor } from "../executor/index.mjs";
import { reviewerRequest } from "../scripts/reviewer-request.mjs";

const SIDECAR_URL = "http://127.0.0.1:8809";
const RECEIPTS_DIR = "./mnde-receipts/decision-not-execution";
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

// A minimal policy that allows one tool, so we can obtain a genuine ALLOW.
const POLICY = {
  schema_version: "1.0",
  policy_id: "decision-not-execution",
  version: "1",
  state: "ACTIVE",
  rules: [{ rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }]
};
const REQUEST = {
  schema_version: "1.0",
  request_id: "dne-001",
  timestamp: "2026-01-01T00:00:00.000Z",
  principal: { id: "user-1" },
  agent: { id: "agent-1" },
  tool: { tool_name: "read_status" },
  parameters: {},
  environment: { region: "us-west-2" },
  context: {}
};

async function main() {
  console.log("MNDe — a decision is not an execution grant\n");

  await test("the receipt carries the execution marker in its SIGNED body", async () => {
    const receipt = buildPolicyReceipt(REQUEST, POLICY);
    assert.equal(receipt.decision_output.decision, "ALLOW", "fixture must produce a genuine ALLOW");
    assert.equal(receipt.execution_status, EXECUTION_STATUS_DISABLED);
    const verified = await verifyPolicyReceipt(receipt);
    assert.equal(verified.verified, true, `an ALLOW receipt carrying the marker must still verify: ${verified.reason}`);
    assert.equal(verified.decision, "ALLOW");
  });

  await test("stripping the marker breaks the signature", async () => {
    const receipt = buildPolicyReceipt(REQUEST, POLICY);
    assert.equal(receipt.execution_status, EXECUTION_STATUS_DISABLED);
    // Someone in the middle removes the inconvenient field, leaving what looks
    // like an ordinary signed ALLOW.
    const { execution_status: _stripped, ...tampered } = receipt;
    assert.equal(tampered.execution_status, undefined);
    const verified = await verifyPolicyReceipt(tampered);
    assert.equal(verified.verified, false, "a receipt with the marker removed must NOT verify");
  });

  await test("forging the marker onto a receipt also breaks the signature", async () => {
    // The mirror case: a receipt issued when execution was enabled (no field)
    // cannot have the field added to it either. The signature covers absence too.
    const enabledReceipt = buildPolicyReceipt(REQUEST, POLICY, { executionStatus: null });
    assert.equal(Object.hasOwn(enabledReceipt, "execution_status"), false, "null must omit the field entirely");
    const forged = { ...enabledReceipt, execution_status: EXECUTION_STATUS_DISABLED };
    const verified = await verifyPolicyReceipt(forged);
    assert.equal(verified.verified, false, "a receipt with the marker added must NOT verify");
  });

  await test("the marker is omitted entirely when execution is enabled", () => {
    // Guards the compatibility promise: once dispatch is live, receipts are
    // byte-identical to historical ones and no conformance vector moves.
    // The deployment-wide default reflects the current posture...
    assert.equal(receiptExecutionStatus(), isDispatchEnabled() ? undefined : EXECUTION_STATUS_DISABLED);
    // ...and an execution-enabled receipt carries no trace of the field at all,
    // so its canonical bytes match a historical receipt exactly.
    const enabled = buildPolicyReceipt(REQUEST, POLICY, { executionStatus: null });
    assert.equal(Object.hasOwn(enabled, "execution_status"), false);
  });

  await test("an unsupported execution status is refused rather than silently stamped", () => {
    assert.throws(
      () => buildPolicyReceipt(REQUEST, POLICY, { executionStatus: "ENABLED_TRUST_ME" }),
      /ERR_UNSUPPORTED_EXECUTION_STATUS/
    );
  });

  const sidecar = await startMndeSidecar({ url: SIDECAR_URL, testerId: "DNE-TEST-001" });
  try {
    await test("a live ALLOW decision is reported as non-dispatchable and does not execute", async () => {
      const response = await fetch(`${SIDECAR_URL}/v1/decisions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(reviewerRequest({ requestId: "dne-live-001", tool: "read_status", testerId: "DNE", installationId: "DNE" }))
      });
      const body = await response.json();
      // Whatever policy decided, the envelope states execution availability.
      assert.equal(body.execution?.dispatchable, false);

      // And the executor refuses regardless.
      let ran = false;
      const mnde = createMndeExecutor({ sidecarUrl: SIDECAR_URL, receiptsDir: RECEIPTS_DIR });
      const result = await mnde.execute({
        action: "read_status",
        input: {},
        executionId: "dne-live-exec-001",
        run: async () => { ran = true; }
      });
      assert.equal(result.executed, false);
      assert.equal(ran, false, "no protected effect may run while execution is disabled");
    });
  } finally {
    await sidecar.stop();
  }

  const passed = results.filter(Boolean).length;
  console.log(`\n${passed === results.length ? "PASS" : "FAIL"} decision-is-not-execution (${passed}/${results.length})`);
  if (passed !== results.length) process.exit(1);
}

await main();
