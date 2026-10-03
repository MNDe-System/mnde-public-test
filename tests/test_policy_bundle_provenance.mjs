#!/usr/bin/env node
// Signed Policy Bundle provenance gates. Provenance is receipt evidence, not
// policy-engine input: it must be signed, replay-stable, and optional for
// legacy policy-engine receipts.

import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "./support/bootstrap_dev_receipt_keys.mjs";
import { buildPolicyReceipt, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
bootstrapReceiptKeys({ repoRoot });

const request = {
  schema_version: "1.0", request_id: "bundle-provenance-1", timestamp: "2026-06-23T12:00:00.000Z",
  principal: { id: "operator" }, agent: { id: "agent" }, tool: { tool_name: "read_status" },
  parameters: {}, environment: {}, context: {}
};
const policy = {
  schema_version: "1.0", policy_id: "ops-policy", version: "7.0.0", state: "ACTIVE",
  rules: [{ rule_id: "allow-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }]
};
const provenance = {
  bundle_id: "ops-policy-serial-7", serial: 7,
  policy_hash: "sha256:pending", signer_key_id: "policy-1",
  activation_mode: "enforce", rollback_authorization_id: null
};
const results = [];
let testChain = Promise.resolve();

function test(name, fn) {
  testChain = testChain.then(async () => {
    try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
    catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
  });
}

function signedBundleReceipt() {
  const first = buildPolicyReceipt(request, policy);
  return buildPolicyReceipt(request, policy, {
    policyBundleProvenance: { ...provenance, policy_hash: first.policy_hash }
  });
}

console.log("MNDe Signed Policy Bundle provenance gates\n");

test("valid bundle provenance appears in a signed policy receipt", async () => {
  const receipt = signedBundleReceipt();
  assert.deepEqual(receipt.policy_bundle_provenance, { ...provenance, policy_hash: receipt.policy_hash });
  assert.equal((await verifyPolicyReceipt(receipt)).verified, true);
});

test("replay preserves signed bundle provenance", async () => {
  const receipt = signedBundleReceipt();
  const result = await verifyPolicyReceipt(receipt);
  assert.equal(result.verified, true, result.reason);
  assert.deepEqual(result.policy_bundle_provenance, receipt.policy_bundle_provenance);
});

test("tampering bundle serial fails offline verification", async () => {
  const receipt = signedBundleReceipt();
  receipt.policy_bundle_provenance.serial = 8;
  assert.equal((await verifyPolicyReceipt(receipt)).verified, false);
});

test("tampering bundle id fails offline verification", async () => {
  const receipt = signedBundleReceipt();
  receipt.policy_bundle_provenance.bundle_id = "attacker-bundle";
  assert.equal((await verifyPolicyReceipt(receipt)).verified, false);
});

test("provenance policy hash must match the replayed policy", async () => {
  const receipt = signedBundleReceipt();
  receipt.policy_bundle_provenance.policy_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
  assert.equal((await verifyPolicyReceipt(receipt)).verified, false);
});

test("legacy policy receipts remain unchanged", async () => {
  const receipt = buildPolicyReceipt(request, policy);
  assert.equal("policy_bundle_provenance" in receipt, false);
  assert.equal((await verifyPolicyReceipt(receipt)).verified, true);
});

await testChain;
const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL policy bundle provenance gates (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS policy bundle provenance gates (${results.length}/${results.length})`);
