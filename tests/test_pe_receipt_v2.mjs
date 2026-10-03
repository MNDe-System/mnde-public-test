#!/usr/bin/env node
// mnde.pe.receipt.v2 — versioned receipt format that binds the matched rule_id
// into decision_output AND decision_hash, while leaving the frozen v1 format
// byte-identical. These tests prove the compatibility boundary between v1 and v2:
// v1 stays exactly as frozen, v2 cryptographically binds rule_id, and the two
// verification paths never cross-accept each other's shapes.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildPolicyReceipt, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { evaluatePolicyRequest } from "../src/policy-engine/index.mjs";
import { verifyAnyReceiptFile } from "../tools/verify.mjs";
import { canonicalizeJson } from "../shared/json.ts";
import { sha256 } from "../src/crypto/provider.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const conf = join(repoRoot, "conformance", "vectors");
const NOW = "2026-06-25T00:00:00.000Z";
const load = (name) => JSON.parse(readFileSync(join(conf, name), "utf8"));

const v1Vector = load("mnde.pe.receipt.v1.allow.json");
const request = JSON.parse(v1Vector.canonical_request);
const policy = JSON.parse(v1Vector.canonical_policy);

let passed = 0;
function check(name, cond) {
  assert.equal(cond, true, name);
  console.log(`  [PASS] ${name}`);
  passed += 1;
}

// 1. The frozen v1 conformance vector still verifies unchanged, with no rule_id.
{
  const authorityBundle = load("mnde.authority.bundle.v1.json");
  const res = await verifyAnyReceiptFile(join(conf, "mnde.pe.receipt.v1.allow.json"), {
    authorityBundle,
    trustedRootFingerprint: authorityBundle.root_key.fingerprint,
    now: NOW
  });
  check("frozen v1 vector still verifies against the conformance authority", res.verified === true);
  check("frozen v1 decision_output carries no rule_id", !Object.hasOwn(v1Vector.decision_output, "rule_id"));
  check("frozen v1 decision schema_version is 1.0", v1Vector.decision_output.schema_version === "1.0");
}

// 2. v1 replay still rejects decision drift (drift check is not weakened).
{
  const receipt = buildPolicyReceipt(request, policy, { now: NOW });
  const tampered = structuredClone(receipt);
  tampered.decision_output.reason_code = "OK_ALLOW_TAMPERED";
  const res = await verifyPolicyReceipt(tampered, { now: NOW });
  check("v1 replay rejects reason_code drift", res.verified === false && /decision drift: reason_code/.test(res.reason));
}

// 3. v2 replay verifies the bound rule_id.
{
  const receipt = buildPolicyReceipt(request, policy, { now: NOW, receiptSchema: "mnde.pe.receipt.v2" });
  const res = await verifyPolicyReceipt(receipt, { now: NOW });
  check("v2 receipt verifies", res.verified === true);
  check("v2 decision_output.rule_id is the matched allow rule", receipt.decision_output.rule_id === "allow-read-status");
  check("v2 decision schema_version is 2.0", receipt.decision_output.schema_version === "2.0");
}

// 4. Tampering with v2 rule_id fails on the drift check (before signature).
{
  const receipt = buildPolicyReceipt(request, policy, { now: NOW, receiptSchema: "mnde.pe.receipt.v2" });
  const tampered = structuredClone(receipt);
  tampered.decision_output.rule_id = "allow-read-status-EVIL";
  const res = await verifyPolicyReceipt(tampered, { now: NOW });
  check("v2 tampered rule_id fails on decision drift", res.verified === false && /decision drift: rule_id/.test(res.reason));
}

// 5. Changing only rule_id changes decision_hash (rule_id is bound into material).
{
  const d1 = evaluatePolicyRequest(request, policy, { now: NOW });
  const d2 = evaluatePolicyRequest(request, policy, { now: NOW, decisionSchemaVersion: "2.0" });
  // Same request, policy, decision, reason_code, evaluated_at — the ONLY
  // difference in the hash material is the rule_id v2 binds and v1 omits.
  check(
    "v1 and v2 share every other hash input",
    d1.request_hash === d2.request_hash &&
      d1.policy_hash === d2.policy_hash &&
      d1.authority_chain_hash === d2.authority_chain_hash &&
      d1.decision === d2.decision &&
      d1.reason_code === d2.reason_code &&
      d1.evaluated_at === d2.evaluated_at
  );
  check("binding rule_id changes decision_hash", d1.decision_hash !== d2.decision_hash);
  const material = (ruleId) => canonicalizeJson({
    request_hash: d2.request_hash,
    policy_hash: d2.policy_hash,
    authority_chain_hash: d2.authority_chain_hash,
    decision: "ALLOW",
    reason_code: "OK_ALLOW",
    rule_id: ruleId,
    evaluated_at: NOW
  });
  check("distinct rule_ids produce distinct decision_hash material", sha256(material("rule-a")) !== sha256(material("rule-b")));
}

// 6. v1 and v2 verification paths do not cross-accept malformed shapes.
{
  const rV1 = buildPolicyReceipt(request, policy, { now: NOW });
  const rV2 = buildPolicyReceipt(request, policy, { now: NOW, receiptSchema: "mnde.pe.receipt.v2" });
  const v1BodyV2Header = structuredClone(rV1);
  v1BodyV2Header.schema_version = "mnde.pe.receipt.v2";
  const v2BodyV1Header = structuredClone(rV2);
  v2BodyV1Header.schema_version = "mnde.pe.receipt.v1";
  const a = await verifyPolicyReceipt(v1BodyV2Header, { now: NOW });
  const b = await verifyPolicyReceipt(v2BodyV1Header, { now: NOW });
  check("v1 decision body under a v2 header is rejected", a.verified === false && /decision schema mismatch/.test(a.reason));
  check("v2 decision body under a v1 header is rejected", b.verified === false && /decision schema mismatch/.test(b.reason));
}

// 7. Unknown/future versions fail closed on both verify and mint.
{
  const receipt = buildPolicyReceipt(request, policy, { now: NOW, receiptSchema: "mnde.pe.receipt.v2" });
  const future = structuredClone(receipt);
  future.schema_version = "mnde.pe.receipt.v3";
  const res = await verifyPolicyReceipt(future, { now: NOW });
  check("unknown future receipt version fails closed on verify", res.verified === false && res.reason === "unsupported schema");
  let threw = false;
  try {
    buildPolicyReceipt(request, policy, { now: NOW, receiptSchema: "mnde.pe.receipt.v3" });
  } catch (error) {
    threw = /ERR_UNSUPPORTED_RECEIPT_SCHEMA/.test(error?.message ?? "");
  }
  check("buildPolicyReceipt refuses to mint an unknown receipt version", threw);
}

console.log(`\nPASS pe-receipt-v2 tests (${passed}/${passed})`);
