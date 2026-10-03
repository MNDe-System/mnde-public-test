#!/usr/bin/env node
// Historical signed-policy-bundle verification gates.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "./support/bootstrap_dev_receipt_keys.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { buildPolicyReceipt, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { activateSignedPolicyBundle, signPolicyBundle, signRollbackAuthorization } from "../src/policy-bundles/index.mjs";
import { verifyAnyReceiptObject } from "../tools/verify.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
bootstrapReceiptKeys({ repoRoot });

const NOW = "2026-06-23T12:00:00.000Z";
const LATER = "2026-06-24T12:00:00.000Z";
const results = [];
let testChain = Promise.resolve();

function test(name, fn) {
  testChain = testChain.then(async () => {
    try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
    catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
  });
}

function policy(version) {
  return {
    schema_version: "1.0", policy_id: "ops-policy", version, state: "ACTIVE",
    rules: [{ rule_id: "allow-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }]
  };
}

function request() {
  return {
    schema_version: "1.0", request_id: "history-1", timestamp: NOW,
    principal: { id: "operator" }, agent: { id: "agent" }, tool: { tool_name: "read_status" },
    parameters: {}, environment: {}, context: {}
  };
}

async function fixture() {
  const root = { keyId: "root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const approvalKey = { keyId: "approval-1", ...generateAuthorityKeyPair() };
  const authorityBundle = await buildAuthorityBundle({
    authorityId: "history-authority", issuedAt: "2026-01-01T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z", root,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    approvalKeys: [{ keyId: approvalKey.keyId, publicPem: approvalKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const dir = mkdtempSync(join(tmpdir(), "mnde-history-bundle-"));
  return { policyKey, approvalKey, authorityBundle, statePath: join(dir, "state.json"), dir };
}

async function bundle(f, serial, version, extra = {}) {
  return await signPolicyBundle({
    bundle_id: `ops-${serial}-${version}`, policy_id: "ops-policy", serial, issued_at: NOW,
    policy_document: policy(version), ...extra
  }, { keyId: f.policyKey.keyId, privateKeyPem: f.policyKey.privatePem });
}

async function activate(f, signed) {
  return await activateSignedPolicyBundle({
    bundle: signed, authorityBundle: f.authorityBundle,
    trustedRootFingerprint: f.authorityBundle.root_key.fingerprint,
    statePath: f.statePath, now: NOW
  });
}

function historicalOptions(f, signed) {
  return {
    historicalPolicyBundle: signed,
    policyAuthorityBundle: f.authorityBundle,
    policyTrustedRootFingerprint: f.authorityBundle.root_key.fingerprint
  };
}

async function receiptFor(f, signed) {
  const activation = await activate(f, signed);
  assert.equal(activation.ok, true, activation.reason);
  return buildPolicyReceipt(request(), activation.policy, { policyBundleProvenance: activation.policyBundleProvenance });
}

console.log("MNDe historical policy bundle verification\n");

test("historical signed bundle verifies policy receipt provenance", async () => {
  const f = await fixture();
  try {
    const signed = await bundle(f, 7, "7.0.0");
    const receipt = await receiptFor(f, signed);
    assert.equal((await verifyPolicyReceipt(receipt, historicalOptions(f, signed))).verified, true);
    assert.equal((await verifyAnyReceiptObject(receipt, historicalOptions(f, signed))).verified, true);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("a different historical bundle fails provenance verification", async () => {
  const f = await fixture();
  try {
    const signed = await bundle(f, 7, "7.0.0");
    const receipt = await receiptFor(f, signed);
    const wrong = await bundle(f, 8, "8.0.0");
    assert.equal((await verifyPolicyReceipt(receipt, historicalOptions(f, wrong))).verified, false);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("same serial with a different signed bundle fails provenance verification", async () => {
  const f = await fixture();
  try {
    const signed = await bundle(f, 7, "7.0.0");
    const receipt = await receiptFor(f, signed);
    const collision = await bundle(f, 7, "7.0.1");
    assert.equal((await verifyPolicyReceipt(receipt, historicalOptions(f, collision))).verified, false);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("a historical bundle with a tampered signature fails closed", async () => {
  const f = await fixture();
  try {
    const signed = await bundle(f, 7, "7.0.0");
    const receipt = await receiptFor(f, signed);
    const tampered = structuredClone(signed);
    tampered.signature.value = tampered.signature.value.replace(/.$/, tampered.signature.value.endsWith("0") ? "1" : "0");
    assert.equal((await verifyPolicyReceipt(receipt, historicalOptions(f, tampered))).verified, false);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("no historical bundle preserves current offline verification behavior", async () => {
  const f = await fixture();
  try {
    const signed = await bundle(f, 7, "7.0.0");
    const receipt = await receiptFor(f, signed);
    assert.equal((await verifyPolicyReceipt(receipt)).verified, true);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("rollback provenance verifies against its signed rollback authorization", async () => {
  const f = await fixture();
  try {
    const accepted = await activate(f, await bundle(f, 7, "7.0.0"));
    assert.equal(accepted.ok, true);
    const rollback = await signRollbackAuthorization({
      authorization_id: "rollback-7-to-6", policy_id: "ops-policy", from_serial: 7, to_serial: 6,
      issued_at: NOW, expires_at: LATER
    }, { keyId: f.approvalKey.keyId, privateKeyPem: f.approvalKey.privatePem });
    const signed = await bundle(f, 6, "6.0.0", { allow_rollback: true });
    const rollbackBundle = { ...signed, rollback_authorization: rollback };
    const receipt = await receiptFor(f, rollbackBundle);
    assert.equal(receipt.policy_bundle_provenance.rollback_authorization_id, "rollback-7-to-6");
    assert.equal((await verifyPolicyReceipt(receipt, historicalOptions(f, rollbackBundle))).verified, true);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("unified offline CLI accepts optional historical bundle inputs", async () => {
  const f = await fixture();
  try {
    const signed = await bundle(f, 7, "7.0.0");
    const receipt = await receiptFor(f, signed);
    const receiptPath = join(f.dir, "receipt.json");
    const policyBundlePath = join(f.dir, "policy-bundle.json");
    const authorityBundlePath = join(f.dir, "authority-bundle.json");
    writeFileSync(receiptPath, JSON.stringify(receipt));
    writeFileSync(policyBundlePath, JSON.stringify(signed));
    writeFileSync(authorityBundlePath, JSON.stringify(f.authorityBundle));
    const run = spawnSync(process.execPath, [
      "tools/verify.mjs", receiptPath,
      "--policy-bundle", policyBundlePath,
      "--policy-authority-bundle", authorityBundlePath,
      "--policy-root-fingerprint", f.authorityBundle.root_key.fingerprint
    ], { cwd: repoRoot, encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr || run.stdout);
    assert.match(run.stdout, /FINAL VERDICT: VERIFIED/);
  } finally { rmSync(f.dir, { recursive: true, force: true }); }
});

await testChain;
const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL historical policy bundle verification (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS historical policy bundle verification (${results.length}/${results.length})`);
