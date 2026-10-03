// Cryptographic authority chain tests for the policy engine.
//
//   npm run test:policy-trust
//
// Proves that when trust anchors are supplied, a policy must be signed by a
// trusted policy key and an authority grant must be signed by a trusted
// authority key — with distinct fail-closed reason codes — and that a verifier
// with the wrong anchors rejects the receipt. No external services.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "./support/bootstrap_dev_receipt_keys.mjs";
import { evaluatePolicyRequest } from "../src/policy-engine/index.mjs";
import { signPolicy, signAuthorityGrant } from "../src/policy-engine/trust.mjs";
import { buildPolicyReceipt, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
bootstrapReceiptKeys({ repoRoot });

const results = [];
let testChain = Promise.resolve();
function test(name, fn) {
  testChain = testChain.then(async () => {
    try {
      await fn();
      results.push(true);
      console.log(`  [PASS] ${name}`);
    } catch (error) {
      results.push(false);
      console.log(`  [FAIL] ${name}: ${error.message}`);
    }
  });
}

function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { pub: publicKey.export({ type: "spki", format: "pem" }), priv: privateKey.export({ type: "pkcs8", format: "pem" }) };
}

const policyKey = keypair();
const authorityKey = keypair();
const attackerKey = keypair();
const NOW = "2026-06-14T00:00:00.000Z";

const trustAnchors = {
  policy_keys: [{ key_id: "policy-key-1", public_key: policyKey.pub }],
  authority_keys: [{ key_id: "authority-key-1", public_key: authorityKey.pub }]
};

function request(toolName = "deploy") {
  return {
    schema_version: "1.0", request_id: "req-1", timestamp: NOW,
    principal: { id: "alice" }, agent: { id: "agent-1" }, tool: { tool_name: toolName },
    parameters: {}, environment: {}, context: {}
  };
}
function basePolicy() {
  return {
    schema_version: "1.0", policy_id: "pol-1", version: "1", state: "ACTIVE",
    rules: [{ rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "deploy" }, authority_required: ["grant-deploy"] }]
  };
}
function grant(overrides = {}) {
  return { authority_id: "grant-deploy", valid_from: "2026-01-01T00:00:00.000Z", valid_until: "2026-12-31T00:00:00.000Z", ...overrides };
}

test("unsigned policy is refused when trust anchors are required", () => {
  const d = evaluatePolicyRequest(request(), basePolicy(), { trustAnchors, now: NOW, authorities: [] });
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "POLICY_UNSIGNED");
});

test("policy signed by an untrusted key is refused", () => {
  const policy = signPolicy(basePolicy(), { keyId: "policy-key-1", privateKeyPem: attackerKey.priv });
  const d = evaluatePolicyRequest(request(), policy, { trustAnchors, now: NOW, authorities: [] });
  assert.equal(d.reason_code, "POLICY_SIGNATURE_INVALID");
});

test("ALLOW requires a validly signed authority grant from a trusted issuer", () => {
  const policy = signPolicy(basePolicy(), { keyId: "policy-key-1", privateKeyPem: policyKey.priv });
  const signedGrant = signAuthorityGrant(grant(), { keyId: "authority-key-1", privateKeyPem: authorityKey.priv });
  const d = evaluatePolicyRequest(request(), policy, { trustAnchors, now: NOW, authorities: [signedGrant] });
  assert.equal(d.decision, "ALLOW");
  assert.equal(d.reason_code, "OK_ALLOW");
});

test("a forged authority grant is rejected with AUTHORITY_SIGNATURE_INVALID", () => {
  const policy = signPolicy(basePolicy(), { keyId: "policy-key-1", privateKeyPem: policyKey.priv });
  const forged = signAuthorityGrant(grant(), { keyId: "authority-key-1", privateKeyPem: attackerKey.priv }); // wrong key
  const d = evaluatePolicyRequest(request(), policy, { trustAnchors, now: NOW, authorities: [forged] });
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "AUTHORITY_SIGNATURE_INVALID");
});

test("a grant from an unknown issuer is rejected as untrusted", () => {
  const policy = signPolicy(basePolicy(), { keyId: "policy-key-1", privateKeyPem: policyKey.priv });
  const wrongIssuer = signAuthorityGrant(grant(), { keyId: "unknown-key", privateKeyPem: authorityKey.priv });
  const d = evaluatePolicyRequest(request(), policy, { trustAnchors, now: NOW, authorities: [wrongIssuer] });
  assert.equal(d.reason_code, "AUTHORITY_UNTRUSTED_ISSUER");
});

test("trust-enforced receipt round-trips with matching trust anchors", async () => {
  const policy = signPolicy(basePolicy(), { keyId: "policy-key-1", privateKeyPem: policyKey.priv });
  const signedGrant = signAuthorityGrant(grant(), { keyId: "authority-key-1", privateKeyPem: authorityKey.priv });
  const receipt = buildPolicyReceipt(request(), policy, { authorities: [signedGrant], trustAnchors, now: NOW });
  assert.equal(receipt.trust_enforced, true);
  assert.equal(receipt.decision_output.decision, "ALLOW");
  assert.equal((await verifyPolicyReceipt(receipt, { trustAnchors })).verified, true);
});

test("a verifier with the WRONG trust anchors does not accept the receipt", async () => {
  const policy = signPolicy(basePolicy(), { keyId: "policy-key-1", privateKeyPem: policyKey.priv });
  const signedGrant = signAuthorityGrant(grant(), { keyId: "authority-key-1", privateKeyPem: authorityKey.priv });
  const receipt = buildPolicyReceipt(request(), policy, { authorities: [signedGrant], trustAnchors, now: NOW });
  const wrongAnchors = { policy_keys: [{ key_id: "policy-key-1", public_key: attackerKey.pub }], authority_keys: [] };
  assert.equal((await verifyPolicyReceipt(receipt, { trustAnchors: wrongAnchors })).verified, false);
});

test("a trust-enforced receipt cannot be verified without trust anchors", async () => {
  const policy = signPolicy(basePolicy(), { keyId: "policy-key-1", privateKeyPem: policyKey.priv });
  const signedGrant = signAuthorityGrant(grant(), { keyId: "authority-key-1", privateKeyPem: authorityKey.priv });
  const receipt = buildPolicyReceipt(request(), policy, { authorities: [signedGrant], trustAnchors, now: NOW });
  assert.equal((await verifyPolicyReceipt(receipt)).verified, false);
});

await testChain;
const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL policy-trust tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS policy-trust tests (${results.length}/${results.length})`);
