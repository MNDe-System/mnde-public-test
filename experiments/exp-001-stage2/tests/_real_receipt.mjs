// TEST HELPER (not production). Mints GENUINELY verifiable MNDe receipts from an
// in-memory / temp-file ephemeral authority and runs them through the REAL
// production verifier.
//
// Two artifacts:
//   makeRealSignedReceipt          → a POLICY-ENGINE receipt (authentic decision,
//                                     but NOT executor-bound). Used to prove a
//                                     policy-only receipt cannot gain execution
//                                     authority.
//   makeRealExecutorBoundReceipt   → an `mnde.signed-receipt.v2` EXECUTOR-bound
//                                     envelope (the exact-action execution
//                                     authority the Stage 2 design requires),
//                                     verifiable with requireExecutor:true.
//
// Private keys used for the v2 attestation are written to an OS temp dir OUTSIDE
// the repository and deleted immediately after signing (verification needs only
// the public bundle). The root/receipt/executor keys otherwise live in memory.

import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalizeJson } from "../../../shared/json.ts";
import { RECEIPT_SIGNATURE_ALGORITHM } from "../../../shared/index.ts";
import { buildAuthorityBundle, fingerprintOf, generateAuthorityKeyPair, signCanonical } from "../../../src/custody/index.mjs";
import { issueExecutorCredential } from "../../../src/custody/executor-credential.mjs";
import { evaluatePolicyRequest } from "../../../src/policy-engine/index.mjs";
import { loadSigningConfig, signReceiptForDelivery, LIVE_RECEIPT_SIGNING_MODES } from "../../../src/authority-signing/index.mjs";
import { verifyDeclaration } from "../src/declaration.mjs";

const SIGNED_AT = "2026-06-25T00:00:00.000Z";
const ENVIRONMENT_ID = "prod";
export const TEST_EXECUTOR_ID = "mnde:local:prod:executor:exp001s2:01";

const DEFAULT_PARAMS = () => ({
  repository: { owner: "mnde-labs", repo: "exp-001" },
  pull_request: 17,
  expected_source_sha: "a".repeat(40),
  target_ref: "main",
  expected_target_sha: "b".repeat(40),
  merge_method: "merge"
});

function policyRequest({ subject = "EXP001S2-SUBJECT", executionId = "EXP001S2-EXEC-1", action = "github.pull_request.merge", parameters }) {
  return {
    schema_version: "1.0", request_id: executionId, timestamp: SIGNED_AT,
    principal: { id: subject }, agent: { id: "agent-1" },
    tool: { tool_name: action }, parameters: parameters ?? DEFAULT_PARAMS(),
    environment: { region: "us-west-2" }, context: {}
  };
}
function allowPolicy(action) {
  return { schema_version: "1.0", policy_id: "pol-s2", version: "1", state: "ACTIVE",
    rules: [{ rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: action } }] };
}

// Build an authority bundle + a signed inner policy receipt under that authority.
async function buildAuthorityAndInner(over) {
  const authorityId = over.authorityId ?? "mnde-exp001s2-authority";
  const root = { keyId: `${authorityId}-root`, ...generateAuthorityKeyPair() };
  const receiptKey = { keyId: `${authorityId}-receipt`, ...generateAuthorityKeyPair() };
  const authorityBundle = await buildAuthorityBundle({
    authorityId, issuedAt: SIGNED_AT, notAfter: "2027-06-25T00:00:00.000Z", root,
    receiptKeys: [{ keyId: receiptKey.keyId, publicPem: receiptKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }]
  });
  const request = policyRequest(over);
  const policy = allowPolicy(request.tool.tool_name);
  const decision = evaluatePolicyRequest(request, policy, { now: SIGNED_AT });
  const payload = {
    schema_version: "mnde.pe.receipt.v1",
    canonical_request: canonicalizeJson(request), canonical_policy: canonicalizeJson(policy),
    authorities: [], trust_enforced: false,
    request_hash: decision.request_hash, policy_hash: decision.policy_hash, authority_chain_hash: decision.authority_chain_hash,
    decision_output: decision
  };
  const inner = {
    ...payload,
    verifiable_signature: {
      algorithm: RECEIPT_SIGNATURE_ALGORITHM, authority_id: authorityBundle.authority_id, key_id: receiptKey.keyId,
      public_key_fingerprint: fingerprintOf(receiptKey.publicPem), signed_at: SIGNED_AT,
      value: await signCanonical(canonicalizeJson(payload), receiptKey.privatePem)
    }
  };
  return { authorityBundle, root, receiptKey, inner };
}

// A POLICY-ONLY receipt (authentic decision, no executor binding).
export async function makeRealSignedReceipt(over = {}) {
  const { authorityBundle, inner } = await buildAuthorityAndInner(over);
  return { receipt: inner, trustedConfig: { authorityBundle, trustedRootFingerprint: authorityBundle.root_key.fingerprint, now: SIGNED_AT } };
}

// An EXECUTOR-BOUND `mnde.signed-receipt.v2` envelope — the exact-action
// execution authority. Temp key files are removed before returning.
export async function makeRealExecutorBoundReceipt(over = {}) {
  const { authorityBundle, root, receiptKey, inner } = await buildAuthorityAndInner(over);
  const executorId = over.executorId ?? TEST_EXECUTOR_ID;
  const executorKey = generateAuthorityKeyPair();
  const credential = await issueExecutorCredential({
    authorityBundle, rootPrivatePem: root.privatePem, executorId, publicPem: executorKey.publicPem,
    environmentId: ENVIRONMENT_ID, capabilities: ["sign_execution_receipt"],
    issuedAt: SIGNED_AT, notBefore: "2026-01-01T00:00:00.000Z", expiresAt: "2027-01-01T00:00:00.000Z"
  });

  const dir = mkdtempSync(join(tmpdir(), "exp001s2-v2-"));
  let signed;
  try {
    const bundlePath = join(dir, "bundle.json"); writeFileSync(bundlePath, JSON.stringify(authorityBundle));
    const rkPath = join(dir, "receipt.key.pem"); writeFileSync(rkPath, receiptKey.privatePem);
    const cfg = await loadSigningConfig({
      MNDE_RECEIPT_SIGNING_MODE: "custody", MNDE_KEY_CUSTODY: "file-backed-production",
      MNDE_AUTHORITY_BUNDLE: bundlePath, MNDE_RECEIPT_SIGNING_KEY: rkPath, MNDE_RECEIPT_KEY_ID: receiptKey.keyId
    });
    if (!cfg.ok) throw new Error(`custody signing config failed: ${cfg.reason_code}`);
    const executorIdentity = { credential, executor_id: credential.executor_id, key_id: credential.key_id, credential_id: credential.credential_id, environment_id: credential.environment_id };
    const executorSigner = { sign: (c) => signCanonical(c, executorKey.privatePem) };
    signed = await signReceiptForDelivery(inner, cfg, { signingMode: LIVE_RECEIPT_SIGNING_MODES.EXECUTOR_AND_AUTHORITY, executorIdentity, executorSigner, now: SIGNED_AT });
  } finally {
    rmSync(dir, { recursive: true, force: true }); // remove temp key files immediately
  }
  if (!signed.ok) throw new Error(`v2 signing failed: ${signed.reason_code}`);
  return {
    receipt: signed.receipt,
    trustedConfig: { authorityBundle, trustedRootFingerprint: authorityBundle.root_key.fingerprint, environmentId: ENVIRONMENT_ID, expectedExecutorId: executorId, requireExecutor: true, now: SIGNED_AT }
  };
}

// Sign + verify a real executor-bound receipt through the production verifier,
// returning the production-verified declaration (or throwing).
export async function makeRealVerifiedDeclaration(over = {}) {
  const { receipt, trustedConfig } = await makeRealExecutorBoundReceipt(over);
  const decl = await verifyDeclaration(receipt, trustedConfig);
  if (!decl.ok) throw new Error(`expected an executor-bound receipt to verify, got: ${decl.reason} ${decl.detail ?? ""}`);
  return decl;
}
