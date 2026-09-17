// TEST HELPER (not production). Mints a GENUINELY verifiable MNDe policy-engine
// receipt from an in-memory, ephemeral authority, then runs it through the REAL
// production verifier (verifyDeclaration → tools/verify.mjs) to obtain a
// production-verified A⁺ declaration.
//
// Keys are generated in memory as PEM strings and are NEVER written to disk —
// nothing to clean up, nothing enters the repository. This is the offline analogue
// of "generate a real local authority bundle + valid receipt, verify with the
// real trusted verifier."

import { canonicalizeJson } from "../../../shared/json.ts";
import { RECEIPT_SIGNATURE_ALGORITHM } from "../../../shared/index.ts";
import { buildAuthorityBundle, fingerprintOf, generateAuthorityKeyPair, signCanonical } from "../../../src/custody/index.mjs";
import { evaluatePolicyRequest } from "../../../src/policy-engine/index.mjs";
import { verifyDeclaration } from "../src/declaration.mjs";

const SIGNED_AT = "2026-06-25T00:00:00.000Z";

// Build the signed policy receipt (in-memory authority). Returns { receipt,
// trustedConfig } where trustedConfig is what the real verifier needs.
export async function makeRealSignedReceipt(over = {}) {
  const subject = over.subject ?? "EXP001S2-SUBJECT";
  const executionId = over.executionId ?? "EXP001S2-EXEC-1";
  const parameters = over.parameters ?? {
    repository: { owner: "mnde-labs", repo: "exp-001" },
    pull_request: 17,
    expected_source_sha: "a".repeat(40),
    target_ref: "main",
    expected_target_sha: "b".repeat(40),
    merge_method: "merge"
  };
  const request = {
    schema_version: "1.0",
    request_id: executionId,
    timestamp: SIGNED_AT,
    principal: { id: subject },
    agent: { id: "agent-1" },
    tool: { tool_name: over.action ?? "github.pull_request.merge" },
    parameters,
    environment: { region: "us-west-2" },
    context: {}
  };
  const policy = {
    schema_version: "1.0", policy_id: "pol-s2", version: "1", state: "ACTIVE",
    rules: [{ rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: request.tool.tool_name } }]
  };

  const authorityId = over.authorityId ?? "mnde-exp001s2-authority";
  const root = { keyId: `${authorityId}-root`, ...generateAuthorityKeyPair() };
  const receiptKey = { keyId: `${authorityId}-receipt`, ...generateAuthorityKeyPair() };
  const authorityBundle = await buildAuthorityBundle({
    authorityId, issuedAt: SIGNED_AT, notAfter: "2027-06-25T00:00:00.000Z", root,
    receiptKeys: [{ keyId: receiptKey.keyId, publicPem: receiptKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }]
  });

  const decision = evaluatePolicyRequest(request, policy, { now: SIGNED_AT });
  const payload = {
    schema_version: "mnde.pe.receipt.v1",
    canonical_request: canonicalizeJson(request),
    canonical_policy: canonicalizeJson(policy),
    authorities: [], trust_enforced: false,
    request_hash: decision.request_hash,
    policy_hash: decision.policy_hash,
    authority_chain_hash: decision.authority_chain_hash,
    decision_output: decision
  };
  const receipt = {
    ...payload,
    verifiable_signature: {
      algorithm: RECEIPT_SIGNATURE_ALGORITHM,
      authority_id: authorityBundle.authority_id,
      key_id: receiptKey.keyId,
      public_key_fingerprint: fingerprintOf(receiptKey.publicPem),
      signed_at: SIGNED_AT,
      value: await signCanonical(canonicalizeJson(payload), receiptKey.privatePem)
    }
  };
  return {
    receipt,
    trustedConfig: { authorityBundle, trustedRootFingerprint: authorityBundle.root_key.fingerprint, now: SIGNED_AT }
  };
}

// Convenience: sign + verify through the real production verifier, returning the
// production-verified declaration (or throwing if verification failed).
export async function makeRealVerifiedDeclaration(over = {}) {
  const { receipt, trustedConfig } = await makeRealSignedReceipt(over);
  const decl = await verifyDeclaration(receipt, trustedConfig);
  if (!decl.ok) throw new Error(`expected a real receipt to verify, got: ${decl.reason} ${decl.detail ?? ""}`);
  return decl;
}
