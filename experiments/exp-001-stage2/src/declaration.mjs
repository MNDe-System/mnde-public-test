// EXP-001 Stage 2 — verified declaration (A⁺) handling.
//
// A "verified declaration" is the ONLY thing Unit 1 will build a request from.
// It is produced in one of two ways:
//
//   verifyDeclaration(envelope, trustedConfig)   PRODUCTION-FACING. Runs the real
//       MNDe receipt verifier (tools/verify.mjs → verifyAnyReceiptObject). Fails
//       closed unless the receipt actually verifies. This is the path a real
//       deployment uses.
//
//   testOnlyVerifiedDeclaration(aPlus)           TEST-ONLY, clearly labelled. Mints
//       a branded declaration WITHOUT real crypto so the offline wiring units can
//       be exercised without a running sidecar. Its provenance is
//       "TEST_ONLY_UNVERIFIED"; it can NEVER yield a live PASS downstream.
//
// A plain object with `verified:true` is NOT accepted anywhere: acceptance is
// gated by membership in a module-private WeakSet that only the two minters above
// can populate.
//
// A⁺ field names follow the corrected Stage 2 design. expected_target_sha is
// carried through the declaration and evidence, but is NEVER placed in the merge
// request body — the PR merge endpoint does not enforce it (target/base binding
// is UNRESOLVED).

import { createHash } from "node:crypto";
import { verifyAnyReceiptObject } from "../../../tools/verify.mjs";
import { canonicalizeJson } from "../../../shared/json.ts";

// Two module-private brands, neither exported.
//   VERIFIED            — wiring brand: set by BOTH verifyDeclaration and the
//                         labelled test-only fixture. Gates the pure builder
//                         (Unit 1), which is a construction unit, not an
//                         authorization boundary.
//   PRODUCTION_VERIFIED — set ONLY by verifyDeclaration after the REAL verifier
//                         returned verified:true. This is the authorization
//                         boundary the adapter (dispatch) requires. The test-only
//                         fixture can never enter this set, so a JS brand or a
//                         {verified:true} field alone cannot authorize a dispatch.
const VERIFIED = new WeakSet();
const PRODUCTION_VERIFIED = new WeakSet();

export const EXPECTED_MERGE_ACTION = "github.pull_request.merge";
export const ALLOWED_PARAM_KEYS = Object.freeze([
  "repository", "pull_request", "expected_source_sha",
  "target_ref", "expected_target_sha", "merge_method"
]);

function sha256hex(text) {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const v of Object.values(value)) deepFreeze(v);
    Object.freeze(value);
  }
  return value;
}

// Pull A⁺ out of the AUTHENTICATED canonical_request (its hash is what the
// receipt signs, so once the receipt verifies these values are trustworthy).
// Handles both engine shapes: the legacy `execution_request.tool_calls` form and
// the policy-engine flat `{ tool, parameters, principal }` form.
function extractAPlus(envelope) {
  const inner = envelope?.receipt && typeof envelope.receipt === "object" ? envelope.receipt : envelope;
  let cr = inner?.canonical_request;
  if (typeof cr === "string") { try { cr = JSON.parse(cr); } catch { cr = null; } }
  cr = cr && typeof cr === "object" ? cr : {};
  const er = cr.execution_request && typeof cr.execution_request === "object" ? cr.execution_request : null;

  let subject, executionId, action, params;
  if (er) {
    const tc = Array.isArray(er.tool_calls) && er.tool_calls.length === 1 ? er.tool_calls[0] : null;
    subject = typeof er.actor?.user_id === "string" ? er.actor.user_id : null;
    executionId = er.request_id ?? er.release_request?.execution_id ?? null;
    action = typeof tc?.tool === "string" ? tc.tool : null;
    params = tc && typeof tc.parameters === "object" && tc.parameters !== null ? tc.parameters : {};
  } else {
    subject = typeof cr.principal?.id === "string" ? cr.principal.id : null;
    executionId = cr.request_id ?? null;
    action = typeof cr.tool?.tool_name === "string" ? cr.tool.tool_name : (typeof cr.tool === "string" ? cr.tool : null);
    params = cr.parameters && typeof cr.parameters === "object" ? cr.parameters : {};
  }
  return {
    subject,
    executionId,
    action,
    repository: params.repository ?? null,
    pull_request: params.pull_request ?? null,
    expected_source_sha: params.expected_source_sha ?? null,
    target_ref: params.target_ref ?? null,
    expected_target_sha: params.expected_target_sha ?? null,     // carried, NOT enforced by merge
    merge_method: params.merge_method ?? null,
    parameterKeys: Object.keys(params).sort(),
    policy: {
      hash: inner?.decision_output?.policy_hash ?? null,
      version: inner?.decision_output?.policy_version ?? null
    },
    receiptRef: {
      schema: envelope?.schema_version ?? inner?.schema_version ?? null,
      request_hash: inner?.request_hash ?? null
    }
  };
}

function brandedDeclaration({ provenance, verifiedAt, signedCanonicalDigest, aPlus, trust, receiptRef, production = false }) {
  const decl = deepFreeze({
    ok: true,
    provenance,
    verifiedAt,
    signedCanonicalDigest,
    declaration: aPlus,
    receiptRef,
    trust
  });
  VERIFIED.add(decl);
  if (production) PRODUCTION_VERIFIED.add(decl);
  return decl;
}

// PRODUCTION-FACING. Real verification, fail closed.
export async function verifyDeclaration(envelope, trustedConfig = {}) {
  if (!envelope || typeof envelope !== "object") {
    return Object.freeze({ ok: false, reason: "ERR_NO_ENVELOPE" });
  }
  let result;
  try {
    result = await verifyAnyReceiptObject(envelope, trustedConfig);
  } catch {
    return Object.freeze({ ok: false, reason: "ERR_VERIFY_THREW" });
  }
  if (result?.verified !== true) {
    return Object.freeze({ ok: false, reason: "ERR_RECEIPT_UNVERIFIED", detail: result?.reason ?? null });
  }
  // Snapshot + freeze the authenticated values BEFORE returning, so later mutation
  // of the caller's envelope cannot change what we authorized.
  const aPlus = deepFreeze(structuredClone(extractAPlus(envelope)));
  let signedCanonicalDigest = null;
  try {
    const inner = envelope.receipt ?? envelope;
    const cr = typeof inner.canonical_request === "string" ? JSON.parse(inner.canonical_request) : inner.canonical_request;
    signedCanonicalDigest = sha256hex(canonicalizeJson(cr));
  } catch { /* leave null */ }
  return brandedDeclaration({
    provenance: "VERIFIED",
    verifiedAt: new Date().toISOString(),
    signedCanonicalDigest,
    aPlus,
    receiptRef: aPlus.receiptRef,
    trust: { source: result.trust_source ?? result.kind ?? null, key_id: result.custody?.key_id ?? null },
    production: true      // only the REAL verifier reaches here → production brand
  });
}

// TEST-ONLY. Does NOT verify crypto. Provenance marks it unverified so it can
// exercise wiring but never satisfies the live-PASS provenance gate.
export function testOnlyVerifiedDeclaration(aPlus) {
  const frozen = deepFreeze(structuredClone(aPlus));
  return brandedDeclaration({
    provenance: "TEST_ONLY_UNVERIFIED",
    verifiedAt: new Date().toISOString(),
    signedCanonicalDigest: sha256hex(canonicalizeJson(frozen)),
    aPlus: frozen,
    receiptRef: frozen.receiptRef ?? null,
    trust: { source: "TEST_ONLY", key_id: null }
  });
}

// Wiring brand — used by the pure request builder (Unit 1). NOT sufficient to
// authorize a dispatch.
export function isVerifiedDeclaration(value) {
  return VERIFIED.has(value);
}

// Authorization boundary — true ONLY for a declaration minted by verifyDeclaration
// after real receipt verification. The adapter (dispatch) requires this; the
// test-only fixture can never satisfy it.
export function isProductionVerified(value) {
  return PRODUCTION_VERIFIED.has(value);
}

// Convenience for tests/fixtures: assemble a well-formed A⁺.
export function makeAPlus(overrides = {}) {
  return {
    subject: "EXP001S2-SUBJECT",
    executionId: "EXP001S2-EXEC-1",
    action: EXPECTED_MERGE_ACTION,
    repository: { owner: "mnde-labs", repo: "exp-001" },
    pull_request: 17,
    expected_source_sha: "a".repeat(40),
    target_ref: "main",
    expected_target_sha: "b".repeat(40),
    merge_method: "merge",
    parameterKeys: ["expected_source_sha", "expected_target_sha", "merge_method", "pull_request", "repository", "target_ref"],
    policy: { hash: "ph-s2", version: "s2.v1" },
    receiptRef: { schema: "mnde.signed-receipt.v2", request_hash: "rh-s2" },
    ...overrides
  };
}
