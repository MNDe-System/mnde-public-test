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

import { verifyExecutorCredential } from "../../../src/custody/executor-credential.mjs";
import { evaluateRevocation, findBundleKey } from "../../../src/custody/bundle.mjs";
import { createHash } from "node:crypto";
import { verifyAnyReceiptObject } from "../../../tools/verify.mjs";
import { SIGNED_RECEIPT_SCHEMA } from "../../../src/authority-signing/index.mjs";
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

  let subject, executionId, action, params, grantId;
  if (er) {
    const tc = Array.isArray(er.tool_calls) && er.tool_calls.length === 1 ? er.tool_calls[0] : null;
    subject = typeof er.actor?.user_id === "string" ? er.actor.user_id : null;
    executionId = er.request_id ?? er.release_request?.execution_id ?? null;
    action = typeof tc?.tool === "string" ? tc.tool : null;
    params = tc && typeof tc.parameters === "object" && tc.parameters !== null ? tc.parameters : {};
    grantId = er.grant_id ?? er.release_request?.grant_id ?? null;
  } else {
    subject = typeof cr.principal?.id === "string" ? cr.principal.id : null;
    executionId = cr.request_id ?? null;
    action = typeof cr.tool?.tool_name === "string" ? cr.tool.tool_name : (typeof cr.tool === "string" ? cr.tool : null);
    params = cr.parameters && typeof cr.parameters === "object" ? cr.parameters : {};
    grantId = cr.grant_id ?? null;
  }
  return {
    subject,
    executionId,
    expires_at: cr.expires_at ?? er?.expires_at ?? null,
    grant_id: grantId ?? null,        // grant/nonce identity where present (signed)
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

function brandedDeclaration({ provenance, verifiedAt, signedCanonicalDigest, aPlus, trust, receiptRef, receiptHash = null, freshness = null, production = false }) {
  const decl = deepFreeze({
    ok: true,
    provenance,
    verifiedAt,
    signedCanonicalDigest,
    aplusDigest: sha256hex(canonicalizeJson(aPlus)),
    declaration: aPlus,
    receiptRef,
    receiptHash,
    trust,
    freshness
  });
  VERIFIED.add(decl);
  if (production) PRODUCTION_VERIFIED.add(decl);
  return decl;
}

// PRODUCTION-FACING. The exact-action execution authority path.
//
// The Stage 2 design requires an EXECUTOR-BOUND `mnde.signed-receipt.v2` envelope
// (mirroring the Stage 1 executor's requireExecutor gate). A policy decision that
// is merely authentic is NOT execution authority: it lacks the executor binding.
// So the production marker is minted ONLY when the real verifier returns a
// custody-signed, executor-and-authority-verified result for a v2 envelope.
//
// trustedConfig MUST carry the out-of-band trust anchors the verifier needs:
// { authorityBundle, trustedRootFingerprint, environmentId, expectedExecutorId,
//   requireExecutor: true }. The trusted key comes from the caller's configured
// bundle+fingerprint, never from the receipt itself.
//
// IMPORTANT: verification proves the approval is AUTHENTIC and executor-bound. It
// does NOT prove the execution id was durably claimed/consumed — that is a
// separate property (F-001/F-002) the verifier deliberately never touches. The
// returned declaration records this limit and never claims single-use.
export async function verifyDeclaration(envelope, trustedConfig = {}) {
  if (!envelope || typeof envelope !== "object") {
    return Object.freeze({ ok: false, reason: "ERR_NO_ENVELOPE" });
  }
  // Copy BEFORE the first await: both verification and extraction use this snapshot.
  try {
    envelope = deepFreeze(structuredClone(envelope));
    trustedConfig = deepFreeze(structuredClone(trustedConfig));
  } catch { return Object.freeze({ ok: false, reason: "ERR_INVALID_SNAPSHOT" }); }
  if (!trustedConfig || typeof trustedConfig !== "object" || Array.isArray(trustedConfig)
      || (Object.hasOwn(trustedConfig, "namespace") && (typeof trustedConfig.namespace !== "string" || !trustedConfig.namespace))
      || (Object.hasOwn(trustedConfig, "revokedGrantIds") && (!Array.isArray(trustedConfig.revokedGrantIds) || trustedConfig.revokedGrantIds.some(v => typeof v !== "string" || !v)))) {
    return Object.freeze({ ok: false, reason: "ERR_INVALID_CONFIG" });
  }
  // Structural gate first: only a v2 executor-bound envelope can be exact-action
  // authority. A policy-only receipt (or any other schema) is refused here before
  // it can be mistaken for execution authority.
  if (envelope.schema_version !== SIGNED_RECEIPT_SCHEMA) {
    return Object.freeze({ ok: false, reason: "ERR_NOT_EXECUTOR_BOUND", detail: `schema ${envelope.schema_version ?? "?"} is not ${SIGNED_RECEIPT_SCHEMA}` });
  }
  // The verifier MUST be asked to require the executor layer. Without an out-of-band
  // executor identity + environment the executor binding cannot verify.
  if (typeof trustedConfig.expectedExecutorId !== "string" || !trustedConfig.expectedExecutorId) {
    return Object.freeze({ ok: false, reason: "ERR_EXPECTED_EXECUTOR_REQUIRED" });
  }
  const opts = { ...trustedConfig, now: trustedConfig.now ?? new Date().toISOString(), requireExecutor: true };
  let result;
  try {
    result = await verifyAnyReceiptObject(envelope, opts);
  } catch {
    return Object.freeze({ ok: false, reason: "ERR_VERIFY_THREW" });
  }
  const executorBound = result?.verified === true
    && result?.kind === "custody-signed"
    && result?.state === "executor_and_authority_verified";
  if (!executorBound) {
    const reason = result?.verified === true ? "ERR_NOT_EXECUTOR_BOUND" : "ERR_RECEIPT_UNVERIFIED";
    return Object.freeze({ ok: false, reason, detail: result?.reason ?? result?.state ?? null });
  }
  if (result.decision !== "ALLOW") return Object.freeze({ ok: false, reason: "ERR_NOT_ALLOW" });
  // Historical authenticity alone does not grant current execution authority.
  const current = await verifyExecutorCredential(envelope.executor.credential, {
    ...opts, requiredCapability: "sign_execution_receipt"
  });
  if (!current.ok) return Object.freeze({ ok: false, reason: current.code });
  const receiptKey = findBundleKey(opts.authorityBundle, "receipt", envelope.custody_attestation.signing_key_id, opts.now, opts.now);
  const keyIds = [envelope.executor.credential.key_id, opts.authorityBundle.root_key.key_id];
  if (!receiptKey.ok || receiptKey.revoked_now || keyIds.some(key_id =>
    evaluateRevocation(opts.authorityBundle.revocation, { key_id }, opts.now, opts.now).revoked_now)) {
    return Object.freeze({ ok: false, reason: "ERR_CURRENT_KEY_UNTRUSTED" });
  }
  // Snapshot + freeze the authenticated values BEFORE returning, so later mutation
  // of the caller's envelope cannot change what we authorized.
  const aPlus = deepFreeze(structuredClone(extractAPlus(envelope)));
  const cr = typeof envelope.receipt.canonical_request === "string" ? JSON.parse(envelope.receipt.canonical_request) : envelope.receipt.canonical_request;
  const er = cr.execution_request;
  const identityFields = er
    ? [cr.request_id, er.request_id, er.release_request?.execution_id, envelope.receipt.decision_output?.execution_id].filter(v => v !== undefined)
    : [cr.request_id, envelope.receipt.decision_output?.execution_id].filter(v => v !== undefined);
  const grants = er ? [cr.grant_id, er.grant_id, er.release_request?.grant_id].filter(v => v !== undefined) : [cr.grant_id];
  if (!identityFields.length || identityFields.some(v => typeof v !== "string" || !v || v !== aPlus.executionId)
      || !grants.length || grants.some(v => typeof v !== "string" || !v || v !== aPlus.grant_id)
      || typeof aPlus.subject !== "string" || !aPlus.subject) {
    return Object.freeze({ ok: false, reason: "ERR_AUTHORITY_IDENTITY" });
  }
  if ((Object.hasOwn(cr, "expires_at") || (er && Object.hasOwn(er, "expires_at"))) && (typeof aPlus.expires_at !== "string" || !Number.isFinite(Date.parse(aPlus.expires_at)) || Date.parse(opts.now) >= Date.parse(aPlus.expires_at))) {
    return Object.freeze({ ok: false, reason: "ERR_AUTHORITY_EXPIRED" });
  }
  if (trustedConfig.revokedGrantIds?.includes(aPlus.grant_id)) return Object.freeze({ ok: false, reason: "ERR_GRANT_REVOKED" });
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
    receiptHash: envelope.custody_attestation?.receipt_hash ?? null,   // signed inner-receipt hash
    trust: { namespace: trustedConfig.namespace ?? null, valid_until: envelope.executor.credential.expires_at, source: result.trust_source ?? result.kind ?? null, key_id: result.custody?.key_id ?? null, executor_id: result.executor_id ?? null },
    // Consumption is NOT established by verification. Never treat this as single-use.
    freshness: { durably_consumed: false, basis: "NOT_ESTABLISHED_BY_VERIFICATION", note: "authenticity + executor binding only; durable single-use is F-001/F-002, unproven here" },
    production: true      // executor-bound v2 verified → production brand
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
