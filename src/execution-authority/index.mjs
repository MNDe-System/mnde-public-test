// Authenticated execution authority — the action-agnostic half of a typed effect.
//
// WHAT THIS IS. A typed effect needs two different facts before it may touch the
// world, and they are produced by two different mechanisms:
//
//   1. THIS FILE: the authorization is authentic, executor-bound, current, and
//      says exactly what is about to be done. That is a signature check.
//   2. src/freshness/claim.mjs: the authority has not been spent before. That is
//      a durable write, and no signature can substitute for it (F-001).
//
// Keeping them apart is the point. A verified receipt is a signature, and a
// signature can be presented twice, so this module deliberately reports
// `freshness.durably_consumed: false` and never claims single-use.
//
// WHY IT IS SEPARATE FROM THE EFFECT. Nothing here knows what git.push is. It
// returns the authenticated action name and parameters exactly as they were
// signed; deciding whether those parameters describe a permissible push is the
// effect's job. A second typed effect reuses this file unchanged.
//
// THE AUTHORIZATION BOUNDARY IS A WeakSet, NOT A FIELD. A plain object carrying
// `{ ok: true }` is not execution authority. Acceptance downstream is gated by
// membership in a module-private WeakSet that only the real verification path
// populates, so a forged object literal — or a test fixture — can never reach a
// dispatch. This mirrors the brand discipline proven in
// experiments/exp-001-stage2/src/declaration.mjs, generalized out of that
// experiment's merge-specific parameter list.
//
// Verification is READ-ONLY and has no side effects.

import { SIGNED_RECEIPT_SCHEMA } from "../authority-signing/index.mjs";
import { REPO_LOCAL_TRUST_SOURCE } from "../../shared/authority-manifest.mjs";
import { evaluateRevocation, findBundleKey } from "../custody/bundle.mjs";
import { verifyExecutorCredential } from "../custody/executor-credential.mjs";
import { canonicalizeJson } from "../../shared/json.ts";
import { sha256 } from "../crypto/provider.mjs";
import { verifyAnyReceiptObject } from "../../tools/verify.mjs";

// The one brand that matters. Populated ONLY by verifyExecutionAuthority after
// the real verifier returned an executor-and-authority-verified result.
const PRODUCTION_VERIFIED = new WeakSet();

export const ERR_NO_ENVELOPE = "ERR_NO_ENVELOPE";
export const ERR_INVALID_SNAPSHOT = "ERR_INVALID_SNAPSHOT";
export const ERR_INVALID_CONFIG = "ERR_INVALID_CONFIG";
export const ERR_NOT_EXECUTOR_BOUND = "ERR_NOT_EXECUTOR_BOUND";
export const ERR_EXPECTED_EXECUTOR_REQUIRED = "ERR_EXPECTED_EXECUTOR_REQUIRED";
export const ERR_RECEIPT_UNVERIFIED = "ERR_RECEIPT_UNVERIFIED";
export const ERR_VERIFY_THREW = "ERR_VERIFY_THREW";
export const ERR_NOT_ALLOW = "ERR_NOT_ALLOW";
export const ERR_CURRENT_KEY_UNTRUSTED = "ERR_CURRENT_KEY_UNTRUSTED";
export const ERR_AUTHORITY_IDENTITY = "ERR_AUTHORITY_IDENTITY";
export const ERR_AUTHORITY_EXPIRED = "ERR_AUTHORITY_EXPIRED";
export const ERR_GRANT_REVOKED = "ERR_GRANT_REVOKED";
export const ERR_EXECUTOR_IDENTITY_MISMATCH = "ERR_EXECUTOR_IDENTITY_MISMATCH";
export const ERR_REPO_LOCAL_TRUST = "ERR_REPO_LOCAL_TRUST";

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const v of Object.values(value)) deepFreeze(v);
    Object.freeze(value);
  }
  return value;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function fail(reason, detail = null) {
  return Object.freeze(detail === null ? { ok: false, reason } : { ok: false, reason, detail });
}

// Pull the authenticated action out of the signed canonical_request. Once the
// receipt verifies, canonical_request is authenticated (its hash is the signed
// request_hash), so these values are trustworthy. Both engine shapes are handled:
// the legacy nested `execution_request.tool_calls` form and the policy engine's
// flat `{ tool, parameters, principal }` form.
function extractAuthenticatedAction(envelope) {
  const inner = isPlainObject(envelope?.receipt) ? envelope.receipt : envelope;
  let cr = inner?.canonical_request;
  if (typeof cr === "string") {
    try { cr = JSON.parse(cr); } catch { cr = null; }
  }
  cr = isPlainObject(cr) ? cr : {};
  const er = isPlainObject(cr.execution_request) ? cr.execution_request : null;

  let subject, executionId, action, parameters, grantId;
  if (er) {
    // Exactly one tool call, or the action is unbindable and stays null.
    const tc = Array.isArray(er.tool_calls) && er.tool_calls.length === 1 ? er.tool_calls[0] : null;
    subject = nonEmptyString(er.actor?.user_id) ? er.actor.user_id : null;
    executionId = er.request_id ?? er.release_request?.execution_id ?? null;
    action = nonEmptyString(tc?.tool) ? tc.tool : (nonEmptyString(tc?.tool?.tool_name) ? tc.tool.tool_name : null);
    parameters = isPlainObject(tc?.parameters) ? tc.parameters : {};
    grantId = er.grant_id ?? er.release_request?.grant_id ?? null;
  } else {
    subject = nonEmptyString(cr.principal?.id) ? cr.principal.id : null;
    executionId = cr.request_id ?? null;
    action = nonEmptyString(cr.tool?.tool_name) ? cr.tool.tool_name : (nonEmptyString(cr.tool) ? cr.tool : null);
    parameters = isPlainObject(cr.parameters) ? cr.parameters : {};
    grantId = cr.grant_id ?? null;
  }

  return {
    subject,
    execution_id: executionId,
    grant_id: grantId ?? null,
    expires_at: cr.expires_at ?? er?.expires_at ?? null,
    action,
    parameters,
    parameter_keys: Object.keys(parameters).sort(),
    policy: {
      hash: inner?.decision_output?.policy_hash ?? null,
      version: inner?.decision_output?.policy_version ?? null
    },
    receipt_ref: {
      schema: envelope?.schema_version ?? inner?.schema_version ?? null,
      request_hash: inner?.request_hash ?? null
    }
  };
}

// PRODUCTION-FACING. The only way to mint execution authority.
//
// `trustedConfig` carries the out-of-band trust anchors, which come from the
// operator's configured bundle and pinned fingerprint — never from the receipt:
//   { authorityBundle, trustedRootFingerprint, environmentId, expectedExecutorId,
//     namespace?, revokedGrantIds?, now? }
//
// Returns a frozen, branded authority on success, or a frozen { ok:false, reason }.
export async function verifyExecutionAuthority(envelope, trustedConfig = {}) {
  if (!isPlainObject(envelope)) return fail(ERR_NO_ENVELOPE);

  // Snapshot BEFORE the first await, so later mutation of the caller's object
  // cannot change what was authorized.
  try {
    envelope = deepFreeze(structuredClone(envelope));
    trustedConfig = deepFreeze(structuredClone(trustedConfig));
  } catch {
    return fail(ERR_INVALID_SNAPSHOT);
  }

  if (!isPlainObject(trustedConfig)
    || (Object.hasOwn(trustedConfig, "namespace") && !nonEmptyString(trustedConfig.namespace))
    || (Object.hasOwn(trustedConfig, "revokedGrantIds")
      && (!Array.isArray(trustedConfig.revokedGrantIds) || trustedConfig.revokedGrantIds.some((v) => !nonEmptyString(v))))) {
    return fail(ERR_INVALID_CONFIG);
  }

  // Structural gate first. Only an executor-bound v2 envelope can be execution
  // authority; a merely authentic policy decision is not, because it carries no
  // executor binding and so names no executor that may act on it.
  if (envelope.schema_version !== SIGNED_RECEIPT_SCHEMA) {
    return fail(ERR_NOT_EXECUTOR_BOUND, `schema ${envelope.schema_version ?? "?"} is not ${SIGNED_RECEIPT_SCHEMA}`);
  }
  if (!nonEmptyString(trustedConfig.expectedExecutorId)) {
    return fail(ERR_EXPECTED_EXECUTOR_REQUIRED);
  }

  const opts = { ...trustedConfig, now: trustedConfig.now ?? new Date().toISOString(), requireExecutor: true };

  let result;
  try {
    result = await verifyAnyReceiptObject(envelope, opts);
  } catch {
    return fail(ERR_VERIFY_THREW);
  }

  const executorBound = result?.verified === true
    && result?.kind === "custody-signed"
    && result?.state === "executor_and_authority_verified";
  if (!executorBound) {
    return fail(result?.verified === true ? ERR_NOT_EXECUTOR_BOUND : ERR_RECEIPT_UNVERIFIED,
      result?.reason ?? result?.state ?? null);
  }
  if (result.decision !== "ALLOW") return fail(ERR_NOT_ALLOW);

  // Neither layer may rest on the authority bundle that ships inside the
  // package. The outer envelope can be production-signed while the INNER policy
  // decision falls back to the demo authority — the verifier drops the
  // configured bundle for an inner receipt whose authority id is not the
  // configured one — and the whole thing still reports verified. Execution
  // authority is the last place that confusion may survive, so both layers are
  // checked. (Same rule as the executor's production posture; see #43.)
  if (result.trust_source === REPO_LOCAL_TRUST_SOURCE || result.inner?.trust_source === REPO_LOCAL_TRUST_SOURCE) {
    return fail(ERR_REPO_LOCAL_TRUST,
      "a layer of this receipt verifies only against the authority bundle shipped in the package, which is not a trust root anyone chose");
  }

  // The verifier answers "was this authentic when signed". It does not answer
  // "is the signer trusted right now", so the credential and both keys are
  // re-checked against the bundle's revocation state at `now`.
  const current = await verifyExecutorCredential(envelope.executor?.credential, {
    ...opts, requiredCapability: "sign_execution_receipt"
  });
  if (!current.ok) return fail(current.code ?? ERR_CURRENT_KEY_UNTRUSTED);

  const receiptKey = findBundleKey(opts.authorityBundle, "receipt", envelope.custody_attestation?.signing_key_id, opts.now, opts.now);
  const keyIds = [envelope.executor?.credential?.key_id, opts.authorityBundle?.root_key?.key_id];
  if (!receiptKey.ok || receiptKey.revoked_now
    || keyIds.some((key_id) => evaluateRevocation(opts.authorityBundle?.revocation, { key_id }, opts.now, opts.now).revoked_now)) {
    return fail(ERR_CURRENT_KEY_UNTRUSTED);
  }

  const authenticated = deepFreeze(structuredClone(extractAuthenticatedAction(envelope)));

  // Identity cross-check. A receipt may carry the execution id and grant id in
  // several places depending on engine; EVERY occurrence must agree, because a
  // claim keyed on one of them while dispatch is bound to another is a replay
  // waiting to happen.
  let cr = envelope.receipt?.canonical_request;
  if (typeof cr === "string") {
    try { cr = JSON.parse(cr); } catch { cr = null; }
  }
  if (!isPlainObject(cr)) return fail(ERR_AUTHORITY_IDENTITY, "canonical_request is not an object");
  const er = isPlainObject(cr.execution_request) ? cr.execution_request : null;
  const identityFields = (er
    ? [cr.request_id, er.request_id, er.release_request?.execution_id, envelope.receipt?.decision_output?.execution_id]
    : [cr.request_id, envelope.receipt?.decision_output?.execution_id]).filter((v) => v !== undefined);
  const grants = (er
    ? [cr.grant_id, er.grant_id, er.release_request?.grant_id]
    : [cr.grant_id]).filter((v) => v !== undefined);

  if (!identityFields.length || identityFields.some((v) => !nonEmptyString(v) || v !== authenticated.execution_id)
    || !grants.length || grants.some((v) => !nonEmptyString(v) || v !== authenticated.grant_id)
    || !nonEmptyString(authenticated.subject)
    || !nonEmptyString(authenticated.action)) {
    return fail(ERR_AUTHORITY_IDENTITY);
  }

  // Expiry, when the authorization declared one. A declared-but-unparseable or
  // already-passed expiry is a refusal, never an omission.
  if ((Object.hasOwn(cr, "expires_at") || (er && Object.hasOwn(er, "expires_at")))
    && (!nonEmptyString(authenticated.expires_at)
      || !Number.isFinite(Date.parse(authenticated.expires_at))
      || Date.parse(opts.now) >= Date.parse(authenticated.expires_at))) {
    return fail(ERR_AUTHORITY_EXPIRED);
  }

  if (trustedConfig.revokedGrantIds?.includes(authenticated.grant_id)) return fail(ERR_GRANT_REVOKED);

  // The executor the receipt is bound to must be the executor we are.
  const executorId = result.executor_id ?? envelope.executor?.credential?.executor_id ?? null;
  if (!nonEmptyString(executorId) || executorId !== trustedConfig.expectedExecutorId) {
    return fail(ERR_EXECUTOR_IDENTITY_MISMATCH);
  }

  const receiptHash = envelope.custody_attestation?.receipt_hash ?? null;
  if (!nonEmptyString(receiptHash)) return fail(ERR_AUTHORITY_IDENTITY, "custody attestation carries no receipt hash");

  const authority = deepFreeze({
    ok: true,
    verified_at: new Date().toISOString(),
    execution_id: authenticated.execution_id,
    grant_id: authenticated.grant_id,
    subject: authenticated.subject,
    executor_id: executorId,
    action: authenticated.action,
    parameters: authenticated.parameters,
    parameter_keys: authenticated.parameter_keys,
    expires_at: authenticated.expires_at,
    receipt_hash: receiptHash,
    // Digest of the authenticated action as a whole. This is what goes into the
    // claim record's `aplus_digest` column, so that a claim is bound to the exact
    // action that was authorized and not merely to its id.
    authority_digest: sha256(canonicalizeJson(authenticated)),
    signed_canonical_digest: sha256(canonicalizeJson(cr)),
    policy: authenticated.policy,
    receipt_ref: authenticated.receipt_ref,
    trust: {
      namespace: trustedConfig.namespace ?? null,
      source: result.trust_source ?? result.kind ?? null,
      key_id: result.custody?.key_id ?? null,
      valid_until: envelope.executor?.credential?.expires_at ?? null
    },
    // Verification establishes authenticity, never single-use. Anything that
    // reads this object and dispatches without a durable claim has reopened F-001.
    freshness: {
      durably_consumed: false,
      basis: "NOT_ESTABLISHED_BY_VERIFICATION",
      note: "authenticity + executor binding only; durable single-use is F-001 and is established by src/freshness/claim.mjs, not here"
    }
  });

  PRODUCTION_VERIFIED.add(authority);
  return authority;
}

// The authorization boundary. True ONLY for an object minted above. Every
// dispatch path must gate on this rather than on any field of the object.
export function isProductionExecutionAuthority(value) {
  return PRODUCTION_VERIFIED.has(value);
}
