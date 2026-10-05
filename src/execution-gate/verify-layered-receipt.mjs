// Layered receipt verification — reports the EXACT trust state of a receipt.
//
// Phase 0 / Design A. A receipt can carry up to three independently verifiable
// facts:
//
//   executor layer   — which agent instance signed (executor credential + sig)
//   authority layer  — which MNDe authority countersigned (custody receipt-role)
//   passport binding  — which subject authorized the workload (when present)
//
// The verifier checks each present layer INDEPENDENTLY and returns one exact
// state. A valid authority signature never masks an invalid executor signature,
// and a valid executor signature never masks an invalid authority signature: if
// a present layer fails, the result is verification_failed.
//
//   authority_verified                          authority only (custody)
//   executor_and_authority_verified             executor + authority
//   executor_authority_and_passport_verified    executor + authority + passport
//   legacy_verified                             shared-file (pre-custody) key
//   verification_failed                         any present layer invalid

import { canonicalizeJson } from "../../shared/json.ts";
import { verifyCanonical } from "../custody/index.mjs";
import { verifyExecutorCredential } from "../custody/executor-credential.mjs";
import { EXECUTOR_RECEIPT_CAPABILITY } from "../custody/executor-identity.mjs";
import { verifySignedExecutionReceipt } from "./verify-signed-receipt.mjs";

export const RECEIPT_VERIFICATION_STATES = Object.freeze({
  AUTHORITY: "authority_verified",
  EXECUTOR_AND_AUTHORITY: "executor_and_authority_verified",
  EXECUTOR_AUTHORITY_AND_PASSPORT: "executor_authority_and_passport_verified",
  LEGACY: "legacy_verified",
  FAILED: "verification_failed"
});

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}
function hasOwn(value, key) {
  return Object.hasOwn(value, key);
}
function isValidTimestamp(value) {
  return isNonEmptyString(value) && !Number.isNaN(Date.parse(value));
}
function isCompleteExecutorSignature(value) {
  return isObject(value) &&
    value.algorithm === "ED25519" &&
    isValidTimestamp(value.signed_at) &&
    isNonEmptyString(value.value);
}
function isCompleteAuthoritySignature(value) {
  return isObject(value) &&
    value.algorithm === "ED25519" &&
    isNonEmptyString(value.authority_id) &&
    isNonEmptyString(value.key_id) &&
    isValidTimestamp(value.signed_at) &&
    isNonEmptyString(value.public_key_fingerprint) &&
    isNonEmptyString(value.value);
}

// Body the EXECUTOR signed over: no signatures present at all.
function bodyWithoutSignatures(receipt) {
  const { verifiable_signature: _a, executor_signature: _b, ...rest } = receipt;
  return rest;
}
// Body the AUTHORITY signed over: everything except its own signature (this
// includes executor_signature when present — the authority countersigns it).
function bodyWithoutAuthoritySignature(receipt) {
  const { verifiable_signature: _a, ...rest } = receipt;
  return rest;
}

// Verify a receipt and report its exact trust state.
//
// options:
//   authorityBundle        custody bundle (for the authority layer)
//   trustedRootFingerprint out-of-band root anchor
//   environmentId          expected environment for the executor credential
//   executorCredential     the authority-signed credential for this executor
//   expectedExecutorId     optional exact executor_id to require
//   expectedPassportSubjectId optional exact passport subject to require
//   legacyPublicKeyPem     shared-file public key, for legacy_verified
//   now                    ISO-8601 verification time
export async function verifyLayeredReceipt(receipt, options = {}) {
  const {
    authorityBundle,
    trustedRootFingerprint,
    environmentId,
    executorCredential,
    expectedExecutorId,
    expectedPassportSubjectId,
    legacyPublicKeyPem,
    now = new Date().toISOString()
  } = options;

  const S = RECEIPT_VERIFICATION_STATES;
  const pass = (state, extra = {}) => ({ ok: true, state, ...extra });
  const failed = (reason, extra = {}) => ({ ok: false, state: S.FAILED, reason, ...extra });

  if (!isObject(receipt)) return failed("receipt is not an object");
  const executorFields = [
    "executor_signature",
    "executor_id",
    "executor_key_id",
    "executor_credential_id"
  ];
  const executorFieldPresent = executorFields.some((field) => hasOwn(receipt, field));
  const authorityFieldPresent = hasOwn(receipt, "verifiable_signature");
  const signingMode = receipt.signing_mode ?? (executorFieldPresent ? null : "authority_only");
  if (signingMode === null) return failed("ERR_SIGNING_MODE_MISSING");
  if (signingMode !== "authority_only" && signingMode !== "executor_and_authority") {
    return failed("ERR_SIGNING_MODE_INVALID");
  }

  const hasExecutorIdentity =
    isNonEmptyString(receipt.executor_id) &&
    isNonEmptyString(receipt.executor_key_id) &&
    isNonEmptyString(receipt.executor_credential_id);
  const hasExecutorLayer = hasExecutorIdentity && isCompleteExecutorSignature(receipt.executor_signature);
  const hasAuthoritySig = isCompleteAuthoritySignature(receipt.verifiable_signature);

  const passportPresent = isNonEmptyString(receipt.passport_subject_id);
  if (signingMode === "authority_only" && executorFieldPresent) {
    return failed("ERR_SIGNING_MODE_INVALID");
  }
  if (signingMode === "authority_only" && options.requireExecutor) {
    return failed("ERR_EXECUTOR_REQUIRED");
  }
  if (signingMode === "executor_and_authority") {
    if (!executorFieldPresent || !hasExecutorIdentity) {
      return failed("ERR_EXECUTOR_ENVELOPE_MISSING");
    }
    if (!hasOwn(receipt, "executor_signature")) {
      return failed("ERR_EXECUTOR_SIGNATURE_MISSING", { layer: "executor" });
    }
    if (!hasExecutorLayer) {
      return failed("ERR_EXECUTOR_SIGNATURE_INVALID", { layer: "executor" });
    }
  }
  if (!authorityFieldPresent) {
    return failed("ERR_AUTHORITY_SIGNATURE_MISSING", { layer: "authority" });
  }
  if (!hasAuthoritySig) {
    return failed("ERR_AUTHORITY_SIGNATURE_INVALID", { layer: "authority" });
  }

  // ── Executor layer (verified independently) ─────────────────────────────────
  let executorId;
  if (hasExecutorLayer) {
    if (executorCredential === null || executorCredential === undefined) {
      return failed("ERR_EXECUTOR_CREDENTIAL_MISSING");
    }
    const credRes = await verifyExecutorCredential(executorCredential, {
      authorityBundle,
      trustedRootFingerprint,
      environmentId,
      expectedExecutorId: expectedExecutorId ?? receipt.executor_id,
      requiredCapability: EXECUTOR_RECEIPT_CAPABILITY,
      // Credential validity is evaluated at the authenticated receipt event
      // time, not wall-clock verification time. The executor timestamp is
      // countersigned by the authority layer below.
      now: receipt.executor_signature.signed_at
    });
    if (!credRes.ok) return failed(credRes.code, { detail: credRes.detail });
    // Bind the receipt's identity fields to the verified credential.
    if (receipt.executor_id !== credRes.executor_id) return failed("ERR_EXECUTOR_IDENTITY_MISMATCH");
    if (receipt.executor_key_id !== credRes.key_id) return failed("ERR_EXECUTOR_KEY_MISMATCH");
    if (receipt.executor_credential_id !== credRes.credential_id) return failed("ERR_EXECUTOR_CREDENTIAL_INVALID");
    // Verify the executor signature over the body with no signatures present.
    const execPayload = canonicalizeJson(bodyWithoutSignatures(receipt));
    const execOk = await verifyCanonical(execPayload, receipt.executor_signature.value, credRes.public_key);
    if (!execOk) return failed("ERR_EXECUTOR_SIGNATURE_INVALID", { layer: "executor" });
    executorId = credRes.executor_id;
  }

  // ── Passport binding ────────────────────────────────────────────────────────
  // The subject is inside the signed body, so a modification breaks the layer
  // signatures above/below. Here we additionally enforce an expected value.
  if (isNonEmptyString(expectedPassportSubjectId)) {
    if (!passportPresent) return failed("ERR_PASSPORT_SUBJECT_MISSING");
    if (receipt.passport_subject_id !== expectedPassportSubjectId) {
      return failed("ERR_PASSPORT_SUBJECT_MISMATCH");
    }
  }

  // ── Authority layer (custody bundle, else shared-file legacy) ────────────────
  let authorityKind = null; // "authority" | "legacy"
  if (authorityBundle) {
    const authRes = await verifySignedExecutionReceipt(receipt, { authorityBundle, trustedRootFingerprint, now });
    if (authRes.verified) authorityKind = "authority";
  }
  if (authorityKind === null && isNonEmptyString(legacyPublicKeyPem)) {
    const legacyPayload = canonicalizeJson(bodyWithoutAuthoritySignature(receipt));
    const legacyOk = await verifyCanonical(legacyPayload, receipt.verifiable_signature.value, legacyPublicKeyPem);
    if (legacyOk) authorityKind = "legacy";
  }
  // A present authority signature that verifies against no trusted key fails.
  if (authorityKind === null) return failed("ERR_RECEIPT_SIGNATURE_INVALID", { layer: "authority" });

  // ── Resolve the exact state ─────────────────────────────────────────────────
  if (hasExecutorLayer) {
    if (authorityKind === "authority") {
      return passportPresent
        ? pass(S.EXECUTOR_AUTHORITY_AND_PASSPORT, { executor_id: executorId, passport_subject_id: receipt.passport_subject_id })
        : pass(S.EXECUTOR_AND_AUTHORITY, { executor_id: executorId });
    }
    // executor + legacy shared-file authority is not a defined Phase-0 pairing.
    return failed("ERR_RECEIPT_UNEXPECTED_LAYER_COMBINATION");
  }

  if (authorityKind === "authority") return pass(S.AUTHORITY);
  if (authorityKind === "legacy") return pass(S.LEGACY);
  return failed("no verifiable signature layer present");
}
