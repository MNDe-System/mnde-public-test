// Offline verifier for mnde.execution_result.v2.
//
// Verifies the result record's structural integrity, decision-status
// consistency, and result_hash. When executor_signature is present it
// must be verified against an explicitly supplied executor public key —
// fail closed if the signature is present but no key is provided.
//
// Does NOT verify the signed execution receipt inline; that requires the
// authority bundle and is delegated to verifySignedExecutionReceipt. The
// caller must:
//   1. Verify the signed receipt (verifySignedExecutionReceipt) before calling
//      this verifier.
//   2. Confirm result.execution_receipt_hash === sha256(canonicalizeJson(receipt))
//      after receipt signature verification passes.
//
// This ordering ensures the receipt link is verified before the result is
// accepted, preventing a forged result+receipt pair from passing hash-only
// checks.

import { sha256 } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";
import { fingerprintOf, verifyCanonical } from "../custody/index.mjs";
import { verifyIdentityAssertion } from "../identity/verify-assertion.mjs";
import { canonicalResultPayload, computeResultHash, EXECUTION_RESULT_SCHEMA, validateExecutionResult } from "./result.mjs";

function ok(checks, identityLevel = "ASSERTED_ONLY") {
  return { verified: true, reason: undefined, identity_level: identityLevel, checks };
}
function fail(checks, reason) {
  return { verified: false, reason, checks };
}
function checkEntry(passed, detail) {
  return { ok: passed, ...(detail !== undefined ? { detail } : {}) };
}

// Verify an mnde.execution_result.v2 record.
//
// options:
//   executorPublicKey    — PEM or DER public key for executor_signature
//                          verification. Required when executor_signature is
//                          present; if omitted when signature is present the
//                          check fails closed.
//   originalReceipt      — When provided, result.execution_receipt_hash is
//                          re-verified against sha256(canonicalizeJson(receipt)).
//                          Callers MUST also have already verified the receipt
//                          signature via verifySignedExecutionReceipt.
//   originalRequest      — When provided, result.execution_request_hash is
//                          re-verified against sha256(canonicalizeJson(request)).
//
// Returns { verified, reason?, checks: { [name]: { ok, detail? } } }
export async function verifyExecutionResult(result, options = {}) {
  const { executorPublicKey, originalReceipt, originalRequest } = options;
  const checks = {};

  // ── 1. Schema ──────────────────────────────────────────────────────────────
  const schemaOk = result?.schema_version === EXECUTION_RESULT_SCHEMA;
  checks.schema = checkEntry(schemaOk,
    schemaOk ? undefined : `expected ${EXECUTION_RESULT_SCHEMA}, got ${result?.schema_version ?? "missing"}`);
  if (!schemaOk) return fail(checks, "schema: " + checks.schema.detail);

  // ── 2. Full structural validation ─────────────────────────────────────────
  const validation = validateExecutionResult(result);
  checks.structure = checkEntry(validation.ok,
    validation.ok ? undefined : validation.errors.join("; "));
  if (!validation.ok) return fail(checks, "structure: " + checks.structure.detail);

  // ── 3. Decision-status consistency ────────────────────────────────────────
  // Enforced by validateExecutionResult, but checked again here for an
  // explicit named check in the result so callers can see it clearly.
  const consistencyOk = !(result.decision === "REFUSE" && result.status !== "NOT_EXECUTED");
  checks.decision_status_consistency = checkEntry(consistencyOk,
    consistencyOk ? undefined : `REFUSE decision requires NOT_EXECUTED status, got "${result.status}"`);
  if (!consistencyOk) return fail(checks, "decision_status_consistency: " + checks.decision_status_consistency.detail);

  // ── 4. result_hash integrity ───────────────────────────────────────────────
  const expectedHash = computeResultHash(result);
  const hashOk = result.result_hash === expectedHash;
  checks.result_hash = checkEntry(hashOk,
    hashOk ? undefined : `result_hash mismatch: result claims ${result.result_hash}, computed ${expectedHash}`);
  if (!hashOk) return fail(checks, "result_hash: " + checks.result_hash.detail);

  // ── 5. Executor signature ─────────────────────────────────────────────────
  const hasSig = result.executor_signature !== undefined && result.executor_signature !== null;
  if (hasSig) {
    if (!executorPublicKey) {
      // Signature is present but we have no key to verify it against — fail closed.
      checks.executor_signature = checkEntry(false,
        "executor_signature is present but executorPublicKey was not provided for verification");
      return fail(checks, "executor_signature: " + checks.executor_signature.detail);
    }
    const sig = result.executor_signature;
    // Verify fingerprint: compute from the provided key, do not trust the
    // self-reported fingerprint in the signature object.
    const computedFp = fingerprintOf(executorPublicKey);
    const fpOk = sig.key_fingerprint === computedFp;
    if (!fpOk) {
      checks.executor_signature = checkEntry(false,
        `executor_signature.key_fingerprint claims ${sig.key_fingerprint}, provided key fingerprint is ${computedFp}`);
      return fail(checks, "executor_signature: " + checks.executor_signature.detail);
    }
    // Signature covers canonical payload (same content as result_hash input).
    const canonicalPayload = canonicalResultPayload(result);
    const sigOk = await verifyCanonical(canonicalPayload, sig.value, executorPublicKey);
    checks.executor_signature = checkEntry(sigOk,
      sigOk ? undefined : "Ed25519 executor signature verification failed");
    if (!sigOk) return fail(checks, "executor_signature: Ed25519 executor signature verification failed");
  } else {
    // No signature — this is allowed but the result is executor-asserted only.
    // Recorded explicitly so the caller can see the verification level.
    checks.executor_signature = checkEntry(true, "not present — result is executor-asserted, hash-integrity only");
  }

  // ── 6. Optional: receipt hash binding ────────────────────────────────────
  // IMPORTANT: the caller must have already verified the receipt's Ed25519
  // signature via verifySignedExecutionReceipt before calling this verifier.
  // This check confirms only that the hash in the result matches the receipt
  // provided; it does NOT re-verify the receipt signature.
  if (originalReceipt !== undefined) {
    const receiptHash = sha256(canonicalizeJson(originalReceipt));
    const receiptHashOk = receiptHash === result.execution_receipt_hash;
    checks.receipt_hash_binding = checkEntry(receiptHashOk,
      receiptHashOk ? undefined : `recomputed receipt hash ${receiptHash}, result claims ${result.execution_receipt_hash}`);
    if (!receiptHashOk) return fail(checks, "receipt_hash_binding: " + checks.receipt_hash_binding.detail);
  } else {
    checks.receipt_hash_binding = checkEntry(true, "not verified (originalReceipt not provided — caller must verify receipt signature separately)");
  }

  // ── 7. Optional: request hash binding ────────────────────────────────────
  if (originalRequest !== undefined) {
    const requestHash = sha256(canonicalizeJson(originalRequest));
    const requestHashOk = requestHash === result.execution_request_hash;
    checks.request_hash_binding = checkEntry(requestHashOk,
      requestHashOk ? undefined : `recomputed request hash ${requestHash}, result claims ${result.execution_request_hash}`);
    if (!requestHashOk) return fail(checks, "request_hash_binding: " + checks.request_hash_binding.detail);
  } else {
    checks.request_hash_binding = checkEntry(true, "not verified (originalRequest not provided)");
  }

  // ── 8. Identity assertion (optional) ──────────────────────────────────────
  // When executor.identity_assertion is present, verify its structure and
  // assertion_hash integrity. This is the MNDe-side check: structural only,
  // no network, no live issuer calls. The adapter already proved identity;
  // MNDe verifies the proof record is intact.
  const assertion = result.executor?.identity_assertion;
  let identityLevel = "ASSERTED_ONLY";
  if (assertion !== undefined && assertion !== null) {
    const assertionCheck = verifyIdentityAssertion(assertion);
    checks.identity_assertion = checkEntry(assertionCheck.valid,
      assertionCheck.valid ? undefined : `${assertionCheck.code}: ${assertionCheck.message}`);
    if (!assertionCheck.valid) {
      return fail(checks, `identity_assertion: ${assertionCheck.code}: ${assertionCheck.message}`);
    }
    identityLevel = "ASSERTION_HASH_BOUND";
  } else {
    checks.identity_evidence = checkEntry(true,
      `executor.identity_evidence_asserted_only=true — identity type "${result.executor?.identity_evidence?.type}" is executor-reported; OIDC token verification must be performed out of band`);
  }

  return ok(checks, identityLevel);
}
