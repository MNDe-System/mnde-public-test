// Offline verifier for custody-signed execution gate receipts.
//
// Verifies the receipt fully offline given:
//   - the receipt itself
//   - the authority bundle (public material only)
//   - the trusted root fingerprint (out of band from the bundle)
//
// Fail-closed: any check failure returns verified:false with a distinct reason.
// Checks run in a defined order so a partial failure produces the earliest
// possible diagnosis.

import { sha256 } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";
import { fingerprintOf, findBundleKey, verifyAuthorityBundle, verifyCanonical } from "../custody/index.mjs";

export const SIGNED_EXECUTION_RECEIPT_SCHEMA = "mnde.execution_gate.receipt.v1";

function ok(checks) {
  return { verified: true, reason: undefined, checks };
}
function fail(checks, reason) {
  return { verified: false, reason, checks };
}
function checkEntry(passed, detail) {
  return { ok: passed, ...(detail !== undefined ? { detail } : {}) };
}

// Canonical payload for signature verification — receipt body with
// verifiable_signature excluded (same exclusion pattern as buildSignedExecutionReceipt).
function canonicalPayloadWithoutSignature(receipt) {
  const { verifiable_signature: _omit, ...payload } = receipt;
  return canonicalizeJson(payload);
}

// sha256 hex of the canonical serialisation of an object.
function sha256Hex(obj) {
  return sha256(canonicalizeJson(obj));
}

// Verify a custody-signed execution gate receipt.
//
// options:
//   authorityBundle        — loaded mnde.authority.bundle.v1 object
//   trustedRootFingerprint — hex sha256 of the root public key DER (out of band)
//   now                    — ISO-8601 string for staleness checks (default: Date.now())
//   originalRequest        — optional: if provided, request_hash is re-verified
//
// Returns { verified, reason?, checks: { [name]: { ok, detail? } } }
export async function verifySignedExecutionReceipt(receipt, options = {}) {
  const { authorityBundle, trustedRootFingerprint, now = new Date().toISOString(), originalRequest } = options;
  const checks = {};

  // ── 1. Schema ──────────────────────────────────────────────────────────────
  const schemaOk = receipt?.schema_version === SIGNED_EXECUTION_RECEIPT_SCHEMA;
  checks.schema = checkEntry(schemaOk,
    schemaOk ? undefined : `expected ${SIGNED_EXECUTION_RECEIPT_SCHEMA}, got ${receipt?.schema_version ?? "missing"}`);
  if (!schemaOk) return fail(checks, "schema: " + checks.schema.detail);

  // ── 2. Required fields ─────────────────────────────────────────────────────
  const requiredTopLevel = ["execution_id", "request_hash", "decided_at", "decision", "principal", "action", "resource", "environment", "risk", "evidence", "authority_id", "signing_key_id", "verifiable_signature"];
  const missingFields = requiredTopLevel.filter((f) => receipt[f] === undefined || receipt[f] === null);
  const fieldsOk = missingFields.length === 0;
  checks.required_fields = checkEntry(fieldsOk, fieldsOk ? undefined : `missing fields: ${missingFields.join(", ")}`);
  if (!fieldsOk) return fail(checks, "required_fields: " + checks.required_fields.detail);

  // decision must be ALLOW or REFUSE
  const decisionOk = receipt.decision === "ALLOW" || receipt.decision === "REFUSE";
  checks.decision_value = checkEntry(decisionOk, decisionOk ? undefined : `invalid decision: ${receipt.decision}`);
  if (!decisionOk) return fail(checks, "decision_value: " + checks.decision_value.detail);

  // ── 3. Signature algorithm ─────────────────────────────────────────────────
  const sig = receipt.verifiable_signature;
  const algOk = typeof sig === "object" && sig !== null && sig.algorithm === "ED25519";
  checks.algorithm = checkEntry(algOk, algOk ? undefined : `expected ED25519, got ${sig?.algorithm ?? "missing"}`);
  if (!algOk) return fail(checks, "algorithm: " + checks.algorithm.detail);

  // Required sub-fields of verifiable_signature
  const sigFields = ["authority_id", "key_id", "signed_at", "public_key_fingerprint", "value"];
  const missingSigFields = sigFields.filter((f) => typeof sig[f] !== "string" || sig[f].length === 0);
  const sigFieldsOk = missingSigFields.length === 0;
  checks.signature_fields = checkEntry(sigFieldsOk, sigFieldsOk ? undefined : `missing/empty sig fields: ${missingSigFields.join(", ")}`);
  if (!sigFieldsOk) return fail(checks, "signature_fields: " + checks.signature_fields.detail);

  // ── 4. Authority bundle validity ───────────────────────────────────────────
  if (!authorityBundle) {
    checks.authority_bundle = checkEntry(false, "authority bundle required");
    return fail(checks, "authority_bundle: authority bundle required");
  }
  const bundleCheck = await verifyAuthorityBundle(authorityBundle, { trustedRootFingerprint, now });
  checks.authority_bundle = checkEntry(bundleCheck.ok, bundleCheck.ok ? undefined : bundleCheck.reason);
  if (!bundleCheck.ok) return fail(checks, `authority_bundle: ${bundleCheck.reason}`);

  // ── 5. Authority ID match ──────────────────────────────────────────────────
  const authorityIdOk = sig.authority_id === authorityBundle.authority_id;
  checks.authority_id_match = checkEntry(authorityIdOk,
    authorityIdOk ? undefined : `receipt authority_id ${sig.authority_id} != bundle authority_id ${authorityBundle.authority_id}`);
  if (!authorityIdOk) return fail(checks, "authority_id_match: " + checks.authority_id_match.detail);

  // ── 6. Key lookup (honors revocation + validity window) ────────────────────
  const keyResult = findBundleKey(authorityBundle, "receipt", sig.key_id, sig.signed_at);
  checks.key_lookup = checkEntry(keyResult.ok, keyResult.ok ? undefined : keyResult.reason);
  if (!keyResult.ok) return fail(checks, `key_lookup: ${keyResult.reason}`);

  // ── 7. Fingerprint match ───────────────────────────────────────────────────
  const computedFingerprint = fingerprintOf(keyResult.publicKey);
  const fpOk = sig.public_key_fingerprint === computedFingerprint;
  checks.fingerprint_match = checkEntry(fpOk,
    fpOk ? undefined : `receipt claims ${sig.public_key_fingerprint}, bundle key fingerprint is ${computedFingerprint}`);
  if (!fpOk) return fail(checks, "fingerprint_match: " + checks.fingerprint_match.detail);

  // ── 8. Signature verification ──────────────────────────────────────────────
  const canonicalPayload = canonicalPayloadWithoutSignature(receipt);
  const sigOk = await verifyCanonical(canonicalPayload, sig.value, keyResult.publicKey);
  checks.signature = checkEntry(sigOk, sigOk ? undefined : "Ed25519 signature verification failed");
  if (!sigOk) return fail(checks, "signature: Ed25519 signature verification failed");

  // ── 9. Optional: request hash integrity ────────────────────────────────────
  if (originalRequest !== undefined) {
    const recomputed = sha256Hex(originalRequest);
    const hashOk = recomputed === receipt.request_hash;
    checks.request_hash = checkEntry(hashOk,
      hashOk ? undefined : `recomputed ${recomputed}, receipt claims ${receipt.request_hash}`);
    if (!hashOk) return fail(checks, "request_hash: " + checks.request_hash.detail);
  } else {
    checks.request_hash = checkEntry(true, "not verified (originalRequest not provided)");
  }

  return ok(checks);
}
