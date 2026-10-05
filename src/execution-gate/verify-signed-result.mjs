// Offline verifier for mnde.signed_execution_result.v1.
//
// Verification sequence (fail-closed at each step):
//
//   1.  Schema + trust_model + signed_at format + clock skew
//   2.  authority_chain_id format
//   3.  authority object fields
//   4.  verifiable_signature fields
//   5.  signature_payload_hash format
//   6.  receipt_binding shape
//   7.  Verify unsigned execution_result (verifyExecutionResult)
//   8.  Verify signed execution receipt (verifySignedExecutionReceipt)
//   9.  Bind result to receipt — three-way request hash check
//   10. Decision-status compatibility
//   11. STARTED freshness (if maxOpenStatusAgeMs supplied)
//   12. Verify authority bundle (verifyAuthorityBundle)
//   13. Authority chain lineage check
//   14. Find result signing key (role "result")
//   15. Derive and compare fingerprints (never trust self-reported values)
//   16. Recompute signature_payload_hash
//   17. Verify Ed25519 signature over canonical signature body
//   18. Evidence safety — recursive, case-insensitive forbidden-field scan
//
// Returns a deterministic, stable verdict object.

import { canonicalizeJson } from "../../shared/json.ts";
import { sha256 } from "../crypto/provider.mjs";
import { findBundleKey, fingerprintOf, verifyAuthorityBundle, verifyCanonical } from "../custody/index.mjs";
import { derivePassportSubjectId } from "../identity/passport.mjs";
import { EVIDENCE_FORBIDDEN_FIELDS } from "./result.mjs";
import { verifySignedExecutionReceipt } from "./verify-signed-receipt.mjs";
import { verifyExecutionResult } from "./verify-result.mjs";

export const SIGNED_RESULT_SCHEMA = "mnde.signed_execution_result.v1";
const SIGNED_RESULT_TRUST_MODEL = "offline-root-pinned";
const REQUIRED_ALGORITHM = "ED25519";

// ISO-8601 with explicit timezone.
const ISO8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const HEX64_RE = /^[a-f0-9]{64}$/;
const SAFE_CHAIN_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;

// All error codes emittable by verifySignedExecutionResult.
// Used by code-parity tests to confirm docs stay in sync.
export const SIGNED_RESULT_ERROR_CODES = new Set([
  "SIGNED_RESULT_SCHEMA_INVALID",
  "SIGNED_RESULT_TRUST_MODEL_UNSUPPORTED",
  "SIGNED_RESULT_SIGNED_AT_FUTURE",
  "SIGNED_RESULT_AUTHORITY_CHAIN_INVALID",
  "SIGNED_RESULT_AUTHORITY_INVALID",
  "SIGNED_RESULT_AUTHORITY_MISMATCH",
  "SIGNED_RESULT_ALGORITHM_UNSUPPORTED",
  "SIGNED_RESULT_AUTHORITY_BUNDLE_FINGERPRINT_INVALID",
  "SIGNED_RESULT_SIGNING_KEY_FINGERPRINT_INVALID",
  "SIGNED_RESULT_KEY_NOT_FOUND",
  "SIGNED_RESULT_KEY_REVOKED",
  "SIGNED_RESULT_KEY_EXPIRED",
  "SIGNED_RESULT_KEY_MALFORMED",
  "SIGNED_RESULT_SIGNATURE_MISSING",
  "SIGNED_RESULT_SIGNATURE_INVALID",
  "SIGNED_RESULT_HASH_FORMAT_INVALID",
  "SIGNED_RESULT_PAYLOAD_HASH_INVALID",
  "SIGNED_RESULT_CANONICALIZATION_INVALID",
  "SIGNED_RESULT_RECEIPT_BINDING_INVALID",
  "SIGNED_RESULT_RECEIPT_INVALID",
  "SIGNED_RESULT_RESULT_INVALID",
  "SIGNED_RESULT_KEY_ROLE_INVALID",
  "SIGNED_RESULT_DECISION_STATUS_INVALID",
  "SIGNED_RESULT_STARTED_TOO_OLD",
  "SIGNED_RESULT_EVIDENCE_FORBIDDEN_FIELD",
]);

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function sha256Hex(str) {
  return sha256(str);
}

function payloadHashBody(envelope) {
  const { signature_payload_hash: _sph, verifiable_signature: _vs, ...body } = envelope;
  return canonicalizeJson(body);
}

function signatureBody(envelope) {
  const { verifiable_signature: _vs, ...body } = envelope;
  return canonicalizeJson(body);
}

// Walk value recursively, collecting names of any object keys that are
// forbidden field names (case-insensitive). WeakSet guards against cycles.
function collectForbiddenFields(value, found = [], seen = new WeakSet()) {
  if (Array.isArray(value)) {
    if (seen.has(value)) return found;
    seen.add(value);
    for (const item of value) collectForbiddenFields(item, found, seen);
  } else if (isObject(value)) {
    if (seen.has(value)) return found;
    seen.add(value);
    for (const [k, v] of Object.entries(value)) {
      if (EVIDENCE_FORBIDDEN_FIELDS.has(k.toLowerCase())) found.push(k);
      collectForbiddenFields(v, found, seen);
    }
  }
  return found;
}

// Return shapes.
function pass(checks, envelope, keyId, bundleFp, keyFp, revocationFreshness, identityLevel, passportSubjectId) {
  return {
    valid: true,
    schema: SIGNED_RESULT_SCHEMA,
    result_id: envelope.execution_result?.result_id,
    execution_id: envelope.execution_result?.execution_id,
    status: envelope.execution_result?.status,
    decision: envelope.execution_result?.decision,
    authority_id: envelope.authority?.authority_id,
    authority_chain_id: envelope.authority_chain_id,
    authority_bundle_fingerprint: bundleFp,
    signing_key_fingerprint: keyFp,
    key_id: keyId,
    key_role: "result",
    trust_model: SIGNED_RESULT_TRUST_MODEL,
    identity_evidence: identityLevel ?? "ASSERTED_ONLY",
    passport_subject_id: passportSubjectId ?? null,
    revocation_freshness: revocationFreshness,
    checks
  };
}

function fail(checks, code, message) {
  return { valid: false, code, message, checks };
}

function check(checks, name, passed, detail) {
  checks[name] = { ok: passed, ...(detail !== undefined ? { detail } : {}) };
  return passed;
}

// Verify an mnde.signed_execution_result.v1 envelope.
//
// options:
//   authorityBundle        — loaded mnde.authority.bundle.v1 (public material)
//   trustedRootFingerprint — out-of-band hex sha256 of the root public key DER
//   now                    — ISO-8601 for staleness checks (default: Date.now())
//   nowMs                  — wall-clock milliseconds (overrides `now` for freshness checks)
//   executorPublicKey      — PEM for executor_signature check (required when present)
//   signedReceipt          — the mnde.execution_gate.receipt.v1 to bind against (required)
//   maxClockSkewMs         — max ms signed_at may be in the future (default: 300_000)
//   maxOpenStatusAgeMs     — if set, STARTED results without ended_at older than this fail
//
// Returns a deterministic verdict object.
export async function verifySignedExecutionResult(envelope, options = {}) {
  const {
    authorityBundle,
    trustedRootFingerprint,
    now = new Date().toISOString(),
    executorPublicKey,
    signedReceipt,
    maxClockSkewMs = 300_000,
    maxOpenStatusAgeMs,
    nowMs: nowMsOpt
  } = options;
  const checks = {};

  // ── 1. Schema, trust_model, signed_at, clock skew ────────────────────────
  if (!isObject(envelope) || envelope.schema !== SIGNED_RESULT_SCHEMA) {
    check(checks, "schema", false, `expected "${SIGNED_RESULT_SCHEMA}", got ${JSON.stringify(envelope?.schema)}`);
    return fail(checks, "SIGNED_RESULT_SCHEMA_INVALID", "unknown or missing schema");
  }
  check(checks, "schema", true);

  if (envelope.trust_model !== SIGNED_RESULT_TRUST_MODEL) {
    check(checks, "trust_model", false, `expected "${SIGNED_RESULT_TRUST_MODEL}", got ${JSON.stringify(envelope.trust_model)}`);
    return fail(checks, "SIGNED_RESULT_TRUST_MODEL_UNSUPPORTED", `trust_model must be "${SIGNED_RESULT_TRUST_MODEL}"`);
  }
  check(checks, "trust_model", true);

  if (!ISO8601_RE.test(envelope.signed_at) || Number.isNaN(Date.parse(envelope.signed_at))) {
    check(checks, "signed_at", false, `malformed: ${JSON.stringify(envelope.signed_at)}`);
    return fail(checks, "SIGNED_RESULT_SCHEMA_INVALID", "signed_at must be a valid ISO-8601 datetime");
  }
  check(checks, "signed_at", true);

  const signedAtMs = Date.parse(envelope.signed_at);
  const nowMs = nowMsOpt ?? Date.parse(now);
  if (signedAtMs > nowMs + maxClockSkewMs) {
    check(checks, "signed_at_clock", false, `signed_at is ${signedAtMs - nowMs}ms in the future (maxClockSkewMs=${maxClockSkewMs})`);
    return fail(checks, "SIGNED_RESULT_SIGNED_AT_FUTURE", "signed_at is too far in the future");
  }
  check(checks, "signed_at_clock", true);

  // ── 2. authority_chain_id ─────────────────────────────────────────────────
  if (!SAFE_CHAIN_ID_RE.test(envelope.authority_chain_id)) {
    check(checks, "authority_chain_id", false, `malformed: ${JSON.stringify(envelope.authority_chain_id)}`);
    return fail(checks, "SIGNED_RESULT_AUTHORITY_CHAIN_INVALID", "authority_chain_id must be 1-128 safe chars and must not be a fingerprint");
  }
  if (HEX64_RE.test(envelope.authority_chain_id)) {
    check(checks, "authority_chain_id", false, "authority_chain_id must not be a fingerprint (64-char hex)");
    return fail(checks, "SIGNED_RESULT_AUTHORITY_CHAIN_INVALID", "authority_chain_id must not be a fingerprint");
  }
  check(checks, "authority_chain_id", true);

  // ── 3. authority object ───────────────────────────────────────────────────
  const auth = envelope.authority;
  if (!isObject(auth)) {
    check(checks, "authority", false, "authority object is missing");
    return fail(checks, "SIGNED_RESULT_AUTHORITY_INVALID", "authority is required");
  }
  if (typeof auth.authority_id !== "string" || auth.authority_id.length === 0) {
    check(checks, "authority", false, "authority.authority_id missing");
    return fail(checks, "SIGNED_RESULT_AUTHORITY_INVALID", "authority.authority_id is required");
  }
  if (auth.key_role !== "result") {
    check(checks, "authority", false, `authority.key_role must be "result", got ${JSON.stringify(auth.key_role)}`);
    return fail(checks, "SIGNED_RESULT_KEY_ROLE_INVALID", "authority.key_role must be result");
  }
  if (auth.algorithm !== REQUIRED_ALGORITHM) {
    check(checks, "authority", false, `authority.algorithm must be ED25519, got ${JSON.stringify(auth.algorithm)}`);
    return fail(checks, "SIGNED_RESULT_ALGORITHM_UNSUPPORTED", "authority.algorithm must be ED25519");
  }
  if (!HEX64_RE.test(auth.authority_bundle_fingerprint)) {
    check(checks, "authority", false, "authority.authority_bundle_fingerprint must be 64-char hex");
    return fail(checks, "SIGNED_RESULT_AUTHORITY_BUNDLE_FINGERPRINT_INVALID", "authority.authority_bundle_fingerprint is malformed");
  }
  if (!HEX64_RE.test(auth.signing_key_fingerprint)) {
    check(checks, "authority", false, "authority.signing_key_fingerprint must be 64-char hex");
    return fail(checks, "SIGNED_RESULT_SIGNING_KEY_FINGERPRINT_INVALID", "authority.signing_key_fingerprint is malformed");
  }
  if (typeof auth.key_id !== "string" || auth.key_id.length === 0) {
    check(checks, "authority", false, "authority.key_id missing");
    return fail(checks, "SIGNED_RESULT_KEY_NOT_FOUND", "authority.key_id is required");
  }
  check(checks, "authority", true);

  // ── 4. verifiable_signature ───────────────────────────────────────────────
  const sig = envelope.verifiable_signature;
  if (!isObject(sig)) {
    check(checks, "signature_present", false, "verifiable_signature is missing");
    return fail(checks, "SIGNED_RESULT_SIGNATURE_MISSING", "verifiable_signature is required");
  }
  if (sig.algorithm !== REQUIRED_ALGORITHM) {
    check(checks, "signature_present", false, `expected ED25519, got ${JSON.stringify(sig.algorithm)}`);
    return fail(checks, "SIGNED_RESULT_ALGORITHM_UNSUPPORTED", "verifiable_signature.algorithm must be ED25519");
  }
  if (sig.key_id !== auth.key_id) {
    check(checks, "signature_present", false, `verifiable_signature.key_id (${sig.key_id}) != authority.key_id (${auth.key_id})`);
    return fail(checks, "SIGNED_RESULT_SIGNATURE_INVALID", "verifiable_signature.key_id must equal authority.key_id");
  }
  if (typeof sig.value !== "string" || sig.value.length === 0) {
    check(checks, "signature_present", false, "verifiable_signature.value is missing");
    return fail(checks, "SIGNED_RESULT_SIGNATURE_MISSING", "verifiable_signature.value is required");
  }
  check(checks, "signature_present", true);

  // ── 5. signature_payload_hash format ──────────────────────────────────────
  if (!HEX64_RE.test(envelope.signature_payload_hash)) {
    check(checks, "payload_hash_format", false, "signature_payload_hash must be 64-char lowercase hex");
    return fail(checks, "SIGNED_RESULT_HASH_FORMAT_INVALID", "signature_payload_hash is malformed");
  }
  check(checks, "payload_hash_format", true);

  // ── 6. receipt_binding shape ──────────────────────────────────────────────
  const rb = envelope.receipt_binding;
  if (!isObject(rb) || !HEX64_RE.test(rb.execution_receipt_hash) || !HEX64_RE.test(rb.execution_request_hash) || typeof rb.execution_id !== "string" || typeof rb.receipt_schema !== "string") {
    check(checks, "receipt_binding_shape", false, "receipt_binding missing or malformed");
    return fail(checks, "SIGNED_RESULT_RECEIPT_BINDING_INVALID", "receipt_binding is missing or malformed");
  }
  check(checks, "receipt_binding_shape", true);

  // ── 7. Verify unsigned execution_result ───────────────────────────────────
  const resultCheck = await verifyExecutionResult(envelope.execution_result, { executorPublicKey });
  if (!resultCheck.verified) {
    check(checks, "execution_result", false, resultCheck.reason);
    return fail(checks, "SIGNED_RESULT_RESULT_INVALID", `execution_result invalid: ${resultCheck.reason}`);
  }
  check(checks, "execution_result", true);
  const identityLevel = resultCheck.identity_level ?? "ASSERTED_ONLY";

  // ── 8. Verify signed execution receipt ────────────────────────────────────
  if (!isObject(envelope.execution_result)) {
    check(checks, "signed_receipt", false, "execution_result missing");
    return fail(checks, "SIGNED_RESULT_RECEIPT_INVALID", "cannot verify receipt — execution_result missing");
  }
  if (!signedReceipt) {
    check(checks, "signed_receipt", false, "signed execution receipt must be provided for verification");
    return fail(checks, "SIGNED_RESULT_RECEIPT_INVALID", "signedReceipt is required for verification");
  }
  if (authorityBundle) {
    const earlyBundleCheck = await verifyAuthorityBundle(authorityBundle, { trustedRootFingerprint, now });
    if (!earlyBundleCheck.ok) {
      check(checks, "authority_bundle", false, earlyBundleCheck.reason);
      if (earlyBundleCheck.reason === "KEY_MALFORMED") {
        return fail(checks, "SIGNED_RESULT_KEY_MALFORMED", "authority bundle contains a malformed signing key");
      }
      return fail(checks, "SIGNED_RESULT_AUTHORITY_INVALID", `authority bundle invalid: ${earlyBundleCheck.reason}`);
    }
    check(checks, "authority_bundle", true);
  }
  const receiptCheck = await verifySignedExecutionReceipt(signedReceipt, { authorityBundle, trustedRootFingerprint, now });
  if (!receiptCheck.verified) {
    check(checks, "signed_receipt", false, receiptCheck.reason);
    return fail(checks, "SIGNED_RESULT_RECEIPT_INVALID", `signed receipt invalid: ${receiptCheck.reason}`);
  }
  check(checks, "signed_receipt", true);

  // ── 9. Bind result to receipt — three-way request hash check ──────────────
  const receiptHash = sha256Hex(canonicalizeJson(signedReceipt));
  const er = envelope.execution_result;

  if (rb.execution_receipt_hash !== receiptHash) {
    check(checks, "receipt_binding", false, `receipt_binding.execution_receipt_hash ${rb.execution_receipt_hash} != computed ${receiptHash}`);
    return fail(checks, "SIGNED_RESULT_RECEIPT_BINDING_INVALID", "receipt_binding.execution_receipt_hash does not match verified receipt");
  }
  if (er.execution_receipt_hash !== receiptHash) {
    check(checks, "receipt_binding", false, "execution_result.execution_receipt_hash does not match verified receipt");
    return fail(checks, "SIGNED_RESULT_RECEIPT_BINDING_INVALID", "execution_result.execution_receipt_hash does not match verified receipt");
  }
  // Three-way check: all three sources of execution_request_hash must agree.
  if (rb.execution_request_hash !== signedReceipt.request_hash) {
    check(checks, "receipt_binding", false, `receipt_binding.execution_request_hash ${rb.execution_request_hash} != receipt.request_hash ${signedReceipt.request_hash}`);
    return fail(checks, "SIGNED_RESULT_RECEIPT_BINDING_INVALID", "receipt_binding.execution_request_hash does not match verified receipt");
  }
  if (er.execution_request_hash !== signedReceipt.request_hash) {
    check(checks, "receipt_binding", false, `execution_result.execution_request_hash ${er.execution_request_hash} != receipt.request_hash ${signedReceipt.request_hash}`);
    return fail(checks, "SIGNED_RESULT_RECEIPT_BINDING_INVALID", "execution_result.execution_request_hash does not match verified receipt");
  }
  if (rb.execution_request_hash !== er.execution_request_hash) {
    check(checks, "receipt_binding", false, "receipt_binding.execution_request_hash != execution_result.execution_request_hash");
    return fail(checks, "SIGNED_RESULT_RECEIPT_BINDING_INVALID", "execution_request_hash mismatch between receipt_binding and execution_result");
  }
  if (rb.execution_id !== er.execution_id) {
    check(checks, "receipt_binding", false, "receipt_binding.execution_id != execution_result.execution_id");
    return fail(checks, "SIGNED_RESULT_RECEIPT_BINDING_INVALID", "execution_id mismatch between receipt_binding and execution_result");
  }
  if (er.execution_id !== signedReceipt.execution_id) {
    check(checks, "receipt_binding", false, `execution_result.execution_id ${er.execution_id} != receipt.execution_id ${signedReceipt.execution_id}`);
    return fail(checks, "SIGNED_RESULT_RECEIPT_BINDING_INVALID", "execution_id mismatch between result and receipt");
  }
  if (er.decision !== signedReceipt.decision) {
    check(checks, "receipt_binding", false, `decision mismatch: result "${er.decision}" != receipt "${signedReceipt.decision}"`);
    return fail(checks, "SIGNED_RESULT_RECEIPT_BINDING_INVALID", "decision mismatch between result and receipt");
  }
  const receiptSchemaField = signedReceipt.schema_version ?? signedReceipt.schema;
  if (rb.receipt_schema !== receiptSchemaField) {
    check(checks, "receipt_binding", false, `receipt_binding.receipt_schema ${rb.receipt_schema} != receipt schema ${receiptSchemaField}`);
    return fail(checks, "SIGNED_RESULT_RECEIPT_BINDING_INVALID", "receipt_schema mismatch");
  }
  check(checks, "receipt_binding", true);

  // ── 10. Decision-status compatibility ─────────────────────────────────────
  if (signedReceipt.decision === "REFUSE" && er.status !== "NOT_EXECUTED") {
    check(checks, "decision_status", false, `REFUSE receipt requires NOT_EXECUTED, got "${er.status}"`);
    return fail(checks, "SIGNED_RESULT_DECISION_STATUS_INVALID", `REFUSE decision requires NOT_EXECUTED status, got "${er.status}"`);
  }
  check(checks, "decision_status", true);

  // ── 11. STARTED freshness ─────────────────────────────────────────────────
  if (er.status === "STARTED" && (er.ended_at === undefined || er.ended_at === null)) {
    if (maxOpenStatusAgeMs !== undefined) {
      const ageMs = nowMs - signedAtMs;
      if (ageMs > maxOpenStatusAgeMs) {
        check(checks, "started_freshness", false, `STARTED result is ${ageMs}ms old, max is ${maxOpenStatusAgeMs}ms`);
        return fail(checks, "SIGNED_RESULT_STARTED_TOO_OLD", `STARTED result without ended_at is too old (${ageMs}ms > ${maxOpenStatusAgeMs}ms)`);
      }
    }
    check(checks, "started_freshness", true);
  }

  // ── 12. Verify authority bundle ───────────────────────────────────────────
  if (!authorityBundle) {
    check(checks, "authority_bundle", false, "authorityBundle is required");
    return fail(checks, "SIGNED_RESULT_AUTHORITY_INVALID", "authorityBundle is required");
  }
  const bundleCheck = await verifyAuthorityBundle(authorityBundle, { trustedRootFingerprint, now });
  if (!bundleCheck.ok) {
    check(checks, "authority_bundle", false, bundleCheck.reason);
    if (bundleCheck.reason === "KEY_MALFORMED") {
      return fail(checks, "SIGNED_RESULT_KEY_MALFORMED", "authority bundle contains a malformed signing key");
    }
    return fail(checks, "SIGNED_RESULT_AUTHORITY_INVALID", `authority bundle invalid: ${bundleCheck.reason}`);
  }
  if (auth.authority_id !== authorityBundle.authority_id) {
    check(checks, "authority_bundle", false, `envelope authority_id ${auth.authority_id} != bundle ${authorityBundle.authority_id}`);
    return fail(checks, "SIGNED_RESULT_AUTHORITY_MISMATCH", "authority_id in envelope does not match verified bundle");
  }
  check(checks, "authority_bundle", true);

  // ── 13. Authority chain lineage ───────────────────────────────────────────
  if (authorityBundle.authority_chain_id !== undefined) {
    if (envelope.authority_chain_id !== authorityBundle.authority_chain_id) {
      check(checks, "authority_chain", false, `envelope "${envelope.authority_chain_id}" != bundle "${authorityBundle.authority_chain_id}"`);
      return fail(checks, "SIGNED_RESULT_AUTHORITY_CHAIN_INVALID", "authority_chain_id mismatch between envelope and bundle");
    }
    check(checks, "authority_chain", true, "verified against bundle");
  } else {
    check(checks, "authority_chain", true, "AUTHORITY_CHAIN_ASSERTED_ONLY — bundle does not carry authority_chain_id; asserted by envelope only");
  }

  // ── 14. Find result signing key ───────────────────────────────────────────
  const keyResult = findBundleKey(authorityBundle, "result", auth.key_id, envelope.signed_at);
  if (!keyResult.ok) {
    const code = keyResult.reason === "KEY_REVOKED" ? "SIGNED_RESULT_KEY_REVOKED"
      : keyResult.reason === "KEY_EXPIRED" ? "SIGNED_RESULT_KEY_EXPIRED"
        : "SIGNED_RESULT_KEY_NOT_FOUND";
    check(checks, "key_lookup", false, keyResult.reason);
    return fail(checks, code, `result signing key not usable: ${keyResult.reason}`);
  }
  check(checks, "key_lookup", true, `key_id=${auth.key_id} role=result revocation=${keyResult.revocation_freshness}`);

  // ── 15. Derive and compare fingerprints (never trust self-reported) ────────
  const derivedBundleFp = authorityBundle.root_key.fingerprint;
  if (auth.authority_bundle_fingerprint !== derivedBundleFp) {
    check(checks, "bundle_fingerprint", false, `envelope claims ${auth.authority_bundle_fingerprint}, derived ${derivedBundleFp}`);
    return fail(checks, "SIGNED_RESULT_AUTHORITY_BUNDLE_FINGERPRINT_INVALID", "authority_bundle_fingerprint does not match verified bundle root key");
  }
  check(checks, "bundle_fingerprint", true);

  let derivedKeyFp;
  try {
    derivedKeyFp = fingerprintOf(keyResult.publicKey);
  } catch {
    check(checks, "key_fingerprint", false, "malformed public key PEM in bundle");
    return fail(checks, "SIGNED_RESULT_KEY_MALFORMED", "result signing key has malformed public key PEM");
  }
  if (auth.signing_key_fingerprint !== derivedKeyFp) {
    check(checks, "key_fingerprint", false, `envelope claims ${auth.signing_key_fingerprint}, derived ${derivedKeyFp}`);
    return fail(checks, "SIGNED_RESULT_SIGNING_KEY_FINGERPRINT_INVALID", "signing_key_fingerprint does not match bundle key");
  }
  check(checks, "key_fingerprint", true);

  // ── 16. Recompute signature_payload_hash ──────────────────────────────────
  let payloadHashBytesStr;
  try {
    payloadHashBytesStr = payloadHashBody(envelope);
  } catch {
    check(checks, "payload_hash", false, "canonicalization failed");
    return fail(checks, "SIGNED_RESULT_CANONICALIZATION_INVALID", "failed to canonicalize payload hash body");
  }
  const recomputedPayloadHash = sha256Hex(payloadHashBytesStr);
  if (recomputedPayloadHash !== envelope.signature_payload_hash) {
    check(checks, "payload_hash", false, `stored ${envelope.signature_payload_hash}, recomputed ${recomputedPayloadHash}`);
    return fail(checks, "SIGNED_RESULT_PAYLOAD_HASH_INVALID", "signature_payload_hash does not match recomputed hash");
  }
  check(checks, "payload_hash", true);

  // ── 17. Verify Ed25519 signature ──────────────────────────────────────────
  let sigBodyStr;
  try {
    sigBodyStr = signatureBody(envelope);
  } catch {
    check(checks, "signature", false, "canonicalization failed");
    return fail(checks, "SIGNED_RESULT_CANONICALIZATION_INVALID", "failed to canonicalize signature body");
  }
  const sigOk = await verifyCanonical(sigBodyStr, sig.value, keyResult.publicKey);
  if (!sigOk) {
    check(checks, "signature", false, "Ed25519 signature verification failed");
    return fail(checks, "SIGNED_RESULT_SIGNATURE_INVALID", "Ed25519 signature verification failed");
  }
  check(checks, "signature", true);

  // ── 18. Evidence safety — recursive, case-insensitive forbidden-field scan ─
  const evidenceItems = Array.isArray(er.evidence) ? er.evidence : [];
  const forbidden = [];
  for (const item of evidenceItems) {
    collectForbiddenFields(item, forbidden);
  }
  if (forbidden.length > 0) {
    check(checks, "evidence_safety", false, `forbidden field(s) in evidence: ${forbidden.join(", ")}`);
    return fail(checks, "SIGNED_RESULT_EVIDENCE_FORBIDDEN_FIELD", `evidence contains forbidden field(s): ${forbidden.join(", ")}`);
  }
  check(checks, "evidence_safety", true);

  // ── 19. Derive passport_subject_id ────────────────────────────────────────
  // Computed from the verified assertion's issuer + verified_identity and the
  // envelope's authority_chain_id. Null when no identity_assertion is present.
  // executor.id is NOT used — it is instance evidence, not the passport key.
  const passportSubjectId = identityLevel === "ASSERTION_HASH_BOUND"
    ? derivePassportSubjectId(er.executor?.identity_assertion, envelope.authority_chain_id)
    : null;

  return pass(checks, envelope, auth.key_id, derivedBundleFp, derivedKeyFp, keyResult.revocation_freshness, identityLevel, passportSubjectId);
}
