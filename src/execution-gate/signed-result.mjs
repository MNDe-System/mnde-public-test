// Builder for mnde.signed_execution_result.v1.
//
// Proves that a specific execution result was recorded under MNDe authority,
// bound to a verified signed execution receipt, and verifiable offline.
//
// Does NOT authorize execution. Records what happened after the decision.
//
// Canonical construction — two distinct payloads:
//
//   Payload hash body   = envelope without {signature_payload_hash, verifiable_signature}
//   Signature body      = envelope without {verifiable_signature} only
//                         (includes signature_payload_hash, covering it inside the sig)
//
// This avoids circular hash inclusion: signature_payload_hash is computed over
// a body that does not yet contain it; then the signature covers a body that
// does contain it, so the hash cannot be swapped without breaking the signature.
//
// Role separation: only keys with role "result" may sign. Receipt keys, policy
// keys, and approval keys cannot sign a result envelope.

import { canonicalizeJson } from "../../shared/json.ts";
import { sha256 } from "../crypto/provider.mjs";
import { findBundleKey, fingerprintOf, signCanonical, verifyAuthorityBundle } from "../custody/index.mjs";
import { verifySignedExecutionReceipt } from "./verify-signed-receipt.mjs";
import { verifyExecutionResult } from "./verify-result.mjs";

export const SIGNED_RESULT_SCHEMA = "mnde.signed_execution_result.v1";
export const SIGNED_RESULT_TRUST_MODEL = "offline-root-pinned";

// Canonical payload for signature_payload_hash — excludes both
// signature_payload_hash and verifiable_signature.
function payloadHashBody(envelope) {
  const { signature_payload_hash: _sph, verifiable_signature: _vs, ...body } = envelope;
  return canonicalizeJson(body);
}

// Canonical payload for Ed25519 signing — excludes only verifiable_signature.
// Includes signature_payload_hash so the hash is covered by the signature.
function signatureBody(envelope) {
  const { verifiable_signature: _vs, ...body } = envelope;
  return canonicalizeJson(body);
}

function sha256Hex(str) {
  return sha256(str);
}

// Build an mnde.signed_execution_result.v1 envelope.
//
// options:
//   authorityBundle        — loaded mnde.authority.bundle.v1 (public material)
//   trustedRootFingerprint — out-of-band hex sha256 of the root public key DER
//   signingKeyId           — key_id of the result key in the bundle
//   signingPrivateKeyPem   — Ed25519 private key PEM (never embedded in output)
//   authorityChainId       — stable authority lineage identifier (not a fingerprint)
//   signedAt               — ISO-8601 wall-clock for when this envelope is signed
//   now                    — ISO-8601 for authority bundle staleness check (default: signedAt)
//   signedReceipt          — the verified mnde.execution_gate.receipt.v1 object
//                            (caller must verify it first via verifySignedExecutionReceipt)
//
// Returns the signed result envelope.
// Throws on any precondition failure.
export async function buildSignedExecutionResult(executionResult, options) {
  const {
    authorityBundle,
    trustedRootFingerprint,
    signingKeyId,
    signingPrivateKeyPem,
    authorityChainId,
    signedAt,
    now,
    signedReceipt
  } = options ?? {};

  if (!authorityBundle || !trustedRootFingerprint || !signingKeyId || !signingPrivateKeyPem) {
    throw new Error("buildSignedExecutionResult: authorityBundle, trustedRootFingerprint, signingKeyId, and signingPrivateKeyPem are required");
  }
  if (typeof authorityChainId !== "string" || authorityChainId.length === 0) {
    throw new Error("buildSignedExecutionResult: authorityChainId is required");
  }
  if (typeof signedAt !== "string") {
    throw new Error("buildSignedExecutionResult: signedAt is required");
  }
  if (!signedReceipt) {
    throw new Error("buildSignedExecutionResult: signedReceipt is required — verify the receipt before building the result envelope");
  }

  // ── 1. Verify the unsigned execution result ──────────────────────────────
  const resultVerification = await verifyExecutionResult(executionResult);
  if (!resultVerification.verified) {
    throw new Error(`buildSignedExecutionResult: execution_result is invalid — ${resultVerification.reason}`);
  }

  // ── 2. Verify the signed execution receipt ───────────────────────────────
  const receiptVerification = await verifySignedExecutionReceipt(signedReceipt, {
    authorityBundle,
    trustedRootFingerprint,
    now: now ?? signedAt
  });
  if (!receiptVerification.verified) {
    throw new Error(`buildSignedExecutionResult: signed receipt is invalid — ${receiptVerification.reason}`);
  }

  // ── 3. Bind result to receipt ────────────────────────────────────────────
  const receiptHash = sha256Hex(canonicalizeJson(signedReceipt));
  if (executionResult.execution_receipt_hash !== receiptHash) {
    throw new Error("buildSignedExecutionResult: execution_result.execution_receipt_hash does not match the provided signed receipt");
  }
  if (executionResult.execution_id !== signedReceipt.execution_id) {
    throw new Error("buildSignedExecutionResult: execution_id mismatch between result and receipt");
  }
  if (executionResult.execution_request_hash !== signedReceipt.request_hash) {
    throw new Error("buildSignedExecutionResult: execution_request_hash mismatch between result and receipt");
  }
  if (executionResult.decision !== signedReceipt.decision) {
    throw new Error("buildSignedExecutionResult: decision mismatch between result and receipt");
  }

  // ── 4. Decision-status compatibility ────────────────────────────────────
  // Validated by verifyExecutionResult already; explicit guard here for role-
  // separation clarity: the builder refuses to sign an incompatible envelope.
  if (signedReceipt.decision === "REFUSE" && executionResult.status !== "NOT_EXECUTED") {
    throw new Error(`buildSignedExecutionResult: REFUSE decision requires NOT_EXECUTED status (got "${executionResult.status}")`);
  }

  // ── 5. Verify authority bundle ───────────────────────────────────────────
  const bundleCheck = await verifyAuthorityBundle(authorityBundle, {
    trustedRootFingerprint,
    now: now ?? signedAt
  });
  if (!bundleCheck.ok) {
    throw new Error(`buildSignedExecutionResult: authority bundle invalid — ${bundleCheck.reason}`);
  }

  // ── 6. Find result signing key (role: "result" only) ────────────────────
  const keyResult = findBundleKey(authorityBundle, "result", signingKeyId, signedAt);
  if (!keyResult.ok) {
    throw new Error(`buildSignedExecutionResult: result signing key not usable — ${keyResult.reason}`);
  }

  // ── 7. Derive fingerprints — never trust caller-supplied values ──────────
  const authorityBundleFingerprint = authorityBundle.root_key.fingerprint;
  const signingKeyFingerprint = fingerprintOf(keyResult.publicKey);

  // ── 8. Build the envelope body (no hashes or signatures yet) ────────────
  const envelopeBody = {
    schema: SIGNED_RESULT_SCHEMA,
    signed_at: signedAt,
    trust_model: SIGNED_RESULT_TRUST_MODEL,
    authority_chain_id: authorityChainId,
    execution_result: executionResult,
    receipt_binding: {
      execution_receipt_hash: receiptHash,
      execution_request_hash: executionResult.execution_request_hash,
      execution_id: executionResult.execution_id,
      receipt_schema: signedReceipt.schema_version ?? signedReceipt.schema
    },
    authority: {
      authority_id: authorityBundle.authority_id,
      authority_bundle_fingerprint: authorityBundleFingerprint,
      signing_key_fingerprint: signingKeyFingerprint,
      key_id: signingKeyId,
      key_role: "result",
      algorithm: "ED25519"
    }
  };

  // ── 9. Compute signature_payload_hash ────────────────────────────────────
  // Hash the payload hash body (envelope without signature_payload_hash and
  // without verifiable_signature). This is non-circular: the hash covers a
  // body that does not yet contain it.
  const payloadHashBytes = payloadHashBody(envelopeBody);
  const signaturePayloadHash = sha256Hex(payloadHashBytes);

  // Insert signature_payload_hash into the envelope.
  const envelopeWithHash = { ...envelopeBody, signature_payload_hash: signaturePayloadHash };

  // ── 10. Sign the canonical signature body ────────────────────────────────
  // Sign the envelope that includes signature_payload_hash but excludes
  // verifiable_signature. Ed25519 signs canonical UTF-8 bytes directly.
  const sigBodyBytes = signatureBody(envelopeWithHash);
  const signatureValue = await signCanonical(sigBodyBytes, signingPrivateKeyPem);

  // ── 11. Assemble final envelope ──────────────────────────────────────────
  return {
    ...envelopeWithHash,
    verifiable_signature: {
      algorithm: "ED25519",
      key_id: signingKeyId,
      value: signatureValue
    }
  };
}
