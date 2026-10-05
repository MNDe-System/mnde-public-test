// Structural verifier for mnde.identity_assertion.v1.
//
// Verifies schema, required fields, hash formats, and that assertion_hash
// recomputes correctly from the canonical body. Does NOT:
//   - call the network
//   - re-verify the original OIDC token
//   - check token expiry
//   - fetch JWKS
//
// All live verification happened in the adapter before this object existed.
// MNDe's job here is to verify that the assertion is structurally intact and
// that its hash commits to exactly the fields the verifier recorded.

import { computeAssertionHash, IDENTITY_ASSERTION_SCHEMA, validateIdentityAssertion } from "./assertion.mjs";

function fail(code, message) {
  return { valid: false, code, message };
}

// Verify an mnde.identity_assertion.v1 object.
// Returns { valid, code?, message? }.
export function verifyIdentityAssertion(assertion) {
  // ── 1. Structural validation ─────────────────────────────────────────────
  // validateIdentityAssertion returns structured { field, code, message } errors.
  // Route on .code — never on .message text, which is allowed to change.
  const validation = validateIdentityAssertion(assertion);
  if (!validation.ok) {
    const { code, message } = validation.errors[0];
    return fail(code, message);
  }

  // ── 2. assertion_hash integrity ──────────────────────────────────────────
  // Recompute the hash from the canonical body (excluding assertion_hash itself)
  // and confirm it matches what was recorded. This is the tamper-evidence check.
  const recomputed = computeAssertionHash(assertion);
  if (assertion.assertion_hash !== recomputed) {
    return fail(
      "IDENTITY_ASSERTION_HASH_INVALID",
      `assertion_hash does not match recomputed hash (stored ${assertion.assertion_hash}, computed ${recomputed})`
    );
  }

  return {
    valid: true,
    schema: IDENTITY_ASSERTION_SCHEMA,
    verified_identity: assertion.verified_identity,
    identity_subject: assertion.identity_subject,
    identity_issuer: assertion.identity_issuer,
    identity_verification_method: assertion.identity_verification_method,
    verifier_name: assertion.verifier_name
  };
}
