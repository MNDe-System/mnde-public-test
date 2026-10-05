// Schema and primitives for mnde.identity_assertion.v1.
//
// An identity assertion is produced by an external identity verifier
// (e.g. an OIDC adapter). It is NOT produced by MNDe. MNDe only records
// it, validates its structure and hash integrity, and binds it into the
// signed execution result.
//
// MNDe does not call the internet, fetch JWKS endpoints, or check token
// revocation. All of that happens in the adapter before this object exists.

import { sha256 } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";

export const IDENTITY_ASSERTION_SCHEMA = "mnde.identity_assertion.v1";

const SHA256_TAGGED_RE = /^sha256:[a-f0-9]{64}$/;
const UTC_ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

// Compute assertion_hash over canonical body with assertion_hash excluded.
export function computeAssertionHash(body) {
  const { assertion_hash: _ah, ...rest } = body;
  return "sha256:" + sha256(canonicalizeJson(rest));
}

// Validate an mnde.identity_assertion.v1 object (structural only).
// Returns { ok: true } or { ok: false, errors: { field, code, message }[] }.
// Callers must use .field and .code — do not match on .message text.
export function validateIdentityAssertion(a) {
  if (typeof a !== "object" || a === null || Array.isArray(a)) {
    return {
      ok: false,
      errors: [{ field: "schema", code: "IDENTITY_ASSERTION_SCHEMA_INVALID", message: "identity_assertion must be an object" }]
    };
  }

  const errors = [];

  if (a.schema !== IDENTITY_ASSERTION_SCHEMA) {
    errors.push({ field: "schema", code: "IDENTITY_ASSERTION_SCHEMA_INVALID", message: `schema must be "${IDENTITY_ASSERTION_SCHEMA}", got ${JSON.stringify(a.schema)}` });
  }

  for (const field of [
    "asserted_identity",
    "verified_identity",
    "identity_verification_method",
    "identity_issuer",
    "identity_subject",
    "identity_audience",
    "verifier_name",
    "verifier_version"
  ]) {
    if (typeof a[field] !== "string" || a[field].length === 0) {
      errors.push({ field, code: "IDENTITY_ASSERTION_FIELD_REQUIRED", message: `${field} must be a non-empty string` });
    }
  }

  if (!SHA256_TAGGED_RE.test(a.identity_token_hash)) {
    errors.push({ field: "identity_token_hash", code: "IDENTITY_ASSERTION_TOKEN_HASH_INVALID", message: "identity_token_hash must be sha256:<64-hex>" });
  }
  if (!SHA256_TAGGED_RE.test(a.verifier_policy_hash)) {
    errors.push({ field: "verifier_policy_hash", code: "IDENTITY_ASSERTION_POLICY_HASH_INVALID", message: "verifier_policy_hash must be sha256:<64-hex>" });
  }
  if (!SHA256_TAGGED_RE.test(a.assertion_hash)) {
    errors.push({ field: "assertion_hash", code: "IDENTITY_ASSERTION_HASH_INVALID", message: "assertion_hash must be sha256:<64-hex>" });
  }
  if (typeof a.verified_at !== "string" || !UTC_ISO_RE.test(a.verified_at) || Number.isNaN(Date.parse(a.verified_at))) {
    errors.push({ field: "verified_at", code: "IDENTITY_ASSERTION_VERIFIED_AT_INVALID", message: "verified_at must be a valid ISO-8601 UTC datetime" });
  }

  return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

// Build an mnde.identity_assertion.v1 object.
// The adapter calls this after completing OIDC verification.
// Throws on invalid inputs.
export function buildIdentityAssertion(fields) {
  const body = {
    schema: IDENTITY_ASSERTION_SCHEMA,
    asserted_identity: fields.asserted_identity,
    verified_identity: fields.verified_identity,
    identity_verification_method: fields.identity_verification_method,
    identity_issuer: fields.identity_issuer,
    identity_subject: fields.identity_subject,
    identity_audience: fields.identity_audience,
    identity_token_hash: fields.identity_token_hash,
    verifier_name: fields.verifier_name,
    verifier_version: fields.verifier_version,
    verifier_policy_hash: fields.verifier_policy_hash,
    verified_at: fields.verified_at
  };
  const assertion = { ...body, assertion_hash: computeAssertionHash(body) };
  const validation = validateIdentityAssertion(assertion);
  if (!validation.ok) {
    throw new Error(`buildIdentityAssertion: invalid — ${validation.errors.join("; ")}`);
  }
  return assertion;
}
