// GitHub Actions OIDC adapter for mnde.identity_assertion.v1.
//
// Performs offline OIDC verification using a caller-supplied JWKS and
// verifier policy. Does NOT fetch JWKS from the network. The caller
// pre-fetches the JWKS and pins it via trusted_jwks_hash in the policy.
//
// The JWKS is only accepted if its canonical sha256 hash matches
// trusted_jwks_hash in the policy. This prevents "caller-supplied" from
// becoming "caller-decides trust root."
//
// Input:
//   rawJwt         — the raw GitHub Actions OIDC token (JWT string)
//   verifierPolicy — { issuer, audience (required), subject_allowlist | allow_all_subjects,
//                       trusted_jwks_hash (required), max_token_age_seconds, clock_skew_seconds }
//   jwks           — the pre-fetched JWKS object { keys: [...] }
//   options        — { nowMs?, assertedIdentity?, verifierName?, verifierVersion? }
//
// Policy requirements:
//   audience must be a non-empty string — omitting it would silently skip audience validation.
//   subject_allowlist must be a non-empty string array, OR allow_all_subjects: true must be set.
//   Silence is never allow-all.
//
// Output: mnde.identity_assertion.v1 object, or throws on any failure.

import { createHash, createPublicKey, createVerify } from "node:crypto";

import { canonicalizeJson } from "../../../shared/json.ts";
import { buildIdentityAssertion } from "../assertion.mjs";

export const GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com";
export const VERIFIER_NAME = "mnde-github-actions-verifier";
export const VERIFIER_VERSION = "1.0.0";

// Only RS256 is accepted — GitHub Actions OIDC tokens use RS256.
const SUPPORTED_ALGORITHM = "RS256";

function sha256Tagged(value) {
  return "sha256:" + createHash("sha256").update(value).digest("hex");
}

function sha256TaggedObj(obj) {
  return "sha256:" + createHash("sha256").update(canonicalizeJson(obj), "utf8").digest("hex");
}

// Guard used for both exp and iat — must be a finite number (not NaN, not Infinity,
// not a string, not null, not missing).
function isFiniteNumber(v) {
  return typeof v === "number" && Number.isFinite(v);
}

// Parse a JWT into { header, payload, signature, signingInput }.
// Throws on malformed input.
function parseJwt(rawJwt) {
  if (typeof rawJwt !== "string") throw Object.assign(new Error("rawJwt must be a string"), { code: "OIDC_JWT_MALFORMED" });
  const parts = rawJwt.split(".");
  if (parts.length !== 3) throw Object.assign(new Error("JWT must have exactly three parts"), { code: "OIDC_JWT_MALFORMED" });
  let header, payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    throw Object.assign(new Error("JWT header or payload is not valid JSON"), { code: "OIDC_JWT_MALFORMED" });
  }
  return {
    header,
    payload,
    signature: Buffer.from(parts[2], "base64url"),
    signingInput: parts[0] + "." + parts[1]
  };
}

// Find a JWK in the JWKS by kid. Returns the matching JWK or null.
function findKey(jwks, kid) {
  if (!Array.isArray(jwks?.keys)) return null;
  return jwks.keys.find((k) => k.kid === kid) ?? null;
}

// Verify an RS256 JWT signature against a JWK.
function verifyRs256(signingInput, signature, jwk) {
  let publicKey;
  try {
    publicKey = createPublicKey({ key: jwk, format: "jwk" });
  } catch {
    return false;
  }
  try {
    const v = createVerify("RSA-SHA256");
    v.update(signingInput, "ascii");
    return v.verify(publicKey, signature);
  } catch {
    return false;
  }
}

// Check whether a subject matches an allowlist entry.
// Entries ending in "*" are treated as prefix wildcards.
function matchesAllowlist(subject, allowlist) {
  if (!Array.isArray(allowlist) || allowlist.length === 0) return false;
  return allowlist.some((pattern) => {
    if (typeof pattern !== "string") return false;
    return pattern.endsWith("*")
      ? subject.startsWith(pattern.slice(0, -1))
      : subject === pattern;
  });
}

// Verify a GitHub Actions OIDC token and produce an mnde.identity_assertion.v1.
//
// Throws with a structured .code property on any failure.
// Return value is a fully-built mnde.identity_assertion.v1 object.
export function verifyGitHubActionsOidc(rawJwt, verifierPolicy, jwks, options = {}) {
  const {
    nowMs = Date.now(),
    assertedIdentity,
    verifierName = VERIFIER_NAME,
    verifierVersion = VERIFIER_VERSION
  } = options;

  if (!verifierPolicy || typeof verifierPolicy !== "object") {
    throw Object.assign(new Error("verifierPolicy is required"), { code: "OIDC_JWT_MALFORMED" });
  }

  const {
    issuer = GITHUB_ACTIONS_ISSUER,
    audience,
    subject_allowlist,
    allow_all_subjects: allowAllSubjects = false,
    trusted_jwks_hash,
    max_token_age_seconds = 600,
    clock_skew_seconds = 30
  } = verifierPolicy;

  // ── 1. Policy validation ──────────────────────────────────────────────────
  // All three checks must pass before touching the JWT or JWKS. A misconfigured
  // policy must be rejected loudly — silence is never allow-all.
  if (typeof trusted_jwks_hash !== "string") {
    throw Object.assign(new Error("verifierPolicy.trusted_jwks_hash is required"), { code: "OIDC_JWT_MALFORMED" });
  }
  // audience is required. Omitting it would silently skip audience validation,
  // allowing tokens issued for any service to pass.
  if (typeof audience !== "string" || audience.length === 0) {
    throw Object.assign(new Error("verifierPolicy.audience must be a non-empty string"), { code: "OIDC_JWT_MALFORMED" });
  }
  // subject scope must be explicit. Absent or empty allowlist without allow_all_subjects
  // is rejected — this prevents silent allow-all from a misconfigured policy.
  if (!allowAllSubjects && (!Array.isArray(subject_allowlist) || subject_allowlist.length === 0)) {
    throw Object.assign(
      new Error("verifierPolicy.subject_allowlist must be a non-empty array, or set allow_all_subjects: true"),
      { code: "OIDC_JWT_MALFORMED" }
    );
  }

  // ── 2. JWKS hash must match policy pin ───────────────────────────────────
  // Reject caller-supplied JWKS unless its canonical hash equals trusted_jwks_hash.
  // This prevents an attacker from substituting a JWKS containing their own key.
  const actualJwksHash = sha256TaggedObj(jwks);
  if (actualJwksHash !== trusted_jwks_hash) {
    throw Object.assign(
      new Error(`JWKS canonical hash ${actualJwksHash} does not match trusted_jwks_hash ${trusted_jwks_hash}`),
      { code: "OIDC_JWKS_HASH_MISMATCH" }
    );
  }

  // ── 3. Parse JWT ─────────────────────────────────────────────────────────
  const { header, payload, signature, signingInput } = parseJwt(rawJwt);

  // ── 4. Algorithm must be RS256 ────────────────────────────────────────────
  if (header.alg !== SUPPORTED_ALGORITHM) {
    throw Object.assign(
      new Error(`JWT algorithm must be ${SUPPORTED_ALGORITHM}, got ${JSON.stringify(header.alg)}`),
      { code: "OIDC_ALGORITHM_UNSUPPORTED" }
    );
  }

  // ── 5. Find signing key by kid ────────────────────────────────────────────
  const kid = header.kid;
  if (!kid) {
    throw Object.assign(new Error("JWT header is missing kid"), { code: "OIDC_KEY_NOT_FOUND" });
  }
  const jwk = findKey(jwks, kid);
  if (!jwk) {
    throw Object.assign(new Error(`No key with kid "${kid}" in JWKS`), { code: "OIDC_KEY_NOT_FOUND" });
  }

  // ── 6. Verify signature ───────────────────────────────────────────────────
  if (!verifyRs256(signingInput, signature, jwk)) {
    throw Object.assign(new Error("JWT signature verification failed"), { code: "OIDC_SIGNATURE_INVALID" });
  }

  // ── 7. Require finite exp — enforce AFTER signature so claims are authentic ─
  // Missing, null, string, NaN, or Infinity all fail. If exp cannot be verified,
  // we treat the token as expired (fail-closed).
  if (!isFiniteNumber(payload.exp)) {
    throw Object.assign(new Error("JWT exp claim must be a finite number"), { code: "OIDC_TOKEN_EXPIRED" });
  }

  // ── 8. Require finite iat — enforce AFTER signature so claims are authentic ─
  // Missing, null, string, NaN, or Infinity all fail. If iat cannot be verified,
  // we treat the token as too old (fail-closed).
  if (!isFiniteNumber(payload.iat)) {
    throw Object.assign(new Error("JWT iat claim must be a finite number"), { code: "OIDC_TOKEN_TOO_OLD" });
  }

  // ── 9. Verify issuer ──────────────────────────────────────────────────────
  if (payload.iss !== issuer) {
    throw Object.assign(
      new Error(`JWT issuer "${payload.iss}" does not match expected "${issuer}"`),
      { code: "OIDC_ISSUER_MISMATCH" }
    );
  }

  // ── 10. Verify audience ───────────────────────────────────────────────────
  // audience is guaranteed non-empty string from policy validation above.
  const tokenAud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!tokenAud.includes(audience)) {
    throw Object.assign(
      new Error(`JWT audience ${JSON.stringify(payload.aud)} does not include "${audience}"`),
      { code: "OIDC_AUDIENCE_MISMATCH" }
    );
  }

  // ── 11. Verify subject against allowlist ──────────────────────────────────
  // Skipped only when allow_all_subjects is explicitly true. If !allowAllSubjects,
  // subject_allowlist is guaranteed non-empty from policy validation above.
  const subject = payload.sub;
  if (!allowAllSubjects) {
    if (!matchesAllowlist(subject, subject_allowlist)) {
      throw Object.assign(
        new Error(`JWT subject "${subject}" is not in subject_allowlist`),
        { code: "OIDC_SUBJECT_NOT_ALLOWED" }
      );
    }
  }

  // ── 12. Verify expiry ─────────────────────────────────────────────────────
  // exp is a finite number — guaranteed by step 7.
  const nowS = nowMs / 1000;
  if (nowS > payload.exp + clock_skew_seconds) {
    throw Object.assign(
      new Error(`JWT expired at ${new Date(payload.exp * 1000).toISOString()} (now ${new Date(nowMs).toISOString()})`),
      { code: "OIDC_TOKEN_EXPIRED" }
    );
  }

  // ── 13. Verify not-before ─────────────────────────────────────────────────
  if (typeof payload.nbf === "number" && nowS < payload.nbf - clock_skew_seconds) {
    throw Object.assign(
      new Error(`JWT not valid before ${new Date(payload.nbf * 1000).toISOString()}`),
      { code: "OIDC_TOKEN_NOT_YET_VALID" }
    );
  }

  // ── 14. Verify token age ──────────────────────────────────────────────────
  // iat is a finite number — guaranteed by step 8.
  if (nowS - payload.iat > max_token_age_seconds + clock_skew_seconds) {
    throw Object.assign(
      new Error(`JWT issued at ${new Date(payload.iat * 1000).toISOString()} exceeds max_token_age_seconds ${max_token_age_seconds}`),
      { code: "OIDC_TOKEN_TOO_OLD" }
    );
  }

  // ── 15. Build effective policy and assertion ──────────────────────────────
  // Hash the effective policy — with all defaults applied — so that a policy
  // that omits max_token_age_seconds produces the same hash as one that explicitly
  // sets it to 600. The hash commits to the actual validation parameters used.
  const effectivePolicy = {
    issuer,
    audience,
    trusted_jwks_hash,
    max_token_age_seconds,
    clock_skew_seconds,
    ...(allowAllSubjects ? { allow_all_subjects: true } : { subject_allowlist })
  };

  const verifiedAt = new Date(nowMs).toISOString().replace(/\.\d{3}Z$/, ".000Z");
  const policyHash = sha256TaggedObj(effectivePolicy);
  const tokenHash = sha256Tagged(Buffer.from(rawJwt, "ascii"));
  const resolvedAud = Array.isArray(payload.aud) ? payload.aud[0] : (payload.aud ?? audience);

  return buildIdentityAssertion({
    asserted_identity: assertedIdentity ?? subject,
    verified_identity: subject,
    identity_verification_method: "github_actions_oidc",
    identity_issuer: payload.iss,
    identity_subject: subject,
    identity_audience: resolvedAud,
    identity_token_hash: tokenHash,
    verifier_name: verifierName,
    verifier_version: verifierVersion,
    verifier_policy_hash: policyHash,
    verified_at: verifiedAt
  });
}
