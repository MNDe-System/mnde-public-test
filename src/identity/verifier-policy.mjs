// Signed, versioned verifier policy for the pre-execution identity gate.
//
// Schema: mnde.verifier_policy.v1 (see docs/pre-execution-identity-authority-v1.md §6).
//
// This object is the trust root for principal identity. Because principal keys
// are NOT enrolled in the authority bundle, trust in an external issuer is
// entirely a function of this policy: which verifier_policy_hash values are
// approved, and what minimum identity_level each (environment, authority_scope)
// requires. A poisoned policy is the "poisoned root template" for identity.
//
// Trust anchor (single source): the policy does NOT embed its own root key. It
// is custody-root-signed and REFERENCES the authority via `authority_id` (and
// optional `root_key_id`). Verification uses the root public key carried by the
// already-verified mnde.authority.bundle.v1 — the same custody chain as receipts,
// results, and activations. There is exactly one copy of the trust anchor.
//
// Two verification modes are kept strictly separate:
//   Operational (loadVerifierPolicy): signature + root trust + version high-water
//     mark + optional expiry (only when `now` is supplied). Used when accepting a
//     newly published policy at runtime.
//   Deterministic / replay (verifyPolicySignature + the receipt-recorded
//     decision inputs): signature only, no version/expiry/clock. A receipt must
//     never fail replay because a policy later expired or was superseded.
//
// Design constraints enforced here:
//   - No live OIDC. This file never parses a JWT or fetches a JWKS.
//   - No wall-clock in the deterministic path. verifyPolicySignature,
//     isApprovedPolicyHash, and requiredDecisionPolicy are pure.
//   - Custody-signed (root key), same signing bytes as src/custody/bundle.mjs.
//   - Monotonic policy_version; rollback rejected against a high-water mark.
//   - Fail closed: requiredDecisionPolicy returns DENY when no (environment,
//     authority_scope) rule exists; DENY.accepts(x) is always false.
//
// Default model: one authority bundle ↔ one authority_chain_id. No multi-chain
// allowlist. `authority_scope` in the min-level table is an authority_chain_id.

import { sha256 } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";
import {
  createFileRootSigner,
  signWithRootSigner,
  verifyCanonical
} from "../custody/index.mjs";

export const VERIFIER_POLICY_SCHEMA = "mnde.verifier_policy.v1";

// ── Assurance ladder — single ordered enum ─────────────────────────────────
// Rank is the array index; nothing else defines ordering, so two call sites can
// never disagree. VERIFIED_BY_EXTERNAL_VERIFIER intentionally does not exist:
// the offline verifier cannot re-prove external verification, so the ceiling is
// ASSERTION_HASH_BOUND (see verify-result.mjs — which SHOULD import this enum).
export const IDENTITY_LEVELS = Object.freeze(["ASSERTED_ONLY", "ASSERTION_HASH_BOUND"]);
export function levelRank(level) {
  return IDENTITY_LEVELS.indexOf(level); // -1 for unknown / "DENY"
}

const ENVIRONMENTS = new Set(["dev", "staging", "production"]);
const SHA256_TAGGED_RE = /^sha256:[a-f0-9]{64}$/;

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function isNonEmptyString(v) {
  return typeof v === "string" && v.length > 0;
}

// ── Effective verifier-policy hash (canonical, exact field set) ─────────────
// MUST match the value the OIDC adapter records as verifier_policy_hash
// (github-actions.mjs §15). The hash is:
//
//   "sha256:" + sha256(canonicalizeJson({
//     issuer, audience, trusted_jwks_hash,
//     max_token_age_seconds, clock_skew_seconds,
//     subject_allowlist | allow_all_subjects   // exactly one, mutually exclusive
//   }))
//
// canonicalizeJson sorts keys, so authoring field order is irrelevant. The
// defaults (600 / 30) mirror the adapter's destructuring defaults so an entry
// that omits them hashes identically to a token verified with them. This is the
// single canonical definition; the adapter SHOULD import it (see patch trace).
export function effectiveVerifierPolicyHash(entry) {
  const effective = {
    issuer: entry.issuer,
    audience: entry.audience,
    trusted_jwks_hash: entry.trusted_jwks_hash,
    max_token_age_seconds: entry.max_token_age_seconds ?? 600,
    clock_skew_seconds: entry.clock_skew_seconds ?? 30,
    ...(entry.allow_all_subjects ? { allow_all_subjects: true } : { subject_allowlist: entry.subject_allowlist })
  };
  return "sha256:" + sha256(canonicalizeJson(effective));
}

// Content identity of the signed policy (body without signature). Recorded in
// the receipt so a decision pins the exact policy it was made under.
export function policyDocumentHash(policy) {
  const { signature: _omit, ...body } = policy;
  return "sha256:" + sha256(canonicalizeJson(body));
}

// ── Structural validation ──────────────────────────────────────────────────
// Returns { ok: true } or { ok: false, errors: string[] }. Never throws.
export function validateVerifierPolicy(policy) {
  const errors = [];
  if (!isObject(policy)) return { ok: false, errors: ["policy must be an object"] };

  // Schema version is checked first and exactly — a future version (e.g. v2)
  // MUST be rejected, never silently accepted.
  if (policy.schema_version !== VERIFIER_POLICY_SCHEMA) {
    errors.push(`schema_version must be "${VERIFIER_POLICY_SCHEMA}" (got ${JSON.stringify(policy.schema_version)})`);
  }
  if (!isNonEmptyString(policy.authority_id)) errors.push("authority_id must be a non-empty string");
  if (policy.root_key_id !== undefined && !isNonEmptyString(policy.root_key_id)) {
    errors.push("root_key_id must be a non-empty string when present");
  }
  if (!Number.isInteger(policy.policy_version) || policy.policy_version < 1) {
    errors.push("policy_version must be an integer >= 1");
  }
  if (!isNonEmptyString(policy.issued_at)) errors.push("issued_at must be a non-empty string");
  if (policy.not_after !== null && !isNonEmptyString(policy.not_after)) {
    errors.push("not_after must be a non-empty string or null");
  }

  if (!Array.isArray(policy.verifier_policies) || policy.verifier_policies.length === 0) {
    errors.push("verifier_policies must be a non-empty array");
  } else {
    policy.verifier_policies.forEach((e, i) => {
      if (!isObject(e)) { errors.push(`verifier_policies[${i}] must be an object`); return; }
      if (!isNonEmptyString(e.issuer)) errors.push(`verifier_policies[${i}].issuer required`);
      if (!isNonEmptyString(e.audience)) errors.push(`verifier_policies[${i}].audience required`);
      if (!SHA256_TAGGED_RE.test(e.trusted_jwks_hash)) errors.push(`verifier_policies[${i}].trusted_jwks_hash must be sha256:<64-hex>`);
      const scoped = e.allow_all_subjects === true;
      if (!scoped && (!Array.isArray(e.subject_allowlist) || e.subject_allowlist.length === 0)) {
        errors.push(`verifier_policies[${i}] must set a non-empty subject_allowlist or allow_all_subjects: true`);
      }
      if (e.policy_hash !== undefined && !SHA256_TAGGED_RE.test(e.policy_hash)) {
        errors.push(`verifier_policies[${i}].policy_hash must be sha256:<64-hex> when present`);
      }
    });
  }

  if (!Array.isArray(policy.min_level_table)) {
    errors.push("min_level_table must be an array");
  } else {
    policy.min_level_table.forEach((r, i) => {
      if (!isObject(r)) { errors.push(`min_level_table[${i}] must be an object`); return; }
      if (!ENVIRONMENTS.has(r.environment)) errors.push(`min_level_table[${i}].environment invalid`);
      if (!isNonEmptyString(r.authority_scope)) errors.push(`min_level_table[${i}].authority_scope required`);
      if (!IDENTITY_LEVELS.includes(r.min_level)) errors.push(`min_level_table[${i}].min_level must be one of ${IDENTITY_LEVELS.join(", ")}`);
    });
  }

  const sig = policy.signature;
  if (!isObject(sig) || sig.algorithm !== "ED25519" || !isNonEmptyString(sig.value)) {
    errors.push("signature must be { algorithm: 'ED25519', value }");
  }

  return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

// ── verifyPolicySignature (deterministic / replay-safe) ────────────────────
// Pure. No version, expiry, or wall-clock. Verifies the custody-root signature
// over the canonical body (signature excluded) using a caller-supplied root
// public key — normally authorityBundle.root_key.public_key from an already-
// verified bundle. This is the ONLY policy check that runs on the replay path.
export async function verifyPolicySignature(policy, { rootPublicKey } = {}) {
  if (!isObject(policy) || !isObject(policy.signature)) return { ok: false, reason: "MALFORMED_POLICY" };
  if (!isNonEmptyString(rootPublicKey)) return { ok: false, reason: "MISSING_ROOT_KEY" };
  const { signature, ...body } = policy;
  const ok = await verifyCanonical(canonicalizeJson(body), signature.value, rootPublicKey);
  return ok ? { ok: true } : { ok: false, reason: "POLICY_SIGNATURE_INVALID" };
}

// ── loadVerifierPolicy (operational) ───────────────────────────────────────
// Runtime entry point for accepting a policy. Binds the policy to an already-
// verified authority bundle (single trust anchor), verifies the signature with
// the bundle's root key, enforces the rollback high-water mark, and optionally
// checks not_after when `now` is supplied (operational only — never replay).
// Returns { ok: false, reason } on any failure so the gate fails closed; never
// throws.
//
// options:
//   authorityBundle        — an mnde.authority.bundle.v1 ALREADY verified via
//                            verifyAuthorityBundle (root pinned to the out-of-band
//                            trustedRootFingerprint)
//   trustedRootFingerprint — out-of-band hex sha256 of the custody root key;
//                            re-pinned here against the bundle root
//   highWaterMark          — highest policy_version already accepted (rollback floor)
//   now                    — optional ISO-8601; if given, reject a policy past not_after
export async function loadVerifierPolicy(raw, options = {}) {
  const { authorityBundle, trustedRootFingerprint, highWaterMark = 0, now } = options;

  const structural = validateVerifierPolicy(raw);
  if (!structural.ok) return { ok: false, reason: "POLICY_MALFORMED", errors: structural.errors };

  // Trust anchor comes from the verified bundle — not from the policy itself.
  if (!isObject(authorityBundle) || !isObject(authorityBundle.root_key)) {
    return { ok: false, reason: "MISSING_AUTHORITY_BUNDLE" };
  }
  if (!isNonEmptyString(trustedRootFingerprint) || authorityBundle.root_key.fingerprint !== trustedRootFingerprint) {
    return { ok: false, reason: "UNTRUSTED_ROOT" };
  }
  if (raw.authority_id !== authorityBundle.authority_id) {
    return { ok: false, reason: "AUTHORITY_MISMATCH", policy_authority: raw.authority_id, bundle_authority: authorityBundle.authority_id };
  }
  if (raw.root_key_id !== undefined && raw.root_key_id !== authorityBundle.root_key.key_id) {
    return { ok: false, reason: "ROOT_KEY_MISMATCH" };
  }

  const sigCheck = await verifyPolicySignature(raw, { rootPublicKey: authorityBundle.root_key.public_key });
  if (!sigCheck.ok) return { ok: false, reason: sigCheck.reason };

  // Rollback protection: a signed-but-superseded policy must not be reinstated.
  if (!Number.isInteger(highWaterMark) || raw.policy_version <= highWaterMark) {
    return { ok: false, reason: "POLICY_ROLLBACK", policy_version: raw.policy_version, high_water_mark: highWaterMark };
  }

  // Operational freshness only — excluded from the replay path by design.
  if (isNonEmptyString(now) && isNonEmptyString(raw.not_after)) {
    if (Date.parse(now) > Date.parse(raw.not_after)) return { ok: false, reason: "POLICY_EXPIRED" };
  }

  // Approved set from RECOMPUTED effective hashes (never the stored ones) so it
  // exactly matches what the adapter emits; a stored policy_hash that disagrees
  // is an authoring error and hard-fails loudly.
  const approved = new Set();
  for (const entry of raw.verifier_policies) {
    const h = effectiveVerifierPolicyHash(entry);
    if (entry.policy_hash !== undefined && entry.policy_hash !== h) {
      return { ok: false, reason: "POLICY_HASH_MISMATCH", issuer: entry.issuer, stored: entry.policy_hash, computed: h };
    }
    approved.add(h);
  }

  const levelIndex = new Map();
  for (const rule of raw.min_level_table) {
    levelIndex.set(`${rule.environment} ${rule.authority_scope}`, rule.min_level);
  }

  const documentHash = policyDocumentHash(raw);

  return {
    ok: true,
    version: raw.policy_version,
    authority_id: raw.authority_id,
    policy_document_hash: documentHash,
    policy: raw,

    // Deterministic. Set membership over the recomputed approved hashes.
    isApprovedPolicyHash(hash) {
      return typeof hash === "string" && approved.has(hash);
    },

    // Deterministic, fail-closed. Returns a FROZEN, receipt-ready decision object.
    // The gate records this object verbatim; replay compares against it without
    // reloading the policy. A missing rule yields level "DENY" (accepts() false).
    requiredDecisionPolicy(environment, authorityScope) {
      const level = levelIndex.get(`${environment} ${authorityScope}`) ?? "DENY";
      return Object.freeze({
        level,
        policy_version: raw.policy_version,
        policy_document_hash: documentHash,
        authority_scope: authorityScope,
        accepts(achievedLevel) {
          if (level === "DENY") return false;
          const req = levelRank(level);
          const got = levelRank(achievedLevel);
          return got >= 0 && req >= 0 && got >= req;
        }
      });
    }
  };
}

// ── signVerifierPolicy (authoring / tests) ─────────────────────────────────
// Build and custody-root-sign an mnde.verifier_policy.v1. The policy references
// the authority via authority_id + root_key_id; it does NOT embed the root key.
// Verification pulls the root public key from the matching authority bundle.
//
// input:
//   authorityId, rootKeyId, policyVersion, issuedAt, notAfter (string | null),
//   rootSigner, or rootPrivatePem + rootPublicPem,
//   verifierPolicies: [{ issuer, audience, subject_allowlist? , allow_all_subjects?,
//                        trusted_jwks_hash, max_token_age_seconds?, clock_skew_seconds? }],
//   minLevelTable: [{ environment, authority_scope, min_level }]
export async function signVerifierPolicy(input) {
  const body = {
    schema_version: VERIFIER_POLICY_SCHEMA,
    authority_id: input.authorityId,
    root_key_id: input.rootKeyId,
    policy_version: input.policyVersion,
    issued_at: input.issuedAt,
    not_after: input.notAfter ?? null,
    verifier_policies: input.verifierPolicies.map((e) => ({
      ...e,
      policy_hash: effectiveVerifierPolicyHash(e)
    })),
    min_level_table: input.minLevelTable ?? []
  };
  const root = { keyId: input.rootKeyId, publicPem: input.rootPublicPem ?? input.rootSigner?.publicKeyPem };
  // Production callers must pass a capability obtained from resolveRootSigner;
  // the inline PEM adapter remains for backward-compatible offline authoring.
  const signer = input.rootSigner ?? createFileRootSigner({
    keyId: root.keyId,
    publicKeyPem: root.publicPem,
    privateKeyPem: input.rootPrivatePem
  });
  const signature = await signWithRootSigner(signer, canonicalizeJson(body), root);
  return { ...body, signature: { algorithm: "ED25519", value: signature.value } };
}
