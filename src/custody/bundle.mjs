// Authority bundle format `mnde.authority.bundle.v1` + offline verifier.
//
// A bundle publishes ONLY public material: the root authority public key, and
// the receipt / policy / approval signing public keys with their key ids and
// validity windows, plus a revocation list and a root-signed bundle signature.
// Private keys never appear in a bundle and never appear in a receipt.
//
// Verification is fully offline: a verifier independently holds the trusted root
// key fingerprint (out of band), confirms the bundle's root matches it, verifies
// the bundle signature, rejects a stale bundle, and looks up signing keys while
// honoring validity windows and revocation.

import { generateKeyPair, sign as providerSign, spkiFingerprint, verify as providerVerify } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";
import { createFileRootSigner, signWithRootSigner } from "./root-signer.mjs";

export const BUNDLE_SCHEMA = "mnde.authority.bundle.v1";
export const AUTHORITY_KEY_ROLES = Object.freeze(["receipt", "policy", "approval", "result", "ledger", "activation", "checkpoint"]);

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isValidTimestamp(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

export function fingerprintOf(publicKeyPem) {
  return spkiFingerprint(publicKeyPem);
}
export function generateAuthorityKeyPair() {
  return generateKeyPair();
}
export async function signCanonical(payloadString, privateKeyPem) {
  return providerSign(payloadString, privateKeyPem);
}
export async function verifyCanonical(payloadString, signatureHex, publicKeyPem) {
  return providerVerify(payloadString, signatureHex, publicKeyPem);
}

function bundleWithoutSignature(bundle) {
  const { signature: _omit, ...rest } = bundle;
  return rest;
}

// Build and root-sign an authority bundle (public material only).
export async function buildAuthorityBundle(input) {
  const mapKeys = (keys) => (keys ?? []).map((k) => ({
    key_id: k.keyId ?? k.key_id,
    public_key: k.publicPem ?? k.public_key,
    fingerprint: k.fingerprint ?? fingerprintOf(k.publicPem ?? k.public_key),
    valid_from: k.validFrom ?? k.valid_from,
    valid_until: k.validUntil ?? k.valid_until
  }));

  const mappedKeys = {
    receipt: mapKeys(input.receiptKeys),
    policy: mapKeys(input.policyKeys),
    approval: mapKeys(input.approvalKeys),
    result: mapKeys(input.resultKeys),
    ledger: mapKeys(input.ledgerKeys),
    activation: mapKeys(input.activationKeys)
  };
  // The `checkpoint` role signs authority-state checkpoints. It is emitted only
  // when checkpoint keys are supplied, so bundles built without them are
  // byte-identical to before (no signature/fixture churn).
  if (Array.isArray(input.checkpointKeys) && input.checkpointKeys.length > 0) {
    mappedKeys.checkpoint = mapKeys(input.checkpointKeys);
  }

  // Reject duplicate key_id or fingerprint across all roles.
  const seenKeyIds = new Set();
  const seenFingerprints = new Set();
  for (const [role, keys] of Object.entries(mappedKeys)) {
    for (const k of keys) {
      if (seenKeyIds.has(k.key_id)) throw new Error(`buildAuthorityBundle: duplicate key_id "${k.key_id}" (found again in role "${role}")`);
      seenKeyIds.add(k.key_id);
      if (seenFingerprints.has(k.fingerprint)) throw new Error(`buildAuthorityBundle: duplicate key fingerprint in role "${role}" — same public key used in multiple roles`);
      seenFingerprints.add(k.fingerprint);
    }
  }

  const rootIdentity = {
    keyId: input.root.keyId,
    publicPem: input.root.publicPem,
    fingerprint: fingerprintOf(input.root.publicPem)
  };
  const body = {
    schema_version: BUNDLE_SCHEMA,
    authority_id: input.authorityId,
    issued_at: input.issuedAt,
    not_after: input.notAfter,
    root_key: { key_id: rootIdentity.keyId, public_key: rootIdentity.publicPem, fingerprint: rootIdentity.fingerprint },
    keys: mappedKeys,
    revocation: Array.isArray(input.revocation) ? input.revocation : []
  };
  // Production callers must obtain input.root.signer through resolveRootSigner;
  // the inline PEM adapter exists only for backward-compatible local tooling.
  const rootSigner = input.root.signer ?? createFileRootSigner({
    keyId: rootIdentity.keyId,
    publicKeyPem: rootIdentity.publicPem,
    privateKeyPem: input.root.privatePem
  });
  const signature = await signWithRootSigner(rootSigner, canonicalizeJson(body), rootIdentity);
  return { ...body, signature: { algorithm: "ED25519", value: signature.value } };
}

// Verify a bundle offline. `trustedRootFingerprint` is the out-of-band trust
// anchor; the bundle is never trusted on its own say-so.
export async function verifyAuthorityBundle(bundle, options = {}) {
  if (!isObject(bundle) || bundle.schema_version !== BUNDLE_SCHEMA) return { ok: false, reason: "UNSUPPORTED_BUNDLE" };
  const root = bundle.root_key;
  if (!isObject(root) || typeof root.public_key !== "string" || typeof root.fingerprint !== "string") return { ok: false, reason: "MALFORMED_BUNDLE" };

  let derivedRootFp;
  try {
    derivedRootFp = fingerprintOf(root.public_key);
  } catch {
    return { ok: false, reason: "MALFORMED_ROOT_KEY" };
  }
  if (derivedRootFp !== root.fingerprint) return { ok: false, reason: "ROOT_FINGERPRINT_MISMATCH" };

  if (typeof options.trustedRootFingerprint !== "string" || options.trustedRootFingerprint.length === 0) return { ok: false, reason: "MISSING_TRUSTED_ROOT" };
  if (root.fingerprint !== options.trustedRootFingerprint) return { ok: false, reason: "UNTRUSTED_ROOT" };

  const signature = bundle.signature;
  if (!isObject(signature) || signature.algorithm !== "ED25519" || typeof signature.value !== "string") return { ok: false, reason: "UNSIGNED_BUNDLE" };
  if (!(await verifyCanonical(canonicalizeJson(bundleWithoutSignature(bundle)), signature.value, root.public_key))) return { ok: false, reason: "BUNDLE_SIGNATURE_INVALID" };

  // Reject duplicate key_id or fingerprint across roles — prevents a key from
  // acting simultaneously as receipt, policy, approval, or result key.
  const seenIds = new Set();
  const seenFps = new Set();
  for (const role of AUTHORITY_KEY_ROLES) {
    const roleKeys = Array.isArray(bundle.keys?.[role]) ? bundle.keys[role] : [];
    for (const k of roleKeys) {
      if (!isObject(k) || typeof k.key_id !== "string" || typeof k.public_key !== "string" || typeof k.fingerprint !== "string") {
        return { ok: false, reason: "MALFORMED_BUNDLE_KEY", role };
      }
      let derivedFp;
      try {
        derivedFp = fingerprintOf(k.public_key);
      } catch {
        return { ok: false, reason: "KEY_MALFORMED", role, key_id: k.key_id };
      }
      if (derivedFp !== k.fingerprint) return { ok: false, reason: "KEY_FINGERPRINT_MISMATCH", role, key_id: k.key_id };
      if (seenIds.has(k.key_id)) return { ok: false, reason: "CROSS_ROLE_KEY_ID_CONFLICT", role, key_id: k.key_id };
      seenIds.add(k.key_id);
      if (seenFps.has(k.fingerprint)) return { ok: false, reason: "CROSS_ROLE_KEY_FINGERPRINT_CONFLICT", role, key_id: k.key_id };
      seenFps.add(k.fingerprint);
    }
  }

  const now = options.now ?? new Date().toISOString();
  if (!isValidTimestamp(now)) return { ok: false, reason: "INVALID_NOW" };
  if (isValidTimestamp(bundle.not_after) && Date.parse(now) > Date.parse(bundle.not_after)) return { ok: false, reason: "BUNDLE_STALE" };
  if (options.maxAgeMs && isValidTimestamp(bundle.issued_at) && Date.parse(now) - Date.parse(bundle.issued_at) > options.maxAgeMs) return { ok: false, reason: "BUNDLE_STALE" };
  return { ok: true };
}

// Evaluate a revocation list against a subject at two points in time.
//
// Revocation status changes over time; a single boolean conflates two distinct
// questions. This returns both verdicts (spec: activation-authority-v1 §11):
//   revoked_as_of_event — was the subject revoked at the evaluated event time
//                         (a signature's signed_at, an activation's activated_at)?
//                         The event itself is untrustworthy if true.
//   revoked_now         — is the subject revoked at verification time? Advisory:
//                         stop running / do not activate; historical evidence
//                         produced before revocation remains truthful.
//
// Entry forms:
//   "key-id"                                — legacy string: revoked for all time
//                                             (both verdicts fire; conservative)
//   { key_id | artifact_hash | release_version, revoked_at, reason_code }
//                                           — revoked from `revoked_at` onward.
//                                             Missing/invalid `revoked_at` is
//                                             treated as revoked for all time.
export function evaluateRevocation(revocationList, subject, eventAt, now) {
  const list = Array.isArray(revocationList) ? revocationList : [];
  const none = { revoked_as_of_event: false, revoked_now: false, entry: null };
  if (!isObject(subject)) return none;
  const matchField = (entry, field) => typeof subject[field] === "string" && subject[field].length > 0 && entry[field] === subject[field];
  for (const entry of list) {
    if (typeof entry === "string") {
      if (subject.key_id === entry) return { revoked_as_of_event: true, revoked_now: true, entry };
      continue;
    }
    if (!isObject(entry)) continue;
    if (!(matchField(entry, "key_id") || matchField(entry, "artifact_hash") || matchField(entry, "release_version"))) continue;
    if (!isValidTimestamp(entry.revoked_at)) return { revoked_as_of_event: true, revoked_now: true, entry };
    const revokedAt = Date.parse(entry.revoked_at);
    return {
      revoked_as_of_event: isValidTimestamp(eventAt) ? Date.parse(eventAt) >= revokedAt : true,
      revoked_now: isValidTimestamp(now) ? Date.parse(now) >= revokedAt : true,
      entry
    };
  }
  return none;
}

// Look up a signing key by role + key id, honoring revocation and validity.
//
// Revocation freshness: the revocation list is from the bundle in hand. If the
// bundle is stale, revocations issued after it will not appear here. Callers
// that need authoritative revocation status must fetch a fresh bundle. The
// `revocation_freshness` field on the result always indicates this limitation:
//   "CURRENT_TO_BUNDLE"  — not revoked per this bundle; staleness unknown
//   "KEY_REVOKED"        — positively revoked per this bundle (may be stale too,
//                          but revocation is treated as permanent)
//
// A key revoked as of `signedAt` fails closed (KEY_REVOKED). A key revoked
// after `signedAt` (timestamped entry) still verifies the historical signature
// but the result carries `revoked_now: true` so callers can refuse it for NEW
// signing or surface the advisory verdict.
export function findBundleKey(bundle, role, keyId, signedAt, now = new Date().toISOString()) {
  const revocation = evaluateRevocation(bundle?.revocation, { key_id: keyId }, signedAt, now);
  if (revocation.revoked_as_of_event) return { ok: false, reason: "KEY_REVOKED" };
  const list = bundle?.keys?.[role];
  const key = Array.isArray(list) ? list.find((k) => k.key_id === keyId) : undefined;
  if (!key) return { ok: false, reason: "UNKNOWN_KEY" };
  if (!isValidTimestamp(signedAt)) return { ok: false, reason: "INVALID_SIGNED_AT" };
  const t = Date.parse(signedAt);
  if (isValidTimestamp(key.valid_from) && t < Date.parse(key.valid_from)) return { ok: false, reason: "KEY_EXPIRED" };
  if (isValidTimestamp(key.valid_until) && t >= Date.parse(key.valid_until)) return { ok: false, reason: "KEY_EXPIRED" };
  // Revocation status is current only as of the bundle's issued_at. A stale
  // bundle may miss later revocations. We report this honestly rather than
  // asserting that revocation is globally current.
  return { ok: true, publicKey: key.public_key, revocation_freshness: "CURRENT_TO_BUNDLE", revoked_now: revocation.revoked_now };
}

// Verify a signature over a canonical payload against a bundle key (offline).
// On success, the result includes `revocation_freshness` from findBundleKey to
// let callers know that revocation status is only current as of the bundle used,
// and `revoked_now` for the advisory revocation verdict (see evaluateRevocation).
export async function verifyAgainstBundle(canonicalPayload, signatureHex, role, keyId, signedAt, bundle) {
  const key = findBundleKey(bundle, role, keyId, signedAt);
  if (!key.ok) return key;
  return (await verifyCanonical(canonicalPayload, signatureHex, key.publicKey))
    ? { ok: true, revocation_freshness: key.revocation_freshness, revoked_now: key.revoked_now }
    : { ok: false, reason: "SIGNATURE_INVALID" };
}
