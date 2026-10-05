// Authority key lifecycle — rotation, retirement, and revocation.
//
// Production trust roots must be operable: when a signing key is rotated on
// schedule or compromised, an operator needs a deterministic way to issue a new
// authority bundle that (a) starts using the new key, (b) keeps historical
// receipts verifiable, and (c) immediately rejects revoked keys — all while the
// bundle stays root-signed and offline-verifiable.
//
// These are pure functions over a published `mnde.authority.bundle.v1`. They
// require the ROOT private key only to re-sign the bundle; signing keys' private
// material is never needed here and never touched. The result is validated
// before it is returned, so a broken bundle is never emitted (fail-closed).
//
// Provider-agnostic: the bundle is re-signed by whatever holds the root key
// (file today; HSM/KMS/enclave later) — this layer does not change.

import { createPublicKey } from "node:crypto";

import { buildAuthorityBundle, fingerprintOf, verifyAuthorityBundle } from "./bundle.mjs";
import { assertRootSignerIdentity, createFileRootSigner } from "./root-signer.mjs";

const FAR_FUTURE = "2999-01-01T00:00:00.000Z";
const ROLES = new Set(["receipt", "policy", "approval"]);

function isValidTimestamp(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}
function earliest(a, b) {
  if (!isValidTimestamp(a)) return b;
  if (!isValidTimestamp(b)) return a;
  return Date.parse(a) <= Date.parse(b) ? a : b;
}
function keysToInput(list) {
  return (Array.isArray(list) ? list : []).map((k) => ({
    keyId: k.key_id,
    publicPem: k.public_key,
    validFrom: k.valid_from,
    validUntil: k.valid_until
  }));
}

// The supplied root private key must correspond to the bundle's published root.
export function rootKeyMatches(bundle, rootPrivateKeyPem) {
  try {
    const pub = createPublicKey(rootPrivateKeyPem).export({ type: "spki", format: "pem" });
    return fingerprintOf(pub) === bundle?.root_key?.fingerprint;
  } catch {
    return false;
  }
}

function lifecycleRootSigner(bundle, { rootSigner, rootPrivateKeyPem }) {
  const root = {
    keyId: bundle?.root_key?.key_id,
    publicPem: bundle?.root_key?.public_key,
    fingerprint: bundle?.root_key?.fingerprint
  };
  try {
    if (rootSigner) return assertRootSignerIdentity(rootSigner, root);
    if (!rootKeyMatches(bundle, rootPrivateKeyPem)) return null;
    return createFileRootSigner({
      keyId: root.keyId,
      publicKeyPem: root.publicPem,
      privateKeyPem: rootPrivateKeyPem
    });
  } catch {
    return null;
  }
}

// Re-sign a bundle with updated key material. Pure; returns a new bundle object.
async function reissue(bundle, rootSigner, updates) {
  return buildAuthorityBundle({
    authorityId: bundle.authority_id,
    issuedAt: updates.now,
    notAfter: updates.notAfter ?? bundle.not_after,
    root: { keyId: bundle.root_key.key_id, publicPem: bundle.root_key.public_key, signer: rootSigner },
    receiptKeys: updates.receiptKeys ?? keysToInput(bundle.keys?.receipt),
    policyKeys: updates.policyKeys ?? keysToInput(bundle.keys?.policy),
    approvalKeys: updates.approvalKeys ?? keysToInput(bundle.keys?.approval),
    revocation: updates.revocation ?? bundle.revocation
  });
}

// Validate the produced bundle before returning it. Never emit a broken bundle.
async function finalize(bundle, next, now) {
  const check = await verifyAuthorityBundle(next, { trustedRootFingerprint: bundle.root_key.fingerprint, now });
  if (!check.ok) return { ok: false, reason: `REISSUE_UNVERIFIABLE:${check.reason}` };
  return { ok: true, bundle: next };
}

// Rotate a signing key for a role: add `newKey` (active from `now`), and by
// default retire all current keys of that role by closing their validity window
// at `now`. Receipts signed by the old key BEFORE `now` stay verifiable; the old
// key cannot sign anything dated at/after `now`.
export async function rotateSigningKey(bundle, options = {}) {
  const { role = "receipt", rootPrivateKeyPem, rootSigner, newKey, now, validUntil = FAR_FUTURE, retire = true } = options;
  if (!ROLES.has(role)) return { ok: false, reason: "INVALID_ROLE" };
  if (!isValidTimestamp(now)) return { ok: false, reason: "INVALID_NOW" };
  // Production callers must pass a capability obtained from resolveRootSigner.
  const signer = lifecycleRootSigner(bundle, { rootSigner, rootPrivateKeyPem });
  if (!signer) return { ok: false, reason: "ROOT_KEY_MISMATCH" };
  if (!newKey || typeof newKey.keyId !== "string" || typeof newKey.publicPem !== "string") {
    return { ok: false, reason: "INVALID_NEW_KEY" };
  }
  const existing = keysToInput(bundle.keys?.[role]);
  if (existing.some((k) => k.keyId === newKey.keyId)) return { ok: false, reason: "DUPLICATE_KEY_ID" };

  const retired = retire ? existing.map((k) => ({ ...k, validUntil: earliest(k.validUntil, now) })) : existing;
  const updated = [...retired, { keyId: newKey.keyId, publicPem: newKey.publicPem, validFrom: now, validUntil }];

  const next = await reissue(bundle, signer, { now, [`${role}Keys`]: updated });
  const result = await finalize(bundle, next, now);
  if (!result.ok) return result;
  return { ...result, role, newKeyId: newKey.keyId, retiredKeyIds: retire ? existing.map((k) => k.keyId) : [] };
}

// Revoke a key id across the bundle: it is rejected immediately, even inside its
// validity window. Use for compromise. Historical receipts signed by it stop
// verifying (intended — a compromised key's receipts are no longer trustworthy).
export async function revokeKey(bundle, options = {}) {
  const { rootPrivateKeyPem, rootSigner, keyId, now } = options;
  if (!isValidTimestamp(now)) return { ok: false, reason: "INVALID_NOW" };
  if (typeof keyId !== "string" || keyId.length === 0) return { ok: false, reason: "INVALID_KEY_ID" };
  // Production callers must pass a capability obtained from resolveRootSigner.
  const signer = lifecycleRootSigner(bundle, { rootSigner, rootPrivateKeyPem });
  if (!signer) return { ok: false, reason: "ROOT_KEY_MISMATCH" };
  const revocation = Array.isArray(bundle.revocation) ? bundle.revocation : [];
  if (revocation.includes(keyId)) return { ok: false, reason: "ALREADY_REVOKED" };

  const known = ["receipt", "policy", "approval"].some((r) => (bundle.keys?.[r] ?? []).some((k) => k.key_id === keyId));
  if (!known) return { ok: false, reason: "UNKNOWN_KEY_ID" };

  const next = await reissue(bundle, signer, { now, revocation: [...revocation, keyId] });
  const result = await finalize(bundle, next, now);
  if (!result.ok) return result;
  return { ...result, revokedKeyId: keyId };
}
