// mnde.authority.checkpoint.v1 — an immutable, authority-signed observation of
// one authority-state at one history position (epoch + sequence), chained to the
// previous checkpoint and bound to the exact authority bundle.
//
// Reuses the existing crypto/trust primitives only — canonical JSON, sha256
// digest, Ed25519 sign/verify, the authority bundle verifier, and the shared
// revocation evaluator. No parallel crypto, no init-only formats.
//
// The checkpoint signer is a dedicated `checkpoint`-role key in the authority
// bundle (never the receipt/ledger/etc. role). Root trust is unchanged: a
// checkpoint is only as trusted as the authority bundle it is bound to, which is
// in turn pinned to the out-of-band trusted root fingerprint.

import { canonicalizeJson } from "../../shared/json.ts";
import { hashCanonicalJson } from "../../shared/hash.ts";
import { evaluateRevocation, signCanonical, verifyAuthorityBundle, verifyCanonical } from "../custody/index.mjs";

export const CHECKPOINT_SCHEMA = "mnde.authority.checkpoint.v1";
export const CHECKPOINT_ROLE = "checkpoint";

// Exact set of signed body fields. Strict: any missing or extra top-level field
// (besides `signature`) is malformed — nothing outside the signature is unsigned.
const BODY_FIELDS = Object.freeze([
  "schema",
  "authority_id",
  "authority_epoch",
  "sequence",
  "previous_checkpoint_digest",
  "authority_bundle_digest",
  "issued_at",
  "root_key_id"
]);

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function isInt(v) {
  return typeof v === "number" && Number.isInteger(v) && v >= 0;
}
function isValidTimestamp(v) {
  return typeof v === "string" && !Number.isNaN(Date.parse(v));
}
function isDigest(v) {
  return typeof v === "string" && /^sha256:[0-9a-f]{64}$/.test(v);
}

// Canonical digest of any object body: "sha256:" + sha256(canonical JSON).
export function digestOf(body) {
  return `sha256:${hashCanonicalJson(body)}`;
}

// The signed body of a checkpoint = every field except `signature`.
function bodyOf(checkpoint) {
  const body = {};
  for (const f of BODY_FIELDS) body[f] = checkpoint[f];
  return body;
}

// Deterministic checkpoint identity: the digest of its signed body.
export function checkpointDigest(checkpoint) {
  return digestOf(bodyOf(checkpoint));
}

// Build and authority-sign a checkpoint. `checkpointKeyId` must name a
// `checkpoint`-role key in `authorityBundle`; `checkpointPrivatePem` is its
// private key. `previousCheckpointDigest` is null for genesis (sequence 0).
export async function createCheckpoint({
  authorityId,
  authorityEpoch,
  sequence,
  previousCheckpointDigest = null,
  authorityBundle,
  issuedAt,
  rootKeyId,
  checkpointKeyId,
  checkpointPrivatePem
}) {
  const body = {
    schema: CHECKPOINT_SCHEMA,
    authority_id: authorityId,
    authority_epoch: authorityEpoch,
    sequence,
    previous_checkpoint_digest: previousCheckpointDigest,
    authority_bundle_digest: digestOf(authorityBundle),
    issued_at: issuedAt,
    root_key_id: rootKeyId
  };
  const value = await signCanonical(canonicalizeJson(body), checkpointPrivatePem);
  return { ...body, signature: { algorithm: "ED25519", key_id: checkpointKeyId, value } };
}

// Which role, if any, holds `keyId` in the bundle (for a precise WRONG_ROLE).
function roleOfKey(bundle, keyId) {
  const keys = bundle?.keys;
  if (!isObject(keys)) return null;
  for (const [role, list] of Object.entries(keys)) {
    if (Array.isArray(list) && list.some((k) => k && k.key_id === keyId)) return role;
  }
  return null;
}

// Resolve a checkpoint-role key with fine-grained, stable reasons.
function resolveCheckpointKey(bundle, keyId, signedAt, now) {
  const rev = evaluateRevocation(bundle?.revocation, { key_id: keyId }, signedAt, now);
  if (rev.revoked_as_of_event) return { ok: false, reason: "KEY_REVOKED" };
  const list = bundle?.keys?.[CHECKPOINT_ROLE];
  const key = Array.isArray(list) ? list.find((k) => k && k.key_id === keyId) : undefined;
  if (!key) {
    const other = roleOfKey(bundle, keyId);
    return { ok: false, reason: other ? "WRONG_ROLE" : "UNKNOWN_KEY" };
  }
  const t = Date.parse(signedAt);
  if (isValidTimestamp(key.valid_from) && t < Date.parse(key.valid_from)) return { ok: false, reason: "KEY_NOT_YET_VALID" };
  if (isValidTimestamp(key.valid_until) && t >= Date.parse(key.valid_until)) return { ok: false, reason: "KEY_EXPIRED" };
  return { ok: true, publicKey: key.public_key, revoked_now: rev.revoked_now };
}

// Verify a checkpoint offline. Nothing on the checkpoint is trusted until its
// signature authenticates against a `checkpoint`-role key in a bundle that is
// itself pinned to `trustedRootFingerprint`.
//
// `previousCheckpoint` (optional) enforces the authenticated chain link. When
// the parent committed a different authority bundle (for example during key
// rotation), supply that bundle as `previousAuthorityBundle`. `now` defaults to
// wall-clock; pass it in tests for determinism.
export async function verifyAuthorityCheckpoint({ checkpoint, authorityBundle, trustedRootFingerprint, previousCheckpoint = null, previousAuthorityBundle = null, now } = {}) {
  const at = now ?? new Date().toISOString();
  if (!isObject(checkpoint)) return { ok: false, reason: "MALFORMED" };
  if (checkpoint.schema !== CHECKPOINT_SCHEMA) return { ok: false, reason: "UNSUPPORTED_SCHEMA" };

  // Strict shape: exactly the body fields + signature, nothing smuggled.
  const keys = Object.keys(checkpoint);
  for (const f of BODY_FIELDS) if (!(f in checkpoint)) return { ok: false, reason: "MALFORMED", field: f };
  for (const k of keys) if (k !== "signature" && !BODY_FIELDS.includes(k)) return { ok: false, reason: "MALFORMED", field: k };
  const sig = checkpoint.signature;
  if (!isObject(sig) || sig.algorithm !== "ED25519" || typeof sig.key_id !== "string" || typeof sig.value !== "string") {
    return { ok: false, reason: "MALFORMED", field: "signature" };
  }
  if (typeof checkpoint.authority_id !== "string" || checkpoint.authority_id.length === 0) return { ok: false, reason: "MALFORMED", field: "authority_id" };
  if (typeof checkpoint.root_key_id !== "string" || checkpoint.root_key_id.length === 0) return { ok: false, reason: "MALFORMED", field: "root_key_id" };
  if (!isValidTimestamp(checkpoint.issued_at)) return { ok: false, reason: "MALFORMED", field: "issued_at" };
  if (!isInt(checkpoint.authority_epoch) || !isInt(checkpoint.sequence)) return { ok: false, reason: "EPOCH_INVALID" };
  if (!isDigest(checkpoint.authority_bundle_digest)) return { ok: false, reason: "MALFORMED", field: "authority_bundle_digest" };
  if (checkpoint.previous_checkpoint_digest !== null && !isDigest(checkpoint.previous_checkpoint_digest)) {
    return { ok: false, reason: "MALFORMED", field: "previous_checkpoint_digest" };
  }

  // 1) The authority bundle must itself verify against the pinned root.
  const bundleCheck = await verifyAuthorityBundle(authorityBundle, { trustedRootFingerprint, now: at });
  if (!bundleCheck.ok) return { ok: false, reason: bundleCheck.reason ?? "MALFORMED", stage: "authority_bundle" };

  // 2) Identity + root binding.
  if (checkpoint.authority_id !== authorityBundle.authority_id) return { ok: false, reason: "AUTHORITY_MISMATCH" };
  if (checkpoint.root_key_id !== authorityBundle.root_key?.key_id) return { ok: false, reason: "ROOT_FINGERPRINT_MISMATCH" };
  if (checkpoint.authority_bundle_digest !== digestOf(authorityBundle)) return { ok: false, reason: "BUNDLE_DIGEST_MISMATCH" };

  // 3) Chain position.
  if (checkpoint.sequence === 0) {
    if (checkpoint.previous_checkpoint_digest !== null) return { ok: false, reason: "PREVIOUS_CHECKPOINT_MISMATCH", detail: "genesis must have null previous" };
  } else if (checkpoint.previous_checkpoint_digest === null) {
    return { ok: false, reason: "PREVIOUS_CHECKPOINT_MISMATCH", detail: "non-genesis must reference a previous checkpoint" };
  }
  if (previousCheckpoint) {
    if (checkpoint.previous_checkpoint_digest !== checkpointDigest(previousCheckpoint)) return { ok: false, reason: "PREVIOUS_CHECKPOINT_MISMATCH" };
    if (previousCheckpoint.authority_id !== checkpoint.authority_id) return { ok: false, reason: "AUTHORITY_MISMATCH", detail: "previous checkpoint authority differs" };
    if (previousCheckpoint.sequence !== checkpoint.sequence - 1) return { ok: false, reason: "EPOCH_INVALID", detail: "sequence must increase by one" };
    if (!isInt(previousCheckpoint.authority_epoch) || previousCheckpoint.authority_epoch > checkpoint.authority_epoch) {
      return { ok: false, reason: "EPOCH_INVALID", detail: "authority epoch must not decrease" };
    }

    // A matching digest is only a link to bytes, not proof that those bytes were
    // ever authorized. Authenticate the parent independently under the same
    // pinned root before accepting it as chain history.
    const parentCheck = await verifyAuthorityCheckpoint({
      checkpoint: previousCheckpoint,
      authorityBundle: previousAuthorityBundle ?? authorityBundle,
      trustedRootFingerprint,
      now: at
    });
    if (!parentCheck.ok) return { ok: false, reason: "PREVIOUS_CHECKPOINT_INVALID", detail: parentCheck.reason };
  }

  // 4) Authenticate the signature against a valid, in-role checkpoint key.
  const resolved = resolveCheckpointKey(authorityBundle, sig.key_id, checkpoint.issued_at, at);
  if (!resolved.ok) return { ok: false, reason: resolved.reason };
  const authentic = await verifyCanonical(canonicalizeJson(bodyOf(checkpoint)), sig.value, resolved.publicKey);
  if (!authentic) return { ok: false, reason: "SIGNATURE_INVALID" };

  return { ok: true, checkpoint_digest: checkpointDigest(checkpoint), revoked_now: resolved.revoked_now };
}
