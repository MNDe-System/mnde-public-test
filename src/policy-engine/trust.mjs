// Cryptographic authority chain for the policy engine.
//
// Verifies that a policy and each authority grant are signed by a key the
// verifier independently trusts (a "trust anchor"). Deterministic, no AI, no
// network. Trust anchors are supplied by the caller/verifier out of band — they
// are never taken from the policy or the receipt itself.
//
//   trustAnchors = {
//     policy_keys:    [{ key_id, public_key (PEM) }],
//     authority_keys: [{ key_id, public_key (PEM), valid_from?, valid_until? }]
//   }
//
// Signing is over the canonical JSON of the object WITHOUT its `signature` field.

import { createPrivateKey, sign } from "node:crypto";

import { canonicalizeJson } from "../../shared/json.ts";
import { verifyReceiptPayloadSignature } from "../../shared/index.ts";

function withoutSignature(obj) {
  const { signature: _omit, ...rest } = obj ?? {};
  return rest;
}
function isValidTimestamp(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

export function verifyPolicyTrust(policy, trustAnchors) {
  const signature = policy?.signature;
  if (!signature || typeof signature.key_id !== "string" || typeof signature.value !== "string") {
    return { ok: false, reason: "POLICY_UNSIGNED" };
  }
  const key = (trustAnchors?.policy_keys ?? []).find((candidate) => candidate?.key_id === signature.key_id);
  if (!key || typeof key.public_key !== "string") return { ok: false, reason: "POLICY_UNTRUSTED_ISSUER" };
  try {
    const ok = verifyReceiptPayloadSignature(canonicalizeJson(withoutSignature(policy)), signature.value, key.public_key);
    return ok ? { ok: true } : { ok: false, reason: "POLICY_SIGNATURE_INVALID" };
  } catch {
    return { ok: false, reason: "POLICY_SIGNATURE_INVALID" };
  }
}

export function verifyAuthorityGrant(grant, trustAnchors, now) {
  const signature = grant?.signature;
  if (!signature || typeof signature.key_id !== "string" || typeof signature.value !== "string") {
    return { ok: false, reason: "AUTHORITY_UNSIGNED" };
  }
  const key = (trustAnchors?.authority_keys ?? []).find((candidate) => candidate?.key_id === signature.key_id);
  if (!key || typeof key.public_key !== "string") return { ok: false, reason: "AUTHORITY_UNTRUSTED_ISSUER" };
  // Optional issuer-key validity window.
  if (key.valid_from || key.valid_until) {
    if (!isValidTimestamp(now) || !isValidTimestamp(key.valid_from) || !isValidTimestamp(key.valid_until)) {
      return { ok: false, reason: "AUTHORITY_UNTRUSTED_ISSUER" };
    }
    const t = Date.parse(now);
    if (t < Date.parse(key.valid_from) || t >= Date.parse(key.valid_until)) {
      return { ok: false, reason: "AUTHORITY_UNTRUSTED_ISSUER" };
    }
  }
  try {
    const ok = verifyReceiptPayloadSignature(canonicalizeJson(withoutSignature(grant)), signature.value, key.public_key);
    return ok ? { ok: true } : { ok: false, reason: "AUTHORITY_SIGNATURE_INVALID" };
  } catch {
    return { ok: false, reason: "AUTHORITY_SIGNATURE_INVALID" };
  }
}

// Signing helpers for policy authors and authority issuers (and tests). Sign the
// canonical JSON of the object excluding `signature`, with an Ed25519 private key.
export function signCanonical(obj, privateKeyPem) {
  return sign(null, Buffer.from(canonicalizeJson(withoutSignature(obj)), "utf8"), createPrivateKey(privateKeyPem)).toString("hex");
}
export function signPolicy(policy, { keyId, privateKeyPem }) {
  return { ...withoutSignature(policy), signature: { key_id: keyId, value: signCanonical(policy, privateKeyPem) } };
}
export function signAuthorityGrant(grant, { keyId, privateKeyPem }) {
  return { ...withoutSignature(grant), signature: { key_id: keyId, value: signCanonical(grant, privateKeyPem) } };
}
