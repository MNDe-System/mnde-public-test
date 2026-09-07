// mnde.witness.attestation.v1 + mnde.witness.bundle.v1 + mnde.witness.policy.v1
//
// A witness independently attests "I observed this exact checkpoint digest".
// Witness trust is SEPARATE from MNDe authority trust: a witness key is trusted
// only because it appears in a witness bundle the verifier pinned out of band —
// never because a public key travels inside the attestation (attestations carry
// no public key). This independence is the point: if MNDe controlled every
// witness key, witnessing would not constrain MNDe itself.
//
// Reuses the shared canonical JSON, Ed25519 sign/verify, and revocation evaluator.

import { canonicalizeJson } from "../../shared/json.ts";
import { evaluateRevocation, signCanonical, verifyCanonical } from "../custody/index.mjs";

export const ATTESTATION_SCHEMA = "mnde.witness.attestation.v1";
export const WITNESS_BUNDLE_SCHEMA = "mnde.witness.bundle.v1";
export const WITNESS_POLICY_SCHEMA = "mnde.witness.policy.v1";
export const WITNESS_ROLE = "checkpoint-witness";

const BODY_FIELDS = Object.freeze([
  "schema",
  "checkpoint_digest",
  "authority_id",
  "authority_epoch",
  "witness_id",
  "observed_at",
  "witness_key_id"
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

function bodyOf(attestation) {
  const body = {};
  for (const f of BODY_FIELDS) body[f] = attestation[f];
  return body;
}

// Build and witness-sign an attestation over one checkpoint digest.
export async function createWitnessAttestation({
  checkpointDigest,
  authorityId,
  authorityEpoch,
  witnessId,
  observedAt,
  witnessKeyId,
  witnessPrivatePem
}) {
  const body = {
    schema: ATTESTATION_SCHEMA,
    checkpoint_digest: checkpointDigest,
    authority_id: authorityId,
    authority_epoch: authorityEpoch,
    witness_id: witnessId,
    observed_at: observedAt,
    witness_key_id: witnessKeyId
  };
  const value = await signCanonical(canonicalizeJson(body), witnessPrivatePem);
  return { ...body, signature: { algorithm: "ED25519", key_id: witnessKeyId, value } };
}

// Find the enrolled witness key for (witness_id, key_id) in the trusted bundle.
function findWitnessKey(witnessBundle, witnessId, keyId) {
  const list = witnessBundle?.witnesses;
  if (!Array.isArray(list)) return { ok: false, reason: "UNKNOWN_WITNESS" };
  const forWitness = list.filter((w) => isObject(w) && w.witness_id === witnessId);
  if (forWitness.length === 0) return { ok: false, reason: "UNKNOWN_WITNESS" };
  const entry = forWitness.find((w) => w.key_id === keyId);
  if (!entry || typeof entry.public_key !== "string") return { ok: false, reason: "UNKNOWN_WITNESS" };
  return { ok: true, entry };
}

// Verify one witness attestation offline against the trusted witness bundle.
// When `checkpointDigest` is supplied the attestation must bind to it (an
// attestation over a different checkpoint cannot be replayed onto this one).
export async function verifyWitnessAttestation({ attestation, witnessBundle, checkpointDigest, now } = {}) {
  const at = now ?? new Date().toISOString();
  if (!isObject(attestation)) return { ok: false, reason: "MALFORMED" };
  if (attestation.schema !== ATTESTATION_SCHEMA) return { ok: false, reason: "UNSUPPORTED_SCHEMA" };
  for (const f of BODY_FIELDS) if (!(f in attestation)) return { ok: false, reason: "MALFORMED", field: f };
  for (const k of Object.keys(attestation)) if (k !== "signature" && !BODY_FIELDS.includes(k)) return { ok: false, reason: "MALFORMED", field: k };
  const sig = attestation.signature;
  if (!isObject(sig) || sig.algorithm !== "ED25519" || typeof sig.key_id !== "string" || typeof sig.value !== "string") {
    return { ok: false, reason: "MALFORMED", field: "signature" };
  }
  if (!isDigest(attestation.checkpoint_digest)) return { ok: false, reason: "MALFORMED", field: "checkpoint_digest" };
  if (!isInt(attestation.authority_epoch)) return { ok: false, reason: "MALFORMED", field: "authority_epoch" };
  if (!isValidTimestamp(attestation.observed_at)) return { ok: false, reason: "MALFORMED", field: "observed_at" };
  // The signing key id in the envelope must match the attested witness key id —
  // no signing under one key while claiming another.
  if (sig.key_id !== attestation.witness_key_id) return { ok: false, reason: "MALFORMED", field: "signature.key_id" };

  if (!isObject(witnessBundle) || witnessBundle.schema !== WITNESS_BUNDLE_SCHEMA) return { ok: false, reason: "MALFORMED", field: "witness_bundle" };
  if (typeof checkpointDigest === "string" && attestation.checkpoint_digest !== checkpointDigest) return { ok: false, reason: "CHECKPOINT_DIGEST_MISMATCH" };
  if (witnessBundle.authority_id !== attestation.authority_id) return { ok: false, reason: "AUTHORITY_MISMATCH" };

  const found = findWitnessKey(witnessBundle, attestation.witness_id, attestation.witness_key_id);
  if (!found.ok) return { ok: false, reason: found.reason };
  const entry = found.entry;

  if (!Array.isArray(entry.roles) || !entry.roles.includes(WITNESS_ROLE)) return { ok: false, reason: "WRONG_WITNESS_ROLE" };

  const rev = evaluateRevocation(witnessBundle.revocation, { key_id: attestation.witness_key_id }, attestation.observed_at, at);
  if (entry.revoked === true || rev.revoked_as_of_event) return { ok: false, reason: "WITNESS_REVOKED" };

  const t = Date.parse(attestation.observed_at);
  if (isValidTimestamp(entry.valid_from) && t < Date.parse(entry.valid_from)) return { ok: false, reason: "WITNESS_NOT_YET_VALID" };
  if (isValidTimestamp(entry.valid_until) && t >= Date.parse(entry.valid_until)) return { ok: false, reason: "WITNESS_EXPIRED" };

  const authentic = await verifyCanonical(canonicalizeJson(bodyOf(attestation)), sig.value, entry.public_key);
  if (!authentic) return { ok: false, reason: "WITNESS_SIGNATURE_INVALID" };

  return { ok: true, witness_id: attestation.witness_id, revoked_now: rev.revoked_now };
}

// Count UNIQUE valid, eligible witnesses over one exact checkpoint digest and
// compare to policy.required. Duplicates (same witness_id, even under different
// keys) count once. Ineligible/unknown/invalid witnesses do not count.
export async function evaluateWitnessThreshold({ checkpointDigest, attestations, witnessBundle, policy, now } = {}) {
  if (!isObject(policy) || policy.schema !== WITNESS_POLICY_SCHEMA || !isInt(policy.required)) {
    return { ok: false, reason: "MALFORMED_POLICY" };
  }
  if (!Array.isArray(policy.eligible_witnesses)
      || policy.eligible_witnesses.some((id) => typeof id !== "string" || id.length === 0)
      || new Set(policy.eligible_witnesses).size !== policy.eligible_witnesses.length
      || policy.required > policy.eligible_witnesses.length) {
    return { ok: false, reason: "MALFORMED_POLICY", field: "eligible_witnesses" };
  }
  if (!isDigest(checkpointDigest)) return { ok: false, reason: "MALFORMED", field: "checkpoint_digest" };
  const eligible = new Set(policy.eligible_witnesses);
  const counted = new Set();
  const rejected = [];
  for (const attestation of Array.isArray(attestations) ? attestations : []) {
    const v = await verifyWitnessAttestation({ attestation, witnessBundle, checkpointDigest, now });
    if (!v.ok) {
      rejected.push({ witness_id: isObject(attestation) ? attestation.witness_id : null, reason: v.reason });
      continue;
    }
    if (!eligible.has(v.witness_id)) {
      rejected.push({ witness_id: v.witness_id, reason: "WITNESS_NOT_ELIGIBLE" });
      continue;
    }
    counted.add(v.witness_id);
  }
  const count = counted.size;
  const met = count >= policy.required;
  return {
    ok: met,
    met,
    required: policy.required,
    count,
    witnesses: [...counted].sort(),
    rejected,
    checkpoint_digest: checkpointDigest,
    reason: met ? undefined : "THRESHOLD_NOT_MET"
  };
}
