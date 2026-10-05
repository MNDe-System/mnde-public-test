// Equivocation & fork detection over authority checkpoints and witness
// attestations. This layer DETECTS conflict and packages self-verifying
// evidence — it never resolves a conflict (no "most witnesses wins", no
// consensus). Two validly-signed conflicting histories are surfaced as
// evidence, not silently reconciled.

import { canonicalizeJson } from "../../shared/json.ts";
import { checkpointDigest, verifyAuthorityCheckpoint } from "../authority-checkpoint/checkpoint.mjs";
import { evaluateWitnessThreshold, verifyWitnessAttestation } from "../witness/witness.mjs";

export const EQUIVOCATION_PROOF_SCHEMA = "mnde.authority.equivocation-proof.v1";

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Classify the relationship between two checkpoints that are ALREADY known to be
// validly authority-signed. Pure and offline.
//   CHAIN_FORK           — two different children of the same parent checkpoint
//   AUTHORITY_EQUIVOCATION — same authority + same history position, different digest
export function classifyCheckpointConflict(a, b) {
  if (!isObject(a) || !isObject(b)) return { conflict: false, reason: "MALFORMED" };
  if (a.authority_id !== b.authority_id) return { conflict: false, reason: "DIFFERENT_AUTHORITY" };
  const da = checkpointDigest(a);
  const db = checkpointDigest(b);
  if (da === db) return { conflict: false, reason: "IDENTICAL" };
  if (a.previous_checkpoint_digest !== null && a.previous_checkpoint_digest === b.previous_checkpoint_digest) {
    return { conflict: true, kind: "CHAIN_FORK", digest_a: da, digest_b: db };
  }
  if (a.sequence === b.sequence) return { conflict: true, kind: "AUTHORITY_EQUIVOCATION", digest_a: da, digest_b: db };
  if (a.authority_epoch === b.authority_epoch) return { conflict: true, kind: "AUTHORITY_EQUIVOCATION", digest_a: da, digest_b: db };
  return { conflict: false, reason: "DIFFERENT_POSITION" };
}

// Package two conflicting checkpoints into a self-verifying proof object.
export function buildEquivocationProof(checkpointA, checkpointB, { detectedAt = null } = {}) {
  const cls = classifyCheckpointConflict(checkpointA, checkpointB);
  return {
    schema: EQUIVOCATION_PROOF_SCHEMA,
    authority_id: checkpointA?.authority_id ?? null,
    checkpoint_a: checkpointA,
    checkpoint_b: checkpointB,
    reason: cls.conflict ? cls.kind : (cls.reason ?? "NO_CONFLICT"),
    detected_at: detectedAt
  };
}

// Verify an equivocation proof offline. A valid proof requires BOTH checkpoints
// to independently authenticate under the pinned root, belong to the same
// authority, and occupy a conflicting position with different digests. Each
// checkpoint may bind its own authority bundle (e.g. differing revocation
// state); pass `authorityBundleB` when the two differ.
export async function verifyEquivocationProof({ proof, authorityBundle, authorityBundleB, trustedRootFingerprint, now } = {}) {
  if (!isObject(proof) || proof.schema !== EQUIVOCATION_PROOF_SCHEMA) return { ok: false, reason: "UNSUPPORTED_SCHEMA" };
  const a = proof.checkpoint_a;
  const b = proof.checkpoint_b;
  const va = await verifyAuthorityCheckpoint({ checkpoint: a, authorityBundle, trustedRootFingerprint, now });
  if (!va.ok) return { ok: false, reason: "CHECKPOINT_A_INVALID", detail: va.reason };
  const vb = await verifyAuthorityCheckpoint({ checkpoint: b, authorityBundle: authorityBundleB ?? authorityBundle, trustedRootFingerprint, now });
  if (!vb.ok) return { ok: false, reason: "CHECKPOINT_B_INVALID", detail: vb.reason };
  if (a.authority_id !== proof.authority_id || b.authority_id !== proof.authority_id) return { ok: false, reason: "AUTHORITY_MISMATCH" };
  const cls = classifyCheckpointConflict(a, b);
  if (!cls.conflict) return { ok: false, reason: "NO_CONFLICT", detail: cls.reason };
  return { ok: true, kind: cls.kind, checkpoint_a_digest: va.checkpoint_digest, checkpoint_b_digest: vb.checkpoint_digest };
}

// A witness equivocates when the SAME witness validly attests two DIFFERENT
// checkpoint digests at the SAME authority history position. The same witness
// attesting the same digest twice is a duplicate, not equivocation. Two
// different witnesses attesting conflicting histories is a conflict at the
// authority layer, not per-witness misconduct — kept distinct here.
export async function detectWitnessEquivocation({ attestationA, attestationB, witnessBundle, now } = {}) {
  const va = await verifyWitnessAttestation({ attestation: attestationA, witnessBundle, now });
  if (!va.ok) return { ok: false, reason: "ATTESTATION_A_INVALID", detail: va.reason };
  const vb = await verifyWitnessAttestation({ attestation: attestationB, witnessBundle, now });
  if (!vb.ok) return { ok: false, reason: "ATTESTATION_B_INVALID", detail: vb.reason };
  if (attestationA.witness_id !== attestationB.witness_id) return { ok: false, reason: "NOT_SAME_WITNESS" };
  if (attestationA.authority_id !== attestationB.authority_id || attestationA.authority_epoch !== attestationB.authority_epoch) {
    return { ok: false, reason: "DIFFERENT_POSITION" };
  }
  if (attestationA.checkpoint_digest === attestationB.checkpoint_digest) return { ok: false, reason: "DUPLICATE" };
  return { ok: true, kind: "WITNESS_EQUIVOCATION", witness_id: attestationA.witness_id };
}

// Analyze two competing checkpoint candidates (each with its own attestation
// set) under one threshold policy. Reports which candidates meet threshold, the
// authority-layer conflict, and any witnesses that signed BOTH — WITHOUT
// selecting a winner. If both meet threshold the conflict is surfaced, not
// resolved.
export async function analyzeCheckpointConflict({
  candidateX,
  candidateY,
  authorityBundle,
  authorityBundleY,
  trustedRootFingerprint,
  witnessBundle,
  policy,
  now
} = {}) {
  const vx = await verifyAuthorityCheckpoint({ checkpoint: candidateX.checkpoint, authorityBundle, trustedRootFingerprint, now });
  const vy = await verifyAuthorityCheckpoint({ checkpoint: candidateY.checkpoint, authorityBundle: authorityBundleY ?? authorityBundle, trustedRootFingerprint, now });
  if (!vx.ok) return { ok: false, reason: "CANDIDATE_X_INVALID", detail: vx.reason };
  if (!vy.ok) return { ok: false, reason: "CANDIDATE_Y_INVALID", detail: vy.reason };

  const tx = await evaluateWitnessThreshold({ checkpointDigest: vx.checkpoint_digest, attestations: candidateX.attestations, witnessBundle, policy, now });
  const ty = await evaluateWitnessThreshold({ checkpointDigest: vy.checkpoint_digest, attestations: candidateY.attestations, witnessBundle, policy, now });

  const conflict = classifyCheckpointConflict(candidateX.checkpoint, candidateY.checkpoint);

  // Witnesses that validly signed BOTH conflicting digests = witness equivocators.
  const witnessEquivocators = conflict.conflict
    ? tx.witnesses.filter((w) => ty.witnesses.includes(w))
    : [];

  return {
    ok: true,
    conflict: conflict.conflict ? conflict.kind : null,
    x: { checkpoint_digest: vx.checkpoint_digest, threshold_met: tx.met, count: tx.count, witnesses: tx.witnesses },
    y: { checkpoint_digest: vy.checkpoint_digest, threshold_met: ty.met, count: ty.count, witnesses: ty.witnesses },
    both_meet_threshold: tx.met && ty.met,
    witness_equivocators: witnessEquivocators,
    // Never resolved: when both meet threshold under a conflict, this is strong
    // equivocation evidence. The caller decides; we only surface it.
    resolved: false
  };
}

// Keep canonicalizeJson referenced for parity with the other artifact modules
// (equivocation proofs round-trip through the same canonical form when stored).
export function canonicalEquivocationProof(proof) {
  return canonicalizeJson(proof);
}
