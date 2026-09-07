// Witnessed authority checkpoints — hostile + happy-path suite (F-witness).
//
//   npm run test:witnessed-authority
//
// Covers: checkpoint create/verify, witness attestation + trust, threshold
// counting, authority/witness equivocation, chain forks, threshold conflict,
// serialization round-trips, and rough offline benchmarks. Fully offline;
// deterministic via injected fixed times.

import assert from "node:assert/strict";

import { buildAuthorityBundle, fingerprintOf, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { canonicalizeJson } from "../shared/json.ts";
import {
  CHECKPOINT_SCHEMA,
  checkpointDigest,
  createCheckpoint,
  digestOf,
  verifyAuthorityCheckpoint
} from "../src/authority-checkpoint/checkpoint.mjs";
import {
  ATTESTATION_SCHEMA,
  WITNESS_BUNDLE_SCHEMA,
  WITNESS_POLICY_SCHEMA,
  WITNESS_ROLE,
  createWitnessAttestation,
  evaluateWitnessThreshold,
  verifyWitnessAttestation
} from "../src/witness/witness.mjs";
import {
  analyzeCheckpointConflict,
  buildEquivocationProof,
  classifyCheckpointConflict,
  detectWitnessEquivocation,
  verifyEquivocationProof
} from "../src/equivocation/equivocation.mjs";

// ── fixed times ──────────────────────────────────────────────────────────────
const VALID_FROM = "2026-01-01T00:00:00.000Z";
const VALID_UNTIL = "2027-01-01T00:00:00.000Z";
const ISSUED = "2026-08-12T06:00:00.000Z";
const OBSERVED = "2026-08-12T06:03:00.000Z";
const NOW = "2026-08-12T06:10:00.000Z";

const results = [];
let group = "";
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${group}${name}: ${error.message}`);
  }
}
const clone = (o) => JSON.parse(JSON.stringify(o));
function flipHex(s) {
  const c = s[s.length - 1];
  return s.slice(0, -1) + (c === "0" ? "1" : "0");
}

// ── fixtures ─────────────────────────────────────────────────────────────────
function keypair(keyId) {
  return { keyId, ...generateAuthorityKeyPair() };
}

async function makeAuthorityBundle({ authorityId = "mnde-prod", checkpointKeys, receiptKeys = [], revocation = [] }) {
  const root = keypair("root-2026");
  const bundle = await buildAuthorityBundle({
    authorityId,
    issuedAt: VALID_FROM,
    notAfter: VALID_UNTIL,
    root,
    receiptKeys,
    checkpointKeys,
    revocation
  });
  return { bundle, root, fp: fingerprintOf(root.publicPem) };
}

function witnessEntry(witnessId, kp, over = {}) {
  return {
    witness_id: witnessId,
    key_id: kp.keyId,
    public_key: kp.publicPem,
    roles: [WITNESS_ROLE],
    valid_from: VALID_FROM,
    valid_until: VALID_UNTIL,
    revoked: false,
    ...over
  };
}
function makeWitnessBundle(entries, { authorityId = "mnde-prod", revocation = [] } = {}) {
  return { schema: WITNESS_BUNDLE_SCHEMA, authority_id: authorityId, witnesses: entries, revocation };
}

async function main() {
  console.log("MNDe witnessed authority checkpoints — hostile suite\n");

  // Shared valid fixture: a bundle with a checkpoint key + a receipt key (for
  // wrong-role tests), a genesis checkpoint, and a chained sequence-1 checkpoint.
  const chk = keypair("chk-1");
  const rcpt = keypair("rcpt-1");
  const { bundle, fp } = await makeAuthorityBundle({
    checkpointKeys: [{ keyId: chk.keyId, publicPem: chk.publicPem, validFrom: VALID_FROM, validUntil: VALID_UNTIL }],
    receiptKeys: [{ keyId: rcpt.keyId, publicPem: rcpt.publicPem, validFrom: VALID_FROM, validUntil: VALID_UNTIL }]
  });
  const mkCheckpoint = (over = {}) => createCheckpoint({
    authorityId: "mnde-prod",
    authorityEpoch: over.authorityEpoch ?? 42,
    sequence: over.sequence ?? 0,
    previousCheckpointDigest: over.previousCheckpointDigest ?? null,
    authorityBundle: bundle,
    issuedAt: over.issuedAt ?? ISSUED,
    rootKeyId: over.rootKeyId ?? "root-2026",
    checkpointKeyId: over.checkpointKeyId ?? chk.keyId,
    checkpointPrivatePem: over.checkpointPrivatePem ?? chk.privatePem
  });
  const genesis = await mkCheckpoint({ sequence: 0, authorityEpoch: 42 });
  const cp1 = await mkCheckpoint({ sequence: 1, authorityEpoch: 43, previousCheckpointDigest: checkpointDigest(genesis) });
  const V = { authorityBundle: bundle, trustedRootFingerprint: fp, now: NOW };

  // ─────────────────────────────────────────── §39 checkpoint happy path
  group = "checkpoint-happy: ";
  console.log("§39 Checkpoint happy path");
  await test("create + verify a valid genesis checkpoint", async () => {
    assert.equal((await verifyAuthorityCheckpoint({ checkpoint: genesis, ...V })).ok, true);
  });
  await test("checkpoint digest is deterministic", () => {
    assert.equal(checkpointDigest(genesis), checkpointDigest(clone(genesis)));
    assert.match(checkpointDigest(genesis), /^sha256:[0-9a-f]{64}$/);
  });
  await test("JSON key order does not change the digest", () => {
    const reordered = {};
    for (const k of Object.keys(genesis).reverse()) reordered[k] = genesis[k];
    assert.equal(checkpointDigest(reordered), checkpointDigest(genesis));
  });
  await test("valid previous-checkpoint link passes", async () => {
    assert.equal((await verifyAuthorityCheckpoint({ checkpoint: cp1, previousCheckpoint: genesis, ...V })).ok, true);
  });
  await test("authority bundle digest matches the bound bundle", () => {
    assert.equal(genesis.authority_bundle_digest, digestOf(bundle));
  });
  await test("correct checkpoint role passes", async () => {
    assert.equal((await verifyAuthorityCheckpoint({ checkpoint: genesis, ...V })).ok, true);
  });

  // ─────────────────────────────────────────── §40 checkpoint hostile
  group = "checkpoint-hostile: ";
  console.log("§40 Checkpoint hostile");
  const tamper = async (mut, expectReason) => {
    const bad = clone(genesis);
    mut(bad);
    const r = await verifyAuthorityCheckpoint({ checkpoint: bad, ...V });
    assert.equal(r.ok, false, `expected failure`);
    if (expectReason) assert.equal(r.reason, expectReason, `reason ${r.reason}`);
  };
  await test("tampered authority_id fails", () => tamper((c) => (c.authority_id = "evil-corp"), "AUTHORITY_MISMATCH"));
  await test("tampered epoch fails", () => tamper((c) => (c.authority_epoch = 99)));
  await test("tampered previous digest fails", () => tamper((c) => (c.previous_checkpoint_digest = `sha256:${"a".repeat(64)}`)));
  await test("tampered bundle digest fails", () => tamper((c) => (c.authority_bundle_digest = `sha256:${"b".repeat(64)}`), "BUNDLE_DIGEST_MISMATCH"));
  await test("tampered issued_at fails", () => tamper((c) => (c.issued_at = "2020-01-01T00:00:00.000Z")));
  await test("tampered root_key_id fails", () => tamper((c) => (c.root_key_id = "root-evil"), "ROOT_FINGERPRINT_MISMATCH"));
  await test("tampered signature fails", () => tamper((c) => (c.signature.value = flipHex(c.signature.value)), "SIGNATURE_INVALID"));
  await test("unknown key fails", () => tamper((c) => (c.signature.key_id = "no-such-key"), "UNKNOWN_KEY"));
  await test("wrong role fails (receipt key signing a checkpoint)", async () => {
    const wrong = await mkCheckpoint({ checkpointKeyId: rcpt.keyId, checkpointPrivatePem: rcpt.privatePem });
    const r = await verifyAuthorityCheckpoint({ checkpoint: wrong, ...V });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "WRONG_ROLE");
  });
  await test("revoked key fails", async () => {
    const { bundle: rb, fp: rfp } = await makeAuthorityBundle({
      checkpointKeys: [{ keyId: chk.keyId, publicPem: chk.publicPem, validFrom: VALID_FROM, validUntil: VALID_UNTIL }],
      revocation: [{ key_id: chk.keyId, revoked_at: VALID_FROM }]
    });
    const c = await createCheckpoint({ authorityId: "mnde-prod", authorityEpoch: 42, sequence: 0, previousCheckpointDigest: null, authorityBundle: rb, issuedAt: ISSUED, rootKeyId: "root-2026", checkpointKeyId: chk.keyId, checkpointPrivatePem: chk.privatePem });
    const r = await verifyAuthorityCheckpoint({ checkpoint: c, authorityBundle: rb, trustedRootFingerprint: rfp, now: NOW });
    assert.equal(r.reason, "KEY_REVOKED");
  });
  await test("expired key fails", async () => {
    const { bundle: eb, fp: efp } = await makeAuthorityBundle({ checkpointKeys: [{ keyId: chk.keyId, publicPem: chk.publicPem, validFrom: VALID_FROM, validUntil: "2026-06-01T00:00:00.000Z" }] });
    const c = await createCheckpoint({ authorityId: "mnde-prod", authorityEpoch: 42, sequence: 0, previousCheckpointDigest: null, authorityBundle: eb, issuedAt: ISSUED, rootKeyId: "root-2026", checkpointKeyId: chk.keyId, checkpointPrivatePem: chk.privatePem });
    assert.equal((await verifyAuthorityCheckpoint({ checkpoint: c, authorityBundle: eb, trustedRootFingerprint: efp, now: NOW })).reason, "KEY_EXPIRED");
  });
  await test("not-yet-valid key fails", async () => {
    const { bundle: nb, fp: nfp } = await makeAuthorityBundle({ checkpointKeys: [{ keyId: chk.keyId, publicPem: chk.publicPem, validFrom: "2026-09-01T00:00:00.000Z", validUntil: VALID_UNTIL }] });
    const c = await createCheckpoint({ authorityId: "mnde-prod", authorityEpoch: 42, sequence: 0, previousCheckpointDigest: null, authorityBundle: nb, issuedAt: ISSUED, rootKeyId: "root-2026", checkpointKeyId: chk.keyId, checkpointPrivatePem: chk.privatePem });
    assert.equal((await verifyAuthorityCheckpoint({ checkpoint: c, authorityBundle: nb, trustedRootFingerprint: nfp, now: NOW })).reason, "KEY_NOT_YET_VALID");
  });
  await test("wrong root fingerprint fails", async () => {
    assert.equal((await verifyAuthorityCheckpoint({ checkpoint: genesis, authorityBundle: bundle, trustedRootFingerprint: "sha256-not-the-root", now: NOW })).ok, false);
  });
  await test("demo/substituted manifest cannot anchor the checkpoint", async () => {
    const { bundle: demo, fp: dfp } = await makeAuthorityBundle({ authorityId: "mnde-demo", checkpointKeys: [{ keyId: chk.keyId, publicPem: chk.publicPem, validFrom: VALID_FROM, validUntil: VALID_UNTIL }] });
    assert.equal((await verifyAuthorityCheckpoint({ checkpoint: genesis, authorityBundle: demo, trustedRootFingerprint: dfp, now: NOW })).ok, false);
  });
  await test("unsupported schema fails", () => tamper((c) => (c.schema = "mnde.authority.checkpoint.v2"), "UNSUPPORTED_SCHEMA"));
  await test("missing required field fails", () => tamper((c) => delete c.authority_bundle_digest, "MALFORMED"));
  await test("extra smuggled field fails (strict shape)", () => tamper((c) => (c.evil = "smuggled"), "MALFORMED"));
  await test("malformed signature object fails", () => tamper((c) => (c.signature = "not-an-object"), "MALFORMED"));
  await test("malformed input does not throw", async () => {
    for (const bad of [null, undefined, 42, "x", [], {}, { schema: CHECKPOINT_SCHEMA }]) {
      const r = await verifyAuthorityCheckpoint({ checkpoint: bad, ...V });
      assert.equal(r.ok, false);
    }
  });
  await test("invalidly signed parent checkpoint is rejected", async () => {
    const badParent = clone(genesis);
    badParent.signature.value = flipHex(badParent.signature.value);
    const r = await verifyAuthorityCheckpoint({ checkpoint: cp1, previousCheckpoint: badParent, ...V });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "PREVIOUS_CHECKPOINT_INVALID");
    assert.equal(r.detail, "SIGNATURE_INVALID");
  });
  await test("authority epoch cannot roll back across a checkpoint link", async () => {
    const rollback = await mkCheckpoint({ sequence: 1, authorityEpoch: 1, previousCheckpointDigest: checkpointDigest(genesis) });
    const r = await verifyAuthorityCheckpoint({ checkpoint: rollback, previousCheckpoint: genesis, ...V });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "EPOCH_INVALID");
  });

  // ─────────────────────────────────────────── §41 witness happy path
  group = "witness-happy: ";
  console.log("§41 Witness happy path");
  const wa = keypair("wa-1");
  const wb = keypair("wb-1");
  const wc = keypair("wc-1");
  const wbundle = makeWitnessBundle([witnessEntry("witness-a", wa), witnessEntry("witness-b", wb), witnessEntry("witness-c", wc)]);
  const digest = checkpointDigest(genesis);
  const mkAtt = (kp, witnessId, over = {}) => createWitnessAttestation({
    checkpointDigest: over.checkpointDigest ?? digest,
    authorityId: over.authorityId ?? "mnde-prod",
    authorityEpoch: over.authorityEpoch ?? 42,
    witnessId,
    observedAt: over.observedAt ?? OBSERVED,
    witnessKeyId: kp.keyId,
    witnessPrivatePem: kp.privatePem
  });
  const attA = await mkAtt(wa, "witness-a");
  const attB = await mkAtt(wb, "witness-b");
  await test("valid witness attestation verifies", async () => {
    assert.equal((await verifyWitnessAttestation({ attestation: attA, witnessBundle: wbundle, checkpointDigest: digest, now: NOW })).ok, true);
  });
  await test("attestation binds the checkpoint digest, authority, epoch", async () => {
    const r = await verifyWitnessAttestation({ attestation: attA, witnessBundle: wbundle, checkpointDigest: digest, now: NOW });
    assert.equal(r.ok, true);
    assert.equal(r.witness_id, "witness-a");
  });
  await test("independent witness bundle (not the authority bundle) is the trust source", async () => {
    // The witness public key lives ONLY in the witness bundle, never in the attestation.
    assert.equal("public_key" in attA, false);
  });
  await test("correct witness role passes", async () => {
    assert.equal((await verifyWitnessAttestation({ attestation: attB, witnessBundle: wbundle, now: NOW })).ok, true);
  });

  // ─────────────────────────────────────────── §42 witness hostile
  group = "witness-hostile: ";
  console.log("§42 Witness hostile");
  const wtamper = async (base, mut, expect) => {
    const bad = clone(base);
    mut(bad);
    const r = await verifyWitnessAttestation({ attestation: bad, witnessBundle: wbundle, checkpointDigest: digest, now: NOW });
    assert.equal(r.ok, false);
    if (expect) assert.equal(r.reason, expect, `reason ${r.reason}`);
  };
  await test("tampered checkpoint_digest fails", () => wtamper(attA, (a) => (a.checkpoint_digest = `sha256:${"c".repeat(64)}`), "CHECKPOINT_DIGEST_MISMATCH"));
  await test("tampered authority_id fails", () => wtamper(attA, (a) => (a.authority_id = "evil"), "AUTHORITY_MISMATCH"));
  await test("tampered epoch fails (signature breaks)", () => wtamper(attA, (a) => (a.authority_epoch = 7)));
  await test("tampered witness_id fails", () => wtamper(attA, (a) => (a.witness_id = "witness-b")));
  await test("unknown witness fails", () => wtamper(attA, (a) => { a.witness_id = "ghost"; a.signature.key_id = "wa-1"; }, "UNKNOWN_WITNESS"));
  await test("wrong witness role fails", async () => {
    const wrongRole = makeWitnessBundle([witnessEntry("witness-a", wa, { roles: ["some-other-role"] })]);
    const r = await verifyWitnessAttestation({ attestation: attA, witnessBundle: wrongRole, checkpointDigest: digest, now: NOW });
    assert.equal(r.reason, "WRONG_WITNESS_ROLE");
  });
  await test("revoked witness fails", async () => {
    const revoked = makeWitnessBundle([witnessEntry("witness-a", wa, { revoked: true })]);
    assert.equal((await verifyWitnessAttestation({ attestation: attA, witnessBundle: revoked, checkpointDigest: digest, now: NOW })).reason, "WITNESS_REVOKED");
  });
  await test("expired witness fails", async () => {
    const exp = makeWitnessBundle([witnessEntry("witness-a", wa, { valid_until: "2026-06-01T00:00:00.000Z" })]);
    assert.equal((await verifyWitnessAttestation({ attestation: attA, witnessBundle: exp, checkpointDigest: digest, now: NOW })).reason, "WITNESS_EXPIRED");
  });
  await test("not-yet-valid witness fails", async () => {
    const ny = makeWitnessBundle([witnessEntry("witness-a", wa, { valid_from: "2026-09-01T00:00:00.000Z" })]);
    assert.equal((await verifyWitnessAttestation({ attestation: attA, witnessBundle: ny, checkpointDigest: digest, now: NOW })).reason, "WITNESS_NOT_YET_VALID");
  });
  await test("malformed attestation fails closed (no throw)", async () => {
    for (const bad of [null, {}, 5, "x", { schema: ATTESTATION_SCHEMA }]) {
      assert.equal((await verifyWitnessAttestation({ attestation: bad, witnessBundle: wbundle, now: NOW })).ok, false);
    }
  });
  await test("signature copied from another checkpoint fails (replay onto new digest)", async () => {
    const replay = clone(attA);
    replay.checkpoint_digest = checkpointDigest(cp1); // different checkpoint, old signature
    const r = await verifyWitnessAttestation({ attestation: replay, witnessBundle: wbundle, checkpointDigest: checkpointDigest(cp1), now: NOW });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "WITNESS_SIGNATURE_INVALID");
  });
  await test("authority checkpoint key cannot masquerade as a witness", async () => {
    // chk is an authority checkpoint key; it is not enrolled in the witness bundle.
    const att = await mkAtt(chk, "witness-a"); // signed by authority key, claims witness-a
    const r = await verifyWitnessAttestation({ attestation: att, witnessBundle: wbundle, checkpointDigest: digest, now: NOW });
    assert.equal(r.ok, false); // key_id "chk-1" not enrolled for witness-a
  });
  await test("witness key cannot masquerade as authority checkpoint signer", async () => {
    // Sign a checkpoint with a witness key and claim a checkpoint role id → not in checkpoint role.
    const forged = await mkCheckpoint({ checkpointKeyId: wa.keyId, checkpointPrivatePem: wa.privatePem });
    const r = await verifyAuthorityCheckpoint({ checkpoint: forged, ...V });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "UNKNOWN_KEY");
  });

  // ─────────────────────────────────────────── §43 threshold
  group = "threshold: ";
  console.log("§43 Threshold");
  const policy = (required, eligible) => ({ schema: WITNESS_POLICY_SCHEMA, required, eligible_witnesses: eligible });
  const thr = (attests, pol) => evaluateWitnessThreshold({ checkpointDigest: digest, attestations: attests, witnessBundle: wbundle, policy: pol, now: NOW });
  const attC = await mkAtt(wc, "witness-c");
  const attA2 = await mkAtt(wa, "witness-a"); // duplicate witness A (same key)
  await test("0-of-N passes only with explicit required:0", async () => {
    assert.equal((await thr([], policy(0, ["witness-a", "witness-b", "witness-c"]))).met, true);
  });
  await test("1-of-1 valid passes", async () => {
    assert.equal((await thr([attA], policy(1, ["witness-a"]))).met, true);
  });
  await test("1-of-1 invalid fails", async () => {
    const bad = clone(attA); bad.signature.value = flipHex(bad.signature.value);
    assert.equal((await thr([bad], policy(1, ["witness-a"]))).met, false);
  });
  await test("2-of-3 with A+B passes", async () => {
    assert.equal((await thr([attA, attB], policy(2, ["witness-a", "witness-b", "witness-c"]))).met, true);
  });
  await test("2-of-3 with A only fails", async () => {
    assert.equal((await thr([attA], policy(2, ["witness-a", "witness-b", "witness-c"]))).met, false);
  });
  await test("2-of-3 with A+A (duplicate) fails — counts once", async () => {
    const r = await thr([attA, attA2], policy(2, ["witness-a", "witness-b", "witness-c"]));
    assert.equal(r.count, 1);
    assert.equal(r.met, false);
  });
  await test("2-of-3 with A+B+C passes", async () => {
    assert.equal((await thr([attA, attB, attC], policy(2, ["witness-a", "witness-b", "witness-c"]))).count, 3);
  });
  await test("2-of-3 with A valid + B expired fails", async () => {
    const bexp = makeWitnessBundle([witnessEntry("witness-a", wa), witnessEntry("witness-b", wb, { valid_until: "2026-06-01T00:00:00.000Z" }), witnessEntry("witness-c", wc)]);
    const r = await evaluateWitnessThreshold({ checkpointDigest: digest, attestations: [attA, attB], witnessBundle: bexp, policy: policy(2, ["witness-a", "witness-b", "witness-c"]), now: NOW });
    assert.equal(r.met, false);
    assert.equal(r.count, 1);
  });
  await test("unknown/ineligible witness C is not counted", async () => {
    const r = await thr([attA, attC], policy(2, ["witness-a", "witness-b"])); // C not eligible
    assert.equal(r.count, 1);
    assert.equal(r.met, false);
  });
  await test("attestation over a different checkpoint does not count", async () => {
    const other = await mkAtt(wb, "witness-b", { checkpointDigest: checkpointDigest(cp1) });
    const r = await thr([attA, other], policy(2, ["witness-a", "witness-b"]));
    assert.equal(r.count, 1);
  });
  await test("missing witness eligibility fails closed as a malformed policy", async () => {
    const r = await thr([attA], { schema: WITNESS_POLICY_SCHEMA, required: 1 });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "MALFORMED_POLICY");
  });
  await test("witness eligibility must contain unique non-empty IDs and a possible threshold", async () => {
    for (const eligible_witnesses of ["witness-a", [""], ["witness-a", "witness-a"]]) {
      const r = await thr([attA], { schema: WITNESS_POLICY_SCHEMA, required: 1, eligible_witnesses });
      assert.equal(r.ok, false);
      assert.equal(r.reason, "MALFORMED_POLICY");
    }
    const impossible = await thr([attA], policy(2, ["witness-a"]));
    assert.equal(impossible.ok, false);
    assert.equal(impossible.reason, "MALFORMED_POLICY");
  });

  // ─────────────────────────────────────────── §44 authority equivocation
  group = "authority-equivocation: ";
  console.log("§44 Authority equivocation");
  // Two conflicting checkpoints at the same position (same epoch+sequence), both validly signed.
  const cpX = await mkCheckpoint({ sequence: 5, authorityEpoch: 50, previousCheckpointDigest: `sha256:${"1".repeat(64)}` });
  const cpY = await mkCheckpoint({ sequence: 5, authorityEpoch: 50, previousCheckpointDigest: `sha256:${"2".repeat(64)}` });
  await test("same authority+epoch, same digest → no equivocation", () => {
    assert.equal(classifyCheckpointConflict(cpX, clone(cpX)).conflict, false);
  });
  await test("same authority+position, different digest → equivocation", () => {
    assert.equal(classifyCheckpointConflict(cpX, cpY).kind, "AUTHORITY_EQUIVOCATION");
  });
  await test("different authority → no authority equivocation", async () => {
    const { bundle: ob } = await makeAuthorityBundle({ authorityId: "other-prod", checkpointKeys: [{ keyId: chk.keyId, publicPem: chk.publicPem, validFrom: VALID_FROM, validUntil: VALID_UNTIL }] });
    const oc = await createCheckpoint({ authorityId: "other-prod", authorityEpoch: 50, sequence: 5, previousCheckpointDigest: `sha256:${"1".repeat(64)}`, authorityBundle: ob, issuedAt: ISSUED, rootKeyId: "root-2026", checkpointKeyId: chk.keyId, checkpointPrivatePem: chk.privatePem });
    assert.equal(classifyCheckpointConflict(cpX, oc).conflict, false);
  });
  await test("different epoch with correct chain → no equivocation", () => {
    assert.equal(classifyCheckpointConflict(genesis, cp1).conflict, false);
  });
  await test("same parent, two different children at next position → fork", async () => {
    const parent = checkpointDigest(genesis);
    const childA = await mkCheckpoint({ sequence: 1, authorityEpoch: 43, previousCheckpointDigest: parent, issuedAt: ISSUED });
    const childB = await mkCheckpoint({ sequence: 1, authorityEpoch: 43, previousCheckpointDigest: parent, issuedAt: OBSERVED });
    assert.equal(classifyCheckpointConflict(childA, childB).kind, "CHAIN_FORK");
  });
  await test("one invalid checkpoint → no valid equivocation proof", async () => {
    const badX = clone(cpX); badX.signature.value = flipHex(badX.signature.value);
    const proof = buildEquivocationProof(badX, cpY);
    assert.equal((await verifyEquivocationProof({ proof, authorityBundle: bundle, trustedRootFingerprint: fp, now: NOW })).ok, false);
  });
  await test("both validly signed conflicting checkpoints → valid proof (survives offline verify)", async () => {
    const proof = buildEquivocationProof(cpX, cpY, { detectedAt: NOW });
    const r = await verifyEquivocationProof({ proof, authorityBundle: bundle, trustedRootFingerprint: fp, now: NOW });
    assert.equal(r.ok, true);
    assert.equal(r.kind, "AUTHORITY_EQUIVOCATION");
    // round-trips through canonical JSON without changing verdict
    const roundtrip = JSON.parse(canonicalizeJson(proof));
    assert.equal((await verifyEquivocationProof({ proof: roundtrip, authorityBundle: bundle, trustedRootFingerprint: fp, now: NOW })).ok, true);
  });

  // ─────────────────────────────────────────── §45 witness equivocation
  group = "witness-equivocation: ";
  console.log("§45 Witness equivocation");
  const digX = checkpointDigest(cpX);
  const digY = checkpointDigest(cpY);
  const wAx = await mkAtt(wa, "witness-a", { checkpointDigest: digX, authorityEpoch: 50 });
  const wAx2 = await mkAtt(wa, "witness-a", { checkpointDigest: digX, authorityEpoch: 50 });
  const wAy = await mkAtt(wa, "witness-a", { checkpointDigest: digY, authorityEpoch: 50 });
  const wBy = await mkAtt(wb, "witness-b", { checkpointDigest: digY, authorityEpoch: 50 });
  await test("witness signs A once → fine (not equivocation)", async () => {
    assert.equal((await detectWitnessEquivocation({ attestationA: wAx, attestationB: wAx, witnessBundle: wbundle, now: NOW })).ok, false);
  });
  await test("witness signs A twice → duplicate, not equivocation", async () => {
    assert.equal((await detectWitnessEquivocation({ attestationA: wAx, attestationB: wAx2, witnessBundle: wbundle, now: NOW })).reason, "DUPLICATE");
  });
  await test("witness signs conflicting A and B at same position → witness equivocation", async () => {
    const r = await detectWitnessEquivocation({ attestationA: wAx, attestationB: wAy, witnessBundle: wbundle, now: NOW });
    assert.equal(r.ok, true);
    assert.equal(r.witness_id, "witness-a");
  });
  await test("different witnesses on conflicting histories → not per-witness equivocation", async () => {
    assert.equal((await detectWitnessEquivocation({ attestationA: wAx, attestationB: wBy, witnessBundle: wbundle, now: NOW })).reason, "NOT_SAME_WITNESS");
  });
  await test("invalid witness signature cannot create equivocation", async () => {
    const bad = clone(wAy); bad.signature.value = flipHex(bad.signature.value);
    assert.equal((await detectWitnessEquivocation({ attestationA: wAx, attestationB: bad, witnessBundle: wbundle, now: NOW })).ok, false);
  });

  // ─────────────────────────────────────────── §46 threshold conflict
  group = "threshold-conflict: ";
  console.log("§46 Threshold conflict");
  const wCy = await mkAtt(wc, "witness-c", { checkpointDigest: digY, authorityEpoch: 50 });
  const pol3 = policy(2, ["witness-a", "witness-b", "witness-c"]);
  await test("Scenario A: A+B on X, C on Y → X meets, Y fails, conflict observable", async () => {
    const r = await analyzeCheckpointConflict({
      candidateX: { checkpoint: cpX, attestations: [wAx, wBy && (await mkAtt(wb, "witness-b", { checkpointDigest: digX, authorityEpoch: 50 }))] },
      candidateY: { checkpoint: cpY, attestations: [wCy] },
      authorityBundle: bundle, trustedRootFingerprint: fp, witnessBundle: wbundle, policy: pol3, now: NOW
    });
    assert.equal(r.x.threshold_met, true);
    assert.equal(r.y.threshold_met, false);
    assert.equal(r.conflict, "AUTHORITY_EQUIVOCATION");
    assert.equal(r.resolved, false);
  });
  await test("Scenario B: A+B on X and B+C on Y → both meet, conflict + B witness-equivocation surfaced", async () => {
    const wBx = await mkAtt(wb, "witness-b", { checkpointDigest: digX, authorityEpoch: 50 });
    const r = await analyzeCheckpointConflict({
      candidateX: { checkpoint: cpX, attestations: [wAx, wBx] },
      candidateY: { checkpoint: cpY, attestations: [wBy, wCy] },
      authorityBundle: bundle, trustedRootFingerprint: fp, witnessBundle: wbundle, policy: pol3, now: NOW
    });
    assert.equal(r.both_meet_threshold, true);
    assert.equal(r.conflict, "AUTHORITY_EQUIVOCATION");
    assert.deepEqual(r.witness_equivocators, ["witness-b"]);
    assert.equal(r.resolved, false); // never silently selects X or Y
  });
  await test("malformed threshold policy returns an analysis error instead of success or throw", async () => {
    const r = await analyzeCheckpointConflict({
      candidateX: { checkpoint: cpX, attestations: [wAx] },
      candidateY: { checkpoint: cpY, attestations: [wBy] },
      authorityBundle: bundle,
      trustedRootFingerprint: fp,
      witnessBundle: wbundle,
      policy: { schema: WITNESS_POLICY_SCHEMA, required: 1 },
      now: NOW
    });
    assert.equal(r.ok, false);
    assert.equal(r.reason, "CANDIDATE_X_THRESHOLD_INVALID");
    assert.equal(r.detail, "MALFORMED_POLICY");
  });

  // ─────────────────────────────────────────── §47 serialization
  group = "serialization: ";
  console.log("§47 Serialization");
  await test("checkpoint round-trips and keeps its digest + verdict", async () => {
    const rt = JSON.parse(canonicalizeJson(genesis));
    assert.equal(checkpointDigest(rt), checkpointDigest(genesis));
    assert.equal((await verifyAuthorityCheckpoint({ checkpoint: rt, ...V })).ok, true);
  });
  await test("attestation round-trips and keeps its verdict", async () => {
    const rt = JSON.parse(canonicalizeJson(attA));
    assert.equal((await verifyWitnessAttestation({ attestation: rt, witnessBundle: wbundle, checkpointDigest: digest, now: NOW })).ok, true);
  });
  await test("post-signing mutation is rejected", async () => {
    const m = clone(genesis); m.authority_epoch = 999;
    assert.equal((await verifyAuthorityCheckpoint({ checkpoint: m, ...V })).ok, false);
  });

  // ─────────────────────────────────────────── §48 benchmarks (rough, offline)
  group = "bench: ";
  console.log("§48 Performance (rough, offline)");
  const timeIt = async (label, iters, fn) => {
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < iters; i += 1) await fn();
    const ms = Number(process.hrtime.bigint() - t0) / 1e6 / iters;
    console.log(`    ${label}: ~${ms.toFixed(2)} ms/op (${iters} iters)`);
    return ms;
  };
  await test("benchmarks complete offline within a sane bound", async () => {
    const t1 = await timeIt("checkpoint verify", 50, () => verifyAuthorityCheckpoint({ checkpoint: genesis, ...V }));
    const t2 = await timeIt("1-witness verify", 50, () => verifyWitnessAttestation({ attestation: attA, witnessBundle: wbundle, checkpointDigest: digest, now: NOW }));
    const t3 = await timeIt("3-witness threshold", 50, () => thr([attA, attB, attC], policy(2, ["witness-a", "witness-b", "witness-c"])));
    const proof = buildEquivocationProof(cpX, cpY);
    const t4 = await timeIt("equivocation proof verify", 50, () => verifyEquivocationProof({ proof, authorityBundle: bundle, trustedRootFingerprint: fp, now: NOW }));
    for (const t of [t1, t2, t3, t4]) assert.ok(t < 100, `op too slow: ${t}ms (possible accidental network/IO)`);
  });

  // ── summary ──
  const passed = results.filter(Boolean).length;
  const total = results.length;
  if (passed !== total) {
    console.log(`\nFAIL witnessed-authority (${passed}/${total})`);
    process.exit(1);
  }
  console.log(`\nPASS witnessed-authority (${passed}/${total})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
