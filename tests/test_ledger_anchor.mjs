// MNDe execution-ledger — anchoring (Phase 1) hostile + success-condition tests.
//
//   npm run test:ledger-anchor
//
// Proves the Phase-1 success condition: a FRESH OFFLINE verifier, given one proof
// bundle and the public authority bundle, verifies the whole chain
//   receipt signature -> receipt-to-entry binding -> entry signature
//   -> Merkle inclusion -> signed checkpoint -> authority-bundle key validity
// with no ledger download, no network, no trust in the proof generator. Plus every
// hostile/criteria case, determinism, and cross-language parity vectors.

import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalizeJson } from "../shared/json.ts";
import { appendLedgerEntry, buildLedgerEntry } from "../src/execution-ledger/append.mjs";
import { anchorLedger, computeCheckpoint, buildProofBundle } from "../src/execution-ledger/anchor.mjs";
import { verifyProofBundle } from "../src/execution-ledger/proof.mjs";
import { canonicalReceiptHash, checkpointSignablePayload, LEDGER_ERRORS, LEDGER_ASSURANCE } from "../src/execution-ledger/index.mjs";
import { createLocalDemoCustody } from "../src/custody/index.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair, signCanonical } from "../src/custody/bundle.mjs";
import { signReceiptForDelivery } from "../src/authority-signing/index.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";

const EPOCH_TS = "1970-01-01T00:00:00.000Z";
const FAR_TS = "2999-01-01T00:00:00.000Z";

// A self-consistent, properly root-signed bundle whose ledger key is revoked as of
// 2020 — lets us prove revocation is enforced by policy (not by breaking the sig).
async function revokedLedgerCustody() {
  const root = { keyId: "rk-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "rk-receipt", ...generateAuthorityKeyPair() };
  const ledger = { keyId: "rk-ledger", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "revoked-demo", issuedAt: CREATED_AT, notAfter: FAR_TS, root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: EPOCH_TS, validUntil: FAR_TS }],
    policyKeys: [], approvalKeys: [], resultKeys: [],
    ledgerKeys: [{ keyId: ledger.keyId, publicPem: ledger.publicPem, validFrom: EPOCH_TS, validUntil: FAR_TS }],
    activationKeys: [],
    revocation: [{ key_id: ledger.keyId, revoked_at: "2020-01-01T00:00:00.000Z" }]
  });
  const signLedger = async (payload) => ({ key_id: ledger.keyId, value: await signCanonical(payload, ledger.privatePem), fingerprint: bundle.keys.ledger[0].fingerprint });
  return { bundle, signLedger };
}

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const samplePolicy = join(repoRoot, "examples", "policy-engine", "sample-policy-no-approval.json");
const CREATED_AT = "2026-06-29T00:00:00.000Z";
const ISSUED_AT = "2026-06-29T00:05:00.000Z";

let CUSTODY, SIGN_LEDGER, BUNDLE, SIGNING_CONFIG;

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (e) { results.push(false); console.log(`  [FAIL] ${name}: ${e.message}`); }
}
function tmpRoot() { return mkdtempSync(join(tmpdir(), "mnde-anchor-")); }

async function signedEnvelope(inner, at = CREATED_AT) {
  const r = await signReceiptForDelivery(inner, SIGNING_CONFIG, { now: at });
  assert.equal(r.ok, true, `sign envelope: ${r.reason_code ?? ""}`);
  return r.receipt; // mnde.signed-receipt.v1 envelope
}

// Build a store + signed v2 ledger of `count` custody-signed receipts.
async function buildChain(root, count) {
  const storePath = join(root, "receipts.jsonl");
  const ledgerPath = join(root, ".data", "ledger.jsonl");
  const envelopes = [];
  for (let i = 1; i <= count; i += 1) {
    envelopes.push(await signedEnvelope({
      receipt_id: `r${i}`, schema_version: "mnde.pe.receipt.v1",
      amount_cents: i * 100, decision_output: { decision: "REFUSE", reason_code: "NO_MATCHING_RULE" }
    }));
  }
  writeFileSync(storePath, envelopes.map((e) => canonicalizeJson(e)).join("\n") + "\n");
  for (const env of envelopes) {
    const out = await appendLedgerEntry({
      ledgerPath, receipt: env,
      receiptRef: { path: "receipts.jsonl", receipt_id: null }, // envelopes are looked up by hash
      signLedger: SIGN_LEDGER, createdAt: CREATED_AT
    });
    assert.equal(out.ok, true, `append: ${out.code ?? ""}`);
  }
  const checkpointPath = join(root, ".data", "checkpoints.jsonl");
  return { storePath, ledgerPath, checkpointPath, envelopes, root };
}

async function main() {
  console.log("MNDe ledger anchoring — Phase 1 tests\n");
  CUSTODY = await createLocalDemoCustody();
  SIGN_LEDGER = CUSTODY.signLedger;
  BUNDLE = CUSTODY.getPublicBundle();
  SIGNING_CONFIG = { mode: "custody", provider: CUSTODY };

  // ── THE SUCCESS CONDITION ─────────────────────────────────────────────────────
  let successBundle = null;
  await test("fresh offline verifier verifies one receipt end-to-end (success condition)", async () => {
    const root = tmpRoot();
    const { ledgerPath, checkpointPath, storePath, envelopes } = await buildChain(root, 3);
    const checkpoint = await anchorLedger(ledgerPath, checkpointPath, { signLedger: SIGN_LEDGER, bundle: BUNDLE, issuedAt: ISSUED_AT });
    assert.equal(checkpoint.tree_size, 3);
    const receiptHash = canonicalReceiptHash(envelopes[1]); // r2
    const proof = await buildProofBundle(ledgerPath, checkpoint, { receipt_hash: receiptHash }, { receiptStorePath: storePath, trustedBundle: BUNDLE });

    // Fresh offline machine: ONLY the proof bundle + a fresh copy of the PUBLIC
    // bundle. No ledger path, no filesystem, no network, no generator trust.
    const res = await verifyProofBundle(structuredClone(proof), structuredClone(BUNDLE), { trustedRootFingerprint: BUNDLE.root_key.fingerprint });
    assert.equal(res.ok, true, res.reason);
    assert.equal(res.assurance, LEDGER_ASSURANCE.OPERATOR_SIGNED_INCLUSION);
    assert.equal(res.time_basis, "operator-asserted");
    assert.equal(res.tree_size, 3);
    assert.equal(res.sequence, 2);
    successBundle = proof;
    rmSync(root, { recursive: true, force: true });
  });

  // ── Acceptance criteria ───────────────────────────────────────────────────────
  await test("log_id is the authority ROOT fingerprint (stable, key-independent)", async () => {
    const root = tmpRoot();
    const { ledgerPath, checkpointPath } = await buildChain(root, 2);
    const cp = await computeCheckpoint(ledgerPath, { signLedger: SIGN_LEDGER, bundle: BUNDLE, issuedAt: ISSUED_AT });
    assert.equal(cp.log_id, BUNDLE.root_key.fingerprint);
    assert.notEqual(cp.log_id, cp.key_id, "log_id must not be the ledger signing key id");
    rmSync(root, { recursive: true, force: true });
  });

  await test("tree_size is entry COUNT, not the last sequence number", async () => {
    const root = tmpRoot();
    const { ledgerPath } = await buildChain(root, 3);
    const cp = await computeCheckpoint(ledgerPath, { signLedger: SIGN_LEDGER, bundle: BUNDLE, issuedAt: ISSUED_AT });
    assert.equal(cp.tree_size, 3);
    assert.equal(cp.ledger_head.sequence, 3);
    rmSync(root, { recursive: true, force: true });
  });

  await test("cross-run output is byte-for-byte deterministic (same inputs)", async () => {
    const root = tmpRoot();
    const { ledgerPath } = await buildChain(root, 3);
    const a = await computeCheckpoint(ledgerPath, { signLedger: SIGN_LEDGER, bundle: BUNDLE, issuedAt: ISSUED_AT });
    const b = await computeCheckpoint(ledgerPath, { signLedger: SIGN_LEDGER, bundle: BUNDLE, issuedAt: ISSUED_AT });
    assert.equal(canonicalizeJson(a), canonicalizeJson(b), "checkpoint must be deterministic (Ed25519 is deterministic)");
    rmSync(root, { recursive: true, force: true });
  });

  await test("tampered checkpoint root fails (checkpoint signature invalid)", async () => {
    const b = structuredClone(successBundle);
    b.checkpoint.root_hash = `sha256:${"0".repeat(64)}`;
    const res = await verifyProofBundle(b, BUNDLE, {});
    assert.equal(res.ok, false);
    assert.match(res.reason, /CHECKPOINT_SIGNATURE_INVALID|INCLUSION_INVALID/);
  });

  await test("checkpoint re-signed by a foreign key fails (CHECKPOINT_SIGNATURE_INVALID)", async () => {
    const attacker = await createLocalDemoCustody();
    const b = structuredClone(successBundle);
    // Attacker signs the exact checkpoint payload with a key they control. key_id is
    // left as ours so epoch mapping passes — only the signature is foreign.
    const forged = await attacker.signLedger(checkpointSignablePayload(b.checkpoint));
    b.checkpoint.signature = { algorithm: "ED25519", key_id: b.checkpoint.key_id, value: forged.value };
    const res = await verifyProofBundle(b, BUNDLE, {});
    assert.equal(res.ok, false);
    assert.match(res.reason, /CHECKPOINT_SIGNATURE_INVALID/);
  });

  await test("excision + mixed-key re-anchor is rejected before checkpoint signing", async () => {
    const root = tmpRoot();
    const { ledgerPath, checkpointPath, storePath, envelopes } = await buildChain(root, 3);
    const honest = await anchorLedger(ledgerPath, checkpointPath, { signLedger: SIGN_LEDGER, bundle: BUNDLE, issuedAt: ISSUED_AT });
    // A counterparty holding r2's honest proof can always still prove inclusion.
    const r2 = await buildProofBundle(ledgerPath, honest, { receipt_hash: canonicalReceiptHash(envelopes[1]) }, { receiptStorePath: storePath, trustedBundle: BUNDLE });
    assert.equal((await verifyProofBundle(r2, BUNDLE, {})).ok, true);

    // Attacker excises entry 2 and re-anchors with a key they control.
    const attacker = await createLocalDemoCustody();
    const eRoot = tmpRoot();
    const eLedger = join(eRoot, ".data", "ledger.jsonl");
    const eCkpt = join(eRoot, ".data", "checkpoints.jsonl");
    mkdirSync(dirname(eLedger), { recursive: true });
    const lines = readFileSync(ledgerPath, "utf8").split("\n").filter((l) => l.trim() !== "");
    const e1 = JSON.parse(lines[0]);
    const e2b = await buildLedgerEntry({ sequence: 2, previousEntryHash: e1.entry_hash, receipt: envelopes[2], receiptRef: { path: "receipts.jsonl", receipt_id: null }, signLedger: attacker.signLedger, createdAt: CREATED_AT });
    writeFileSync(eLedger, [lines[0], canonicalizeJson(e2b)].join("\n") + "\n");
    writeFileSync(join(eRoot, "receipts.jsonl"), [envelopes[0], envelopes[2]].map((e) => canonicalizeJson(e)).join("\n") + "\n");
    let threw = null;
    try {
      await anchorLedger(eLedger, eCkpt, { signLedger: attacker.signLedger, bundle: attacker.getPublicBundle(), issuedAt: ISSUED_AT });
    } catch (error) {
      threw = error;
    }
    assert.ok(threw && [
      LEDGER_ERRORS.SIGNATURE_INVALID,
      LEDGER_ERRORS.SIGNATURE_KEY_UNTRUSTED
    ].includes(threw.code), `expected signature rejection, got ${threw?.code}`);
    rmSync(root, { recursive: true, force: true });
    rmSync(eRoot, { recursive: true, force: true });
  });

  await test("latency gap: a receipt beyond the checkpoint is NOT_ANCHORED", async () => {
    const root = tmpRoot();
    const { ledgerPath, checkpointPath, storePath } = await buildChain(root, 2);
    const cp = await anchorLedger(ledgerPath, checkpointPath, { signLedger: SIGN_LEDGER, bundle: BUNDLE, issuedAt: ISSUED_AT });
    // Append a 3rd receipt AFTER the checkpoint.
    const env3 = await signedEnvelope({ receipt_id: "r3", schema_version: "mnde.pe.receipt.v1", amount_cents: 300, decision_output: { decision: "REFUSE", reason_code: "NO_MATCHING_RULE" } });
    writeFileSync(storePath, readFileSync(storePath, "utf8") + canonicalizeJson(env3) + "\n");
    await appendLedgerEntry({ ledgerPath, receipt: env3, receiptRef: { path: "receipts.jsonl", receipt_id: null }, signLedger: SIGN_LEDGER, createdAt: CREATED_AT });
    let threw = null;
    try { await buildProofBundle(ledgerPath, cp, { receipt_hash: canonicalReceiptHash(env3) }, { receiptStorePath: storePath, trustedBundle: BUNDLE }); }
    catch (e) { threw = e; }
    assert.ok(threw && threw.code === LEDGER_ERRORS.NOT_ANCHORED, `expected NOT_ANCHORED, got ${threw?.code}`);
    rmSync(root, { recursive: true, force: true });
  });

  await test("revoked ledger key: anchoring rejects the revoked entry before signing a checkpoint", async () => {
    const { bundle, signLedger } = await revokedLedgerCustody();
    const root = tmpRoot();
    const ledgerPath = join(root, ".data", "ledger.jsonl");
    writeFileSync(join(root, "receipts.jsonl"), canonicalizeJson({ receipt_id: "r1" }) + "\n");
    // Append still works (append is not a policy boundary); anchoring must refuse.
    await appendLedgerEntry({ ledgerPath, receipt: { receipt_id: "r1" }, receiptRef: { path: "receipts.jsonl", receipt_id: null }, signLedger, createdAt: CREATED_AT });
    let threw = null;
    try { await computeCheckpoint(ledgerPath, { signLedger, bundle, issuedAt: ISSUED_AT }); }
    catch (e) { threw = e; }
    assert.ok(threw && threw.code === LEDGER_ERRORS.SIGNATURE_KEY_UNTRUSTED, `expected SIGNATURE_KEY_UNTRUSTED, got ${threw?.code}`);
    rmSync(root, { recursive: true, force: true });
  });

  await test("key_epoch that disagrees with the bundle fails (CHECKPOINT_KEY_EPOCH_MISMATCH)", async () => {
    const b = structuredClone(successBundle);
    b.checkpoint.key_epoch = 99; // no such epoch
    const res = await verifyProofBundle(b, BUNDLE, {});
    assert.equal(res.ok, false);
    assert.match(res.reason, /CHECKPOINT_KEY_EPOCH_MISMATCH/);
  });

  await test("tampered entry signature fails (SIGNATURE_INVALID)", async () => {
    const b = structuredClone(successBundle);
    const v = b.entry.signature.value;
    b.entry.signature.value = (v[0] === "a" ? "b" : "a") + v.slice(1);
    const res = await verifyProofBundle(b, BUNDLE, {});
    assert.equal(res.ok, false);
    assert.match(res.reason, /SIGNATURE_INVALID|SIGNATURE_KEY_UNTRUSTED/);
  });

  await test("no trusted bundle fails closed (NO_TRUST_BUNDLE)", async () => {
    const res = await verifyProofBundle(structuredClone(successBundle), null, {});
    assert.equal(res.ok, false);
    assert.match(res.reason, /NO_TRUST_BUNDLE/);
  });

  await test("root-signed authority bundle is verified before any bundled key is trusted", async () => {
    const altered = structuredClone(BUNDLE);
    altered.authority_id = "attacker-modified-after-root-signing";
    const res = await verifyProofBundle(structuredClone(successBundle), altered, {});
    assert.equal(res.ok, false);
    assert.match(res.reason, /authority bundle rejected: BUNDLE_SIGNATURE_INVALID/);
  });

  await test("malformed checkpoint and algorithm-confusion inputs fail closed", async () => {
    const badSize = structuredClone(successBundle);
    badSize.checkpoint.tree_size = Number.MAX_VALUE;
    assert.match((await verifyProofBundle(badSize, BUNDLE, {})).reason, /CHECKPOINT_MALFORMED/);

    const badEntryAlgorithm = structuredClone(successBundle);
    badEntryAlgorithm.entry.signature.algorithm = "RSA";
    assert.match((await verifyProofBundle(badEntryAlgorithm, BUNDLE, {})).reason, /SIGNATURE_MISSING/);

    const badCheckpointAlgorithm = structuredClone(successBundle);
    badCheckpointAlgorithm.checkpoint.signature.algorithm = "RSA";
    assert.match((await verifyProofBundle(badCheckpointAlgorithm, BUNDLE, {})).reason, /CHECKPOINT_MALFORMED/);
  });

  await test("local checkpoint continuity rejects ledger rollback", async () => {
    const root = tmpRoot();
    const { ledgerPath, checkpointPath } = await buildChain(root, 2);
    await anchorLedger(ledgerPath, checkpointPath, { signLedger: SIGN_LEDGER, bundle: BUNDLE, issuedAt: ISSUED_AT });
    const first = readFileSync(ledgerPath, "utf8").split("\n").find((line) => line.trim() !== "");
    writeFileSync(ledgerPath, `${first}\n`);
    let threw = null;
    try {
      await anchorLedger(ledgerPath, checkpointPath, { signLedger: SIGN_LEDGER, bundle: BUNDLE, issuedAt: ISSUED_AT });
    } catch (error) {
      threw = error;
    }
    assert.equal(threw?.code, LEDGER_ERRORS.CHECKPOINT_ROLLBACK);
    rmSync(root, { recursive: true, force: true });
  });

  // ── Live sidecar round-trip (endpoints) ───────────────────────────────────────
  await test("live: decisions append, on-demand /ledger/anchor, /ledger/proof returns a verified proof", async () => {
    const liveRoot = tmpRoot();
    const port = 8802;
    const url = `http://127.0.0.1:${port}`;
    const sidecar = await startMndeSidecar({ url, env: {
      MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: samplePolicy, MNDE_BIND_PORT: String(port),
      MNDE_RECEIPT_LOG: join(liveRoot, "receipts.jsonl"),
      MNDE_LEDGER_ANCHOR_TICK_MS: "3600000" // disable the background timer; drive anchoring on-demand
    } });
    try {
      const decide = (tool, id) => fetch(`${url}/v1/decisions`, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ schema_version: "1.0", request_id: id, timestamp: "2026-06-29T00:00:00.000Z", principal: { id: "alice" }, agent: { id: "a1" }, tool: { tool_name: tool }, parameters: {}, environment: {}, context: {} }) }).then((r) => r.json());
      const d1 = await decide("read_status", "req-a");
      await decide("read_status", "req-b");
      assert.equal(d1.ledger.appended, true, "decision must append a ledger entry");
      // The ledger references receipts by content hash; select the proof that way.
      const receiptHash = canonicalReceiptHash(d1.receipt);

      const anchored = await fetch(`${url}/ledger/anchor`, { method: "POST" }).then((r) => r.json());
      assert.equal(anchored.anchored, true, JSON.stringify(anchored));
      assert.ok(anchored.checkpoint.tree_size >= 2, `tree_size ${anchored.checkpoint.tree_size}`);

      const head = await fetch(`${url}/ledger/checkpoint`).then((r) => r.json());
      assert.equal(head.checkpoint.tree_size, anchored.checkpoint.tree_size);

      const proof = await fetch(`${url}/ledger/proof?receipt_hash=${encodeURIComponent(receiptHash)}`).then((r) => r.json());
      // proofResponse self-verified the bundle against the sidecar's own bundle before
      // returning; ok:true means the full chain reproduced end-to-end for real.
      assert.equal(proof.ok, true, JSON.stringify(proof));
      assert.equal(proof.proof.schema, "mnde.execution_ledger.inclusion_proof.v1");
      assert.equal(proof.proof.entry.sequence, 1);
    } finally {
      await sidecar.stop();
      rmSync(liveRoot, { recursive: true, force: true });
    }
  });

  // ── Cross-language parity vectors (criterion #14) ─────────────────────────────
  await test("parity vectors verify (static, self-contained, no private keys)", async () => {
    const vdir = resolve(repoRoot, "tests", "vectors", "ledger-anchoring");
    if (!existsSync(join(vdir, "proof-bundle.json"))) {
      mkdirSync(vdir, { recursive: true });
      writeFileSync(join(vdir, "authority-bundle.public.json"), JSON.stringify(BUNDLE, null, 2) + "\n");
      writeFileSync(join(vdir, "proof-bundle.json"), JSON.stringify(successBundle, null, 2) + "\n");
      writeFileSync(join(vdir, "expected.json"), JSON.stringify({ ok: true, assurance: LEDGER_ASSURANCE.OPERATOR_SIGNED_INCLUSION, tree_size: 3, sequence: 2 }, null, 2) + "\n");
      writeFileSync(join(vdir, "README.md"), "# Ledger anchoring parity vectors\n\nStatic Phase-1 inclusion-proof vectors. A verifier in ANY language must load\n`proof-bundle.json` + `authority-bundle.public.json` and reproduce `expected.json`\n(ok:true, assurance operator-signed-inclusion). Public material only — NO private\nkeys. Regenerating requires rerunning the anchor test with fresh keys.\n");
      console.log("  [note] generated parity vectors under tests/vectors/ledger-anchoring — commit them");
    }
    const proof = JSON.parse(readFileSync(join(vdir, "proof-bundle.json"), "utf8"));
    const bundle = JSON.parse(readFileSync(join(vdir, "authority-bundle.public.json"), "utf8"));
    const expected = JSON.parse(readFileSync(join(vdir, "expected.json"), "utf8"));
    const res = await verifyProofBundle(proof, bundle, { trustedRootFingerprint: bundle.root_key.fingerprint });
    assert.equal(res.ok, expected.ok, res.reason);
    assert.equal(res.assurance, expected.assurance);
    assert.equal(res.tree_size, expected.tree_size);
    assert.equal(res.sequence, expected.sequence);
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) { console.log(`FAIL ledger-anchor tests (${results.length - failed}/${results.length})`); process.exit(1); }
  console.log(`PASS ledger-anchor tests (${results.length}/${results.length})`);
}

main().catch((e) => { console.error(e); process.exit(1); });
