// MNDe V2 Execution Ledger — hostile tests.
//
//   npm run test:execution-ledger
//
// Proves the tamper-evident append-only chain over finalized receipts: normal
// signed append/verify, every tamper class fails closed with the right error
// code, the SIGNATURE contract (unsigned/legacy rejected, stripped/forged/
// wrong-key signatures rejected, excision-and-rebuild without the ledger key
// rejected), the production fail-closed and disable-in-production rules hold, and
// — critically — the ledger never changes receipt bytes, the signed envelope, or
// standalone receipt verification. A live sidecar run proves entries are appended
// (and signature-verified) for real decisions and that the reads are authority-gated.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalizeJson } from "../shared/json.ts";
import {
  LEDGER_ENTRY_SCHEMA,
  LEDGER_ENTRY_SCHEMA_V2,
  LEDGER_ERRORS,
  canonicalReceiptHash,
  computeEntryHash
} from "../src/execution-ledger/index.mjs";
import { appendLedgerEntry, buildLedgerEntry, LEGACY_LEDGER_ARCHIVE_SUFFIX } from "../src/execution-ledger/append.mjs";
import { verifyLedger } from "../src/execution-ledger/verify.mjs";
import { ledgerStartupGate } from "../src/execution-ledger/paths.mjs";
import { resolveLedgerRuntime, recordReceiptInLedger } from "../src/execution-ledger/sidecar.mjs";
import { buildPolicyReceipt, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { createLocalDemoCustody } from "../src/custody/index.mjs";
import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const samplePolicy = join(repoRoot, "examples", "policy-engine", "sample-policy-no-approval.json");

// Ledger signing custody for the tests. SIGN_LEDGER mints signed v2 entries;
// TRUSTED_BUNDLE is the public bundle the verifier checks them against.
let SIGN_LEDGER = null;
let TRUSTED_BUNDLE = null;

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

function tmpRoot() {
  return mkdtempSync(join(tmpdir(), "mnde-ledger-"));
}

// Build a store + 3-entry SIGNED ledger. Receipts carry a receipt_id so we can
// exercise the precise edit-vs-delete distinction (RECEIPT_HASH vs RECEIPT_MISSING).
async function buildChain(root) {
  const storePath = join(root, "receipts.jsonl");
  const ledgerPath = join(root, ".data", "ledger.jsonl");
  const receipts = [1, 2, 3].map((n) => ({
    receipt_id: `r${n}`,
    schema_version: "mnde.pe.receipt.v1",
    request_hash: `rh${n}`,
    amount_cents: n * 100,
    decision_output: { decision: "REFUSE", reason_code: "NO_MATCHING_RULE" }
  }));
  writeFileSync(storePath, receipts.map((r) => canonicalizeJson(r)).join("\n") + "\n");
  for (const r of receipts) {
    const out = await appendLedgerEntry({ ledgerPath, receipt: r, receiptRef: { path: "receipts.jsonl", receipt_id: r.receipt_id }, signLedger: SIGN_LEDGER });
    assert.equal(out.ok, true, `append ${r.receipt_id}: ${out.code ?? ""} ${out.message ?? ""}`);
  }
  return { storePath, ledgerPath, receipts, receiptRoot: root };
}

// A legacy (unsigned v1) entry, built by hand — the pre-signing format.
function buildLegacyV1Entry({ sequence, previousEntryHash, receipt, receiptRef }) {
  const body = {
    schema: LEDGER_ENTRY_SCHEMA,
    sequence,
    created_at: "2026-06-29T00:00:00.000Z",
    receipt_hash: canonicalReceiptHash(receipt),
    previous_entry_hash: previousEntryHash ?? null,
    receipt_ref: { storage: "local", path: receiptRef.path, receipt_id: receiptRef.receipt_id ?? null },
    engine: { name: "mnde-policy-engine", version: null }
  };
  return { ...body, entry_hash: computeEntryHash(body) };
}

function ledgerLines(ledgerPath) {
  return readFileSync(ledgerPath, "utf8").split("\n").filter((l) => l.trim() !== "");
}

async function main() {
  console.log("MNDe execution ledger — hostile tests\n");
  bootstrapReceiptKeys({ repoRoot });

  const custody = await createLocalDemoCustody();
  SIGN_LEDGER = custody.signLedger;
  TRUSTED_BUNDLE = custody.getPublicBundle();

  // ── Core append / verify ────────────────────────────────────────────────────
  await test("empty ledger verifies ok with entries_checked 0", async () => {
    const root = tmpRoot();
    const ledgerPath = join(root, ".data", "ledger.jsonl");
    mkdirSync(dirname(ledgerPath), { recursive: true });
    writeFileSync(ledgerPath, "");
    const r = await verifyLedger({ ledgerPath, receiptRoot: root, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, true);
    assert.equal(r.entries_checked, 0);
    assert.equal(r.head, null);
    rmSync(root, { recursive: true, force: true });
  });

  await test("first append creates a signed v2 entry, sequence 1, previous_entry_hash null", async () => {
    const root = tmpRoot();
    const ledgerPath = join(root, ".data", "ledger.jsonl");
    const r1 = { receipt_id: "r1", v: 1 };
    writeFileSync(join(root, "receipts.jsonl"), canonicalizeJson(r1) + "\n");
    const out = await appendLedgerEntry({ ledgerPath, receipt: r1, receiptRef: { path: "receipts.jsonl", receipt_id: "r1" }, signLedger: SIGN_LEDGER });
    assert.equal(out.ok, true);
    assert.equal(out.sequence, 1);
    const entry = JSON.parse(ledgerLines(ledgerPath)[0]);
    assert.equal(entry.sequence, 1);
    assert.equal(entry.previous_entry_hash, null);
    assert.equal(entry.schema, LEDGER_ENTRY_SCHEMA_V2);
    assert.equal(entry.signature.algorithm, "ED25519");
    assert.ok(typeof entry.signature.value === "string" && entry.signature.value.length > 0);
    rmSync(root, { recursive: true, force: true });
  });

  await test("append without a signer fails closed (SIGNER_REQUIRED)", async () => {
    const root = tmpRoot();
    const ledgerPath = join(root, ".data", "ledger.jsonl");
    writeFileSync(join(root, "receipts.jsonl"), canonicalizeJson({ receipt_id: "r1" }) + "\n");
    const out = await appendLedgerEntry({ ledgerPath, receipt: { receipt_id: "r1" }, receiptRef: { path: "receipts.jsonl", receipt_id: "r1" } });
    assert.equal(out.ok, false);
    assert.equal(out.code, LEDGER_ERRORS.SIGNER_REQUIRED);
    rmSync(root, { recursive: true, force: true });
  });

  await test("second append links to the first entry_hash", async () => {
    const root = tmpRoot();
    const { ledgerPath } = await buildChain(root);
    const [l1, l2] = ledgerLines(ledgerPath).map((l) => JSON.parse(l));
    assert.equal(l2.previous_entry_hash, l1.entry_hash);
    assert.equal(l2.sequence, 2);
    rmSync(root, { recursive: true, force: true });
  });

  await test("receipt_hash matches the canonical receipt bytes", async () => {
    const root = tmpRoot();
    const { ledgerPath, receipts } = await buildChain(root);
    const entry = JSON.parse(ledgerLines(ledgerPath)[0]);
    assert.equal(entry.receipt_hash, canonicalReceiptHash(receipts[0]));
    rmSync(root, { recursive: true, force: true });
  });

  await test("verification passes after normal signed appends", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const r = await verifyLedger({ ledgerPath, receiptRoot, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, true, JSON.stringify(r.errors));
    assert.equal(r.entries_checked, 3);
    assert.equal(r.head.sequence, 3);
    rmSync(root, { recursive: true, force: true });
  });

  // ── Signature contract ──────────────────────────────────────────────────────
  await test("verifying signed entries with NO trusted bundle fails (NO_TRUST_BUNDLE)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const r = await verifyLedger({ ledgerPath, receiptRoot, trustedBundle: null });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.NO_TRUST_BUNDLE);
    rmSync(root, { recursive: true, force: true });
  });

  await test("stripping the signature fails (SIGNATURE_MISSING)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    const e = JSON.parse(lines[0]);
    delete e.signature; // entry_hash still recomputes; signature is gone
    lines[0] = canonicalizeJson(e);
    writeFileSync(ledgerPath, lines.join("\n") + "\n");
    const r = await verifyLedger({ ledgerPath, receiptRoot, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.SIGNATURE_MISSING);
    rmSync(root, { recursive: true, force: true });
  });

  await test("a legacy unsigned v1 entry is rejected in strict mode (LEGACY_ENTRY_REJECTED)", async () => {
    const root = tmpRoot();
    const ledgerPath = join(root, ".data", "ledger.jsonl");
    const r1 = { receipt_id: "r1", v: 1 };
    writeFileSync(join(root, "receipts.jsonl"), canonicalizeJson(r1) + "\n");
    mkdirSync(dirname(ledgerPath), { recursive: true });
    const legacy = buildLegacyV1Entry({ sequence: 1, previousEntryHash: null, receipt: r1, receiptRef: { path: "receipts.jsonl", receipt_id: "r1" } });
    writeFileSync(ledgerPath, canonicalizeJson(legacy) + "\n");
    const strict = await verifyLedger({ ledgerPath, receiptRoot: root, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(strict.ok, false);
    assert.equal(strict.errors[0].code, LEDGER_ERRORS.LEGACY_ENTRY_REJECTED);
    // …but readable in explicit legacy/audit mode.
    const legacyRead = await verifyLedger({ ledgerPath, receiptRoot: root, trustedBundle: TRUSTED_BUNDLE, strict: false });
    assert.equal(legacyRead.ok, true, JSON.stringify(legacyRead.errors));
    assert.equal(legacyRead.entries_checked, 1);
    rmSync(root, { recursive: true, force: true });
  });

  await test("append rolls a legacy v1 ledger into an audit archive and starts a fresh v2 chain", async () => {
    const root = tmpRoot();
    const ledgerPath = join(root, ".data", "ledger.jsonl");
    const receiptPath = join(root, "receipts.jsonl");
    const r1 = { receipt_id: "r1", v: 1 };
    const r2 = { receipt_id: "r2", v: 2 };
    writeFileSync(receiptPath, `${canonicalizeJson(r1)}\n${canonicalizeJson(r2)}\n`);
    mkdirSync(dirname(ledgerPath), { recursive: true });
    const legacy = buildLegacyV1Entry({ sequence: 1, previousEntryHash: null, receipt: r1, receiptRef: { path: "receipts.jsonl", receipt_id: "r1" } });
    writeFileSync(ledgerPath, `${canonicalizeJson(legacy)}\n`);

    const out = await appendLedgerEntry({
      ledgerPath,
      receipt: r2,
      receiptRef: { path: "receipts.jsonl", receipt_id: "r2" },
      signLedger: SIGN_LEDGER
    });
    const archivePath = `${ledgerPath}${LEGACY_LEDGER_ARCHIVE_SUFFIX}`;
    assert.equal(out.ok, true, out.message);
    assert.equal(out.rolled_over_legacy, true);
    assert.equal(out.legacy_ledger_path, archivePath);
    assert.equal(existsSync(archivePath), true);
    assert.equal(JSON.parse(ledgerLines(archivePath)[0]).schema, LEDGER_ENTRY_SCHEMA);
    const active = JSON.parse(ledgerLines(ledgerPath)[0]);
    assert.equal(active.schema, LEDGER_ENTRY_SCHEMA_V2);
    assert.equal(active.sequence, 1);
    assert.equal(active.previous_entry_hash, null);
    const verified = await verifyLedger({ ledgerPath, receiptRoot: root, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(verified.ok, true, JSON.stringify(verified.errors));
    rmSync(root, { recursive: true, force: true });
  });

  await test("ledger CLI accepts documented bare --legacy boolean flag", () => {
    const root = tmpRoot();
    try {
      const ledgerPath = join(root, "legacy.jsonl");
      const r1 = { receipt_id: "r1", v: 1 };
      writeFileSync(join(root, "receipts.jsonl"), `${canonicalizeJson(r1)}\n`);
      const legacy = buildLegacyV1Entry({ sequence: 1, previousEntryHash: null, receipt: r1, receiptRef: { path: "receipts.jsonl", receipt_id: "r1" } });
      writeFileSync(ledgerPath, `${canonicalizeJson(legacy)}\n`);
      const cli = spawnSync(process.execPath, [
        join(repoRoot, "scripts", "verify-ledger.mjs"),
        "verify",
        "--legacy",
        `--ledger=${ledgerPath}`,
        `--receipt-root=${root}`
      ], { encoding: "utf8" });
      assert.equal(cli.status, 0, cli.stderr || cli.stdout);
      assert.match(cli.stdout, /PASS execution-ledger verification/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  await test("an unknown signing key_id is rejected (SIGNATURE_KEY_UNTRUSTED)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    const e = JSON.parse(lines[0]);
    e.signature = { ...e.signature, key_id: "attacker-unknown-key" };
    lines[0] = canonicalizeJson(e);
    writeFileSync(ledgerPath, lines.join("\n") + "\n");
    const r = await verifyLedger({ ledgerPath, receiptRoot, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.SIGNATURE_KEY_UNTRUSTED);
    rmSync(root, { recursive: true, force: true });
  });

  // THE headline test: an attacker who can fully rewrite the store but does NOT
  // hold the ledger signing key cannot produce a chain that verifies.
  await test("excision-and-rebuild without the ledger key fails (SIGNATURE_INVALID)", async () => {
    const root = tmpRoot();
    const { ledgerPath, storePath, receipts, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    const e1 = JSON.parse(lines[0]);

    // Attacker forges a new "entry 2" that references r3 (excising the real r2),
    // links correctly to entry 1, recomputes entry_hash — and signs with a key
    // they DO control (a different custody; same local-demo key_id, different key).
    const attacker = await createLocalDemoCustody();
    const forged = await buildLedgerEntry({
      sequence: 2,
      previousEntryHash: e1.entry_hash,
      receipt: receipts[2],
      receiptRef: { path: "receipts.jsonl", receipt_id: "r3" },
      signLedger: attacker.signLedger
    });
    // Rewrite the store to drop r2 as well, so nothing but the signature is wrong.
    writeFileSync(storePath, [receipts[0], receipts[2]].map((r) => canonicalizeJson(r)).join("\n") + "\n");
    writeFileSync(ledgerPath, [lines[0], canonicalizeJson(forged)].join("\n") + "\n");

    const r = await verifyLedger({ ledgerPath, receiptRoot, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.SIGNATURE_INVALID);
    rmSync(root, { recursive: true, force: true });
  });

  // ── Tampering the receipt store ─────────────────────────────────────────────
  await test("editing a receipt makes verification fail (RECEIPT_HASH)", async () => {
    const root = tmpRoot();
    const { ledgerPath, storePath, receipts, receiptRoot } = await buildChain(root);
    const edited = [{ ...receipts[0], amount_cents: 99999 }, receipts[1], receipts[2]];
    writeFileSync(storePath, edited.map((r) => canonicalizeJson(r)).join("\n") + "\n");
    const r = await verifyLedger({ ledgerPath, receiptRoot, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.RECEIPT_HASH);
    rmSync(root, { recursive: true, force: true });
  });

  await test("deleting a receipt makes verification fail (RECEIPT_MISSING)", async () => {
    const root = tmpRoot();
    const { ledgerPath, storePath, receipts, receiptRoot } = await buildChain(root);
    writeFileSync(storePath, [receipts[1], receipts[2]].map((r) => canonicalizeJson(r)).join("\n") + "\n");
    const r = await verifyLedger({ ledgerPath, receiptRoot, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.RECEIPT_MISSING);
    rmSync(root, { recursive: true, force: true });
  });

  // ── Tampering the ledger itself ─────────────────────────────────────────────
  await test("editing a ledger line body makes verification fail (ENTRY_HASH)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    const e = JSON.parse(lines[1]);
    e.created_at = "1999-01-01T00:00:00.000Z"; // change body, keep stored entry_hash
    lines[1] = canonicalizeJson(e);
    writeFileSync(ledgerPath, lines.join("\n") + "\n");
    const r = await verifyLedger({ ledgerPath, receiptRoot, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.ENTRY_HASH);
    rmSync(root, { recursive: true, force: true });
  });

  await test("deleting a middle ledger line makes verification fail (SEQUENCE)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    writeFileSync(ledgerPath, [lines[0], lines[2]].join("\n") + "\n");
    const r = await verifyLedger({ ledgerPath, receiptRoot, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.SEQUENCE);
    rmSync(root, { recursive: true, force: true });
  });

  await test("reordering ledger lines makes verification fail", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    writeFileSync(ledgerPath, [lines[1], lines[0], lines[2]].join("\n") + "\n");
    const r = await verifyLedger({ ledgerPath, receiptRoot, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, false);
    assert.ok([LEDGER_ERRORS.SEQUENCE, LEDGER_ERRORS.CHAIN_BROKEN].includes(r.errors[0].code), r.errors[0].code);
    rmSync(root, { recursive: true, force: true });
  });

  await test("duplicate sequence fails (DUPLICATE_SEQUENCE)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    writeFileSync(ledgerPath, [lines[0], lines[0]].join("\n") + "\n");
    const r = await verifyLedger({ ledgerPath, receiptRoot, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.DUPLICATE_SEQUENCE);
    rmSync(root, { recursive: true, force: true });
  });

  await test("duplicate entry_hash on a distinct sequence fails (DUPLICATE_ENTRY_HASH)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    const e1 = JSON.parse(lines[0]);
    const forged = { ...e1, sequence: 2, previous_entry_hash: e1.entry_hash };
    writeFileSync(ledgerPath, [lines[0], canonicalizeJson(forged)].join("\n") + "\n");
    const r = await verifyLedger({ ledgerPath, receiptRoot, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.DUPLICATE_ENTRY_HASH);
    rmSync(root, { recursive: true, force: true });
  });

  await test("a validly-signed entry with an unsafe receipt_ref.path still fails (RECEIPT_REF_UNSAFE)", async () => {
    const root = tmpRoot();
    const ledgerPath = join(root, ".data", "ledger.jsonl");
    mkdirSync(dirname(ledgerPath), { recursive: true });
    // Sign a real entry whose receipt_ref path escapes the root — a valid
    // signature must NOT buy a path-traversal past the safety check.
    const entry = await buildLedgerEntry({ sequence: 1, previousEntryHash: null, receipt: { receipt_id: "r1" }, receiptRef: { path: "../../etc/passwd", receipt_id: "r1" }, signLedger: SIGN_LEDGER });
    writeFileSync(ledgerPath, canonicalizeJson(entry) + "\n");
    const r = await verifyLedger({ ledgerPath, receiptRoot: root, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.RECEIPT_REF_UNSAFE);
    rmSync(root, { recursive: true, force: true });
  });

  await test("malformed JSONL line fails (PARSE)", async () => {
    const root = tmpRoot();
    const { ledgerPath, receiptRoot } = await buildChain(root);
    const lines = ledgerLines(ledgerPath);
    writeFileSync(ledgerPath, [lines[0], "{ this is not json", lines[2]].join("\n") + "\n");
    const r = await verifyLedger({ ledgerPath, receiptRoot, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, false);
    assert.equal(r.errors[0].code, LEDGER_ERRORS.PARSE);
    rmSync(root, { recursive: true, force: true });
  });

  // ── Profile / fail-closed rules ─────────────────────────────────────────────
  await test("production startup fails if ledger disabled", () => {
    assert.equal(ledgerStartupGate({ MNDE_PROFILE: "production", MNDE_EXECUTION_LEDGER: "off" }).ok, false);
    assert.equal(ledgerStartupGate({ MNDE_PROFILE: "production", MNDE_EXECUTION_LEDGER: "off" }).code, LEDGER_ERRORS.DISABLED_IN_PRODUCTION);
    assert.equal(ledgerStartupGate({ MNDE_PROFILE: "local", MNDE_EXECUTION_LEDGER: "off" }).ok, true);
    assert.equal(ledgerStartupGate({ MNDE_PROFILE: "production" }).ok, true);
  });

  await test("production decision fails closed if ledger append fails", async () => {
    const root = tmpRoot();
    const badLedgerDir = join(root, "ledger-as-dir");
    mkdirSync(badLedgerDir, { recursive: true });
    const runtime = { enabled: true, ledgerPath: badLedgerDir, receiptRoot: root, receiptStorePath: join(root, "receipts.jsonl") };
    const receipt = { receipt_id: "x", v: 1 };
    const out = await recordReceiptInLedger({ runtime, receipt, durable: Promise.resolve(), profile: "production", engine: { name: "mnde-policy-engine", version: null }, signLedger: SIGN_LEDGER });
    assert.equal(out.appended, false);
    assert.equal(out.failClosed, true);
    assert.equal(out.code, LEDGER_ERRORS.APPEND_FAILED);
    rmSync(root, { recursive: true, force: true });
  });

  await test("local mode reports append failure without mutating the receipt", async () => {
    const root = tmpRoot();
    const badLedgerDir = join(root, "ledger-as-dir");
    mkdirSync(badLedgerDir, { recursive: true });
    const runtime = { enabled: true, ledgerPath: badLedgerDir, receiptRoot: root, receiptStorePath: join(root, "receipts.jsonl") };
    const receipt = { receipt_id: "x", v: 1 };
    const before = canonicalizeJson(receipt);
    const out = await recordReceiptInLedger({ runtime, receipt, durable: Promise.resolve(), profile: "local", engine: { name: "mnde-policy-engine", version: null }, signLedger: SIGN_LEDGER });
    assert.equal(out.appended, false);
    assert.equal(out.failClosed, false);
    assert.equal(canonicalizeJson(receipt), before, "receipt bytes must be unchanged");
    assert.equal("ledger" in receipt, false, "receipt must not gain a ledger field");
    rmSync(root, { recursive: true, force: true });
  });

  // ── Receipt-format-unchanged proofs (a real signed pe.receipt.v1) ────────────
  const realRequest = { schema_version: "1.0", request_id: "req-ledger", timestamp: "2026-06-29T00:00:00.000Z", principal: { id: "alice" }, agent: { id: "a1" }, tool: { tool_name: "read_status" }, parameters: {}, environment: {}, context: {} };
  const realPolicy = JSON.parse(readFileSync(samplePolicy, "utf8"));
  const realReceipt = buildPolicyReceipt(realRequest, realPolicy, {});

  await test("recording a receipt does not change its canonical bytes", async () => {
    const root = tmpRoot();
    const before = canonicalizeJson(realReceipt);
    writeFileSync(join(root, "receipts.jsonl"), before + "\n");
    await appendLedgerEntry({ ledgerPath: join(root, ".data", "l.jsonl"), receipt: realReceipt, receiptRef: { path: "receipts.jsonl", receipt_id: null }, signLedger: SIGN_LEDGER });
    assert.equal(canonicalizeJson(realReceipt), before, "ledger append must not mutate the receipt");
    rmSync(root, { recursive: true, force: true });
  });

  await test("a recorded receipt still verifies as a standalone pe.receipt.v1", async () => {
    assert.equal((await verifyPolicyReceipt(realReceipt)).verified, true);
    assert.equal("ledger" in realReceipt, false);
    assert.equal("entry_hash" in realReceipt, false);
  });

  await test("recording by content hash (no receipt_id) round-trips and verifies", async () => {
    const root = tmpRoot();
    const ledgerPath = join(root, ".data", "l.jsonl");
    writeFileSync(join(root, "receipts.jsonl"), canonicalizeJson(realReceipt) + "\n");
    const out = await appendLedgerEntry({ ledgerPath, receipt: realReceipt, receiptRef: { path: "receipts.jsonl", receipt_id: null }, signLedger: SIGN_LEDGER });
    assert.equal(out.ok, true);
    const r = await verifyLedger({ ledgerPath, receiptRoot: root, trustedBundle: TRUSTED_BUNDLE });
    assert.equal(r.ok, true, JSON.stringify(r.errors));
    assert.equal(r.entries_checked, 1);
    rmSync(root, { recursive: true, force: true });
  });

  // ── Live sidecar integration ────────────────────────────────────────────────
  // Isolate the receipt log (hence the ledger next to it) to a fresh temp dir.
  // Local mode signs the ledger with an ephemeral per-process key, so a ledger
  // left by an earlier process at the shared default path would not verify under
  // this process's bundle — an isolated fresh path keeps the live check
  // deterministic and self-contained (production uses a durable custody key).
  const liveRoot = tmpRoot();
  const port = 8801;
  const url = `http://127.0.0.1:${port}`;
  const sidecar = await startMndeSidecar({ url, env: { MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: samplePolicy, MNDE_BIND_PORT: String(port), MNDE_RECEIPT_LOG: join(liveRoot, "receipts.jsonl") } });
  try {
    await test("live decisions append signed ledger entries and /ledger/head verifies (ungated read in local)", async () => {
      const decide = (tool) => fetch(`${url}/v1/decisions`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ schema_version: "1.0", request_id: `req-${tool}`, timestamp: "2026-06-29T00:00:00.000Z", principal: { id: "alice" }, agent: { id: "a1" }, tool: { tool_name: tool }, parameters: {}, environment: {}, context: {} }) }).then((r) => r.json());
      const d1 = await decide("read_status");
      assert.equal(d1.decision_engine, "policy-engine");
      assert.equal(d1.ledger.appended, true, "response must carry ledger metadata outside the receipt");
      assert.equal("ledger" in d1.receipt, false, "ledger metadata must NOT be inside the receipt");
      await decide("read_status");
      const head = await fetch(`${url}/ledger/head`).then((r) => r.json());
      assert.equal(head.ok, true, JSON.stringify(head));
      assert.ok(head.head.sequence >= 2, `expected >= 2 entries, got ${head.head?.sequence}`);
    });

    await test("ledger verify/export endpoints are authority-gated", async () => {
      assert.equal((await fetch(`${url}/ledger/verify`)).status, 403);
      assert.equal((await fetch(`${url}/ledger/export`)).status, 403);
    });
  } finally {
    await sidecar.stop();
    rmSync(liveRoot, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL execution-ledger tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS execution-ledger tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
