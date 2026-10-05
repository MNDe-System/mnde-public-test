// Execution-ledger anchoring (Phase 1) — checkpoints + inclusion-proof assembly.
//
// Runs entirely OFF the append hot path: it reads the append-only ledger file,
// builds a Merkle tree over the entry sequence, and writes a signed checkpoint
// (tree head). Anchors are serialized by their OWN lock file — the ledger append
// lock is never taken here. Checkpoint output is deterministic given the same
// entries + issued_at, for cross-run/cross-language parity.

import { openSync, closeSync, writeSync, fsyncSync, readFileSync, existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";

import { canonicalizeJson } from "../../shared/json.ts";
import {
  LEDGER_CHECKPOINT_SCHEMA,
  LEDGER_CHECKPOINT_VERSION,
  LEDGER_INCLUSION_PROOF_SCHEMA,
  LEDGER_ENTRY_SCHEMA_V2,
  LEDGER_SIGNING_ROLE,
  LEDGER_SIGNATURE_ALGORITHM,
  LEDGER_ERRORS,
  canonicalReceiptHash,
  computeEntryHash,
  ledgerSignablePayload,
  checkpointSignablePayload
} from "./index.mjs";
import { leafHash, merkleRoot, inclusionProof } from "./merkle.mjs";
import { findBundleKey, verifyAgainstBundle, verifyAuthorityBundle } from "../custody/bundle.mjs";
import { verifyProofBundle } from "./proof.mjs";

const CKPT_LOCK_SUFFIX = ".ckpt.lock";
const LOCK_MAX_ATTEMPTS = 100;
const LOCK_RETRY_MS = 5;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function fail(code, message) {
  const e = new Error(message);
  e.code = code;
  return e;
}

// Read + structurally validate the append-only ledger. Recomputes each entry_hash
// and checks the chain links so we never anchor a structurally broken ledger.
// (Full signature crypto is re-run at proof-verify time, the security boundary.)
export function readLedgerEntries(ledgerPath) {
  if (!existsSync(ledgerPath)) return [];
  const raw = readFileSync(ledgerPath, "utf8");
  const lines = raw.split("\n").filter((l) => l.trim() !== "");
  const entries = [];
  let prevHash = null;
  for (let i = 0; i < lines.length; i += 1) {
    let entry;
    try {
      entry = JSON.parse(lines[i]);
    } catch {
      throw fail(LEDGER_ERRORS.PARSE, `ledger line ${i + 1} is not valid JSON`);
    }
    if (typeof entry !== "object" || entry === null || Array.isArray(entry) ||
        entry.schema !== LEDGER_ENTRY_SCHEMA_V2) {
      throw fail(LEDGER_ERRORS.SCHEMA, `anchoring requires signed v2 entries; got '${entry.schema}' at line ${i + 1}`);
    }
    if (!Number.isSafeInteger(entry.sequence) || entry.sequence !== i + 1) {
      throw fail(LEDGER_ERRORS.SEQUENCE, `expected sequence ${i + 1}, got ${entry.sequence}`);
    }
    if ((entry.previous_entry_hash ?? null) !== prevHash) {
      throw fail(LEDGER_ERRORS.CHAIN_BROKEN, `chain broken at sequence ${entry.sequence}`);
    }
    if (computeEntryHash(entry) !== entry.entry_hash) {
      throw fail(LEDGER_ERRORS.ENTRY_HASH, `entry_hash mismatch at sequence ${entry.sequence}`);
    }
    entries.push(entry);
    prevHash = entry.entry_hash;
  }
  return entries;
}

// Resolve the ledger key that is active at `issuedAt` from the published bundle,
// honoring validity windows + revocation. key_epoch = its index in keys.ledger
// (rotation appends, so index is a stable epoch). If several are active (a rotation
// overlap window), the one with the latest valid_from is "current".
export function resolveActiveLedgerKey(bundle, issuedAt) {
  const ledgerKeys = Array.isArray(bundle?.keys?.ledger) ? bundle.keys.ledger : [];
  let best = null;
  for (let epoch = 0; epoch < ledgerKeys.length; epoch += 1) {
    const k = ledgerKeys[epoch];
    const check = findBundleKey(bundle, "ledger", k.key_id, issuedAt);
    if (!check.ok) continue;
    const from = Date.parse(k.valid_from ?? "1970-01-01T00:00:00.000Z");
    if (!best || from >= best.from) best = { key_id: k.key_id, key_epoch: epoch, from };
  }
  if (!best) throw fail(LEDGER_ERRORS.ANCHOR_KEY_UNRESOLVED, "no active, unrevoked ledger key in the authority bundle at issued_at");
  return { key_id: best.key_id, key_epoch: best.key_epoch };
}

// Build (but do not write) a signed checkpoint over the current ledger prefix.
//   ledgerPath  path to the append-only ledger JSONL
//   signLedger  custody ledger signer -> { key_id, value, fingerprint }
//   bundle      the published authority bundle (for log_id + active-key resolution)
//   issuedAt    ISO time the operator CLAIMS it signed at (untrusted proof of time)
export async function computeCheckpoint(ledgerPath, { signLedger, bundle, issuedAt } = {}) {
  if (typeof signLedger !== "function") throw fail(LEDGER_ERRORS.SIGNER_REQUIRED, "computeCheckpoint requires signLedger");
  if (!bundle?.root_key?.fingerprint) throw fail(LEDGER_ERRORS.ANCHOR_FAILED, "authority bundle with a root_key fingerprint is required");
  const at = issuedAt ?? new Date().toISOString();
  if (Number.isNaN(Date.parse(at))) throw fail(LEDGER_ERRORS.ANCHOR_FAILED, "issuedAt must be a valid timestamp");
  const authority = await verifyAuthorityBundle(bundle, {
    trustedRootFingerprint: bundle.root_key.fingerprint,
    now: at
  });
  if (!authority.ok) {
    throw fail(LEDGER_ERRORS.ANCHOR_KEY_UNRESOLVED, `authority bundle rejected: ${authority.reason}`);
  }

  const entries = readLedgerEntries(ledgerPath);
  const treeSize = entries.length;                 // entry COUNT, not last sequence
  if (treeSize === 0) throw fail(LEDGER_ERRORS.ANCHOR_FAILED, "nothing to anchor: empty ledger");
  for (const entry of entries) {
    const sig = entry.signature;
    if (!sig || sig.algorithm !== LEDGER_SIGNATURE_ALGORITHM ||
        typeof sig.key_id !== "string" || typeof sig.value !== "string") {
      throw fail(LEDGER_ERRORS.SIGNATURE_MISSING, `entry ${entry.sequence} signature missing/malformed`);
    }
    const checked = await verifyAgainstBundle(
      ledgerSignablePayload(entry),
      sig.value,
      LEDGER_SIGNING_ROLE,
      sig.key_id,
      entry.created_at,
      bundle
    );
    if (!checked.ok) {
      const code = checked.reason === "SIGNATURE_INVALID"
        ? LEDGER_ERRORS.SIGNATURE_INVALID
        : LEDGER_ERRORS.SIGNATURE_KEY_UNTRUSTED;
      throw fail(code, `entry ${entry.sequence} signature rejected: ${checked.reason}`);
    }
  }

  const leaves = entries.map((e) => leafHash(e.entry_hash));
  const rootHash = merkleRoot(leaves);
  const { key_id, key_epoch } = resolveActiveLedgerKey(bundle, at);
  const head = entries[treeSize - 1];

  const body = {
    schema: LEDGER_CHECKPOINT_SCHEMA,
    version: LEDGER_CHECKPOINT_VERSION,
    log_id: bundle.root_key.fingerprint,           // STABLE across ledger-key rotation
    tree_size: treeSize,
    root_hash: rootHash,
    key_id,
    key_epoch,
    issued_at: at,
    ledger_head: { sequence: head.sequence, entry_hash: head.entry_hash }
  };
  const sig = await signLedger(checkpointSignablePayload(body));
  // The key custody actually signed with MUST be the one we resolved & recorded,
  // or the checkpoint's key_id/epoch would lie about who signed — fail closed.
  if (sig.key_id !== key_id) {
    throw fail(LEDGER_ERRORS.ANCHOR_KEY_UNRESOLVED, `signer key_id '${sig.key_id}' != resolved active ledger key '${key_id}'`);
  }
  return { ...body, signature: { algorithm: LEDGER_SIGNATURE_ALGORITHM, key_id: sig.key_id, value: sig.value } };
}

async function withCheckpointLock(checkpointPath, fn) {
  const lockPath = `${checkpointPath}${CKPT_LOCK_SUFFIX}`;
  let acquired = false;
  for (let attempt = 0; attempt < LOCK_MAX_ATTEMPTS; attempt += 1) {
    try { closeSync(openSync(lockPath, "wx")); acquired = true; break; }
    catch (e) { if (e?.code !== "EEXIST") throw e; await sleep(LOCK_RETRY_MS); }
  }
  if (!acquired) throw fail(LEDGER_ERRORS.LOCK_FAILED, "could not acquire checkpoint lock within retry budget");
  try { return await fn(); }
  finally { try { unlinkSync(lockPath); } catch { /* best effort */ } }
}

// Append a checkpoint to the checkpoint log (JSONL; last line = current head).
export function writeCheckpoint(checkpointPath, checkpoint) {
  mkdirSync(dirname(checkpointPath), { recursive: true });
  const fd = openSync(checkpointPath, "a");
  try {
    writeSync(fd, `${canonicalizeJson(checkpoint)}\n`);
    try { fsyncSync(fd); } catch { /* some FS reject fsync on append */ }
  } finally { closeSync(fd); }
}

export function readCheckpointHead(checkpointPath) {
  if (!existsSync(checkpointPath)) return null;
  const lines = readFileSync(checkpointPath, "utf8").split("\n").filter((l) => l.trim() !== "");
  if (lines.length === 0) return null;
  return JSON.parse(lines[lines.length - 1]);
}

// Compute a new checkpoint and append it, serialized by the checkpoint lock (never
// the ledger append lock). Returns the checkpoint.
export async function anchorLedger(ledgerPath, checkpointPath, opts) {
  return withCheckpointLock(checkpointPath, async () => {
    const previous = readCheckpointHead(checkpointPath);
    if (previous) {
      const entries = readLedgerEntries(ledgerPath);
      if (!Number.isSafeInteger(previous.tree_size) || previous.tree_size < 1 ||
          entries.length < previous.tree_size) {
        throw fail(LEDGER_ERRORS.CHECKPOINT_ROLLBACK, "ledger is shorter than the previous checkpoint");
      }
      const previousRoot = merkleRoot(
        entries.slice(0, previous.tree_size).map((entry) => leafHash(entry.entry_hash))
      );
      if (previousRoot !== previous.root_hash) {
        throw fail(LEDGER_ERRORS.CHECKPOINT_EQUIVOCATION, "ledger prefix disagrees with the previous checkpoint");
      }
      if (entries.length === previous.tree_size) return previous;
    }
    const checkpoint = await computeCheckpoint(ledgerPath, opts);
    writeCheckpoint(checkpointPath, checkpoint);
    return checkpoint;
  });
}

function loadReceiptByHash(receiptStorePath, receiptHash) {
  if (!existsSync(receiptStorePath)) return null;
  const raw = readFileSync(receiptStorePath, "utf8");
  for (const line of raw.split("\n")) {
    if (line.trim() === "") continue;
    let receipt;
    try { receipt = JSON.parse(line); } catch { continue; }
    if (canonicalReceiptHash(receipt) === receiptHash) return receipt;
  }
  return null;
}

// Build a single-receipt inclusion proof bundle against `checkpoint`, then
// SELF-VERIFY it end to end before returning. Fails closed if the ledger, the
// Merkle recomputation, the checkpoint, and the authority bundle disagree.
//   selector: { receipt_id } or { receipt_hash }
export async function buildProofBundle(ledgerPath, checkpoint, selector, {
  receiptStorePath,
  trustedBundle,
  executorEnvironmentId,
  expectedExecutorId
} = {}) {
  if (!checkpoint || typeof checkpoint.tree_size !== "number") throw fail(LEDGER_ERRORS.CHECKPOINT_MALFORMED, "checkpoint required");
  const entries = readLedgerEntries(ledgerPath).slice(0, checkpoint.tree_size);
  if (entries.length !== checkpoint.tree_size) throw fail(LEDGER_ERRORS.ANCHOR_FAILED, "ledger shorter than checkpoint tree_size");

  const target = entries.find((e) =>
    (selector.receipt_id != null && e.receipt_ref?.receipt_id === selector.receipt_id) ||
    (selector.receipt_hash != null && e.receipt_hash === selector.receipt_hash));
  if (!target) throw fail(LEDGER_ERRORS.NOT_ANCHORED, "receipt not found within the checkpoint's anchored prefix");

  const leafIndex = target.sequence - 1;
  const leaves = entries.map((e) => leafHash(e.entry_hash));
  const auditPath = inclusionProof(leaves, leafIndex);

  const receipt = loadReceiptByHash(receiptStorePath, target.receipt_hash);
  if (!receipt) throw fail(LEDGER_ERRORS.RECEIPT_MISSING, "receipt bytes not found in the receipt store");

  const bundle = {
    schema: LEDGER_INCLUSION_PROOF_SCHEMA,
    receipt,
    entry: target,
    inclusion: { tree_size: checkpoint.tree_size, leaf_index: leafIndex, audit_path: auditPath },
    checkpoint
  };

  // Fail closed unless the whole chain verifies against the trusted bundle.
  const check = await verifyProofBundle(bundle, trustedBundle, {
    trustedRootFingerprint: trustedBundle?.root_key?.fingerprint,
    executorEnvironmentId,
    expectedExecutorId
  });
  if (!check.ok) throw fail(LEDGER_ERRORS.ANCHOR_FAILED, `proof self-verify failed: ${check.reason}`);
  return bundle;
}
