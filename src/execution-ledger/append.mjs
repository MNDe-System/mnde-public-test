// Execution-ledger append path.
//
// Append-only, one JSON line per entry, serialized across processes by an
// exclusive lock file. The read-modify-write (read last entry → compute next →
// sign → append) happens entirely while the lock is held. The one await inside
// the critical section is the ledger signature: because the lock is a real
// OS-exclusive file lock (open "wx"), holding it across that await is safe for
// correctness — no other appender can acquire it, so sequences stay monotonic.
// It does hold the lock for the duration of signing; with a local Ed25519 key
// that is sub-millisecond, and with a future KMS/HSM signer it becomes a network
// round-trip that lengthens lock hold time (a contention cost, not a correctness
// risk — see the O(n)/lock-squat items on the readiness board).
// If the lock cannot be acquired within a bounded retry budget, the append fails
// closed (ERR_LEDGER_LOCK_FAILED) — it never writes without the lock.

import { openSync, writeSync, fsyncSync, closeSync, readFileSync, existsSync, mkdirSync, unlinkSync, renameSync } from "node:fs";
import { dirname } from "node:path";

import { canonicalizeJson } from "../../shared/json.ts";
import {
  LEDGER_ENTRY_SCHEMA,
  LEDGER_ENTRY_SCHEMA_V2,
  LEDGER_SIGNATURE_ALGORITHM,
  LEDGER_ERRORS,
  canonicalReceiptHash,
  computeEntryHash,
  ledgerSignablePayload
} from "./index.mjs";
import { LEDGER_LOCK_SUFFIX } from "./paths.mjs";

const LOCK_MAX_ATTEMPTS = 100;
const LOCK_RETRY_MS = 5;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export const LEGACY_LEDGER_ARCHIVE_SUFFIX = ".legacy-v1.jsonl";

// Entry builder. Given the prior chain head, the receipt, and the ref, produce a
// complete signed v2 entry: body → entry_hash → custody ledger signature over the
// entry (with its entry_hash). `signLedger` is the custody provider's ledger
// signer, returning { key_id, value, fingerprint }. Async because signing is
// async. Exported so tests can construct entries deterministically (pass createdAt
// for stable bytes; pass the same signer the verifier's bundle trusts).
export async function buildLedgerEntry({ sequence, previousEntryHash, receipt, receiptRef, engine, createdAt, signLedger }) {
  if (typeof signLedger !== "function") {
    throw new Error(LEDGER_ERRORS.SIGNER_REQUIRED);
  }
  const body = {
    schema: LEDGER_ENTRY_SCHEMA_V2,
    sequence,
    created_at: createdAt ?? new Date().toISOString(),
    receipt_hash: canonicalReceiptHash(receipt),
    previous_entry_hash: previousEntryHash ?? null,
    receipt_ref: {
      storage: "local",
      path: receiptRef.path,
      receipt_id: receiptRef.receipt_id ?? null
    },
    engine: {
      name: engine?.name ?? "mnde-policy-engine",
      version: engine?.version ?? null
    }
  };
  const withHash = { ...body, entry_hash: computeEntryHash(body) };
  const sig = await signLedger(ledgerSignablePayload(withHash));
  return {
    ...withHash,
    signature: {
      algorithm: LEDGER_SIGNATURE_ALGORITHM,
      key_id: sig.key_id,
      value: sig.value,
      fingerprint: sig.fingerprint ?? null
    }
  };
}

function readChainHead(ledgerPath) {
  if (!existsSync(ledgerPath)) return null;
  const raw = readFileSync(ledgerPath, "utf8");
  const lines = raw.split("\n").filter((line) => line.trim() !== "");
  if (lines.length === 0) return null;
  const entries = lines.map((line) => JSON.parse(line));
  for (const entry of entries) {
    if (entry.schema !== LEDGER_ENTRY_SCHEMA && entry.schema !== LEDGER_ENTRY_SCHEMA_V2) {
      throw new Error(`ledger contains unsupported entry schema '${entry.schema ?? "missing"}'`);
    }
  }
  // Extend only a parseable chain. A corrupt/partial trailing line (e.g. a crash
  // mid-append) fails closed rather than silently chaining onto garbage.
  const last = entries[entries.length - 1];
  if (!Number.isSafeInteger(last.sequence) || typeof last.entry_hash !== "string") {
    throw new Error("ledger head is not a well-formed entry");
  }
  return {
    sequence: last.sequence,
    entry_hash: last.entry_hash,
    requiresLegacyRollover: entries.some((entry) => entry.schema === LEDGER_ENTRY_SCHEMA)
  };
}

function rolloverLegacyLedger(ledgerPath) {
  const archivePath = `${ledgerPath}${LEGACY_LEDGER_ARCHIVE_SUFFIX}`;
  if (existsSync(archivePath)) {
    throw new Error(`legacy ledger archive already exists at ${archivePath}; refusing to overwrite`);
  }
  renameSync(ledgerPath, archivePath);
  return archivePath;
}

async function acquireLock(lockPath) {
  for (let attempt = 0; attempt < LOCK_MAX_ATTEMPTS; attempt += 1) {
    try {
      const fd = openSync(lockPath, "wx");
      closeSync(fd);
      return true;
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      await sleep(LOCK_RETRY_MS);
    }
  }
  return false;
}

function releaseLock(lockPath) {
  try {
    unlinkSync(lockPath);
  } catch {
    // Best-effort: a missing lock on release is not an error.
  }
}

function appendDurable(ledgerPath, line) {
  const fd = openSync(ledgerPath, "a");
  try {
    writeSync(fd, line);
    try {
      fsyncSync(fd);
    } catch {
      // Best-effort flush; some filesystems reject fsync on append handles.
    }
  } finally {
    closeSync(fd);
  }
}

// Append one ledger entry for a finalized receipt.
//   ledgerPath  absolute or cwd-relative path to the ledger JSONL
//   receipt     the receipt object as persisted (hashed via canonicalizeJson)
//   receiptRef  { path, receipt_id } locating the receipt for the verifier
//   engine      { name, version } provenance
//   createdAt   optional ISO timestamp (defaults to now)
//   signLedger  custody ledger signer (REQUIRED — v2 entries are always signed)
//   lock        set false ONLY in single-writer tests
// Returns { ok, sequence, entry_hash, receipt_hash } or { ok:false, code, message }.
export async function appendLedgerEntry({ ledgerPath, receipt, receiptRef, engine, createdAt, signLedger, lock = true }) {
  if (typeof signLedger !== "function") {
    return { ok: false, code: LEDGER_ERRORS.SIGNER_REQUIRED, message: "ledger append requires a signLedger custody function (v2 entries are signed)" };
  }
  try {
    mkdirSync(dirname(ledgerPath), { recursive: true });
  } catch (error) {
    return { ok: false, code: LEDGER_ERRORS.APPEND_FAILED, message: `mkdir failed: ${error.message}` };
  }

  const lockPath = `${ledgerPath}${LEDGER_LOCK_SUFFIX}`;
  if (lock) {
    let acquired;
    try {
      acquired = await acquireLock(lockPath);
    } catch (error) {
      return { ok: false, code: LEDGER_ERRORS.LOCK_FAILED, message: `lock error: ${error.message}` };
    }
    if (!acquired) {
      return { ok: false, code: LEDGER_ERRORS.LOCK_FAILED, message: "could not acquire ledger lock within retry budget" };
    }
  }

  try {
    let head = readChainHead(ledgerPath);
    let legacyLedgerPath = null;
    if (head?.requiresLegacyRollover) {
      legacyLedgerPath = rolloverLegacyLedger(ledgerPath);
      head = null;
    }
    const sequence = head ? head.sequence + 1 : 1;
    const previousEntryHash = head ? head.entry_hash : null;
    const entry = await buildLedgerEntry({ sequence, previousEntryHash, receipt, receiptRef, engine, createdAt, signLedger });
    appendDurable(ledgerPath, `${canonicalizeJson(entry)}\n`);
    return {
      ok: true,
      sequence,
      entry_hash: entry.entry_hash,
      receipt_hash: entry.receipt_hash,
      ...(legacyLedgerPath ? { rolled_over_legacy: true, legacy_ledger_path: legacyLedgerPath } : {})
    };
  } catch (error) {
    return { ok: false, code: LEDGER_ERRORS.APPEND_FAILED, message: error.message };
  } finally {
    if (lock) releaseLock(lockPath);
  }
}
