// Execution-ledger verification.
//
// Walks the ledger in order and proves the full integrity contract: append-only
// monotonic sequence, an unbroken hash chain, each entry_hash recomputing from
// its own body, no duplicate sequence or entry hash, every receipt_ref path safe,
// every referenced receipt present, and every receipt's canonical bytes matching
// the committed receipt_hash. Any deviation fails closed with a stable error code.
//
// A receipt store is the JSONL the receipts were persisted to (the sidecar's
// receipts log). Receipts are matched by receipt_id when the entry carries one,
// otherwise by canonical content hash.

import { existsSync, readFileSync } from "node:fs";

import {
  LEDGER_ENTRY_SCHEMA,
  LEDGER_ENTRY_SCHEMA_V2,
  LEDGER_ENTRY_SCHEMAS,
  LEDGER_SIGNING_ROLE,
  LEDGER_SIGNATURE_ALGORITHM,
  LEDGER_VERIFY_RESULT_SCHEMA,
  LEDGER_ERRORS,
  canonicalReceiptHash,
  computeEntryHash,
  ledgerSignablePayload
} from "./index.mjs";
import { safeResolveReceiptRefPath } from "./paths.mjs";
import { verifyAgainstBundle } from "../custody/bundle.mjs";

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function loadReceiptStore(absolutePath) {
  if (!existsSync(absolutePath)) return null;
  const raw = readFileSync(absolutePath, "utf8");
  const byId = new Map();
  const hashes = new Set();
  for (const line of raw.split("\n")) {
    if (line.trim() === "") continue;
    let receipt;
    try {
      receipt = JSON.parse(line);
    } catch {
      // A malformed receipt-store line simply won't match anything; entries
      // referencing it surface as RECEIPT_MISSING / RECEIPT_HASH, not a crash.
      continue;
    }
    const hash = canonicalReceiptHash(receipt);
    hashes.add(hash);
    if (typeof receipt.receipt_id === "string" && receipt.receipt_id.length > 0) {
      byId.set(receipt.receipt_id, hash);
    }
  }
  return { byId, hashes };
}

// Verify the ledger at ledgerPath.
//   receiptRoot   the approved root every receipt_ref.path must resolve inside.
//   trustedBundle an mnde.authority.bundle.v1 (public) whose "ledger" keys sign
//                 v2 entries. REQUIRED to verify signatures.
//   strict        true (default): v2 + a valid signature is mandatory; a legacy
//                 v1 entry is rejected (ERR_LEDGER_LEGACY_ENTRY_REJECTED). false:
//                 v1 entries are accepted as hash-chain-only (audit/migration
//                 reads); v2 entries are still signature-checked when a bundle is
//                 supplied. A signature is never accepted as valid without the
//                 trusted bundle — there is no silent downgrade.
export async function verifyLedger({ ledgerPath, receiptRoot = process.cwd(), trustedBundle = null, strict = true } = {}) {
  const errors = [];
  const done = (ok, entriesChecked, head) => ({
    schema: LEDGER_VERIFY_RESULT_SCHEMA,
    ok,
    entries_checked: entriesChecked,
    head: ok ? head : null,
    errors
  });

  // A missing or empty ledger has nothing to contradict. (Deletion of the entire
  // ledger + receipt store is explicitly outside the threat model.)
  if (!existsSync(ledgerPath)) return done(true, 0, null);
  const raw = readFileSync(ledgerPath, "utf8");
  const lines = raw.split("\n").map((line, index) => [line, index]).filter(([line]) => line.trim() !== "");
  if (lines.length === 0) return done(true, 0, null);

  const storeCache = new Map();
  const seenSequence = new Set();
  const seenEntryHash = new Set();
  let prev = null;
  let checked = 0;
  let head = null;

  for (const [line, index] of lines) {
    const expectedSequence = prev ? prev.sequence + 1 : 1;

    let entry;
    try {
      entry = JSON.parse(line);
    } catch {
      errors.push({ code: LEDGER_ERRORS.PARSE, sequence: expectedSequence, message: `ledger line ${index + 1} is not valid JSON` });
      return done(false, checked, null);
    }

    if (!LEDGER_ENTRY_SCHEMAS.includes(entry.schema)) {
      errors.push({ code: LEDGER_ERRORS.SCHEMA, sequence: entry.sequence ?? null, message: `unexpected schema '${entry.schema}'` });
      return done(false, checked, null);
    }
    if (!Number.isSafeInteger(entry.sequence) || entry.sequence < 1) {
      errors.push({ code: LEDGER_ERRORS.SEQUENCE, sequence: entry.sequence ?? null, message: "sequence must be a positive integer" });
      return done(false, checked, null);
    }
    if (seenSequence.has(entry.sequence)) {
      errors.push({ code: LEDGER_ERRORS.DUPLICATE_SEQUENCE, sequence: entry.sequence, message: "duplicate sequence" });
      return done(false, checked, null);
    }
    if (entry.sequence !== expectedSequence) {
      errors.push({ code: LEDGER_ERRORS.SEQUENCE, sequence: entry.sequence, message: `expected sequence ${expectedSequence}` });
      return done(false, checked, null);
    }

    const expectedPrev = prev ? prev.entry_hash : null;
    if ((entry.previous_entry_hash ?? null) !== expectedPrev) {
      errors.push({ code: LEDGER_ERRORS.CHAIN_BROKEN, sequence: entry.sequence, message: "previous_entry_hash does not match prior entry_hash" });
      return done(false, checked, null);
    }

    if (typeof entry.entry_hash !== "string" || entry.entry_hash.length === 0) {
      errors.push({ code: LEDGER_ERRORS.ENTRY_HASH, sequence: entry.sequence, message: "entry_hash missing" });
      return done(false, checked, null);
    }
    // Checked before recompute so a forged duplicate (copied entry_hash on a
    // distinct sequence) surfaces as DUPLICATE_ENTRY_HASH, not ENTRY_HASH.
    if (seenEntryHash.has(entry.entry_hash)) {
      errors.push({ code: LEDGER_ERRORS.DUPLICATE_ENTRY_HASH, sequence: entry.sequence, message: "duplicate entry_hash" });
      return done(false, checked, null);
    }
    if (computeEntryHash(entry) !== entry.entry_hash) {
      errors.push({ code: LEDGER_ERRORS.ENTRY_HASH, sequence: entry.sequence, message: "entry_hash does not match recomputed body hash" });
      return done(false, checked, null);
    }

    // ── Signature (v2 authenticity) ───────────────────────────────────────────
    // The hash chain proves internal consistency; the signature proves the entry
    // was minted by the ledger key. Without it, an attacker who can write the
    // store can recompute a fully consistent forged chain (excision-and-rebuild).
    const isV2 = entry.schema === LEDGER_ENTRY_SCHEMA_V2;
    if (strict && !isV2) {
      errors.push({ code: LEDGER_ERRORS.LEGACY_ENTRY_REJECTED, sequence: entry.sequence, message: `legacy ${entry.schema} entry rejected in strict mode` });
      return done(false, checked, null);
    }
    if (isV2) {
      if (!trustedBundle) {
        errors.push({ code: LEDGER_ERRORS.NO_TRUST_BUNDLE, sequence: entry.sequence, message: "a trusted authority bundle is required to verify signed entries" });
        return done(false, checked, null);
      }
      const sig = entry.signature;
      if (!isObject(sig) || sig.algorithm !== LEDGER_SIGNATURE_ALGORITHM || typeof sig.value !== "string" || sig.value.length === 0 || typeof sig.key_id !== "string" || sig.key_id.length === 0) {
        errors.push({ code: LEDGER_ERRORS.SIGNATURE_MISSING, sequence: entry.sequence, message: "entry signature missing or malformed" });
        return done(false, checked, null);
      }
      const check = await verifyAgainstBundle(ledgerSignablePayload(entry), sig.value, LEDGER_SIGNING_ROLE, sig.key_id, entry.created_at, trustedBundle);
      if (!check.ok) {
        // SIGNATURE_INVALID = bytes don't verify; everything else (UNKNOWN_KEY,
        // KEY_REVOKED, KEY_EXPIRED, INVALID_SIGNED_AT) is an untrusted-key verdict.
        const code = check.reason === "SIGNATURE_INVALID" ? LEDGER_ERRORS.SIGNATURE_INVALID : LEDGER_ERRORS.SIGNATURE_KEY_UNTRUSTED;
        errors.push({ code, sequence: entry.sequence, message: `ledger signature rejected: ${check.reason}` });
        return done(false, checked, null);
      }
    }

    const ref = entry.receipt_ref ?? {};
    const safe = safeResolveReceiptRefPath(ref.path, receiptRoot);
    if (!safe.ok) {
      errors.push({ code: LEDGER_ERRORS.RECEIPT_REF_UNSAFE, sequence: entry.sequence, message: safe.reason });
      return done(false, checked, null);
    }
    if (!storeCache.has(safe.absolutePath)) storeCache.set(safe.absolutePath, loadReceiptStore(safe.absolutePath));
    const store = storeCache.get(safe.absolutePath);
    if (!store) {
      errors.push({ code: LEDGER_ERRORS.RECEIPT_MISSING, sequence: entry.sequence, message: "referenced receipt store not found" });
      return done(false, checked, null);
    }

    const refId = typeof ref.receipt_id === "string" && ref.receipt_id.length > 0 ? ref.receipt_id : null;
    if (refId) {
      if (!store.byId.has(refId)) {
        errors.push({ code: LEDGER_ERRORS.RECEIPT_MISSING, sequence: entry.sequence, message: `receipt_id '${refId}' not found in store` });
        return done(false, checked, null);
      }
      if (store.byId.get(refId) !== entry.receipt_hash) {
        errors.push({ code: LEDGER_ERRORS.RECEIPT_HASH, sequence: entry.sequence, message: "referenced receipt bytes do not match receipt_hash" });
        return done(false, checked, null);
      }
    } else if (!store.hashes.has(entry.receipt_hash)) {
      errors.push({ code: LEDGER_ERRORS.RECEIPT_MISSING, sequence: entry.sequence, message: "no receipt in store matches receipt_hash" });
      return done(false, checked, null);
    }

    seenSequence.add(entry.sequence);
    seenEntryHash.add(entry.entry_hash);
    prev = { sequence: entry.sequence, entry_hash: entry.entry_hash };
    head = { sequence: entry.sequence, entry_hash: entry.entry_hash, receipt_hash: entry.receipt_hash, created_at: entry.created_at };
    checked += 1;
  }

  return done(true, checked, head);
}
