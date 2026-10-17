// Executor-local spent ledger — the rollback-resistance half of F-001.
//
// WHY THIS EXISTS. The PostgreSQL claim row is the only thing that says an
// authority is spent. Whoever administers that database can restore a snapshot
// taken before the claim, and the same authorization then claims as fresh and
// pushes a second time. Nothing in the database can detect its own rewind.
//
// WHAT THIS ADDS. A second record of "this executor began this authorization",
// held where a database restore cannot reach: files on the executor host, one per
// grant id and one per execution id, created exclusively and fsynced (file, then
// directory) BEFORE the execution-start record and before any push. It is
// consulted BEFORE the database and before any write credential is minted.
//
//   ledger says spent            -> refuse, whatever the database says
//   database says CLAIMED, but
//   the ledger already has it    -> the database was rolled back: refuse
//
// WHAT IT DOES NOT DO. It does not survive loss or restore of the executor
// host's own state. An attacker or administrator who can restore BOTH the
// database and this directory to the same older moment revives spent authority;
// closing that needs a witness neither of them controls (docs/F001-ROLLBACK-
// TRUST-BOUNDARY.md). It also cannot tell a never-used authorization from one
// used before the ledger existed; see the initialization rule below.
//
// INITIALIZATION IS EXPLICIT AFTER FIRST USE. A pristine ledger directory (no
// marker, no files) is initialized on first use. A directory that holds anything
// but a valid marker — or a marker with entries stripped by a wipe that left the
// evidence directory behind — is refused, never silently re-initialized, so a
// missing or replaced ledger fails closed instead of accepting everything.

import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { randomBytes, sha256 } from "../crypto/provider.mjs";

export const LEDGER_SCHEMA = "mnde.local-spent-ledger.v1";
export const ENTRY_SCHEMA = "mnde.local-spent-entry.v1";
export const ERR_LEDGER_UNAVAILABLE = "ERR_LEDGER_UNAVAILABLE";
export const ERR_LEDGER_SPENT = "ERR_LEDGER_SPENT";
export const ERR_LEDGER_ROLLBACK_DETECTED = "ERR_LEDGER_ROLLBACK_DETECTED";
export const ERR_LEDGER_QUARANTINED = "ERR_LEDGER_QUARANTINED";

const MARKER = "LEDGER.json";
const QUARANTINE = "QUARANTINE.json";
const QUARANTINED_DETAIL = "a database rollback was detected; every push refuses until an operator investigates and removes QUARANTINE.json";
const key = (kind, namespace, value) => `${kind}-${sha256(`${namespace}\n${value}`)}.json`;

// Windows needs a writable handle to flush a directory (FlushFileBuffers); POSIX opens it read-only.
function syncPath(path) {
  const fd = openSync(path, process.platform === "win32" ? "r+" : "r");
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function writeExclusive(path, body) {
  const fd = openSync(path, "wx", 0o600);
  try {
    writeFileSync(fd, body, "utf8");
    fsyncSync(fd);
  } finally { closeSync(fd); }
}

// `hasHistory` is the executor's statement that the surrounding evidence
// directory already records attempts. A ledger that is absent next to history is
// a lost or replaced ledger, not a new deployment.
export function openLocalSpentLedger(dir, { hasHistory = false } = {}) {
  if (typeof dir !== "string" || dir.length === 0) {
    return { ok: false, reason: ERR_LEDGER_UNAVAILABLE, detail: "no ledger directory" };
  }
  try {
    mkdirSync(dir, { recursive: true });
    const names = readdirSync(dir);
    // A detected rollback is not cleared by retrying. A store that forgot one
    // spent authority cannot be trusted about the others; only an operator who
    // has investigated removes this file.
    if (names.includes(QUARANTINE)) {
      return { ok: false, reason: ERR_LEDGER_QUARANTINED, detail: QUARANTINED_DETAIL };
    }
    let ledgerId;
    if (names.includes(MARKER)) {
      const marker = JSON.parse(readFileSync(join(dir, MARKER), "utf8"));
      if (marker?.schema !== LEDGER_SCHEMA || typeof marker.ledger_id !== "string" || !marker.ledger_id) {
        return { ok: false, reason: ERR_LEDGER_UNAVAILABLE, detail: "ledger marker is malformed" };
      }
      ledgerId = marker.ledger_id;
    } else {
      if (names.length > 0 || hasHistory) {
        return { ok: false, reason: ERR_LEDGER_UNAVAILABLE,
          detail: "ledger marker is missing next to existing state; refusing to re-initialize a ledger that may have been lost" };
      }
      ledgerId = randomBytes(16).toString("hex");
      writeExclusive(join(dir, MARKER), `${JSON.stringify({ schema: LEDGER_SCHEMA, ledger_id: ledgerId, created_at: new Date().toISOString() })}\n`);
      syncPath(dir);
    }
    return { ok: true, ledger: makeLedger(dir, ledgerId) };
  } catch (error) {
    return { ok: false, reason: ERR_LEDGER_UNAVAILABLE, detail: String(error?.code ?? error?.message ?? error) };
  }
}

function makeLedger(dir, ledgerId) {
  const paths = (record) => [
    join(dir, key("grant", record.namespace, record.grant_id)),
    join(dir, key("exec", record.namespace, record.execution_id))
  ];
  const exists = (path) => {
    try { readFileSync(path); return true; } catch (error) { if (error?.code === "ENOENT") return false; throw error; }
  };
  return Object.freeze({
    ledger_id: ledgerId,
    quarantine(detail) {
      try {
        writeExclusive(join(dir, QUARANTINE), `${JSON.stringify({ at: new Date().toISOString(), detail: String(detail).slice(0, 500) })}\n`);
        syncPath(dir);
      } catch { /* already quarantined, or unwritable: the caller refuses either way */ }
    },
    // Read-only. Any I/O error other than "absent" is unavailable, never "unspent".
    // The quarantine latch is re-read on every use: a long-lived executor (the Hub)
    // holds this object open, and a latch set by one request must stop the next.
    isSpent(record) {
      if (exists(join(dir, QUARANTINE))) return { ok: false, reason: ERR_LEDGER_QUARANTINED, detail: QUARANTINED_DETAIL };
      try { return { ok: true, spent: paths(record).some(exists) }; }
      catch (error) { return { ok: false, reason: ERR_LEDGER_UNAVAILABLE, detail: String(error?.code ?? error) }; }
    },
    // Durable before return. `conflict` means an entry already existed: the
    // caller was told "fresh" by a store that has forgotten.
    commit(record) {
      if (exists(join(dir, QUARANTINE))) return { ok: false, reason: ERR_LEDGER_QUARANTINED, detail: QUARANTINED_DETAIL };
      const body = `${JSON.stringify({
        schema: ENTRY_SCHEMA, ledger_id: ledgerId, namespace: record.namespace, grant_id: record.grant_id,
        execution_id: record.execution_id, receipt_hash: record.receipt_hash, aplus_digest: record.aplus_digest,
        recorded_at: new Date().toISOString()
      }, null, 2)}\n`;
      try {
        for (const path of paths(record)) writeExclusive(path, body);
        syncPath(dir);
        return { ok: true };
      } catch (error) {
        if (error?.code === "EEXIST") return { ok: false, conflict: true, reason: ERR_LEDGER_ROLLBACK_DETECTED };
        return { ok: false, reason: ERR_LEDGER_UNAVAILABLE, detail: String(error?.code ?? error?.message ?? error) };
      }
    }
  });
}
