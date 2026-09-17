// EXP-001 Stage 2 — durable claim backend interface + a reference MODEL backend.
//
// The claim backend is the freshness anchor that closes F-001/F-002: it must
// provide an ATOMIC conditional first-claim (unique constraint), a DURABLE
// acknowledgement, and CONSISTENT reads across executor processes — and it must
// live OUTSIDE the executor's local rollback domain (separately controlled
// storage, credentials, and backups). Restoring the executor's local files must
// not un-spend a claim.
//
// createFileClaimBackend is a MODEL backend (one file per uniqueness key via
// O_EXCL). It demonstrates the mechanism and, when its `dir` is a genuinely
// separate/independently-controlled location, models the out-of-rollback-domain
// property. It is NOT a production backend: a real deployment uses a database or
// service whose unique constraint + durable ack + consistent reads are backed by
// independent infrastructure. See FRESHNESS-DESIGN.md.

import { mkdirSync, openSync, closeSync, writeSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";

export const CLAIM = Object.freeze({ CLAIMED: "CLAIMED", ALREADY_SPENT: "ALREADY_SPENT", UNKNOWN: "UNKNOWN" });

const US = ""; // unit separator — unambiguous key joins
const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");

// The TWO independent uniqueness keys. The namespace comes from trusted config
// (never an agent field). execKey guards the execution id; grantKey guards the
// grant/nonce (when present). Independence means: changing only the execution id
// still collides on the grant, and changing only the grant still collides on the
// execution id.
export function claimKeys(record) {
  const ns = record.namespace;
  if (typeof ns !== "string" || ns.length === 0) throw new Error("claim record needs a trusted namespace");
  if (typeof record.execution_id !== "string" || record.execution_id.length === 0) throw new Error("claim record needs an execution_id");
  const execKey = "e_" + sha([ns, "exec", record.execution_id].join(US));
  const grantKey = record.grant_id != null && record.grant_id !== ""
    ? "g_" + sha([ns, "grant", String(record.grant_id)].join(US))
    : null;
  return { execKey, grantKey };
}

export function createFileClaimBackend({ dir } = {}) {
  if (typeof dir !== "string" || dir.length === 0) throw new Error("file claim backend requires { dir }");
  mkdirSync(dir, { recursive: true, mode: 0o700 });

  function tryCreate(key, payload) {
    let fd;
    try { fd = openSync(join(dir, key), "wx"); } // O_CREAT|O_EXCL — atomic, cross-process
    catch (e) { if (e.code === "EEXIST") return { created: false }; throw e; }
    try { writeSync(fd, payload); } finally { closeSync(fd); }
    return { created: true };
  }
  function readKey(key) { try { return JSON.parse(readFileSync(join(dir, key), "utf8")); } catch { return null; } }

  return {
    kind: "file-model",
    health() { return { ok: true }; },
    // Atomic first-claim across BOTH uniqueness keys. Any prior collision -> spent.
    claim(record) {
      const { execKey, grantKey } = claimKeys(record);
      const now = new Date().toISOString();
      const payload = JSON.stringify({ ...record, claimed_at: now });
      const e = tryCreate(execKey, payload);
      if (!e.created) return { status: CLAIM.ALREADY_SPENT, collided_on: "execution_id", prior: readKey(execKey) };
      if (grantKey) {
        const g = tryCreate(grantKey, JSON.stringify({ ref: execKey, execution_id: record.execution_id, claimed_at: now }));
        if (!g.created) {
          // The grant was already spent by a different execution id. This attempt
          // is spent too (burning this execution id is an acceptable fail-closed
          // outcome). We do NOT roll back the exec key: authority is at-most-once.
          return { status: CLAIM.ALREADY_SPENT, collided_on: "grant_id", prior: readKey(grantKey) };
        }
      }
      return { status: CLAIM.CLAIMED, record: readKey(execKey) };
    },
    lookup(record) {
      const { execKey, grantKey } = claimKeys(record);
      const rec = readKey(execKey) ?? (grantKey ? readKey(grantKey) : null);
      return rec ? { found: true, record: rec } : { found: false };
    }
  };
}

// ── Fault-injection MODEL backends (for bounded offline tests only) ──────────
export function createUnavailableBackend() {
  return { kind: "unavailable", health() { return { ok: false, reason: "unavailable" }; },
    claim() { throw new Error("backend unavailable"); }, lookup() { throw new Error("backend unavailable"); } };
}
// Claim submission times out / response lost, and a subsequent lookup is also
// uncertain — the caller must classify UNKNOWN and send nothing.
export function createTimeoutBackend() {
  return { kind: "timeout", health() { return { ok: true }; },
    claim() { const e = new Error("claim timed out"); e.timeout = true; throw e; },
    lookup() { const e = new Error("lookup timed out"); e.timeout = true; throw e; } };
}
// Returns data inconsistent with the claim contract.
export function createContradictoryBackend() {
  return { kind: "contradictory", health() { return { ok: true }; },
    claim() { return { status: "MAYBE" }; }, lookup() { return { found: true, record: { contradictory: true } }; } };
}
// A claim that timed out on submit but IS durably present on lookup (must be
// treated as spent, never re-sent).
export function createLostAckButPresentBackend(inner) {
  return { kind: "lost-ack", health() { return { ok: true }; },
    async claim(record) { await inner.claim(record); const e = new Error("ack lost"); e.timeout = true; throw e; },
    lookup(record) { return inner.lookup(record); } };
}
