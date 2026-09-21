// EXP-001 Stage 2 — durable claim backends.
//
// Deployment requires an independent backend with atomic conditional first-claim (unique
// constraint on BOTH identities), durable acknowledgement, consistent reads
// across executor processes, and it must live OUTSIDE the executor-local rollback
// domain (separately controlled storage, credentials, backups).
//
// Backends here:
//   createSqliteClaimBackend  — same-machine integration model: one transactional INSERT with
//     two unique indexes (namespace,exec_id) and (namespace,grant_id). Atomic
//     across both identities; durable (WAL + synchronous=FULL); consistent across
//     processes (SQLite locking + busy_timeout). production:false; same-machine integration only.
//   createFileClaimBackend    — crash-safe MODEL: a single atomic commit record
//     + reconciled index files, serialized per instance. production:false.
//   createFileClaimBackendUnsafe — the ORIGINAL two-write model, kept ONLY to
//     demonstrate the non-atomic partial-claim reuse in a regression test.
//   fault backends            — for bounded offline fault injection.
//
// NOTE ON F-002: a backend on the same machine (SQLite file or model dir) only
// MODELS the out-of-rollback-domain property when placed in separate storage. A
// deployment closes F-002 only with genuinely independent infrastructure.

import { mkdirSync, openSync, closeSync, writeSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";

// Lazy so environments without node:sqlite still load this module; if it is
// missing the SQLite factory throws and the caller must keep dispatch disabled.
const _require = createRequire(import.meta.url);
let _sqlite = null;
function loadSqlite() { if (!_sqlite) _sqlite = _require("node:sqlite"); return _sqlite; }

export const CLAIM = Object.freeze({ CLAIMED: "CLAIMED", ALREADY_SPENT: "ALREADY_SPENT", UNKNOWN: "UNKNOWN" });

const US = "";
const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");

// The TWO independent uniqueness keys. namespace comes from trusted config.
export function claimKeys(record) {
  const ns = record.namespace;
  if (typeof ns !== "string" || ns.length === 0) throw new Error("claim record needs a trusted namespace");
  if (typeof record.execution_id !== "string" || record.execution_id.length === 0) throw new Error("claim record needs an execution_id");
  const execKey = "e_" + sha([ns, "exec", record.execution_id].join(US));
  const grantKey = record.grant_id != null && record.grant_id !== "" ? "g_" + sha([ns, "grant", String(record.grant_id)].join(US)) : null;
  return { execKey, grantKey };
}

// ── SQLite integration model: single transactional insert + two unique constraints ──
export function createSqliteClaimBackend({ dbPath } = {}) {
  if (typeof dbPath !== "string" || dbPath.length === 0) throw new Error("sqlite claim backend requires { dbPath }");
  const { DatabaseSync } = loadSqlite();
  const db = new DatabaseSync(dbPath);
  try {
    // The timeout goes FIRST, before any statement that can meet a competing
    // writer. Setting the journal mode takes a brief exclusive lock, and a second
    // executor opening the same file at the same moment runs into it. Installed
    // after that statement, as it was, the timeout was still SQLite's default of
    // zero when the only contended statement ran, so the loser failed instantly
    // with SQLITE_BUSY instead of waiting. This is a bounded wait, not a retry
    // loop: contention that outlives the timeout still refuses.
    db.exec("PRAGMA busy_timeout=3000");        // wait, don't fail, on a competing writer
    db.exec("PRAGMA journal_mode=WAL");
    db.exec("PRAGMA synchronous=FULL");         // durable acknowledgement
    db.exec("CREATE TABLE IF NOT EXISTS claims (namespace TEXT NOT NULL, exec_id TEXT NOT NULL, grant_id TEXT, subject TEXT, executor_id TEXT, receipt_hash TEXT, aplus_digest TEXT, record TEXT NOT NULL, claimed_at TEXT NOT NULL)");
    db.exec("CREATE UNIQUE INDEX IF NOT EXISTS ux_exec ON claims(namespace, exec_id)");
    db.exec("CREATE UNIQUE INDEX IF NOT EXISTS ux_grant ON claims(namespace, grant_id) WHERE grant_id IS NOT NULL");
    const ins = db.prepare("INSERT INTO claims(namespace,exec_id,grant_id,subject,executor_id,receipt_hash,aplus_digest,record,claimed_at) VALUES(?,?,?,?,?,?,?,?,?)");
    const selExec = db.prepare("SELECT record FROM claims WHERE namespace=? AND exec_id=?");
    const selGrant = db.prepare("SELECT record FROM claims WHERE namespace=? AND grant_id=?");

    return {
      kind: "sqlite", production: false,
      health() { try { db.prepare("SELECT 1 AS ok").get(); return { ok: true }; } catch (e) { return { ok: false, reason: String(e?.message ?? e) }; } },
      async claim(record) {
        const now = new Date().toISOString();
        const full = JSON.stringify({ ...record, claimed_at: now });
        try {
          ins.run(record.namespace, record.execution_id, record.grant_id ?? null, record.subject ?? null, record.executor_id ?? null, record.receipt_hash ?? null, record.aplus_digest ?? null, full, now);
          return { status: CLAIM.CLAIMED, record: JSON.parse(full) };
        } catch (e) {
          const msg = String(e?.message ?? e);
          if (/UNIQUE|constraint/i.test(msg)) {
            const collided = /exec_id/.test(msg) ? "execution_id" : (/grant_id/.test(msg) ? "grant_id" : null);
            const prior = selExec.get(record.namespace, record.execution_id) ?? (record.grant_id != null ? selGrant.get(record.namespace, record.grant_id) : null);
            return { status: CLAIM.ALREADY_SPENT, collided_on: collided, prior: prior?.record ? JSON.parse(prior.record) : null };
          }
          throw e; // genuine backend error -> caller treats as unavailable/unknown
        }
      },
      lookup(record) {
        const r = selExec.get(record.namespace, record.execution_id) ?? (record.grant_id != null ? selGrant.get(record.namespace, record.grant_id) : null);
        return r?.record ? { found: true, record: JSON.parse(r.record) } : { found: false };
      },
      close() { try { db.close(); } catch { /* already closed */ } }
    };
  } catch (error) {
    // Never leak the handle when initialization fails. The caller keeps dispatch
    // disabled and may open again in the same process, and a failure to clean up
    // must not replace the failure that actually matters.
    try { db.close(); } catch { /* preserve the initialization failure */ }
    throw error;
  }
}

// ── CRASH-SAFE MODEL backend: one atomic commit record + reconciled index ────
export function createFileClaimBackend({ dir } = {}) {
  if (typeof dir !== "string" || dir.length === 0) throw new Error("file claim backend requires { dir }");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  let chain = Promise.resolve();
  const withMutex = (fn) => { const run = chain.then(fn, fn); chain = run.then(() => {}, () => {}); return run; };

  const p = (name) => join(dir, name);
  const tryCreate = (name, payload) => { let fd; try { fd = openSync(p(name), "wx"); } catch (e) { if (e.code === "EEXIST") return false; throw e; } try { writeSync(fd, payload); } finally { closeSync(fd); } return true; };
  const readName = (name) => { try { return JSON.parse(readFileSync(p(name), "utf8")); } catch { return null; } };
  const recName = (r) => "rec_" + sha([r.namespace, "rec", r.execution_id, r.grant_id ?? ""].join(US));

  // Heal any committed record whose index entries are missing (crash after the
  // atomic commit, before the index writes). Idempotent.
  function reconcile() {
    let names; try { names = readdirSync(dir); } catch { return; }
    for (const n of names) {
      if (!n.startsWith("rec_")) continue;
      const rec = readName(n); if (!rec) continue;
      if (rec.execKey) tryCreate(rec.execKey, JSON.stringify({ ref: n, record: rec.record }));
      if (rec.grantKey) tryCreate(rec.grantKey, JSON.stringify({ ref: n, record: rec.record }));
    }
  }

  return {
    kind: "file-model", production: false,
    health() { return { ok: true }; },
    claim(record) {
      return withMutex(() => {
        const { execKey, grantKey } = claimKeys(record);
        reconcile();
        if (existsSync(p(execKey))) return { status: CLAIM.ALREADY_SPENT, collided_on: "execution_id", prior: readName(execKey)?.record ?? null };
        if (grantKey && existsSync(p(grantKey))) return { status: CLAIM.ALREADY_SPENT, collided_on: "grant_id", prior: readName(grantKey)?.record ?? null };
        const now = new Date().toISOString();
        const committed = { namespace: record.namespace, execKey, grantKey, record: { ...record, claimed_at: now } };
        // The atomic commit point: one O_EXCL create. Everything after is
        // reconstructable from it.
        if (!tryCreate(recName(record), JSON.stringify(committed))) {
          reconcile();
          return { status: CLAIM.ALREADY_SPENT, collided_on: "replay", prior: committed.record };
        }
        tryCreate(execKey, JSON.stringify({ ref: recName(record), record: committed.record }));
        if (grantKey) tryCreate(grantKey, JSON.stringify({ ref: recName(record), record: committed.record }));
        return { status: CLAIM.CLAIMED, record: committed.record };
      });
    },
    lookup(record) {
      return withMutex(() => {
        reconcile();
        const { execKey, grantKey } = claimKeys(record);
        const r = readName(execKey) ?? (grantKey ? readName(grantKey) : null);
        return r?.record ? { found: true, record: r.record } : { found: false };
      });
    },
    // TEST-ONLY: model a crash AFTER the atomic commit but BEFORE the index writes
    // (writes the commit record, skips the index). Reconcile must heal it.
    __simulateCrashAfterCommit(record) {
      const { execKey, grantKey } = claimKeys(record);
      const now = new Date().toISOString();
      tryCreate(recName(record), JSON.stringify({ namespace: record.namespace, execKey, grantKey, record: { ...record, claimed_at: now } }));
    }
  };
}

// ── ORIGINAL NON-ATOMIC backend — kept ONLY to demonstrate the flaw ──────────
// Two independent O_EXCL writes with no commit record and no reconcile. A crash
// between them leaves one identity unclaimed and REUSABLE. Do not use.
export function createFileClaimBackendUnsafe({ dir } = {}) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const p = (n) => join(dir, n);
  const tryCreate = (n, payload) => { let fd; try { fd = openSync(p(n), "wx"); } catch (e) { if (e.code === "EEXIST") return false; throw e; } try { writeSync(fd, payload); } finally { closeSync(fd); } return true; };
  return {
    kind: "file-unsafe", production: false,
    health() { return { ok: true }; },
    async claim(record) {
      const { execKey, grantKey } = claimKeys(record);
      if (!tryCreate(execKey, JSON.stringify(record))) return { status: CLAIM.ALREADY_SPENT, collided_on: "execution_id" };
      if (grantKey && !tryCreate(grantKey, JSON.stringify({ ref: execKey }))) return { status: CLAIM.ALREADY_SPENT, collided_on: "grant_id" };
      return { status: CLAIM.CLAIMED, record };
    },
    lookup() { return { found: false }; },
    // TEST-ONLY: simulate a crash after the exec write, before the grant write.
    __simulateCrashAfterExec(record) { const { execKey } = claimKeys(record); tryCreate(execKey, JSON.stringify(record)); }
  };
}

// ── Fault-injection MODEL backends ───────────────────────────────────────────
export function createUnavailableBackend() {
  return { kind: "unavailable", health() { return { ok: false, reason: "unavailable" }; }, claim() { throw new Error("backend unavailable"); }, lookup() { throw new Error("backend unavailable"); } };
}
export function createTimeoutBackend() {
  return { kind: "timeout", health() { return { ok: true }; }, claim() { const e = new Error("claim timed out"); e.timeout = true; throw e; }, lookup() { const e = new Error("lookup timed out"); e.timeout = true; throw e; } };
}
export function createContradictoryBackend() {
  return { kind: "contradictory", health() { return { ok: true }; }, claim() { return { status: "MAYBE" }; }, lookup() { return { found: true, record: { contradictory: true } }; } };
}
export function createLostAckButPresentBackend(inner) {
  return { kind: "lost-ack", production: inner.production, health() { return inner.health(); },
    async claim(record) { await inner.claim(record); const e = new Error("ack lost"); e.timeout = true; throw e; },
    lookup(record) { return inner.lookup(record); } };
}
