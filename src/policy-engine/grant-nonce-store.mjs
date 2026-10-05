// Durable, atomic reservation store for scope-bound authority grants
// (mnde.authority_grant.v1). Mirrors sidecar/auth_authority.mjs's nonce
// reservation mechanism: one file per key, created with O_EXCL, so two
// concurrent workers (separate OS processes, separate threads, or a process
// restart) racing on the same key can never both win — exactly one gets the
// file, every other attempt gets EEXIST and is refused.
//
// TWO independent keys are reserved per grant — grant_id and nonce — so that
// neither alone can be replayed:
//   - reusing a nonce (even under a different grant_id) fails, because the
//     nonce file already exists.
//   - reusing a grant_id (even paired with a different nonce) fails, because
//     the grant_id file already exists.
// Both reservations must succeed for the grant to authorize. If the grant_id
// reservation succeeds but the nonce reservation then fails, the grant_id
// stays burned (no rollback): a grant that has been partially matched must
// never become retryable, even under an unrelated transient failure.
//
// Lifecycle per key: RESERVED (file created, transition not yet confirmed) ->
// CONSUMED (terminal; replay is impossible from here on). In this codebase
// there is no separate "confirm downstream execution" callback — the policy
// engine is a single synchronous call that returns ALLOW/REFUSE — so a
// successful reservation is consumed immediately in the same call, per the
// safest-default rule: a grant is spent once authorization has been granted,
// even if whatever runs next fails. A RESERVED-without-CONSUMED file can only
// be observed if a process crashed between the two steps; on retry this
// correctly refuses (AUTHORITY_GRANT_ALREADY_RESERVED) rather than silently
// treating the crash as "never happened."

import { closeSync, mkdirSync, openSync, readdirSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { join } from "node:path";

const KEY_PATTERN = /^[A-Za-z0-9._-]{1,256}$/;
const STATE_RESERVED = "RESERVED";
const STATE_CONSUMED = "CONSUMED";
const MAX_CACHE_SIZE = 50_000;

// In-process fast-path caches (performance only; the filesystem is the source
// of truth, exactly as in auth_authority.mjs).
const seenGrantIds = new Map(); // grantId -> expiresAtMs
const seenNonces = new Map(); // nonce -> expiresAtMs

let lastCleanupMs = 0;

export function grantStoreDirPath() {
  const base = process.env.MNDE_GRANT_NONCE_STORE ?? join(process.cwd(), "grant-nonce-store.json");
  return base.endsWith(".json") ? `${base.slice(0, -5)}.d` : `${base}.d`;
}

function subDir(dir, kind) {
  return join(dir, kind);
}

function evictExpired(cache, now) {
  for (const [key, expiresAt] of cache) {
    if (expiresAt <= now) cache.delete(key);
  }
}

// Read a reservation file's state. Returns null if the file does not exist.
// Crash-safety: a file that exists but is empty (O_EXCL create succeeded, the
// write that follows never ran) must NOT be treated as "no reservation" —
// that would let a crash reopen a slot that was, from the outside, already
// claimed. Treat an unreadable/empty file as RESERVED (the more conservative,
// fail-closed state), never as absent.
function readState(filePath) {
  let raw;
  try {
    raw = readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
  const trimmed = raw.trim();
  if (trimmed.length === 0) return STATE_RESERVED;
  const [state] = trimmed.split(":");
  return state === STATE_CONSUMED ? STATE_CONSUMED : STATE_RESERVED;
}

// Attempt to atomically create a reservation file. Returns "created" on
// success, "exists" on EEXIST, "error" on any other failure (fails closed).
function createReservation(filePath, expiresAtMs) {
  let fd;
  try {
    fd = openSync(filePath, "wx"); // O_CREAT | O_EXCL: atomic, single syscall
  } catch (error) {
    return error?.code === "EEXIST" ? "exists" : "error";
  }
  try {
    writeSync(fd, `${STATE_RESERVED}:${expiresAtMs}`);
  } finally {
    closeSync(fd);
  }
  return "created";
}

function markConsumed(filePath, expiresAtMs) {
  // The reservation file already exists (we just created it in this same
  // call) and no other process can be writing to it — a plain truncating
  // write is safe here, this is a state transition, not a new reservation.
  const fd = openSync(filePath, "w");
  try {
    writeSync(fd, `${STATE_CONSUMED}:${expiresAtMs}`);
  } finally {
    closeSync(fd);
  }
}

// Reserve and immediately consume a (grant_id, nonce) pair. `nowMs` and
// `expiresAtMs` are both required — expiresAtMs bounds how long the
// reservation file is kept before cleanup may remove it (it must always be
// at or after the grant's own expires_at, never used to shorten replay
// protection).
//
// Returns one of:
//   { ok: true }
//   { ok: false, reason: "AUTHORITY_GRANT_MALFORMED" }              (bad key format)
//   { ok: false, reason: "AUTHORITY_GRANT_ALREADY_CONSUMED" }       (grant_id burned)
//   { ok: false, reason: "AUTHORITY_GRANT_ALREADY_RESERVED" }       (grant_id mid-flight / crash residue)
//   { ok: false, reason: "AUTHORITY_GRANT_REPLAY" }                 (nonce already used, by this or another grant_id)
export function reserveAndConsumeGrant({ grantId, nonce, nowMs, expiresAtMs }) {
  if (!KEY_PATTERN.test(String(grantId)) || !KEY_PATTERN.test(String(nonce))) {
    return { ok: false, reason: "AUTHORITY_GRANT_MALFORMED" };
  }

  evictExpired(seenGrantIds, nowMs);
  evictExpired(seenNonces, nowMs);

  // In-process fast path. A grant_id or nonce already seen in this process
  // during its reservation window is refused without touching the filesystem.
  if (seenGrantIds.has(grantId)) return { ok: false, reason: "AUTHORITY_GRANT_ALREADY_CONSUMED" };
  if (seenNonces.has(nonce)) return { ok: false, reason: "AUTHORITY_GRANT_REPLAY" };

  const dir = grantStoreDirPath();
  const grantDir = subDir(dir, "grant");
  const nonceDir = subDir(dir, "nonce");
  try {
    mkdirSync(grantDir, { recursive: true });
    mkdirSync(nonceDir, { recursive: true });
  } catch {
    return { ok: false, reason: "AUTHORITY_GRANT_ALREADY_RESERVED" };
  }

  const grantPath = join(grantDir, grantId);
  const noncePath = join(nonceDir, nonce);

  const grantResult = createReservation(grantPath, expiresAtMs);
  if (grantResult !== "created") {
    const state = readState(grantPath);
    seenGrantIds.set(grantId, expiresAtMs);
    return {
      ok: false,
      reason: state === STATE_CONSUMED ? "AUTHORITY_GRANT_ALREADY_CONSUMED" : "AUTHORITY_GRANT_ALREADY_RESERVED"
    };
  }

  const nonceResult = createReservation(noncePath, expiresAtMs);
  if (nonceResult !== "created") {
    // Deliberately NOT rolled back: the grant_id reservation we just created
    // stays in place. A grant whose nonce collided must never be retryable
    // under the same grant_id either.
    seenNonces.set(nonce, expiresAtMs);
    seenGrantIds.set(grantId, expiresAtMs);
    return { ok: false, reason: "AUTHORITY_GRANT_REPLAY" };
  }

  markConsumed(grantPath, expiresAtMs);
  markConsumed(noncePath, expiresAtMs);
  seenGrantIds.set(grantId, expiresAtMs);
  seenNonces.set(nonce, expiresAtMs);

  scheduleCleanup(dir, nowMs);
  return { ok: true };
}

function scheduleCleanup(dir, nowMs) {
  if (nowMs - lastCleanupMs < 60_000) return;
  lastCleanupMs = nowMs;
  setImmediate(() => {
    cleanupDir(subDir(dir, "grant"), nowMs);
    cleanupDir(subDir(dir, "nonce"), nowMs);
  });
}

// Delete reservation files past their expiry. Bounded scan so a large
// directory cannot stall the event loop. Empty (crash-residue) files are
// preserved forever by readState's own logic returning RESERVED — but the
// expiry stamp is still parseable for cleanup purposes only when non-empty;
// an unparseable/empty entry is left in place rather than guessed at.
export function _cleanupGrantStoreForTest(dir, nowMs) {
  cleanupDir(subDir(dir, "grant"), nowMs);
  cleanupDir(subDir(dir, "nonce"), nowMs);
}
function cleanupDir(dir, nowMs) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  let scanned = 0;
  for (const entry of entries) {
    if (scanned++ >= 500) break;
    if (!KEY_PATTERN.test(entry)) continue;
    const filePath = join(dir, entry);
    let raw;
    try {
      raw = readFileSync(filePath, "utf8").trim();
    } catch {
      continue;
    }
    if (raw.length === 0) continue; // crash residue: never evict
    const expiresAtMs = Number(raw.split(":")[1]);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs > nowMs) continue;
    try {
      unlinkSync(filePath);
    } catch {
      // best-effort
    }
  }
}

// Test-only: clear the in-process fast-path caches so a test can simulate a
// process restart without touching the filesystem. The durable file store is
// unaffected — this proves replay protection survives restart, not just the
// in-process cache.
export function _resetInProcessGrantCacheForTest() {
  seenGrantIds.clear();
  seenNonces.clear();
}
