// Durable execution ID dedup store.
//
// Uses one file per execution ID under a configured directory. File creation
// uses O_EXCL (openSync "wx") — a single atomic kernel syscall that either
// creates the file exclusively or fails EEXIST. This means:
//
//   - Two worker threads racing on the same execution_id can never both win.
//   - Files survive process restart, so a replayed execution_id is refused
//     even after the sidecar is restarted.
//   - An in-process Map is kept as a fast first-pass cache; the file is the
//     global, durable source of truth.
//
// Execution ID format: mirrored from the release_request.execution_id field.
// Allowed characters: URL-safe alphanumeric plus . _ - (no path separators).

import { closeSync, mkdirSync, openSync, writeSync } from "node:fs";
import { join } from "node:path";

// Pattern for safe execution IDs. Must be non-empty, 1-256 chars, URL-safe.
// No slashes, no dots that could traverse directories.
const EXEC_ID_PATTERN = /^[A-Za-z0-9._-]{1,256}$/;

// In-process dedup cache: avoids FS hit for IDs already seen in this process.
const seenIds = new Set();

// Returns the configured execution ID store directory, or null if MNDE_EXEC_ID_CACHE
// is not set. Absence fails closed; this local store is not deployment authority.
export function execIdDirPath() {
  return process.env.MNDE_EXEC_ID_CACHE ?? null;
}

// Attempt to reserve an execution ID globally.
//
// Returns true iff this is the FIRST reservation of this ID (globally, across
// all workers and restarts). Returns false if already reserved (either in the
// in-process cache or because the file already exists on disk).
//
// Fails closed on any filesystem error.
export function reserveExecutionId(executionId) {
  if (typeof executionId !== "string" || !EXEC_ID_PATTERN.test(executionId)) return false;

  if (seenIds.has(executionId)) return false;

  const dir = execIdDirPath();
  if (typeof dir !== "string" || dir.length === 0) return false;

  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch {
    return false;
  }

  const filePath = join(dir, executionId);
  let fd;
  try {
    fd = openSync(filePath, "wx"); // O_CREAT | O_EXCL: atomic
  } catch (error) {
    // EEXIST: already reserved — add to in-process cache for fast-path future checks.
    // Any other error (EACCES, ENOSPC, etc.): fail closed but don't poison the cache;
    // a transient error should not permanently block the ID in this session.
    if (error.code === "EEXIST") seenIds.add(executionId);
    return false;
  }
  try {
    writeSync(fd, String(Date.now()));
  } finally {
    closeSync(fd);
  }

  seenIds.add(executionId);
  return true;
}

// Exposed for testing only: clear the in-process cache so tests can simulate
// a restart without touching the filesystem. The file-based store is unaffected.
export function _resetInProcessCacheForTest() {
  seenIds.clear();
}
