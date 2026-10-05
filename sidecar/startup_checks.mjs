// Startup security checks for writable directories used by the sidecar.
//
// These directories receive security-critical writes (nonce reservations,
// execution ID reservations, receipt logs, auth audit logs). A world-writable
// directory lets any local user pre-create or delete files, undermining dedup
// and audit integrity.
//
// Checks run before traffic is served and fail hard so misconfiguration is
// caught at startup, not discovered during an incident.
//
// Platform note: world-write mode bits are a POSIX concept. On Windows,
// file ACLs work differently and `stat.mode` does not carry meaningful
// group/world bits. The check is skipped on Windows to avoid false positives.

import { mkdirSync, statSync } from "node:fs";

const IS_POSIX = process.platform !== "win32";

// Check that `dir` is not world-writable. Creates the directory if absent
// (so the check works before first use). Returns { ok, reason } — never throws.
export function checkDirectoryPermissions(dir) {
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch (error) {
    return { ok: false, reason: `could not create directory '${dir}': ${error?.message ?? String(error)}` };
  }

  if (!IS_POSIX) {
    // Windows: skip mode check; ACLs are not surfaced via stat.mode.
    return { ok: true };
  }

  let stat;
  try {
    stat = statSync(dir);
  } catch (error) {
    return { ok: false, reason: `could not stat directory '${dir}': ${error?.message ?? String(error)}` };
  }

  // eslint-disable-next-line no-bitwise
  if (stat.mode & 0o002) {
    return {
      ok: false,
      reason: `directory '${dir}' is world-writable (mode 0o${(stat.mode & 0o777).toString(8)}). ` +
        "An attacker with local access could pre-create or delete security-critical files. " +
        "Run: chmod o-w \"" + dir + "\""
    };
  }

  return { ok: true };
}

// Run all startup directory checks. Exits the process with a clear message if
// any check fails. Call this before the sidecar begins serving traffic.
export function assertStartupDirectoryPermissions(paths) {
  for (const { name, dir } of paths) {
    if (dir === null || dir === undefined) continue; // optional path not configured
    const result = checkDirectoryPermissions(dir);
    if (!result.ok) {
      process.stderr.write(`\nMNDe refused to start — insecure ${name} directory.\n  ${result.reason}\n\n`);
      process.exit(1);
    }
  }
}
