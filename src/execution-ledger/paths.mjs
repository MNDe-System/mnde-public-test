// Execution-ledger path resolution + receipt-reference path safety.
//
// The ledger and the receipt store it references are both local files. The
// verifier must load receipts named by a ledger entry's receipt_ref.path, so a
// hostile or buggy entry must never let that path escape the approved receipt
// root (path traversal, absolute paths, Windows drives, UNC, encoded traversal,
// null bytes). All of that is rejected here, in one place, fail-closed.

import path from "node:path";

export const DEFAULT_LEDGER_PATH = ".data/mnde-execution-ledger.jsonl";
export const LEDGER_LOCK_SUFFIX = ".lock";

// Resolve the ledger file path. Env override wins; otherwise the documented
// default under the current working directory.
export function resolveLedgerPath(env = process.env) {
  const override = env.MNDE_EXECUTION_LEDGER_PATH;
  if (typeof override === "string" && override.trim() !== "") return override;
  return DEFAULT_LEDGER_PATH;
}

// MNDE_EXECUTION_LEDGER=off is the only recognized disable value. Anything else
// (including unset) leaves the ledger enabled — default-on by design.
export function isLedgerDisabled(env = process.env) {
  return String(env.MNDE_EXECUTION_LEDGER ?? "").trim().toLowerCase() === "off";
}

// True only for an explicit, well-formed production profile. Mirrors the
// sidecar's runtime-profile gate without importing it (avoids a cycle).
export function isProductionProfile(env = process.env) {
  return String(env.MNDE_PROFILE ?? "").trim().toLowerCase() === "production";
}

// Startup rule: a disabled ledger is a development-only convenience. In
// production it must fail closed at startup — no silent unsafe operation.
export function ledgerStartupGate(env = process.env) {
  if (isProductionProfile(env) && isLedgerDisabled(env)) {
    return {
      ok: false,
      code: "ERR_LEDGER_DISABLED_IN_PRODUCTION",
      detail: "MNDE_EXECUTION_LEDGER=off is not permitted when MNDE_PROFILE=production."
    };
  }
  return { ok: true };
}

const WINDOWS_DRIVE = /^[a-zA-Z]:/;

// Validate a receipt_ref.path and resolve it inside an approved receipt root.
// Returns { ok, absolutePath } or { ok:false, reason }. Rejects every shape that
// could read outside the root.
export function safeResolveReceiptRefPath(relativePath, receiptRoot) {
  if (typeof relativePath !== "string" || relativePath.length === 0) {
    return { ok: false, reason: "receipt_ref.path must be a non-empty string" };
  }
  if (relativePath.includes("\0")) {
    return { ok: false, reason: "receipt_ref.path contains a null byte" };
  }
  // Reject percent-encoded traversal / separators before any normalization.
  const decodedProbe = relativePath.toLowerCase();
  if (decodedProbe.includes("%2e") || decodedProbe.includes("%2f") || decodedProbe.includes("%5c")) {
    return { ok: false, reason: "receipt_ref.path contains encoded traversal" };
  }
  if (path.isAbsolute(relativePath) || WINDOWS_DRIVE.test(relativePath)) {
    return { ok: false, reason: "receipt_ref.path must be relative" };
  }
  // UNC / leading double-separator.
  if (relativePath.startsWith("\\\\") || relativePath.startsWith("//")) {
    return { ok: false, reason: "receipt_ref.path must not be a UNC path" };
  }
  const segments = relativePath.split(/[\\/]+/);
  if (segments.some((segment) => segment === "..")) {
    return { ok: false, reason: "receipt_ref.path must not contain '..'" };
  }
  const root = path.resolve(receiptRoot);
  const resolved = path.resolve(root, relativePath);
  const rel = path.relative(root, resolved);
  if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) {
    return { ok: false, reason: "receipt_ref.path escapes the receipt root" };
  }
  return { ok: true, absolutePath: resolved };
}

// Normalize an absolute receipt-store path to a safe relative ref against the
// receipt root, for writing into a ledger entry. Throws if it cannot be made
// relative safely (caller treats that as an append failure).
export function receiptRefPathFor(absoluteReceiptPath, receiptRoot) {
  const root = path.resolve(receiptRoot);
  const rel = path.relative(root, path.resolve(absoluteReceiptPath));
  const probe = safeResolveReceiptRefPath(rel.split(path.sep).join("/"), root);
  if (!probe.ok) throw new Error(`ERR_LEDGER_RECEIPT_REF_UNSAFE: ${probe.reason}`);
  return rel.split(path.sep).join("/");
}
