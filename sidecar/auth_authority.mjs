import { createPublicKey, timingSafeEqual, verify } from "node:crypto";
import { appendFileSync, closeSync, mkdirSync, openSync, readdirSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { dirname, join } from "node:path";

export const ROLE_CAPABILITIES = {
  ADMIN: new Set(["activate_policy", "manage_runtime", "export_audit", "manage_integrations", "manage_users", "view_runtime", "replay_decisions", "inspect_receipts", "verify_receipts", "view_dashboard"]),
  OPERATOR: new Set(["view_runtime", "replay_decisions", "inspect_receipts", "verify_receipts", "view_dashboard"]),
  AUDITOR: new Set(["inspect_receipts", "verify_receipts", "replay_decisions", "export_audit", "view_dashboard"]),
  VIEWER: new Set(["view_dashboard"])
};

const SENSITIVE_PATHS = new Map([
  ["/", "view_dashboard"],
  ["/dashboard", "view_dashboard"],
  ["/hub/discovery", "view_dashboard"],
  ["/hub/pair", "manage_runtime"],
  ["/identity", "view_runtime"],
  ["/metrics", "view_runtime"],
  ["/policy/current", "view_runtime"],
  ["/capabilities", "view_runtime"],
  ["/receipts/recent", "inspect_receipts"],
  ["/policy/activate", "activate_policy"],
  ["/audit/bundle", "export_audit"],
  ["/replay/recent", "replay_decisions"],
  ["/receipts/verify", "verify_receipts"],
  ["/verify", "verify_receipts"],
  ["/ledger/head", "inspect_receipts"],
  ["/ledger/verify", "verify_receipts"],
  ["/ledger/export", "export_audit"],
  // Anchoring routes (PR #7). Previously ABSENT here, so requiredCapabilityForPath
  // returned null and authorizeAuthorityAction treated them as "no authority
  // required" (fail-open) — an unauthenticated authorization bypass. Each is now
  // mapped to an explicit, least-privilege capability drawn from the existing
  // vocabulary, mirroring its closest sibling:
  //   checkpoint = read the checkpoint head        → inspect_receipts (like /ledger/head)
  //   proof      = read a single-receipt proof      → verify_receipts  (like /ledger/verify)
  //   anchor     = MINT a signed checkpoint (state-changing) → manage_runtime (ADMIN-only;
  //                strictly stronger than the read caps so a read-only authority can NEVER anchor)
  ["/ledger/checkpoint", "inspect_receipts"],
  ["/ledger/proof", "verify_receipts"],
  ["/ledger/anchor", "manage_runtime"]
]);

// Namespaces whose sub-routes are security-sensitive. An UNKNOWN path under one
// of these must fail closed in production rather than silently 404 (i.e. become
// unauthenticated-reachable) if a route is ever added without a capability
// mapping. The trailing "/" makes the match segment-boundary-aware, so
// "/ledgerfoo" does NOT match "/ledger/" while "/ledger/anything" does.
const SENSITIVE_NAMESPACE_PREFIXES = ["/ledger/"];

// True iff pathname falls under a sensitive namespace. The caller (request guard)
// passes the SAME canonical pathname the router matches on, so the guard and the
// router can never disagree about which path is being evaluated.
export function isSensitiveNamespacePath(pathname) {
  if (typeof pathname !== "string") return false;
  return SENSITIVE_NAMESPACE_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

const ASSERTION_ISSUER = "mnde-desktop";
const ASSERTION_AUDIENCE = "mnde-sidecar";
const ASSERTION_MAX_LIFETIME_MS = 120_000;
const ASSERTION_CLOCK_SKEW_MS = 30_000;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{24,128}$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// In-process dedup cache: O(1) first-pass check so we skip the filesystem for
// nonces already seen in this process. The file-based store is the global truth.
const seenNonces = new Map(); // nonce -> expiresAt (ms)
const MAX_NONCE_CACHE_SIZE = 10_000;

// Rate-limited background cleanup of the nonce directory (once per 60s max).
let lastDirCleanupMs = 0;

export function requiredCapabilityForPath(pathname) {
  return SENSITIVE_PATHS.get(pathname) ?? null;
}

export function parseAuthorityAssertion(headers) {
  const raw = headers?.["x-mnde-authority-assertion"];
  if (Array.isArray(raw)) return raw.length === 1 && typeof raw[0] === "string" ? raw[0] : null;
  return typeof raw === "string" && raw.trim() !== "" ? raw.trim() : null;
}

export function validateAuthorityAssertion(assertion, now = Date.now()) {
  if (typeof assertion !== "string" || assertion.trim() === "") return { ok: false, reason: "ERR_AUTH_REQUIRED" };
  const publicKeyB64 = process.env.MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64;
  if (typeof publicKeyB64 !== "string" || publicKeyB64.trim() === "") return { ok: false, reason: "ERR_AUTH_ASSERTION_KEY_MISSING" };

  const parts = assertion.split(".");
  if (parts.length !== 2 || parts.some((part) => part.length === 0)) return { ok: false, reason: "ERR_AUTH_ASSERTION_MALFORMED" };
  const [payloadPart, signaturePart] = parts;
  let payload;
  let signature;
  try {
    payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
    signature = Buffer.from(signaturePart, "base64url");
  } catch {
    return { ok: false, reason: "ERR_AUTH_ASSERTION_MALFORMED" };
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return { ok: false, reason: "ERR_AUTH_ASSERTION_MALFORMED" };
  if (!verifyAuthoritySignature(publicKeyB64, payloadPart, signature)) return { ok: false, reason: "ERR_AUTH_SIGNATURE_INVALID" };

  const claims = validateAssertionClaims(payload, now);
  if (!claims.ok) return claims;
  return { ok: true, actor: sanitizeActor(claims.actor), capabilities: claims.capabilities, nonce: payload.nonce };
}

export function authorizeAuthorityAction(pathname, assertion, now = Date.now()) {
  const capability = requiredCapabilityForPath(pathname);
  if (!capability) {
    // Fail closed at the authorization boundary for any path inside a sensitive
    // namespace that has no explicit capability mapping. This makes the security
    // rule independent of route ordering: a handler registered under /ledger/*
    // but forgotten in SENSITIVE_PATHS can never receive an allow result here,
    // regardless of where it sits relative to the post-dispatch namespace guard,
    // and regardless of whether the caller presents a valid, invalid, or absent
    // authority assertion. The uniform ERR_AUTH_CAPABILITY_UNMAPPED signals a
    // server-side mapping gap (a deploy-time misconfiguration), never anything
    // about the caller's credentials. Unmapped paths OUTSIDE a sensitive
    // namespace keep their historical "no authority required" behavior.
    if (isSensitiveNamespacePath(pathname)) {
      return { ok: false, reason: "ERR_AUTH_CAPABILITY_UNMAPPED", status: 403, actor: null, capability: null };
    }
    return { ok: true, actor: null, capability: null };
  }
  const context = validateAuthorityAssertion(assertion, now);
  if (!context.ok) return { ...context, capability };
  if (!context.capabilities.has(capability)) return { ok: false, reason: "ERR_AUTHZ_REFUSED", actor: context.actor, capability };
  if (!reserveNonce(context.nonce, now)) return { ok: false, reason: "ERR_AUTH_REPLAY", actor: context.actor, capability };
  return { ok: true, actor: context.actor, capability };
}

export function refusalBody(reason, actor = null, target = null) {
  return {
    status: "REFUSED",
    decision: "REFUSE",
    reason_code: reason,
    reason,
    actor: actor ? sanitizeActor(actor) : null,
    target
  };
}

export function appendAuthAuditEvent(path, event) {
  mkdirSync(dirname(path), { recursive: true });
  const actor = event.actor ? sanitizeActor(event.actor) : {};
  const record = {
    timestamp: new Date().toISOString(),
    user_id: actor.user_id ?? null,
    display_name: actor.display_name ?? null,
    role: actor.role ?? null,
    tenant_id: actor.tenant_id ?? null,
    provider: actor.provider ?? null,
    action: event.action,
    target: event.target ?? null,
    result: event.result,
    decision_hash: event.decision_hash ?? null,
    reason: event.reason ?? null
  };
  appendFileSync(path, `${JSON.stringify(record)}\n`, { encoding: "utf8" });
  return record;
}

export function sanitizeActor(input) {
  return {
    user_id: String(input.user_id ?? input.subject),
    display_name: String(input.display_name ?? input.subject),
    email: String(input.email ?? ""),
    tenant_id: String(input.tenant_id ?? ""),
    provider: String(input.provider ?? "enterprise_oidc"),
    role: String(input.role ?? input.roles?.[0]),
    login_time: String(input.login_time ?? new Date(Number(input.issued_at)).toISOString()),
    session_expiry: String(input.session_expiry ?? new Date(Number(input.expires_at)).toISOString()),
    session_id: String(input.session_id ?? "")
  };
}

// Derive the nonce store directory from the configured (or default) cache path.
// The directory uses a .d suffix so it is clearly machine-managed and distinct
// from any pre-existing legacy JSON file at the same base path.
export function nonceDirPath() {
  const base = process.env.MNDE_AUTH_NONCE_CACHE ?? join(process.cwd(), "auth-nonce-cache.json");
  return base.endsWith(".json") ? `${base.slice(0, -5)}.d` : `${base}.d`;
}

// Reserve a nonce globally. Returns true iff this is the first reservation.
//
// Mechanism: one file per nonce under nonceDirPath(). The filename IS the nonce
// (already URL-safe alphanumeric per NONCE_PATTERN). File creation uses O_EXCL
// (openSync "wx") which is a single atomic syscall on both POSIX and Windows —
// it either creates the file exclusively or fails with EEXIST. This means two
// concurrent workers (separate OS processes) racing on the same nonce can never
// both succeed: exactly one gets the file, the other gets EEXIST and returns false.
//
// The in-process Map is a performance layer only — it avoids a filesystem call
// for nonces already seen in this process. The file is the global source of truth.
export function reserveNonce(nonce, now) {
  // Defense-in-depth: validate the nonce pattern here even though the normal
  // call path (authorizeAuthorityAction → validateAssertionClaims) already does
  // so. This prevents path traversal if reserveNonce is ever called directly.
  if (!NONCE_PATTERN.test(nonce)) return false;

  // Evict expired in-process entries and enforce the size cap.
  evictExpiredNonces(now);
  if (seenNonces.size >= MAX_NONCE_CACHE_SIZE) {
    // More live nonces than the cap — fail closed rather than risk unbounded growth.
    return false;
  }

  // Fast path: already reserved in this process.
  if (seenNonces.has(nonce)) return false;

  // Slow path: attempt atomic file creation (cross-process exclusive reservation).
  const dir = nonceDirPath();
  try {
    mkdirSync(dir, { recursive: true });
  } catch {
    return false;
  }

  const expiresAt = now + ASSERTION_MAX_LIFETIME_MS + ASSERTION_CLOCK_SKEW_MS;
  const filePath = join(dir, nonce);
  let fd;
  try {
    // "wx" = O_WRONLY | O_CREAT | O_EXCL: fails EEXIST if already reserved by ANY process.
    fd = openSync(filePath, "wx");
  } catch {
    // EEXIST (or any other error) = nonce already reserved or unwritable dir → refuse.
    seenNonces.set(nonce, expiresAt); // cache to avoid future FS hits for this nonce
    return false;
  }
  try {
    writeSync(fd, String(expiresAt));
  } finally {
    closeSync(fd);
  }

  // Record in-process so future calls skip the filesystem entirely for this nonce.
  seenNonces.set(nonce, expiresAt);

  // Background cleanup: scan the directory for expired nonce files, rate-limited.
  scheduleNonceDirCleanup(dir, now);

  return true;
}

function evictExpiredNonces(now) {
  for (const [nonce, expiresAt] of seenNonces) {
    if (expiresAt <= now) seenNonces.delete(nonce);
  }
}

function scheduleNonceDirCleanup(dir, now) {
  if (now - lastDirCleanupMs < 60_000) return;
  lastDirCleanupMs = now;
  // Run after the current call returns so it does not block the request path.
  setImmediate(() => cleanupNonceDir(dir));
}

// Delete expired nonce files. Bounded scan so a large directory cannot stall
// the event loop — any remaining expired files are caught on the next cycle.
//
// IMPORTANT: empty content must NOT be treated as expiry=0. Number("") === 0,
// which is finite and always <= now, so the naive check would delete files left
// by a crashed process (O_EXCL open succeeded, writeSync never ran). Those files
// represent reservations that were accepted — deleting them reopens replay.
// The guard `raw.length > 0` preserves them until writeSync has clearly run.
export function _cleanupNonceDirForTest(dir) { cleanupNonceDir(dir); }
function cleanupNonceDir(dir) {
  const now = Date.now();
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  let scanned = 0;
  for (const entry of entries) {
    if (scanned++ >= 500) break;
    if (!NONCE_PATTERN.test(entry)) continue;
    const filePath = join(dir, entry);
    try {
      const raw = readFileSync(filePath, "utf8").trim();
      const expiresAt = Number(raw);
      // raw.length === 0 means the file is empty (crash between O_EXCL open and
      // writeSync). Leave it — the reservation was accepted, the nonce is used.
      if (raw.length > 0 && Number.isFinite(expiresAt) && expiresAt <= now) unlinkSync(filePath);
    } catch {
      // File may have been removed by another worker already — ignore.
    }
  }
}

function verifyAuthoritySignature(publicKeyB64, payloadPart, signature) {
  try {
    const rawPublicKey = Buffer.from(publicKeyB64, "base64url");
    if (rawPublicKey.length !== 32 || signature.length !== 64) return false;
    const publicKey = createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]), format: "der", type: "spki" });
    return verify(null, Buffer.from(payloadPart, "utf8"), publicKey, signature);
  } catch {
    return false;
  }
}

function validateAssertionClaims(payload, now) {
  const stringClaims = ["issuer", "audience", "subject", "nonce", "session_id"];
  const missing = stringClaims.filter((key) => typeof payload[key] !== "string" || payload[key].trim() === "");
  if (missing.length > 0) return { ok: false, reason: "ERR_AUTH_CLAIMS_MISSING", missing };
  if (!constantStringEqual(payload.issuer, ASSERTION_ISSUER)) return { ok: false, reason: "ERR_AUTH_ISSUER_INVALID" };
  if (!constantStringEqual(payload.audience, ASSERTION_AUDIENCE)) return { ok: false, reason: "ERR_AUTH_AUDIENCE_INVALID" };
  if (!NONCE_PATTERN.test(payload.nonce)) return { ok: false, reason: "ERR_AUTH_NONCE_INVALID" };
  if (!Number.isFinite(payload.issued_at) || !Number.isFinite(payload.expires_at)) return { ok: false, reason: "ERR_AUTH_TIME_INVALID" };
  if (payload.expires_at <= now) return { ok: false, reason: "ERR_AUTH_EXPIRED" };
  if (payload.issued_at > now + ASSERTION_CLOCK_SKEW_MS) return { ok: false, reason: "ERR_AUTH_CLOCK_SKEW" };
  if (payload.issued_at < now - ASSERTION_MAX_LIFETIME_MS - ASSERTION_CLOCK_SKEW_MS) return { ok: false, reason: "ERR_AUTH_CLOCK_SKEW" };
  if (payload.expires_at - payload.issued_at > ASSERTION_MAX_LIFETIME_MS) return { ok: false, reason: "ERR_AUTH_ASSERTION_TOO_LONG" };
  if (!Array.isArray(payload.roles) || payload.roles.length === 0) return { ok: false, reason: "ERR_AUTH_ROLE_INVALID" };
  if (!Array.isArray(payload.capabilities) || payload.capabilities.length === 0) return { ok: false, reason: "ERR_AUTH_CAPABILITY_INVALID" };
  const roles = [...new Set(payload.roles.map((role) => typeof role === "string" ? role.trim() : ""))].filter(Boolean);
  if (roles.length !== payload.roles.length || roles.some((role) => !ROLE_CAPABILITIES[role])) return { ok: false, reason: "ERR_AUTH_ROLE_INVALID" };
  const allowedCapabilities = new Set(roles.flatMap((role) => [...ROLE_CAPABILITIES[role]]));
  const assertedCapabilities = new Set(payload.capabilities.map((capability) => typeof capability === "string" ? capability.trim() : "").filter(Boolean));
  if (assertedCapabilities.size !== payload.capabilities.length) return { ok: false, reason: "ERR_AUTH_CAPABILITY_INVALID" };
  if ([...assertedCapabilities].some((capability) => !allowedCapabilities.has(capability))) return { ok: false, reason: "ERR_AUTH_CAPABILITY_INVALID" };
  return { ok: true, actor: { ...payload, role: roles[0] }, capabilities: assertedCapabilities };
}

function constantStringEqual(left, right) {
  const leftBuffer = Buffer.from(String(left), "utf8");
  const rightBuffer = Buffer.from(String(right), "utf8");
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}
