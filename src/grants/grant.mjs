// mnde.execution-grant.v1 — shared schema, validators, and canonical form.
//
// An execution grant is a cryptographically signed, independently verifiable
// capability representing permission for ONE bounded execution. It EXTENDS a
// signed decision receipt: it references that receipt by its four binding hashes
// (execution_id, decision_hash, request_hash, policy_hash) and adds an egress
// scope, resource/cost limits, and a short TTL.
//
// CAP-1 scope: this module (with issue.mjs / verify.mjs) proves only that MNDe
// can MINT and INDEPENDENTLY VERIFY such a capability. It does NOT decide who
// receives one (CAP-2), whether one is required at the execution boundary
// (CAP-3), redemption / single-use enforcement (CAP-3), or deployment-level
// bypass prevention (CAP-4). Nothing here is wired into a runtime path yet.
//
// Grant object shape (signature covers everything EXCEPT issuer_key_id +
// signature, so those two are added after signing and stripped before verify):
//
//   {
//     schema_version: "mnde.execution-grant.v1",
//     grant_id,                                  // single-use nonce (redeemed in CAP-3)
//     execution_id, decision_hash,               // ── receipt binding ──
//     request_hash, policy_hash,
//     scope:  { protocol, resource, target },    // where this grant may act
//     limits: { max_cost_cents, max_calls,       // hard caps + validity window
//               not_before, not_after },
//     issued_at,
//     issuer_key_id,                             // (outside signed payload)
//     signature: { algorithm, authority_id, key_id, value }  // (outside signed payload)
//   }

export const EXECUTION_GRANT_SCHEMA = "mnde.execution-grant.v1";

// Stable verification/issuance failure codes. Never change these strings without
// a schema bump — downstream (CAP-3 proxy) branches on them.
export const GRANT_ERR = Object.freeze({
  MALFORMED: "ERR_GRANT_MALFORMED",
  SCHEMA_UNSUPPORTED: "ERR_GRANT_SCHEMA_UNSUPPORTED",
  SCOPE_INVALID: "ERR_GRANT_SCOPE_INVALID",
  LIMITS_INVALID: "ERR_GRANT_LIMITS_INVALID",
  NOT_YET_VALID: "ERR_GRANT_NOT_YET_VALID",
  EXPIRED: "ERR_GRANT_EXPIRED",
  BUNDLE_REQUIRED: "ERR_GRANT_BUNDLE_REQUIRED",
  BUNDLE_UNTRUSTED: "ERR_GRANT_BUNDLE_UNTRUSTED",
  INVALID_SIGNATURE: "ERR_GRANT_INVALID_SIGNATURE",
  REQUEST_MISMATCH: "ERR_GRANT_REQUEST_MISMATCH",
  // issuance-only
  RECEIPT_NOT_ALLOW: "ERR_GRANT_RECEIPT_NOT_ALLOW",
  RECEIPT_UNBINDABLE: "ERR_GRANT_RECEIPT_UNBINDABLE",
  RECEIPT_UNVERIFIED: "ERR_GRANT_RECEIPT_UNVERIFIED",
  SCOPE_EXCEEDS_RECEIPT: "ERR_GRANT_SCOPE_EXCEEDS_RECEIPT",
  SIGNING_FAILED: "ERR_GRANT_SIGNING_FAILED",
  SIGNING_KEY_INVALID: "ERR_GRANT_SIGNING_KEY_INVALID"
});

// Hard ceiling on a grant's validity window. A grant is permission for ONE
// bounded execution held for a short moment, not a standing credential — an
// over-long window is exactly a standing credential. Enforced in validateLimits
// so BOTH issuance and verification reject it (defense in depth). Overridable by
// an issuance policy in a later rung; the artifact contract is a hard cap here.
export const MAX_GRANT_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Protocols treated as database egress for the first Rung 1 target (destructive
// DB operations). For these, the scope MUST name a database and an operation.
const DB_PROTOCOLS = new Set(["postgres", "mysql", "mariadb", "sqlite", "mssql", "mongodb", "cockroach", "db"]);
const DB_OPERATIONS = new Set(["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER", "CREATE", "GRANT", "REVOKE"]);

export function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

// The exact bytes-to-sign / bytes-to-verify: the grant minus the two fields that
// are attached after signing. Deterministic — key order and formatting come from
// canonicalizeJson (see verify/issue).
export function canonicalGrantPayload(grant) {
  if (!isPlainObject(grant)) return grant;
  const { issuer_key_id: _issuerKeyId, signature: _signature, ...payload } = grant;
  return payload;
}

// Structural validation of a grant object (shape/types only — no crypto). Returns
// a GRANT_ERR code string, or null when structurally valid.
export function validateGrantStructure(grant) {
  if (!isPlainObject(grant)) return GRANT_ERR.MALFORMED;
  if (grant.schema_version !== EXECUTION_GRANT_SCHEMA) return GRANT_ERR.SCHEMA_UNSUPPORTED;
  const strings = ["grant_id", "execution_id", "decision_hash", "request_hash", "policy_hash", "issued_at", "issuer_key_id"];
  for (const key of strings) {
    if (typeof grant[key] !== "string" || grant[key].length === 0) return GRANT_ERR.MALFORMED;
  }
  if (Number.isNaN(Date.parse(grant.issued_at))) return GRANT_ERR.MALFORMED;
  if (!isPlainObject(grant.scope) || !isPlainObject(grant.limits)) return GRANT_ERR.MALFORMED;
  const sig = grant.signature;
  if (!isPlainObject(sig) || sig.algorithm !== "ED25519" || typeof sig.value !== "string" || sig.value.length === 0) return GRANT_ERR.MALFORMED;
  if (typeof sig.key_id !== "string" || sig.key_id !== grant.issuer_key_id) return GRANT_ERR.MALFORMED;
  return null;
}

// Scope must be well-formed and, for database protocols, must name the exact
// database + operation this grant permits. Returns a GRANT_ERR code or null.
export function validateScope(scope) {
  if (!isPlainObject(scope)) return GRANT_ERR.SCOPE_INVALID;
  if (typeof scope.protocol !== "string" || scope.protocol.length === 0) return GRANT_ERR.SCOPE_INVALID;
  if (typeof scope.resource !== "string" || scope.resource.length === 0) return GRANT_ERR.SCOPE_INVALID;
  if (!isPlainObject(scope.target)) return GRANT_ERR.SCOPE_INVALID;
  if (DB_PROTOCOLS.has(scope.protocol)) {
    if (typeof scope.target.database !== "string" || scope.target.database.length === 0) return GRANT_ERR.SCOPE_INVALID;
    if (typeof scope.target.operation !== "string" || !DB_OPERATIONS.has(scope.target.operation)) return GRANT_ERR.SCOPE_INVALID;
    if (scope.target.table !== undefined && typeof scope.target.table !== "string") return GRANT_ERR.SCOPE_INVALID;
  }
  return null;
}

// Limits: hard caps must be non-negative safe integers, at least one call, and a
// coherent validity window. Returns a GRANT_ERR code or null.
export function validateLimits(limits) {
  if (!isPlainObject(limits)) return GRANT_ERR.LIMITS_INVALID;
  if (!Number.isInteger(limits.max_cost_cents) || limits.max_cost_cents < 0) return GRANT_ERR.LIMITS_INVALID;
  if (!Number.isInteger(limits.max_calls) || limits.max_calls < 1) return GRANT_ERR.LIMITS_INVALID;
  for (const key of ["not_before", "not_after"]) {
    if (typeof limits[key] !== "string" || Number.isNaN(Date.parse(limits[key]))) return GRANT_ERR.LIMITS_INVALID;
  }
  if (Date.parse(limits.not_after) <= Date.parse(limits.not_before)) return GRANT_ERR.LIMITS_INVALID;
  // Bounded validity window: a grant is a short-lived capability, not a standing
  // credential. Reject an over-long window (fail closed). "short TTL" is now a
  // enforced property, not just a documented aspiration.
  if (Date.parse(limits.not_after) - Date.parse(limits.not_before) > MAX_GRANT_TTL_MS) return GRANT_ERR.LIMITS_INVALID;
  return null;
}

// Validity-window state at `now`. Returns a GRANT_ERR code or null. Assumes
// validateLimits already passed.
export function ttlState(limits, now) {
  const t = Date.parse(now);
  if (Number.isNaN(t)) return GRANT_ERR.NOT_YET_VALID;
  if (t < Date.parse(limits.not_before)) return GRANT_ERR.NOT_YET_VALID;
  if (t > Date.parse(limits.not_after)) return GRANT_ERR.EXPIRED;
  return null;
}

// Extract the four binding facts a grant pins from a decision receipt, tolerant
// of the legacy pipeline, policy-engine, and custody-envelope shapes. Returns
// { decision, execution_id, decision_hash, request_hash, policy_hash } with null
// for anything absent.
export function receiptFacts(receipt) {
  let r = receipt;
  if (
    isPlainObject(r) &&
    (r.schema_version === "mnde.signed-receipt.v1" || r.schema_version === "mnde.signed-receipt.v2") &&
    isPlainObject(r.receipt)
  ) {
    r = r.receipt; // unwrap custody envelope to the inner receipt
  }
  const dout = isPlainObject(r?.decision_output) ? r.decision_output : {};
  let executionId = typeof dout.execution_id === "string" ? dout.execution_id : null;
  if (!executionId && typeof r?.canonical_request === "string") {
    try {
      const cr = JSON.parse(r.canonical_request);
      const er = isPlainObject(cr?.execution_request) ? cr.execution_request : cr;
      if (isPlainObject(er)) {
        if (typeof er.request_id === "string") executionId = er.request_id;
        else if (isPlainObject(er.release_request) && typeof er.release_request.execution_id === "string") executionId = er.release_request.execution_id;
      }
    } catch {
      /* leave null */
    }
  }
  const str = (v) => (typeof v === "string" && v.length > 0 ? v : null);
  return {
    decision: str(dout.decision),
    execution_id: executionId,
    decision_hash: str(dout.decision_hash),
    request_hash: str(dout.request_hash) ?? str(r?.request_hash),
    policy_hash: str(dout.policy_hash) ?? str(r?.policy_hash)
  };
}

// Extract the DB action a receipt actually APPROVED, from the signed
// canonical_request parameters. Returns { database, operation, table } with null
// for anything absent. This reads the same signed request the decision covered
// (request_hash binds it), so it is trusted state, not attacker input. Operation
// is upper-cased to match validateScope's DB_OPERATIONS vocabulary.
export function approvedDbTarget(receipt) {
  let r = receipt;
  if (
    isPlainObject(r) &&
    (r.schema_version === "mnde.signed-receipt.v1" || r.schema_version === "mnde.signed-receipt.v2") &&
    isPlainObject(r.receipt)
  ) {
    r = r.receipt; // unwrap custody envelope to the inner receipt
  }
  let params = null;
  if (typeof r?.canonical_request === "string") {
    try {
      const cr = JSON.parse(r.canonical_request);
      const er = isPlainObject(cr?.execution_request) ? cr.execution_request : cr;
      if (isPlainObject(er?.parameters)) params = er.parameters;
    } catch {
      /* leave null */
    }
  }
  if (!isPlainObject(params)) return { database: null, operation: null, table: null };
  const str = (v) => (typeof v === "string" && v.length > 0 ? v : null);
  const op = str(params.operation) ?? str(params.op);
  return {
    database: str(params.database) ?? str(params.db),
    operation: op ? op.toUpperCase() : null,
    table: str(params.table)
  };
}

// Bound a DB-egress grant's scope to the receipt's approved action so a grant can
// never WIDEN what the decision authorized (operation / database / table). The
// first Rung 1 target is destructive DB operations, so DB scopes are constrained
// here; non-DB protocols are not yet constrained (documented limitation — a later
// rung settles the resource vocabulary for HTTP/other egress). Returns a
// GRANT_ERR code or null. Fails CLOSED: a DB scope whose approved action the
// receipt does not name is refused, not silently minted.
export function validateScopeAgainstReceipt(scope, receipt) {
  if (!isPlainObject(scope) || !DB_PROTOCOLS.has(scope.protocol)) return null;
  const approved = approvedDbTarget(receipt);
  // The receipt must actually name the DB operation + database this grant claims.
  if (!approved.operation || !approved.database) return GRANT_ERR.SCOPE_EXCEEDS_RECEIPT;
  if (scope.target.operation !== approved.operation) return GRANT_ERR.SCOPE_EXCEEDS_RECEIPT;
  if (scope.target.database !== approved.database) return GRANT_ERR.SCOPE_EXCEEDS_RECEIPT;
  const claimsWholeDb = !(typeof scope.target.table === "string" && scope.target.table.length > 0 && scope.target.table !== "*");
  const approvesWholeDb = !approved.table || approved.table === "*";
  if (claimsWholeDb) {
    // Grant claims the whole database — the receipt must approve the whole database too.
    if (!approvesWholeDb) return GRANT_ERR.SCOPE_EXCEEDS_RECEIPT;
  } else if (!approvesWholeDb && approved.table !== scope.target.table) {
    // Grant claims a specific table the receipt did not approve.
    return GRANT_ERR.SCOPE_EXCEEDS_RECEIPT;
  }
  return null;
}
