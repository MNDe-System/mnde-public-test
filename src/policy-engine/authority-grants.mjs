// Scope-bound authority grants (mnde.authority_grant.v1).
//
// Replaces the bearer-style authority grant in trust.mjs (matched only by an
// `authority_id` string against a policy rule's `authority_required` array —
// any validly-signed grant of the right id satisfies any principal, tool, or
// tenant, and can be replayed indefinitely) with a single-use, fully
// scope-bound grant: it proves exactly who received authority, what they may
// authorize, where that authority applies, and when it expires, and can
// authorize exactly one execution.
//
// See docs/authority-grant-v1.md for the full spec, validation order, and
// known limitations.

import { createHash, createPrivateKey, randomBytes, randomUUID, sign as ed25519Sign } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalizeJson } from "../../shared/json.ts";
import { verifyReceiptPayloadSignature } from "../../shared/index.ts";
import { findAnyAuthorityKey, findAuthorityReceiptKey, loadAuthorityBundleForReceipt } from "../../shared/authority-manifest.mjs";
import { reserveAndConsumeGrant } from "./grant-nonce-store.mjs";

export const GRANT_SCHEMA = "mnde.authority_grant.v1";

// Bounded default lifetime for a newly issued grant. Callers may pass a
// shorter lifetimeMs; there is no unbounded/"no expiry" option.
export const DEFAULT_GRANT_LIFETIME_MS = 5 * 60 * 1000; // 5 minutes
export const DEFAULT_CLOCK_SKEW_MS = 60 * 1000; // 60 seconds

const KEY_ID_PATTERN = /^[A-Za-z0-9._-]{1,256}$/;

// Default: relative to this module's own install location (unchanged behavior
// for every source-checkout test/flow). MNDE_HOME overrides it so the packaged
// CLI reads the authority manifest under the caller's own directory, never
// inside node_modules — same override convention as shared/receipt-signing.ts.
const repoRootDefault = process.env.MNDE_HOME
  ? resolve(process.env.MNDE_HOME)
  : resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}
function isValidTimestamp(value) {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}
function withoutSignature(obj) {
  const { signature: _omit, ...rest } = obj ?? {};
  return rest;
}

function malformed(reason = "AUTHORITY_GRANT_MALFORMED") {
  return { ok: false, reason };
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

// Issue a signed, scope-bound authority grant. `tool` and `scope.action` are
// always identical by design (this architecture's tool_name is already the
// action-granularity identifier — see docs/authority-grant-v1.md §Scope
// model); the field is duplicated so the grant's `scope` sub-object is
// self-contained and independently meaningful, not because they may diverge.
export function issueAuthorityGrant({
  authorityId,
  principal,
  tool,
  tenant,
  scope = {},
  issuer,
  authorityKeyId,
  privateKeyPem,
  now,
  lifetimeMs = DEFAULT_GRANT_LIFETIME_MS,
  grantId = randomUUID(),
  nonce = randomBytes(32).toString("base64url")
}) {
  if (!isNonEmptyString(authorityId)) throw new Error("issueAuthorityGrant: authorityId is required");
  if (!isNonEmptyString(principal)) throw new Error("issueAuthorityGrant: principal is required");
  if (!isNonEmptyString(tool)) throw new Error("issueAuthorityGrant: tool is required");
  if (!isNonEmptyString(tenant)) throw new Error("issueAuthorityGrant: tenant is required");
  if (!isNonEmptyString(issuer)) throw new Error("issueAuthorityGrant: issuer is required");
  if (!isNonEmptyString(authorityKeyId)) throw new Error("issueAuthorityGrant: authorityKeyId is required");
  if (!Number.isSafeInteger(lifetimeMs) || lifetimeMs <= 0) throw new Error("issueAuthorityGrant: lifetimeMs must be a positive bounded integer");

  const issuedAtMs = now instanceof Date ? now.getTime() : Date.parse(now);
  if (!Number.isFinite(issuedAtMs)) throw new Error("issueAuthorityGrant: now is required and must be a valid time");
  const issuedAt = new Date(issuedAtMs).toISOString();
  const expiresAt = new Date(issuedAtMs + lifetimeMs).toISOString();

  const unsigned = {
    schema_version: GRANT_SCHEMA,
    grant_id: grantId,
    authority_id: authorityId,
    principal,
    tool,
    tenant,
    scope: {
      action: tool,
      ...(isNonEmptyString(scope.resource) ? { resource: scope.resource } : {}),
      constraints: isPlainObject(scope.constraints) ? scope.constraints : {}
    },
    nonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
    issuer,
    authority_key_id: authorityKeyId
  };

  const value = ed25519Sign(null, Buffer.from(canonicalizeJson(unsigned), "utf8"), createPrivateKey(privateKeyPem)).toString("hex");
  return { ...unsigned, signature: { key_id: authorityKeyId, value } };
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function resolveAuthenticatedPrincipal(options) {
  const caller = options?.caller;
  if (caller && isNonEmptyString(caller.id)) return caller.id;
  return null; // never fall back to the request body's unauthenticated principal.id
}

function resolveRequestTenant(request) {
  const tenantId = request?.principal?.tenant_id;
  return isNonEmptyString(tenantId) ? tenantId : null;
}

function scopeMatches(grant, request) {
  const scope = grant.scope;
  if (!isPlainObject(scope) || !isNonEmptyString(scope.action)) return false;
  if (scope.action !== request?.tool?.tool_name) return false;
  if (scope.resource !== undefined) {
    if (!isNonEmptyString(scope.resource) || scope.resource !== request?.parameters?.resource) return false;
  }
  const constraints = isPlainObject(scope.constraints) ? scope.constraints : {};
  for (const [key, value] of Object.entries(constraints)) {
    if (!isPlainObject(request?.parameters) || request.parameters[key] !== value) return false;
  }
  return true;
}

const REQUIRED_FIELDS = [
  "schema_version",
  "grant_id",
  "authority_id",
  "principal",
  "tool",
  "tenant",
  "scope",
  "nonce",
  "issued_at",
  "expires_at",
  "issuer",
  "authority_key_id",
  "signature"
];

// Validate a scope-bound authority grant against a runtime request, and — iff
// every check passes and options.consume !== false — atomically reserve and
// consume it so it can never authorize a second execution.
//
// options:
//   repoRoot     - defaults to this repo's root; override only for tests.
//   now          - ISO timestamp, the authenticated evaluation time (required).
//   caller       - { id } the sidecar's authenticated bearer-token caller. The
//                  ONLY accepted source of principal identity; request.principal.id
//                  is never trusted for grant binding.
//   clockSkewMs  - defaults to DEFAULT_CLOCK_SKEW_MS.
//   consume      - defaults to true. Pass false for offline receipt replay/audit,
//                  where re-verifying a past decision must not touch the durable
//                  nonce store (and must not re-invent whether it was consumed).
//   grantStoreDirOverride - test-only; see grant-nonce-store.mjs.
//
// Returns { ok: true, grant_id, authority_id, ... auditFields } or
// { ok: false, reason: "AUTHORITY_GRANT_*" }.
export function verifyAndConsumeAuthorityGrant(grant, request, options = {}) {
  const repoRoot = options.repoRoot ?? repoRootDefault;
  const clockSkewMs = Number.isSafeInteger(options.clockSkewMs) ? options.clockSkewMs : DEFAULT_CLOCK_SKEW_MS;
  const consume = options.consume !== false;

  // 1. Parse the grant.
  if (!isPlainObject(grant)) return malformed();

  // 2. Reject malformed or unknown versions.
  if (grant.schema_version !== GRANT_SCHEMA) return { ok: false, reason: "AUTHORITY_GRANT_VERSION_UNSUPPORTED" };

  // 3. Confirm all required fields exist.
  for (const field of REQUIRED_FIELDS) {
    if (!(field in grant)) return malformed();
  }
  if (!isNonEmptyString(grant.grant_id) || !KEY_ID_PATTERN.test(grant.grant_id)) return malformed();
  if (!isNonEmptyString(grant.authority_id)) return malformed();
  if (!isNonEmptyString(grant.principal)) return malformed();
  if (!isNonEmptyString(grant.tool)) return malformed();
  if (!isNonEmptyString(grant.tenant)) return malformed();
  if (!isPlainObject(grant.scope) || !isNonEmptyString(grant.scope.action)) return malformed();
  if (!isNonEmptyString(grant.nonce) || !KEY_ID_PATTERN.test(grant.nonce)) return malformed();
  if (!isValidTimestamp(grant.issued_at) || !isValidTimestamp(grant.expires_at)) return malformed();
  if (!isNonEmptyString(grant.issuer) || !isNonEmptyString(grant.authority_key_id)) return malformed();
  const signature = grant.signature;
  if (!isPlainObject(signature) || !isNonEmptyString(signature.key_id) || !isNonEmptyString(signature.value)) return malformed();

  // 4. Reject duplicate or ambiguous representations.
  //    - signature.key_id must agree with the signed authority_key_id: these
  //      name the same key through two different paths (one inside the signed
  //      payload, one in the unsigned signature wrapper), and must never disagree.
  //    - tool and scope.action must agree: this architecture's tool_name IS the
  //      action-granularity identifier, so a grant claiming a different action
  //      than its own tool is an internally contradictory (tampered) grant.
  if (signature.key_id !== grant.authority_key_id) return malformed();
  if (grant.scope.action !== grant.tool) return malformed();

  // 5. Canonicalize the signed payload.
  const canonicalPayload = canonicalizeJson(withoutSignature(grant));

  // 6. Resolve the issuer and authority key (existence only — validity/revocation
  //    is checked separately at step 8, using the grant's own authenticated
  //    issued_at, never an unsigned timestamp).
  const bundle = loadAuthorityBundleForReceipt(repoRoot, grant.issuer);
  if (!bundle.ok) return { ok: false, reason: "AUTHORITY_GRANT_ISSUER_UNTRUSTED" };
  const anyKey = findAnyAuthorityKey(bundle.manifest, { authorityId: grant.issuer, keyId: grant.authority_key_id });
  if (!anyKey.ok) return { ok: false, reason: "AUTHORITY_GRANT_KEY_INVALID" };

  // 7. Verify the signature.
  let signatureOk;
  try {
    signatureOk = verifyReceiptPayloadSignature(canonicalPayload, signature.value, anyKey.key.public_key);
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) return { ok: false, reason: "AUTHORITY_GRANT_SIGNATURE_INVALID" };

  // 8. Validate the key twice: first at the grant's signed issued_at, then at
  //    the authenticated evaluation time. The first check proves the key could
  //    issue the grant then. The second prevents a leaked expired key from
  //    minting a long-lived grant backdated into its former validity window.
  //    In live evaluation `now` is verifier-local server time; during offline
  //    receipt replay it is the receipt's signed decision_output.evaluated_at.
  const now = options.now;
  if (!isValidTimestamp(now)) return malformed();
  const issuedKeyValidity = findAuthorityReceiptKey(bundle.manifest, {
    authorityId: grant.issuer,
    keyId: grant.authority_key_id,
    validAt: grant.issued_at
  });
  const liveKeyValidity = issuedKeyValidity.ok ? findAuthorityReceiptKey(bundle.manifest, {
    authorityId: grant.issuer,
    keyId: grant.authority_key_id,
    validAt: now,
    activeOnly: true
  }) : issuedKeyValidity;
  if (!liveKeyValidity.ok) {
    return { ok: false, reason: /revoked/i.test(liveKeyValidity.reason) ? "AUTHORITY_GRANT_KEY_REVOKED" : "AUTHORITY_GRANT_KEY_INVALID" };
  }

  // 9. Validate issued_at and expires_at.
  const nowMs = Date.parse(now);
  const issuedAtMs = Date.parse(grant.issued_at);
  const expiresAtMs = Date.parse(grant.expires_at);
  if (expiresAtMs <= issuedAtMs) return malformed(); // expires_at must be strictly later than issued_at
  if (issuedAtMs - nowMs > clockSkewMs) return { ok: false, reason: "AUTHORITY_GRANT_NOT_YET_VALID" };
  // Expiry boundary: exclusive, matching the house convention already used for
  // authority-key windows and approvals (>= expires_at is expired). Documented
  // in docs/authority-grant-v1.md and covered by the exact-boundary test.
  if (nowMs >= expiresAtMs) return { ok: false, reason: "AUTHORITY_GRANT_EXPIRED" };

  // 10. Match tenant.
  const requestTenant = resolveRequestTenant(request);
  if (requestTenant === null || requestTenant !== grant.tenant) return { ok: false, reason: "AUTHORITY_GRANT_TENANT_MISMATCH" };

  // 11. Match principal (authenticated caller identity only — see resolveAuthenticatedPrincipal).
  const requestPrincipal = resolveAuthenticatedPrincipal(options);
  if (requestPrincipal === null || requestPrincipal !== grant.principal) return { ok: false, reason: "AUTHORITY_GRANT_PRINCIPAL_MISMATCH" };

  // 12. Match tool.
  if (request?.tool?.tool_name !== grant.tool) return { ok: false, reason: "AUTHORITY_GRANT_TOOL_MISMATCH" };

  // 13. Match requested scope.
  if (!scopeMatches(grant, request)) return { ok: false, reason: "AUTHORITY_GRANT_SCOPE_MISMATCH" };

  // 14. Check grant revocation, if a grant-revocation mechanism exists. None
  //     does today (only authority-KEY revocation, handled at step 8) — a
  //     dedicated grant-revocation list is out of scope for this slice; see
  //     docs/authority-grant-v1.md "Known limitations".

  // 15. Reserve or consume the nonce and grant_id atomically. Skipped only for
  //     offline replay/audit (options.consume === false), which re-verifies
  //     everything above without mutating durable state.
  if (consume) {
    const reservation = reserveAndConsumeGrant({
      grantId: grant.grant_id,
      nonce: grant.nonce,
      nowMs,
      expiresAtMs
    });
    if (!reservation.ok) return reservation;
  }

  // 16. Authorize execution.
  return {
    ok: true,
    grant_id: grant.grant_id,
    authority_id: grant.authority_id,
    grant_version: grant.schema_version,
    issuer: grant.issuer,
    authority_key_id: grant.authority_key_id,
    principal: grant.principal,
    tool: grant.tool,
    tenant: grant.tenant,
    scope_digest: `sha256:${canonicalHashHex(grant.scope)}`,
    nonce_digest: `sha256:${canonicalHashHex(grant.nonce)}`,
    issued_at: grant.issued_at,
    expires_at: grant.expires_at
  };
}

// Small local hash helper (sha256 over canonical JSON), used only to produce
// safe, non-reversible digests for receipt/audit embedding — never to gate
// any security decision above.
function canonicalHashHex(value) {
  return createHash("sha256").update(canonicalizeJson(value), "utf8").digest("hex");
}
