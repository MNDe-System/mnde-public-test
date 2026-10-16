// Issuance guard — the single authoritative check for NEW authorization.
//
// Two different things read a policy:
//
//   1. Historical replay and offline verification (`verifyPolicyReceipt`,
//      `evaluatePolicyRequest`). They must reproduce what was decided when the
//      receipt was issued, including receipts issued before this guard existed.
//      They never call this module, and must not.
//
//   2. New issuance (`buildPolicyReceiptPayload` and everything above it: the
//      sidecar, `mnde decide`, the Hub, `authorize-git-push`). A receipt produced
//      here can authorize an effect, so the configuration behind it must be
//      sound BEFORE the policy is evaluated.
//
// The evaluator treats `approval_required` as inert when no approval trust
// anchors are supplied (src/policy-engine/index.mjs, `approvalEnforced`). That
// behaviour is frozen because replay depends on it. This module is where the
// matching fail-closed rule for new issuance lives, in one place, so no caller
// has to remember it.
//
// Nothing here evaluates a request or signs anything.

// No direct node:crypto import: tests/test_ci_contract.mjs keeps that inside
// src/crypto. The provider parses the key; the type is checked on the DER bytes.
import { spkiFingerprint } from "../crypto/provider.mjs";

// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410): SEQUENCE(42) {
// SEQUENCE(5) { OID 1.3.101.112 }, BIT STRING(33) { 0x00, 32 key bytes } }.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function isEd25519PublicKeyPem(pem) {
  const match = /^\s*-----BEGIN PUBLIC KEY-----([A-Za-z0-9+/=\s]+)-----END PUBLIC KEY-----\s*$/.exec(pem);
  if (!match) return false;
  const der = Buffer.from(match[1].replace(/\s+/g, ""), "base64");
  return der.length === ED25519_SPKI_PREFIX.length + 32 && der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX);
}

export const ERR_APPROVAL_REQUIRED_WITHOUT_ANCHORS = "ERR_PE_APPROVAL_REQUIRED_WITHOUT_TRUST_ANCHORS";
export const ERR_APPROVAL_REQUIRED_MALFORMED = "ERR_PE_APPROVAL_REQUIRED_MALFORMED";
export const ERR_APPROVAL_ANCHORS_INVALID = "ERR_PE_APPROVAL_ANCHORS_INVALID";
export const ERR_POLICY_UNKNOWN_RULE_KEY = "ERR_PE_POLICY_UNKNOWN_RULE_KEY";

// Every key the evaluator understands on a rule, plus `description`, which is
// documentation. Anything else is silently ignored by the evaluator, so a typo in
// a gate (`requires_approval`, `approvals_required`) would leave the rule
// unprotected without any error. Refusing unknown keys at issuance turns that
// silent downgrade into a startup failure.
export const KNOWN_RULE_KEYS = Object.freeze(["rule_id", "effect", "match", "authority_required", "approval_required", "description"]);

export class IssuanceRefusedError extends Error {
  constructor(code, detail) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "IssuanceRefusedError";
    this.code = code;
    this.detail = detail ?? null;
  }
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isValidTimestamp(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

// True when any rule declares `approval_required`, whatever the value. The test is
// "the author asked for a human gate", not "the value is valid".
export function policyDeclaresApprovalRequired(policy) {
  return Array.isArray(policy?.rules) && policy.rules.some((rule) => isPlainObject(rule) && Object.hasOwn(rule, "approval_required"));
}

// The only accepted shapes are the ones the evaluator can actually satisfy:
// `true` (one approval) or a positive safe integer (that many).
function isValidApprovalCount(value) {
  return value === true || (Number.isSafeInteger(value) && value > 0);
}

// Validate approval trust anchors against the documented schema
// (authenticated-approvals.mjs): { approval_keys: [{ key_id, public_key (Ed25519
// PEM), valid_from?, valid_until? }] }. The evaluator would quietly treat a
// malformed set as "no key matches" and refuse every approval; this makes the
// mistake loud at configuration time instead.
export function validateApprovalTrustAnchors(anchors) {
  if (!isPlainObject(anchors)) return { ok: false, code: ERR_APPROVAL_ANCHORS_INVALID, detail: "anchors must be an object with an approval_keys array" };
  if (!Array.isArray(anchors.approval_keys)) return { ok: false, code: ERR_APPROVAL_ANCHORS_INVALID, detail: "approval_keys must be an array" };
  if (anchors.approval_keys.length === 0) return { ok: false, code: ERR_APPROVAL_ANCHORS_INVALID, detail: "approval_keys is empty, so no approval could ever be satisfied" };
  const ids = new Set();
  for (const [index, key] of anchors.approval_keys.entries()) {
    const at = `approval_keys[${index}]`;
    if (!isPlainObject(key)) return { ok: false, code: ERR_APPROVAL_ANCHORS_INVALID, detail: `${at} must be an object` };
    if (typeof key.key_id !== "string" || key.key_id.length === 0) return { ok: false, code: ERR_APPROVAL_ANCHORS_INVALID, detail: `${at}.key_id must be a non-empty string` };
    if (ids.has(key.key_id)) return { ok: false, code: ERR_APPROVAL_ANCHORS_INVALID, detail: `${at}.key_id duplicates an earlier key` };
    ids.add(key.key_id);
    if (typeof key.public_key !== "string" || key.public_key.trim().length === 0) return { ok: false, code: ERR_APPROVAL_ANCHORS_INVALID, detail: `${at}.public_key must be a PEM string` };
    try {
      spkiFingerprint(key.public_key); // throws on anything the crypto provider cannot parse
    } catch {
      return { ok: false, code: ERR_APPROVAL_ANCHORS_INVALID, detail: `${at}.public_key is not a parseable public key` };
    }
    if (!isEd25519PublicKeyPem(key.public_key)) return { ok: false, code: ERR_APPROVAL_ANCHORS_INVALID, detail: `${at}.public_key must be an Ed25519 SPKI public key (PEM)` };
    const hasFrom = key.valid_from !== undefined;
    const hasUntil = key.valid_until !== undefined;
    if (hasFrom || hasUntil) {
      // The evaluator rejects a key with only one bound, so accepting one here
      // would configure a key that can never approve anything.
      if (!isValidTimestamp(key.valid_from) || !isValidTimestamp(key.valid_until)) return { ok: false, code: ERR_APPROVAL_ANCHORS_INVALID, detail: `${at} needs both valid_from and valid_until as timestamps, or neither` };
      if (Date.parse(key.valid_from) >= Date.parse(key.valid_until)) return { ok: false, code: ERR_APPROVAL_ANCHORS_INVALID, detail: `${at}.valid_from must be before valid_until` };
    }
  }
  return { ok: true };
}

// THE routine. Decides whether (policy, approvalTrustAnchors) may be used to issue
// a receipt that could authorize an effect. Returns { ok:true } or
// { ok:false, code, detail }; never throws and never evaluates a request.
//
// `approvalTrustAnchors === undefined` means "not configured". Any other value,
// including null, false, 0, "" and {}, means the operator configured something,
// and it is validated; a falsy-but-present value is a configuration error, not
// "not configured".
export function checkIssuanceConfiguration(policy, { approvalTrustAnchors } = {}) {
  const anchorsConfigured = approvalTrustAnchors !== undefined;
  const anchors = anchorsConfigured ? validateApprovalTrustAnchors(approvalTrustAnchors) : null;

  if (Array.isArray(policy?.rules)) {
    for (const rule of policy.rules) {
      if (!isPlainObject(rule)) continue; // the evaluator refuses a non-object rule itself
      for (const key of Object.keys(rule)) {
        if (!KNOWN_RULE_KEYS.includes(key)) {
          return { ok: false, code: ERR_POLICY_UNKNOWN_RULE_KEY, detail: `rule ${JSON.stringify(rule.rule_id)} has unknown key ${JSON.stringify(key)}; the engine would ignore it` };
        }
      }
      if (Object.hasOwn(rule, "approval_required") && !isValidApprovalCount(rule.approval_required)) {
        return { ok: false, code: ERR_APPROVAL_REQUIRED_MALFORMED, detail: `rule ${JSON.stringify(rule.rule_id)}: approval_required must be true or a positive integer` };
      }
    }
  }

  if (policyDeclaresApprovalRequired(policy) && !anchorsConfigured) {
    return { ok: false, code: ERR_APPROVAL_REQUIRED_WITHOUT_ANCHORS, detail: "the policy declares approval_required but no approval trust anchors are configured" };
  }
  if (anchors && !anchors.ok) return anchors;
  return { ok: true };
}

// Throwing form, for issuance functions.
export function assertIssuanceConfiguration(policy, options) {
  const result = checkIssuanceConfiguration(policy, options);
  if (!result.ok) throw new IssuanceRefusedError(result.code, result.detail);
}
