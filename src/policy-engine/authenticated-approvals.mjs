// Authenticated approvals for the policy engine.
//
// Proves identity and approval authority: who approved the action, who issued
// the approval, whether that issuer is trusted, and whether the approval was
// valid for this action at decision time. Deterministic, no AI, no network.
//
// Approval trust anchors are supplied by the verifier OUT OF BAND — never read
// from the policy, request, or receipt:
//
//   approvalTrustAnchors = {
//     approval_keys: [{ key_id, public_key (PEM), valid_from?, valid_until? }]
//   }
//
// An approval artifact:
//   {
//     approval_id, approver, issuer, issued_at, expires_at,
//     scope: { tool_name, request_id? },
//     signature: { key_id, value }   // Ed25519 over canonical approval w/o signature
//   }
//
// All approval-auth logic lives in this module; the engine calls one gated hook.

import { createPrivateKey, sign } from "node:crypto";

import { canonicalizeJson } from "../../shared/json.ts";
import { verifyReceiptPayloadSignature } from "../../shared/index.ts";

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isValidTimestamp(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}
function withoutSignature(obj) {
  const { signature: _omit, ...rest } = obj ?? {};
  return rest;
}
function identityId(identity) {
  if (typeof identity === "string") return identity;
  return isPlainObject(identity) && typeof identity.id === "string" ? identity.id : null;
}
function scopeMatches(scope, request) {
  if (!isPlainObject(scope)) return false;
  const tool = typeof scope.tool_name === "string" ? scope.tool_name : null;
  if (!tool) return false;
  if (tool !== "*" && tool !== request?.tool?.tool_name) return false;
  if (typeof scope.request_id === "string" && scope.request_id !== request?.request_id) return false;
  return true;
}

// Verify a single approval against the verifier-supplied anchors and the action.
export function verifyApproval(approval, approvalTrustAnchors, now, request) {
  if (!isPlainObject(approval)) return { ok: false, reason: "APPROVAL_MALFORMED" };
  const signature = approval.signature;
  if (!signature || typeof signature.key_id !== "string" || typeof signature.value !== "string") {
    return { ok: false, reason: "APPROVAL_UNSIGNED" };
  }
  const approverId = identityId(approval.approver);
  const issuerId = identityId(approval.issuer);
  if (!approverId || !issuerId) return { ok: false, reason: "APPROVAL_IDENTITY_INVALID" };
  if (typeof approval.approval_id !== "string" || approval.approval_id.length === 0) return { ok: false, reason: "APPROVAL_MALFORMED" };
  if (!isValidTimestamp(approval.issued_at) || !isValidTimestamp(approval.expires_at) || !isValidTimestamp(now)) {
    return { ok: false, reason: "APPROVAL_MALFORMED" };
  }
  const t = Date.parse(now);
  if (t < Date.parse(approval.issued_at)) return { ok: false, reason: "APPROVAL_NOT_YET_VALID" };
  if (t >= Date.parse(approval.expires_at)) return { ok: false, reason: "APPROVAL_EXPIRED" };
  if (!scopeMatches(approval.scope, request)) return { ok: false, reason: "APPROVAL_SCOPE_MISMATCH" };

  const key = (approvalTrustAnchors?.approval_keys ?? []).find((candidate) => candidate?.key_id === signature.key_id);
  if (!key || typeof key.public_key !== "string") return { ok: false, reason: "APPROVAL_UNTRUSTED_ISSUER" };
  if (key.valid_from || key.valid_until) {
    if (!isValidTimestamp(key.valid_from) || !isValidTimestamp(key.valid_until) ||
        t < Date.parse(key.valid_from) || t >= Date.parse(key.valid_until)) {
      return { ok: false, reason: "APPROVAL_UNTRUSTED_ISSUER" };
    }
  }
  try {
    const ok = verifyReceiptPayloadSignature(canonicalizeJson(withoutSignature(approval)), signature.value, key.public_key);
    return ok ? { ok: true } : { ok: false, reason: "APPROVAL_SIGNATURE_INVALID" };
  } catch {
    return { ok: false, reason: "APPROVAL_SIGNATURE_INVALID" };
  }
}

// Verify every provided approval; return per-approval results plus a count of
// those valid for this action. The results are recorded in the receipt.
export function evaluateApprovals(approvals, approvalTrustAnchors, now, request) {
  const list = Array.isArray(approvals) ? approvals : [];
  const verifications = list.map((approval) => {
    const v = verifyApproval(approval, approvalTrustAnchors, now, request);
    return {
      approval_id: typeof approval?.approval_id === "string" ? approval.approval_id : null,
      approver: identityId(approval?.approver),
      issuer: identityId(approval?.issuer),
      valid_from: typeof approval?.issued_at === "string" ? approval.issued_at : null,
      valid_until: typeof approval?.expires_at === "string" ? approval.expires_at : null,
      scope: isPlainObject(approval?.scope) ? approval.scope : null,
      result: v.ok ? "VALID" : v.reason
    };
  });
  return {
    verifications,
    validCount: verifications.filter((v) => v.result === "VALID").length,
    present: list.length
  };
}

// Signing helper for approval issuers (and tests).
export function signApproval(approval, { keyId, privateKeyPem }) {
  const rest = withoutSignature(approval);
  const value = sign(null, Buffer.from(canonicalizeJson(rest), "utf8"), createPrivateKey(privateKeyPem)).toString("hex");
  return { ...rest, signature: { key_id: keyId, value } };
}
