// Execution gate — main entry point.
//
// Pipeline:
//   1. Validate the request against mnde.execution_request.v1 schema
//   2. Canonicalize and hash the request
//   3. Apply hard-coded policy gates (no external policy engine in this slice)
//   4. Build and return a receipt
//
// Hard gates (in priority order):
//   PRINCIPAL_NOT_VERIFIED     — principal.verified === false
//   APPROVAL_REQUIRED          — production + high/critical risk + approval required + no approval_id
//   DESTRUCTIVE_REQUIRES_APPROVAL — production + destructive + no approval_id
//
// Replay: replayExecutionGate(receipt, request) re-derives the decision from
// the original request and checks that the decision and request_hash match the
// stored receipt. Does not re-validate the schema (the original gate already
// accepted the request).

import { validateExecutionRequest, hashRequest } from "./schema.mjs";
import { buildExecutionGateReceipt } from "./receipt.mjs";
import { buildSignedExecutionReceipt } from "./signed-receipt.mjs";

export { validateExecutionRequest, hashRequest } from "./schema.mjs";
export { extractPolicyAttributes } from "./policy-attributes.mjs";
export { buildExecutionGateReceipt } from "./receipt.mjs";
export { buildSignedExecutionReceipt, SIGNED_EXECUTION_RECEIPT_SCHEMA } from "./signed-receipt.mjs";
export { verifySignedExecutionReceipt } from "./verify-signed-receipt.mjs";
export { verifyLayeredReceipt, RECEIPT_VERIFICATION_STATES } from "./verify-layered-receipt.mjs";

// Hard-coded decision gates. Returns { decision, refusalReason? }.
function applyGates(req) {
  // Gate 1 — principal must be verified.
  if (req.principal.verified === false) {
    return { decision: "REFUSE", refusalReason: "PRINCIPAL_NOT_VERIFIED" };
  }

  const isProduction = req.environment.name === "production";
  const approvalId = req.approval?.approval_id;
  const hasApprovalId = typeof approvalId === "string" && approvalId.length > 0;

  // Gate 2 — production high/critical with required approval but no approval_id.
  if (
    isProduction &&
    (req.risk.level === "high" || req.risk.level === "critical") &&
    req.approval.required === true &&
    !hasApprovalId
  ) {
    return { decision: "REFUSE", refusalReason: "APPROVAL_REQUIRED" };
  }

  // Gate 3 — production destructive without approval_id.
  if (isProduction && req.risk.destructive === true && !hasApprovalId) {
    return { decision: "REFUSE", refusalReason: "DESTRUCTIVE_REQUIRES_APPROVAL" };
  }

  return { decision: "ALLOW" };
}

// Main entry point. Returns { ok: true, receipt } or { ok: false, errors }.
export function evaluateExecutionGate(request) {
  const validation = validateExecutionRequest(request);
  if (!validation.ok) {
    return { ok: false, errors: validation.errors };
  }

  const requestHash = hashRequest(request);
  const { decision, refusalReason } = applyGates(request);

  const receipt = buildExecutionGateReceipt({ request, requestHash, decision, refusalReason });
  return { ok: true, receipt };
}

// Signed variant. Calls the existing gate pipeline, then wraps the result in a
// custody-signed receipt if signing options are present. Falls back to the
// unsigned receipt path if signing options are absent (backward compatible).
//
// options:
//   authorityBundle        — loaded mnde.authority.bundle.v1
//   signingKeyId           — key_id of the receipt key to sign with
//   signingPrivateKeyPem   — Ed25519 private key PEM
//   policyProvenance       — optional policy bundle provenance object
//
// Returns { ok: true, receipt, signed: boolean } or { ok: false, errors }.
export async function authorizeAndSign(request, options = {}) {
  const validation = validateExecutionRequest(request);
  if (!validation.ok) {
    return { ok: false, errors: validation.errors };
  }

  const { decision, refusalReason } = applyGates(request);

  const {
    authorityBundle,
    signingKeyId,
    signingPrivateKeyPem,
    policyProvenance,
    executor,
    passportSubjectId
  } = options;
  const canSign = authorityBundle && signingKeyId && signingPrivateKeyPem;
  const executorRequested = executor !== undefined && executor !== null;

  if (executorRequested && !canSign) {
    return {
      ok: false,
      reason_code: "ERR_EXECUTOR_AUTHORITY_SIGNER_REQUIRED",
      errors: ["ERR_EXECUTOR_AUTHORITY_SIGNER_REQUIRED"]
    };
  }

  if (canSign) {
    try {
      const receipt = await buildSignedExecutionReceipt(request, decision, {
        authorityBundle,
        signingKeyId,
        signingPrivateKeyPem,
        policyProvenance,
        refusalReason,
        executor,
        passportSubjectId
      });
      return { ok: true, receipt, signed: true };
    } catch (error) {
      return { ok: false, errors: [error?.message ?? String(error)] };
    }
  }

  // Unsigned fallback — preserve existing behavior.
  const requestHash = hashRequest(request);
  const receipt = buildExecutionGateReceipt({ request, requestHash, decision, refusalReason });
  return { ok: true, receipt, signed: false };
}

// Replay — re-run the gate from the original request, confirm it matches the receipt.
export function replayExecutionGate(receipt, request) {
  // Re-derive hash and decision from the original request.
  const replayedHash = hashRequest(request);
  if (replayedHash !== receipt.request_hash) {
    return { ok: false, reason: "request_hash mismatch" };
  }

  const { decision, refusalReason } = applyGates(request);
  if (decision !== receipt.decision) {
    return { ok: false, reason: `decision mismatch: got ${decision}, expected ${receipt.decision}` };
  }
  if (refusalReason !== receipt.refusal_reason) {
    return { ok: false, reason: `refusal_reason mismatch: got ${refusalReason}, expected ${receipt.refusal_reason}` };
  }

  return { ok: true };
}
