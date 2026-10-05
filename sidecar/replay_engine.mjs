import { executeDeterministicPipeline, resetRuntimeState, verifySignedReceipt } from "../audit/node_runtime.ts";
import { compareBoundaryReplay } from "../shared/receipt-replay.mjs";

const SUPPORTED_RECEIPT_SCHEMA = "ecs.receipt.v2";

export function replayReceiptDeterministically(receipt) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
    return replayFailure("MALFORMED_RECEIPT", "receipt must be an object", receipt);
  }
  if (receipt.schema_version !== SUPPORTED_RECEIPT_SCHEMA) {
    return replayFailure("REPLAY_UNAVAILABLE", `unsupported schema ${receipt.schema_version ?? "missing"}`, receipt);
  }
  if (!receipt.signature && !receipt.verifiable_signature) {
    return replayFailure("SIGNATURE_FAIL", "receipt signature is missing", receipt);
  }
  if (!verifySignedReceipt(receipt)) {
    return replayFailure("SIGNATURE_FAIL", "receipt signature verification failed", receipt);
  }
  if (typeof receipt.canonical_request !== "string") {
    return replayFailure("MALFORMED_RECEIPT", "canonical_request is required", receipt);
  }
  if (!receipt.decision_output || typeof receipt.decision_output !== "object") {
    return replayFailure("MALFORMED_RECEIPT", "decision_output is required", receipt);
  }

  try {
    const boundary = compareBoundaryReplay(receipt);
    if (boundary.matched) {
      if (boundary.drift) {
        return {
          status: "DRIFT",
          receipt_id: receipt.receipt_id ?? receipt.decision_output.decision_hash ?? null,
          reason: boundary.mismatches.map((item) => item.field).join(", "),
          request_hash: receipt.request_hash ?? null,
          decision_hash: receipt.decision_output.decision_hash ?? null,
          policy_hash: receipt.decision_output.policy_hash ?? null,
          mismatches: boundary.mismatches
        };
      }
      return {
        status: "PASS",
        receipt_id: receipt.receipt_id ?? receipt.decision_output.decision_hash ?? null,
        reason: null,
        request_hash: receipt.request_hash ?? null,
        decision_hash: receipt.decision_output.decision_hash ?? null,
        policy_hash: receipt.decision_output.policy_hash ?? null,
        mismatches: []
      };
    }
    resetRuntimeState();
    const rerun = executeDeterministicPipeline(receipt.canonical_request, { enforceExecutionId: false });
    if ("parse_boundary" in rerun) {
      return replayFailure("DRIFT", rerun.reason_code, receipt, { request_hash: rerun.request_hash, decision_hash: rerun.decision_hash });
    }
    const replayed = rerun.receipt;
    const originalDecision = receipt.decision_output;
    const replayedDecision = replayed.decision_output;
    const mismatches = [];
    compareField(mismatches, "request_hash", receipt.request_hash, replayed.request_hash);
    compareField(mismatches, "decision", originalDecision.decision, replayedDecision.decision);
    compareField(mismatches, "decision_hash", originalDecision.decision_hash, replayedDecision.decision_hash);
    compareField(mismatches, "policy_hash", originalDecision.policy_hash, replayedDecision.policy_hash);
    if (mismatches.length > 0) {
      return {
        status: "DRIFT",
        receipt_id: receipt.receipt_id ?? originalDecision.decision_hash ?? null,
        reason: mismatches.map((item) => item.field).join(", "),
        request_hash: receipt.request_hash ?? null,
        decision_hash: originalDecision.decision_hash ?? null,
        policy_hash: originalDecision.policy_hash ?? null,
        mismatches
      };
    }
    return {
      status: "PASS",
      receipt_id: receipt.receipt_id ?? originalDecision.decision_hash ?? null,
      reason: null,
      request_hash: receipt.request_hash ?? null,
      decision_hash: originalDecision.decision_hash ?? null,
      policy_hash: originalDecision.policy_hash ?? null,
      mismatches: []
    };
  } catch (error) {
    return replayFailure("REPLAY_UNAVAILABLE", error instanceof Error ? error.message : "replay failed", receipt);
  }
}

function compareField(mismatches, field, original, replayed) {
  if (original !== replayed) mismatches.push({ field, original, replayed });
}

function replayFailure(status, reason, receipt, extra = {}) {
  return {
    status,
    receipt_id: receipt?.receipt_id ?? receipt?.decision_output?.decision_hash ?? null,
    reason,
    request_hash: extra.request_hash ?? receipt?.request_hash ?? receipt?.decision_output?.request_hash ?? null,
    decision_hash: extra.decision_hash ?? receipt?.decision_output?.decision_hash ?? null,
    policy_hash: extra.policy_hash ?? receipt?.decision_output?.policy_hash ?? null,
    mismatches: []
  };
}
