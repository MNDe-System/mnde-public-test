// Execution-gate receipt builder.
//
// Builds a deterministic, self-describing receipt for an execution gate
// decision. The receipt is intentionally free of wall-clock timestamps in
// the deterministic path — decided_at is taken from requested_at so that
// the receipt is reproducible from the original request.
//
// receipt_hash covers the receipt body (all fields except receipt_hash itself)
// using canonicalizeJson, making the receipt tamper-evident without requiring
// an external signing key in this slice.

import { sha256 } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";

export const RECEIPT_SCHEMA = "mnde.execution_gate.receipt.v1";

// Build a receipt body (without receipt_hash), then append the hash.
export function buildExecutionGateReceipt({ request, requestHash, decision, refusalReason }) {
  const body = {
    schema_version: RECEIPT_SCHEMA,
    execution_id: request.execution_id,
    request_schema_version: request.schema_version,
    request_hash: requestHash,
    // decided_at is the requested_at value — NOT wall-clock — so replay is deterministic.
    decided_at: request.requested_at,
    decision,
    ...(refusalReason !== undefined ? { refusal_reason: refusalReason } : {}),
    principal: {
      id: request.principal.id,
      type: request.principal.type,
      verified: request.principal.verified
    },
    action: {
      type: request.action.type,
      name: request.action.name,
      dry_run: request.action.dry_run
    },
    resource: {
      kind: request.resource.kind,
      id: request.resource.id,
      name: request.resource.name
    },
    environment: {
      name: request.environment.name
    },
    risk: {
      level: request.risk.level,
      destructive: request.risk.destructive,
      reversible: request.risk.reversible,
      blast_radius: request.risk.blast_radius
    },
    evidence: {
      repo: request.evidence.repo,
      commit_sha: request.evidence.commit_sha,
      branch: request.evidence.branch
    }
  };

  const receiptHash = sha256(canonicalizeJson(body));

  return { ...body, receipt_hash: receiptHash };
}
