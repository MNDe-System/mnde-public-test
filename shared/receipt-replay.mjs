import { createHash } from "node:crypto";
import { canonicalizeJson, parseStrictJson } from "./json.ts";

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function sidecarRefusalReason(parsedCanonicalRequest) {
  return typeof parsedCanonicalRequest?.sidecar_refusal === "string" ? parsedCanonicalRequest.sidecar_refusal : null;
}

export function parseBoundaryDecisionHash(requestHash, reasonCode) {
  return sha256Hex(canonicalizeJson({
    request_hash: requestHash,
    decision: "REFUSE",
    reason_code: reasonCode
  }));
}

export function compareBoundaryReplay(receipt) {
  const parsed = parseStrictJson(receipt?.canonical_request);
  if (!parsed.ok) return { matched: false, error: `canonical_request parse failed: ${parsed.reason}` };
  const reasonCode = sidecarRefusalReason(parsed.value);
  if (!reasonCode) return { matched: false };

  const original = receipt.decision_output;
  const checks = [
    ["request_hash", receipt.request_hash, sha256Hex(receipt.canonical_request)],
    ["decision", original?.decision, "REFUSE"],
    ["reason_code", original?.reason_code, reasonCode],
    ["decision_hash", original?.decision_hash, parseBoundaryDecisionHash(receipt.request_hash, reasonCode)]
  ];
  const mismatches = checks
    .filter(([, left, right]) => left !== right)
    .map(([field, originalValue, replayedValue]) => ({ field, original: originalValue, replayed: replayedValue }));

  return {
    matched: true,
    reason_code: reasonCode,
    drift: mismatches.length > 0,
    mismatches,
    replayed: {
      decision: "REFUSE",
      request_hash: receipt.request_hash,
      reason_code: reasonCode,
      decision_hash: parseBoundaryDecisionHash(receipt.request_hash, reasonCode)
    }
  };
}

export function boundaryReplayEndpointResponse(receipt) {
  const boundary = compareBoundaryReplay(receipt);
  if (!boundary.matched) return null;
  return {
    schema_version: "mnde.receipt_replay.v1",
    request_hash: receipt.request_hash,
    original: receipt.decision_output,
    replayed: boundary.replayed,
    drift: boundary.drift,
    mismatches: boundary.mismatches
  };
}
