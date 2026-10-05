// Execution result schema for mnde.execution_result.v2.
//
// Records what happened after MNDe issued an execution gate decision. This is
// the third link in the audit chain:
//
//   mnde.execution_request.v1  →  what was asked?
//   mnde.execution_gate.receipt.v1  →  was it authorized?  (Ed25519 signed)
//   mnde.execution_result.v2   →  what happened?          (hash-bound + optional executor sig)
//
// The result is executor-asserted. result_hash provides tamper-evidence; it is
// NOT an authority signature. When executor_signature is present the verifier
// checks it against the provided executor public key. When absent the result is
// executor-reported only and the verifier records that explicitly.
//
// duration_ms is intentionally absent — compute it from started_at / ended_at.

import { sha256 } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";
import { validateIdentityAssertion } from "../identity/assertion.mjs";

export const EXECUTION_RESULT_SCHEMA = "mnde.execution_result.v2";

// Safe result_id: "result-" prefix + 1-128 URL-safe chars.
const RESULT_ID_RE = /^result-[A-Za-z0-9._-]{1,128}$/;

// sha256:<lowercase-hex> or null.
const DIGEST_RE = /^sha256:[a-f0-9]{64}$/;

// ISO-8601 with explicit timezone.
const ISO8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

export const VALID_STATUSES = new Set([
  "NOT_EXECUTED", "STARTED", "SUCCEEDED", "FAILED", "PARTIALLY_SUCCEEDED",
  "CANCELLED", "ROLLED_BACK", "ROLLBACK_FAILED", "UNKNOWN"
]);

export const NON_EXECUTION_REASONS = new Set([
  "EXECUTOR_OFFLINE", "USER_CANCELLED", "TIMEOUT", "DEPENDENCY_FAILED",
  "MANUAL_ABORT", "SCHEDULER_CANCELLED", "PRECONDITION_FAILED"
]);

// Field names forbidden in evidence items — prevent leakage of secrets,
// URIs, raw environment data, and credentials.
export const EVIDENCE_FORBIDDEN_FIELDS = new Set([
  "uri", "url", "href", "token", "secret", "password", "authorization",
  "bearer", "private_key", "access_key", "refresh_token", "session_cookie",
  "raw_log", "env", "environment", "stdout", "stderr"
]);

export const VALID_DECISIONS = new Set(["ALLOW", "REFUSE"]);

const EFFECT_TYPES = new Set([
  "deployment", "migration", "config_change", "secret_rotation", "traffic_shift"
]);

const EVIDENCE_TYPES = new Set([
  "workflow_run", "artifact", "log_archive", "audit_event"
]);

const EXECUTOR_TYPES = new Set([
  "github_actions", "gitlab_ci", "jenkins", "service_account", "cli"
]);

const IDENTITY_EVIDENCE_TYPES = new Set([
  "github_oidc", "gitlab_oidc", "service_account_key", "none"
]);

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isTimestamp(v) {
  return typeof v === "string" && ISO8601_RE.test(v) && !Number.isNaN(Date.parse(v));
}

function isDigestOrNull(v) {
  return v === null || (typeof v === "string" && DIGEST_RE.test(v));
}

// Validate a single effect entry.
function validateEffect(effect, path, errors) {
  if (!isObject(effect)) {
    errors.push(`${path} must be an object`);
    return;
  }
  if (!EFFECT_TYPES.has(effect.type)) {
    errors.push(`${path}.type must be one of: ${[...EFFECT_TYPES].join(", ")}`);
  }
  if (typeof effect.resource_id !== "string" || effect.resource_id.length === 0) {
    errors.push(`${path}.resource_id must be a non-empty string`);
  }
  if (!isDigestOrNull(effect.before)) {
    errors.push(`${path}.before must be null or "sha256:<64-hex-chars>"`);
  }
  if (!isDigestOrNull(effect.after)) {
    errors.push(`${path}.after must be null or "sha256:<64-hex-chars>"`);
  }
  if (effect.description !== undefined && typeof effect.description !== "string") {
    errors.push(`${path}.description must be a string when present`);
  }
}

// Validate a single evidence entry.
function validateEvidenceItem(item, path, errors) {
  if (!isObject(item)) {
    errors.push(`${path} must be an object`);
    return;
  }
  if (!EVIDENCE_TYPES.has(item.type)) {
    errors.push(`${path}.type must be one of: ${[...EVIDENCE_TYPES].join(", ")}`);
  }
  if (typeof item.identifier !== "string" || item.identifier.length === 0) {
    errors.push(`${path}.identifier must be a non-empty string`);
  }
  if (item.digest !== undefined && !DIGEST_RE.test(item.digest)) {
    errors.push(`${path}.digest must be "sha256:<64-hex-chars>" when present`);
  }
}

// Validate the rollback sub-object.
function validateRollback(rollback, errors) {
  if (!isObject(rollback)) {
    errors.push("rollback must be an object");
    return;
  }
  if (!isTimestamp(rollback.initiated_at)) {
    errors.push("rollback.initiated_at must be a valid ISO-8601 datetime");
  }
  if (rollback.completed_at !== null && rollback.completed_at !== undefined && !isTimestamp(rollback.completed_at)) {
    errors.push("rollback.completed_at must be a valid ISO-8601 datetime or null");
  }
  if (typeof rollback.method !== "string" || rollback.method.length === 0) {
    errors.push("rollback.method must be a non-empty string");
  }
  if (rollback.rollback_effects !== undefined) {
    if (!Array.isArray(rollback.rollback_effects)) {
      errors.push("rollback.rollback_effects must be an array when present");
    } else {
      rollback.rollback_effects.forEach((e, i) => validateEffect(e, `rollback.rollback_effects[${i}]`, errors));
    }
  }
}

// Validate an mnde.execution_result.v2 object.
// Returns { ok: true } or { ok: false, errors: string[] }.
export function validateExecutionResult(result) {
  if (!isObject(result)) {
    return { ok: false, errors: ["result must be an object"] };
  }

  const errors = [];

  // schema_version
  if (result.schema_version !== EXECUTION_RESULT_SCHEMA) {
    errors.push(`schema_version must be "${EXECUTION_RESULT_SCHEMA}", got ${JSON.stringify(result.schema_version)}`);
  }

  // result_id
  if (!RESULT_ID_RE.test(result.result_id)) {
    errors.push(`result_id must match /^result-[A-Za-z0-9._-]{1,128}$/, got ${JSON.stringify(result.result_id)}`);
  }

  // execution_request_hash / execution_receipt_hash
  if (typeof result.execution_request_hash !== "string" || !/^[a-f0-9]{64}$/.test(result.execution_request_hash)) {
    errors.push("execution_request_hash must be a 64-char lowercase hex string");
  }
  if (typeof result.execution_receipt_hash !== "string" || !/^[a-f0-9]{64}$/.test(result.execution_receipt_hash)) {
    errors.push("execution_receipt_hash must be a 64-char lowercase hex string");
  }

  // execution_id
  if (typeof result.execution_id !== "string" || result.execution_id.length === 0) {
    errors.push("execution_id must be a non-empty string");
  }

  // status
  if (!VALID_STATUSES.has(result.status)) {
    errors.push(`status must be one of: ${[...VALID_STATUSES].join(", ")}`);
  }

  // decision
  if (!VALID_DECISIONS.has(result.decision)) {
    errors.push(`decision must be one of: ${[...VALID_DECISIONS].join(", ")}`);
  }

  // decision-status consistency (fail-closed)
  if (VALID_STATUSES.has(result.status) && VALID_DECISIONS.has(result.decision)) {
    if (result.decision === "REFUSE" && result.status !== "NOT_EXECUTED") {
      errors.push(`status must be "NOT_EXECUTED" when decision is "REFUSE" (got "${result.status}")`);
    }
  }

  // non_execution_reason — required for NOT_EXECUTED, allowed only on CANCELLED
  if (result.status === "NOT_EXECUTED") {
    if (result.non_execution_reason === undefined || result.non_execution_reason === null) {
      errors.push("non_execution_reason is required when status is NOT_EXECUTED");
    } else if (!NON_EXECUTION_REASONS.has(result.non_execution_reason)) {
      errors.push(`non_execution_reason must be one of: ${[...NON_EXECUTION_REASONS].join(", ")}`);
    }
  } else if (result.non_execution_reason !== undefined && result.non_execution_reason !== null) {
    if (result.status === "CANCELLED") {
      if (!NON_EXECUTION_REASONS.has(result.non_execution_reason)) {
        errors.push(`non_execution_reason must be one of: ${[...NON_EXECUTION_REASONS].join(", ")} when present`);
      }
    } else {
      errors.push(`non_execution_reason must not be present when status is "${result.status}"`);
    }
  }
  if (result.status === "CANCELLED") {
    const hasReason = result.non_execution_reason !== undefined && result.non_execution_reason !== null;
    const hasError = isObject(result.error);
    if (!hasReason && !hasError) {
      errors.push("CANCELLED status requires non_execution_reason or error");
    }
  }

  // executor
  if (!isObject(result.executor)) {
    errors.push("executor must be an object");
  } else {
    if (typeof result.executor.id !== "string" || result.executor.id.length === 0) {
      errors.push("executor.id must be a non-empty string");
    }
    if (!EXECUTOR_TYPES.has(result.executor.type)) {
      errors.push(`executor.type must be one of: ${[...EXECUTOR_TYPES].join(", ")}`);
    }
    if (!isObject(result.executor.identity_evidence)) {
      errors.push("executor.identity_evidence must be an object");
    } else {
      if (!IDENTITY_EVIDENCE_TYPES.has(result.executor.identity_evidence.type)) {
        errors.push(`executor.identity_evidence.type must be one of: ${[...IDENTITY_EVIDENCE_TYPES].join(", ")}`);
      }
      if (result.executor.identity_evidence.type !== "none") {
        if (typeof result.executor.identity_evidence.subject !== "string" || result.executor.identity_evidence.subject.length === 0) {
          errors.push("executor.identity_evidence.subject must be a non-empty string when type is not \"none\"");
        }
        if (typeof result.executor.identity_evidence.issuer !== "string" || result.executor.identity_evidence.issuer.length === 0) {
          errors.push("executor.identity_evidence.issuer must be a non-empty string when type is not \"none\"");
        }
      }
    }
    // identity_evidence_asserted_only must be true in v2
    if (result.executor.identity_evidence_asserted_only !== true) {
      errors.push("executor.identity_evidence_asserted_only must be true (identity is executor-asserted, not MNDe-verified)");
    }
    // identity_assertion — optional; when present must be structurally valid
    if (result.executor.identity_assertion !== undefined && result.executor.identity_assertion !== null) {
      const assertionValidation = validateIdentityAssertion(result.executor.identity_assertion);
      if (!assertionValidation.ok) {
        for (const e of assertionValidation.errors) {
          errors.push(`executor.identity_assertion: ${e.message}`);
        }
      }
    }
  }

  // timestamps — executor-reported, validated as ISO-8601 only
  if (!isTimestamp(result.started_at)) {
    errors.push("started_at must be a valid ISO-8601 datetime");
  }
  // ended_at is optional for STARTED (action has not completed yet).
  // For all other statuses it is required.
  if (result.status !== "STARTED") {
    if (!isTimestamp(result.ended_at)) {
      errors.push("ended_at must be a valid ISO-8601 datetime");
    }
  } else if (result.ended_at !== undefined && result.ended_at !== null && !isTimestamp(result.ended_at)) {
    errors.push("ended_at must be a valid ISO-8601 datetime when present");
  }
  if (!isTimestamp(result.recorded_at)) {
    errors.push("recorded_at must be a valid ISO-8601 datetime");
  }
  // Cross-check: started_at must not be after ended_at (when both present).
  if (isTimestamp(result.started_at) && isTimestamp(result.ended_at)) {
    if (Date.parse(result.started_at) > Date.parse(result.ended_at)) {
      errors.push("started_at must not be after ended_at");
    }
  }

  // effects — required non-empty for SUCCEEDED and PARTIALLY_SUCCEEDED; must be empty for NOT_EXECUTED
  if (!Array.isArray(result.effects)) {
    errors.push("effects must be an array");
  } else {
    result.effects.forEach((e, i) => validateEffect(e, `effects[${i}]`, errors));
    if ((result.status === "SUCCEEDED" || result.status === "PARTIALLY_SUCCEEDED") && result.effects.length === 0) {
      errors.push(`effects must be non-empty when status is "${result.status}"`);
    }
    if (result.status === "NOT_EXECUTED" && result.effects.length > 0) {
      errors.push('effects must be empty when status is "NOT_EXECUTED"');
    }
  }

  // evidence — required array (may be empty)
  if (!Array.isArray(result.evidence)) {
    errors.push("evidence must be an array");
  } else {
    result.evidence.forEach((e, i) => validateEvidenceItem(e, `evidence[${i}]`, errors));
  }

  // rollback — required for ROLLED_BACK and ROLLBACK_FAILED
  if (result.status === "ROLLED_BACK" || result.status === "ROLLBACK_FAILED") {
    if (result.rollback === undefined || result.rollback === null) {
      errors.push(`rollback is required when status is "${result.status}"`);
    } else {
      validateRollback(result.rollback, errors);
    }
  } else if (result.rollback !== undefined && result.rollback !== null) {
    validateRollback(result.rollback, errors);
  }

  // error — expected when status is FAILED or ROLLBACK_FAILED
  if (result.status === "FAILED" || result.status === "ROLLBACK_FAILED") {
    if (!isObject(result.error)) {
      errors.push(`error object is required when status is "${result.status}"`);
    } else {
      if (typeof result.error.code !== "string" || result.error.code.length === 0) {
        errors.push("error.code must be a non-empty string");
      }
      if (typeof result.error.message !== "string" || result.error.message.length === 0) {
        errors.push("error.message must be a non-empty string");
      }
    }
  }

  // result_hash format
  if (typeof result.result_hash !== "string" || !/^[a-f0-9]{64}$/.test(result.result_hash)) {
    errors.push("result_hash must be a 64-char lowercase hex string");
  }

  // executor_signature — optional, but if present must have required fields
  if (result.executor_signature !== undefined && result.executor_signature !== null) {
    if (!isObject(result.executor_signature)) {
      errors.push("executor_signature must be an object when present");
    } else {
      if (result.executor_signature.algorithm !== "ED25519") {
        errors.push("executor_signature.algorithm must be \"ED25519\"");
      }
      if (typeof result.executor_signature.key_fingerprint !== "string" || result.executor_signature.key_fingerprint.length === 0) {
        errors.push("executor_signature.key_fingerprint must be a non-empty string");
      }
      if (typeof result.executor_signature.value !== "string" || result.executor_signature.value.length === 0) {
        errors.push("executor_signature.value must be a non-empty string");
      }
    }
  }

  return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

// Compute the canonical payload for result_hash and executor_signature.
// Excludes both result_hash and executor_signature so both hash and signature
// cover identical content.
export function canonicalResultPayload(result) {
  const { result_hash: _rh, executor_signature: _es, ...payload } = result;
  return canonicalizeJson(payload);
}

// Compute the expected result_hash for a result object.
export function computeResultHash(result) {
  return sha256(canonicalResultPayload(result));
}

// Build an mnde.execution_result.v2 object and compute its result_hash.
// Caller must pass a fully-formed body (without result_hash or executor_signature).
// Throws if validation fails.
export function buildExecutionResult(body) {
  const withHash = { ...body, result_hash: computeResultHash(body) };
  const validation = validateExecutionResult(withHash);
  if (!validation.ok) {
    throw new Error(`buildExecutionResult: invalid result — ${validation.errors.join("; ")}`);
  }
  return withHash;
}
