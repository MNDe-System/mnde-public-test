// Execution-gate schema validation and canonicalization.
//
// Validates an mnde.execution_request.v1 object against the required shape,
// enum values, and ISO-8601 datetime pattern. Returns { ok, errors } — never
// throws. Canonicalization delegates to the shared canonicalizeJson utility so
// request hashes are deterministic across platforms.

import { sha256 } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";

export const EXECUTION_REQUEST_SCHEMA = "mnde.execution_request.v1";

// ISO-8601 datetime — require explicit timezone (Z or ±HH:MM).
const ISO8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

const ACTION_TYPES = new Set(["deploy", "migrate", "rollback", "promote"]);
const PRINCIPAL_TYPES = new Set(["github_actor", "service_account", "ci_runner"]);
const RESOURCE_KINDS = new Set(["repo", "branch", "environment", "cluster", "database", "service"]);
const ENVIRONMENT_NAMES = new Set(["dev", "staging", "production"]);
const RISK_LEVELS = new Set(["low", "medium", "high", "critical"]);
const BLAST_RADII = new Set(["local", "service", "environment", "global"]);

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function required(errors, obj, path, type) {
  if (obj === undefined || obj === null) {
    errors.push(`${path} is required`);
    return false;
  }
  if (type && typeof obj !== type) {
    errors.push(`${path} must be a ${type}`);
    return false;
  }
  return true;
}

function enumField(errors, value, path, allowed) {
  if (!allowed.has(value)) {
    errors.push(`${path} must be one of: ${[...allowed].join(", ")} (got ${JSON.stringify(value)})`);
    return false;
  }
  return true;
}

// Validate the full execution request. Returns { ok: true } or { ok: false, errors: string[] }.
export function validateExecutionRequest(req) {
  const errors = [];

  if (!isObject(req)) {
    return { ok: false, errors: ["request must be an object"] };
  }

  // schema_version
  if (req.schema_version === undefined) {
    errors.push("schema_version is required");
  } else if (req.schema_version !== EXECUTION_REQUEST_SCHEMA) {
    errors.push(`unknown schema_version: ${JSON.stringify(req.schema_version)}`);
  }

  // execution_id
  if (!required(errors, req.execution_id, "execution_id", "string") || req.execution_id.length === 0) {
    if (typeof req.execution_id === "string" && req.execution_id.length === 0) {
      errors.push("execution_id must not be empty");
    }
  }

  // requested_at
  if (required(errors, req.requested_at, "requested_at", "string")) {
    if (!ISO8601_RE.test(req.requested_at)) {
      errors.push("requested_at must be a valid ISO-8601 datetime with timezone");
    }
  }

  // action
  if (!required(errors, req.action, "action")) {
    /* skip sub-fields */
  } else if (!isObject(req.action)) {
    errors.push("action must be an object");
  } else {
    if (required(errors, req.action.type, "action.type", "string")) {
      enumField(errors, req.action.type, "action.type", ACTION_TYPES);
    }
    required(errors, req.action.name, "action.name", "string");
    if (req.action.command !== undefined && typeof req.action.command !== "string") {
      errors.push("action.command must be a string when present");
    }
    if (typeof req.action.dry_run !== "boolean") {
      errors.push("action.dry_run must be a boolean");
    }
  }

  // principal
  if (!required(errors, req.principal, "principal")) {
    /* skip */
  } else if (!isObject(req.principal)) {
    errors.push("principal must be an object");
  } else {
    required(errors, req.principal.id, "principal.id", "string");
    if (required(errors, req.principal.type, "principal.type", "string")) {
      enumField(errors, req.principal.type, "principal.type", PRINCIPAL_TYPES);
    }
    required(errors, req.principal.issuer, "principal.issuer", "string");
    if (typeof req.principal.verified !== "boolean") {
      errors.push("principal.verified must be a boolean");
    }
    if (!isObject(req.principal.claims)) {
      errors.push("principal.claims must be an object");
    }
  }

  // resource
  if (!required(errors, req.resource, "resource")) {
    /* skip */
  } else if (!isObject(req.resource)) {
    errors.push("resource must be an object");
  } else {
    if (required(errors, req.resource.kind, "resource.kind", "string")) {
      enumField(errors, req.resource.kind, "resource.kind", RESOURCE_KINDS);
    }
    required(errors, req.resource.id, "resource.id", "string");
    required(errors, req.resource.name, "resource.name", "string");
    if (req.resource.owner !== undefined && typeof req.resource.owner !== "string") {
      errors.push("resource.owner must be a string when present");
    }
  }

  // environment
  if (!required(errors, req.environment, "environment")) {
    /* skip */
  } else if (!isObject(req.environment)) {
    errors.push("environment must be an object");
  } else {
    if (required(errors, req.environment.name, "environment.name", "string")) {
      enumField(errors, req.environment.name, "environment.name", ENVIRONMENT_NAMES);
    }
    for (const opt of ["region", "account", "cluster"]) {
      if (req.environment[opt] !== undefined && typeof req.environment[opt] !== "string") {
        errors.push(`environment.${opt} must be a string when present`);
      }
    }
  }

  // risk
  if (!required(errors, req.risk, "risk")) {
    /* skip */
  } else if (!isObject(req.risk)) {
    errors.push("risk must be an object");
  } else {
    if (required(errors, req.risk.level, "risk.level", "string")) {
      enumField(errors, req.risk.level, "risk.level", RISK_LEVELS);
    }
    if (typeof req.risk.destructive !== "boolean") errors.push("risk.destructive must be a boolean");
    if (typeof req.risk.reversible !== "boolean") errors.push("risk.reversible must be a boolean");
    if (typeof req.risk.touches_secrets !== "boolean") errors.push("risk.touches_secrets must be a boolean");
    if (typeof req.risk.touches_customer_data !== "boolean") errors.push("risk.touches_customer_data must be a boolean");
    if (required(errors, req.risk.blast_radius, "risk.blast_radius", "string")) {
      enumField(errors, req.risk.blast_radius, "risk.blast_radius", BLAST_RADII);
    }
  }

  // cost
  if (!required(errors, req.cost, "cost")) {
    /* skip */
  } else if (!isObject(req.cost)) {
    errors.push("cost must be an object");
  } else {
    if (typeof req.cost.estimated_cents !== "number") {
      errors.push("cost.estimated_cents must be a number");
    }
    if (!isObject(req.cost.dimensions)) {
      errors.push("cost.dimensions must be an object");
    }
  }

  // approval
  if (!required(errors, req.approval, "approval")) {
    /* skip */
  } else if (!isObject(req.approval)) {
    errors.push("approval must be an object");
  } else {
    if (typeof req.approval.required !== "boolean") {
      errors.push("approval.required must be a boolean");
    }
    for (const opt of ["approval_id", "approver_principal", "approval_signature"]) {
      if (req.approval[opt] !== undefined && typeof req.approval[opt] !== "string") {
        errors.push(`approval.${opt} must be a string when present`);
      }
    }
  }

  // evidence
  if (!required(errors, req.evidence, "evidence")) {
    /* skip */
  } else if (!isObject(req.evidence)) {
    errors.push("evidence must be an object");
  } else {
    required(errors, req.evidence.repo, "evidence.repo", "string");
    required(errors, req.evidence.commit_sha, "evidence.commit_sha", "string");
    required(errors, req.evidence.branch, "evidence.branch", "string");
    for (const opt of ["workflow_run_id", "workflow_url", "artifact_digest"]) {
      if (req.evidence[opt] !== undefined && typeof req.evidence[opt] !== "string") {
        errors.push(`evidence.${opt} must be a string when present`);
      }
    }
    if (req.evidence.policy_bundle_id !== undefined && typeof req.evidence.policy_bundle_id !== "string") {
      errors.push("evidence.policy_bundle_id must be a string when present");
    }
    if (req.evidence.policy_bundle_serial !== undefined && typeof req.evidence.policy_bundle_serial !== "number") {
      errors.push("evidence.policy_bundle_serial must be a number when present");
    }
  }

  return errors.length === 0 ? { ok: true } : { ok: false, errors };
}

// Canonicalize and hash the request. Must only be called after validation passes.
export function canonicalizeRequest(req) {
  return canonicalizeJson(req);
}

export function hashRequest(req) {
  return sha256(canonicalizeRequest(req));
}
