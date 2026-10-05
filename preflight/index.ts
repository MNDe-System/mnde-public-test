import { FailClosedError, hashCanonicalJson, parseStrictJson } from "../shared/index.ts";
import type { PolicyObject, RequestObject } from "../shared/types.ts";
import type { PreflightInputEnvelope, PreflightResult } from "./types.ts";

function expectObject(value: unknown, code: string, message: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new FailClosedError("preflight", code, message);
  }
  return value as Record<string, unknown>;
}

function expectString(root: Record<string, unknown>, key: string): string {
  const value = root[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new FailClosedError("preflight", "ERR_INVALID_SCHEMA", `Expected non-empty string at ${key}`);
  }
  return value;
}

function expectBoolean(root: Record<string, unknown>, key: string): boolean {
  const value = root[key];
  if (typeof value !== "boolean") {
    throw new FailClosedError("preflight", "ERR_INVALID_SCHEMA", `Expected boolean at ${key}`);
  }
  return value;
}

function expectPositiveInteger(root: Record<string, unknown>, key: string): number {
  const value = root[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new FailClosedError("preflight", "ERR_INVALID_SCHEMA", `Expected positive integer at ${key}`);
  }
  return value;
}

function expectNonNegativeInteger(root: Record<string, unknown>, key: string): number {
  const value = root[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new FailClosedError("preflight", "ERR_INVALID_SCHEMA", `Expected non-negative integer at ${key}`);
  }
  return value;
}

function rejectUnknownKeys(root: Record<string, unknown>, allowedKeys: string[], scope: string): void {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(root)) {
    if (!allowed.has(key)) {
      throw new FailClosedError("preflight", "ERR_UNKNOWN_FIELD", `Unknown field ${scope}.${key}`);
    }
  }
}

function parseOrbitIntent(root: Record<string, unknown>): RequestObject["orbit_intent"] {
  rejectUnknownKeys(root, ["action", "boundary", "ext", "lifecycle_state", "orbit_version", "payload", "signatures"], "orbit");
  const payloadObject = expectObject(root.payload, "ERR_INVALID_SCHEMA", "orbit.payload must be an object");
  const signaturesValue = root.signatures;
  if (!Array.isArray(signaturesValue) || signaturesValue.length === 0) {
    throw new FailClosedError("preflight", "ERR_INVALID_SCHEMA", "orbit.signatures must be a non-empty array");
  }

  const signatures = signaturesValue.map((item, index) => {
    const signatureRecord = expectObject(item, "ERR_INVALID_SCHEMA", `orbit.signatures[${index}] must be an object`);
    rejectUnknownKeys(signatureRecord, ["alg", "sig"], `orbit.signatures[${index}]`);
    return {
      alg: expectString(signatureRecord, "alg"),
      sig: expectString(signatureRecord, "sig")
    };
  });

  const extValue = root.ext;
  if (extValue !== undefined) {
    expectObject(extValue, "ERR_INVALID_SCHEMA", "orbit.ext must be an object when present");
  }

  return {
    orbit_version: expectString(root, "orbit_version"),
    action: expectString(root, "action"),
    boundary: expectString(root, "boundary"),
    payload: payloadObject,
    lifecycle_state: expectString(root, "lifecycle_state"),
    signatures,
    ...(extValue === undefined ? {} : { ext: extValue as Record<string, unknown> })
  };
}

function parsePolicyObject(root: Record<string, unknown>): PolicyObject {
  rejectUnknownKeys(root, ["allowed_request_keys", "policy_version", "rules", "schema_version", "trust"], "policy");
  const rulesRoot = expectObject(root.rules, "ERR_INVALID_SCHEMA", "policy.rules must be an object");
  rejectUnknownKeys(
    rulesRoot,
    [
      "allow_auto_scale",
      "max_gpu_count",
      "max_hours",
      "max_total_cost_usd",
      "require_manual_approval_above_usd"
    ],
    "policy.rules"
  );

  const trustRoot = expectObject(root.trust, "ERR_INVALID_SCHEMA", "policy.trust must be an object");
  rejectUnknownKeys(trustRoot, ["key_id", "key_version", "signature", "signing_public_key"], "policy.trust");

  const allowedRequestKeys = root.allowed_request_keys;
  if (!Array.isArray(allowedRequestKeys) || allowedRequestKeys.length === 0) {
    throw new FailClosedError("preflight", "ERR_INVALID_SCHEMA", "policy.allowed_request_keys must be a non-empty array");
  }

  return {
    schema_version: expectString(root, "schema_version") as PolicyObject["schema_version"],
    policy_version: expectString(root, "policy_version"),
    allowed_request_keys: allowedRequestKeys.map((value, index) => {
      if (typeof value !== "string" || value.length === 0) {
        throw new FailClosedError("preflight", "ERR_INVALID_SCHEMA", `policy.allowed_request_keys[${index}] must be a non-empty string`);
      }
      return value;
    }),
    rules: {
      max_total_cost_usd: expectPositiveInteger(rulesRoot, "max_total_cost_usd"),
      allow_auto_scale: expectBoolean(rulesRoot, "allow_auto_scale"),
      max_gpu_count: expectPositiveInteger(rulesRoot, "max_gpu_count"),
      max_hours: expectPositiveInteger(rulesRoot, "max_hours"),
      require_manual_approval_above_usd: expectPositiveInteger(rulesRoot, "require_manual_approval_above_usd")
    },
    trust: {
      key_version: expectString(trustRoot, "key_version") as PolicyObject["trust"]["key_version"],
      key_id: expectString(trustRoot, "key_id"),
      signing_public_key: expectString(trustRoot, "signing_public_key"),
      signature: expectString(trustRoot, "signature")
    }
  };
}

function parseEnvelope(rawInput: string): PreflightInputEnvelope {
  const parsed = parseStrictJson(rawInput);
  if (!parsed.ok) {
    throw new FailClosedError("preflight", "ERR_INPUT_PARSE", parsed.reason);
  }

  const root = expectObject(parsed.value, "ERR_INVALID_SCHEMA", "Input root must be an object");
  rejectUnknownKeys(root, ["orbit", "policy", "release", "request", "runtime"], "root");

  const requestRoot = expectObject(root.request, "ERR_INVALID_SCHEMA", "request must be an object");
  rejectUnknownKeys(requestRoot, ["execution", "job_id", "pricing", "region", "resources", "user_id"], "request");

  const resourcesRoot = expectObject(requestRoot.resources, "ERR_INVALID_SCHEMA", "request.resources must be an object");
  rejectUnknownKeys(resourcesRoot, ["gpu_count", "gpu_type", "hours"], "request.resources");

  const pricingRoot = expectObject(requestRoot.pricing, "ERR_INVALID_SCHEMA", "request.pricing must be an object");
  rejectUnknownKeys(pricingRoot, ["gpu_hour_usd"], "request.pricing");

  const executionRoot = expectObject(requestRoot.execution, "ERR_INVALID_SCHEMA", "request.execution must be an object");
  rejectUnknownKeys(executionRoot, ["auto_scale", "max_retries", "max_scale_multiplier", "retry_on_fail"], "request.execution");

  const releaseRoot = expectObject(root.release, "ERR_INVALID_SCHEMA", "release must be an object");
  rejectUnknownKeys(releaseRoot, ["already_consumed", "execution_id", "hold_state"], "release");

  const runtimeRoot = expectObject(root.runtime, "ERR_INVALID_SCHEMA", "runtime must be an object");
  rejectUnknownKeys(
    runtimeRoot,
    ["actual_gpu_count", "actual_hours", "actual_total_cost_usd", "kill_switch_active"],
    "runtime"
  );

  const orbitRoot = expectObject(root.orbit, "ERR_INVALID_SCHEMA", "orbit must be an object");
  const policyRoot = expectObject(root.policy, "ERR_INVALID_SCHEMA", "policy must be an object");

  return {
    request: {
      job_id: expectString(requestRoot, "job_id"),
      user_id: expectString(requestRoot, "user_id"),
      region: expectString(requestRoot, "region"),
      resources: {
        gpu_type: expectString(resourcesRoot, "gpu_type"),
        gpu_count: expectPositiveInteger(resourcesRoot, "gpu_count"),
        hours: expectPositiveInteger(resourcesRoot, "hours")
      },
      pricing: {
        gpu_hour_usd: expectPositiveInteger(pricingRoot, "gpu_hour_usd")
      },
      execution: {
        auto_scale: expectBoolean(executionRoot, "auto_scale"),
        max_scale_multiplier: expectPositiveInteger(executionRoot, "max_scale_multiplier"),
        retry_on_fail: expectBoolean(executionRoot, "retry_on_fail"),
        max_retries: expectNonNegativeInteger(executionRoot, "max_retries")
      }
    },
    orbit: parseOrbitIntent(orbitRoot),
    policy: parsePolicyObject(policyRoot),
    release: {
      execution_id: expectString(releaseRoot, "execution_id"),
      hold_state: expectString(releaseRoot, "hold_state") as RequestObject["release_request"]["hold_state"],
      already_consumed: expectBoolean(releaseRoot, "already_consumed")
    },
    runtime: {
      kill_switch_active: expectBoolean(runtimeRoot, "kill_switch_active"),
      actual_gpu_count: expectPositiveInteger(runtimeRoot, "actual_gpu_count"),
      actual_hours: expectPositiveInteger(runtimeRoot, "actual_hours"),
      actual_total_cost_usd: expectNonNegativeInteger(runtimeRoot, "actual_total_cost_usd")
    }
  };
}

export function runPreflight(rawInput: string): PreflightResult {
  const envelope = parseEnvelope(rawInput);
  const requestObject: RequestObject = {
    schema_version: "mnde.request.v1",
    request_id: envelope.request.job_id,
    submitted_region: envelope.request.region,
    actor: {
      user_id: envelope.request.user_id
    },
    resources: envelope.request.resources,
    pricing: envelope.request.pricing,
    execution: envelope.request.execution,
    orbit_intent: envelope.orbit,
    release_request: envelope.release,
    runtime_request: {
      ...envelope.runtime,
      observed_request_hash: "",
      observed_policy_hash: ""
    }
  };

  const requestHash = hashCanonicalJson(requestObject as unknown as import("../shared/json.ts").JsonValue);
  requestObject.runtime_request.observed_request_hash = requestHash;

  return {
    request_object: requestObject,
    policy_object: envelope.policy,
    request_hash: requestHash
  };
}
