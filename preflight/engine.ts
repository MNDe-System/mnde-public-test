import { createHash } from "crypto";
import {
  REASON_CODES,
  canonicalizeJson,
  canonicalPolicyPayload,
  deriveKeyId,
  parseStrictJson,
  policyHash,
  verifyPolicySignature,
  type CanonicalExecutionInput,
  type JsonValue,
  type ParsedEnvelope,
  type TypedFailure
} from "../shared/index.ts";

const PINNED_POLICY_VERSION = "policy.v1";
const RESERVED_UNSAFE_FIELDS = new Set([
  "timestamp",
  "time",
  "now",
  "random",
  "eval",
  "exec",
  "shell",
  "command",
  "commands",
  "__proto__",
  "constructor",
  "prototype",
  "nonce",
  "session_id",
  "depends_on",
  "previous_step_id"
]);

function decisionHashFromFailure(requestHash: string, reasonCode: string): string {
  return createHash("sha256")
    .update(
      canonicalizeJson({
        request_hash: requestHash,
        decision: "REFUSE",
        reason_code: reasonCode
      } as unknown as JsonValue)
    )
    .digest("hex");
}

function typedFailure(requestHash: string, reasonCode: string): TypedFailure {
  return {
    decision: "REFUSE",
    request_hash: requestHash,
    decision_hash: decisionHashFromFailure(requestHash, reasonCode),
    reason_code: reasonCode,
    parse_boundary: true
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function rejectUnknownKeys(root: Record<string, unknown>, allowedKeys: string[]): string | null {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(root)) {
    if (!allowed.has(key)) {
      if (RESERVED_UNSAFE_FIELDS.has(key)) {
        return REASON_CODES.NonDeterministicInput;
      }
      return REASON_CODES.SchemaValidation;
    }
  }
  return null;
}

function rejectReservedFieldsRecursive(value: unknown): string | null {
  if (Array.isArray(value)) {
    for (const item of value) {
      const nested = rejectReservedFieldsRecursive(item);
      if (nested) return nested;
    }
    return null;
  }
  if (!isRecord(value)) {
    return null;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (RESERVED_UNSAFE_FIELDS.has(key)) {
      return REASON_CODES.NonDeterministicInput;
    }
    const nestedResult = rejectReservedFieldsRecursive(nested);
    if (nestedResult) return nestedResult;
  }
  return null;
}

function validateInteger(
  value: unknown,
  minimum: number,
  allowZero: boolean
): { ok: true; value: number } | { ok: false; reason_code: string } {
  if (typeof value !== "number") {
    return { ok: false, reason_code: REASON_CODES.TypeMismatch };
  }
  if (Object.is(value, -0)) {
    return { ok: false, reason_code: REASON_CODES.InvalidJsonNumber };
  }
  if (!Number.isSafeInteger(value)) {
    return { ok: false, reason_code: REASON_CODES.InvalidJsonNumber };
  }
  if (!allowZero && value === 0) {
    return { ok: false, reason_code: REASON_CODES.TypeMismatch };
  }
  if (value < minimum) {
    return {
      ok: false,
      reason_code: value < 0 ? REASON_CODES.TypeMismatch : REASON_CODES.InvalidJsonNumber
    };
  }
  return { ok: true, value };
}

function expectString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function expectBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function parseToolCalls(value: unknown): { ok: true; value: CanonicalExecutionInput["execution_request"]["tool_calls"] } | { ok: false; reason_code: string } {
  if (!Array.isArray(value) || value.length === 0) {
    return { ok: false, reason_code: REASON_CODES.SchemaValidation };
  }
  const parsed: CanonicalExecutionInput["execution_request"]["tool_calls"] = [];
  const seenTools = new Set<string>();
  for (const item of value) {
    if (!isRecord(item)) {
      return { ok: false, reason_code: REASON_CODES.SchemaValidation };
    }
    const unknown = rejectUnknownKeys(item, ["tool", "priority", "parameters"]);
    if (unknown) {
      return { ok: false, reason_code: unknown };
    }
    const tool = expectString(item.tool);
    const priority = validateInteger(item.priority, 0, true);
    if (!tool || !priority.ok) {
      return { ok: false, reason_code: tool ? priority.reason_code : REASON_CODES.TypeMismatch };
    }
    if (seenTools.has(tool)) {
      return { ok: false, reason_code: REASON_CODES.SchemaValidation };
    }
    seenTools.add(tool);
    const parameters = parseParameters(item.parameters);
    if (!parameters.ok) {
      return { ok: false, reason_code: parameters.reason_code };
    }
    parsed.push({
      tool,
      priority: priority.value,
      ...(parameters.value === undefined ? {} : { parameters: parameters.value })
    });
  }
  return { ok: true, value: parsed };
}

function parseParameters(value: unknown): { ok: true; value: Record<string, JsonValue> | undefined } | { ok: false; reason_code: string } {
  if (value === undefined) {
    return { ok: true, value: undefined };
  }
  if (!isRecord(value)) {
    return { ok: false, reason_code: REASON_CODES.SchemaValidation };
  }
  const reserved = rejectReservedFieldsRecursive(value);
  if (reserved) {
    return { ok: false, reason_code: reserved };
  }
  return { ok: true, value: value as Record<string, JsonValue> };
}

export function runStrictPreflight(rawInput: string): ParsedEnvelope | TypedFailure {
  const parsed = parseStrictJson(rawInput);
  if (!parsed.ok) {
    const requestHash = createHash("sha256").update(rawInput).digest("hex");
    const reasonCode =
      parsed.reason === "duplicate_json_keys"
        ? REASON_CODES.DuplicateJsonKeys
        : parsed.reason === "invalid_json_number"
          ? REASON_CODES.InvalidJsonNumber
          : REASON_CODES.InvalidJsonSyntax;
    return typedFailure(requestHash, reasonCode);
  }

  if (!isRecord(parsed.value)) {
    const requestHash = createHash("sha256").update(rawInput).digest("hex");
    return typedFailure(requestHash, REASON_CODES.SchemaValidation);
  }

  const canonicalInput = canonicalizeJson(parsed.value as JsonValue);
  const requestHash = createHash("sha256").update(canonicalInput).digest("hex");
  const root = parsed.value;
  const rootUnknown = rejectUnknownKeys(root, ["execution_request", "policy_document", "pricing_data"]);
  if (rootUnknown) {
    return typedFailure(requestHash, rootUnknown);
  }

  const executionRequest = root.execution_request;
  const policyDocument = root.policy_document;
  const pricingData = root.pricing_data;
  if (!isRecord(executionRequest) || !isRecord(policyDocument) || !isRecord(pricingData)) {
    return typedFailure(requestHash, REASON_CODES.SchemaValidation);
  }

  const executionUnknown = rejectUnknownKeys(
    executionRequest,
    [
      "request_id",
      "submitted_region",
      "actor",
      "resources",
      "execution",
      "tool_calls",
      "parameters",
      "orbit_intent",
      "release_request",
      "runtime_observation",
      "budget_token"
    ]
  );
  if (executionUnknown) {
    return typedFailure(requestHash, executionUnknown);
  }

  const actor = executionRequest.actor;
  const resources = executionRequest.resources;
  const execution = executionRequest.execution;
  const orbitIntent = executionRequest.orbit_intent;
  const releaseRequest = executionRequest.release_request;
  const runtimeObservation = executionRequest.runtime_observation;
  if (!isRecord(actor) || !isRecord(resources) || !isRecord(execution) || !isRecord(orbitIntent) || !isRecord(releaseRequest) || !isRecord(runtimeObservation)) {
    return typedFailure(requestHash, REASON_CODES.SchemaValidation);
  }

  const actorUnknown = rejectUnknownKeys(actor, ["user_id"]);
  const resourcesUnknown = rejectUnknownKeys(resources, ["gpu_type", "gpu_count", "hours"]);
  const executionConfigUnknown = rejectUnknownKeys(execution, ["auto_scale", "max_scale_multiplier", "retry_on_fail", "max_retries"]);
  const orbitUnknown = rejectUnknownKeys(orbitIntent, ["orbit_version", "action", "boundary", "payload", "lifecycle_state", "signatures"]);
  const releaseUnknown = rejectUnknownKeys(releaseRequest, ["execution_id", "hold_state", "already_consumed"]);
  const runtimeUnknown = rejectUnknownKeys(runtimeObservation, ["kill_switch_active", "actual_gpu_count", "actual_hours", "actual_total_cost_cents"]);
  const pricingUnknown = rejectUnknownKeys(pricingData, ["gpu_hour_cents"]);
  if (actorUnknown || resourcesUnknown || executionConfigUnknown || orbitUnknown || releaseUnknown || runtimeUnknown || pricingUnknown) {
    return typedFailure(
      requestHash,
      actorUnknown ?? resourcesUnknown ?? executionConfigUnknown ?? orbitUnknown ?? releaseUnknown ?? runtimeUnknown ?? pricingUnknown ?? REASON_CODES.SchemaValidation
    );
  }

  const policyUnknown = rejectUnknownKeys(policyDocument, ["schema_version", "policy_version", "rules", "trust"]);
  if (policyUnknown) {
    return typedFailure(requestHash, policyUnknown);
  }
  const policyRules = policyDocument.rules;
  if (!isRecord(policyRules)) {
    return typedFailure(requestHash, REASON_CODES.SchemaValidation);
  }
  const policyRulesUnknown = rejectUnknownKeys(policyRules, [
    "max_total_cost_cents",
    "allow_auto_scale",
    "max_gpu_count",
    "max_hours",
    "require_manual_approval_above_cents",
    "max_retry_count"
  ]);
  if (policyRulesUnknown) {
    return typedFailure(requestHash, policyRulesUnknown);
  }

  const requestId = expectString(executionRequest.request_id);
  const submittedRegion = expectString(executionRequest.submitted_region);
  const userId = expectString(actor.user_id);
  const gpuType = expectString(resources.gpu_type);
  const executionId = expectString(releaseRequest.execution_id);
  const holdState = expectString(releaseRequest.hold_state);
  const orbitVersion = expectString(orbitIntent.orbit_version);
  const orbitAction = expectString(orbitIntent.action);
  const orbitBoundary = expectString(orbitIntent.boundary);
  const lifecycleState = expectString(orbitIntent.lifecycle_state);
  const policySchemaVersion = expectString(policyDocument.schema_version);
  const policyVersion = expectString(policyDocument.policy_version);
  const budgetToken = executionRequest.budget_token;
  if (!requestId || !submittedRegion || !userId || !gpuType || !executionId || !holdState || !orbitVersion || !orbitAction || !orbitBoundary || !lifecycleState || !policySchemaVersion || !policyVersion) {
    return typedFailure(requestHash, REASON_CODES.TypeMismatch);
  }
  if (budgetToken !== undefined && expectString(budgetToken) === null) {
    return typedFailure(requestHash, REASON_CODES.TypeMismatch);
  }

  const parsedToolCalls = parseToolCalls(executionRequest.tool_calls);
  if (!parsedToolCalls.ok) {
    return typedFailure(requestHash, parsedToolCalls.reason_code);
  }
  const parameters = parseParameters(executionRequest.parameters);
  if (!parameters.ok) {
    return typedFailure(requestHash, parameters.reason_code);
  }

  if (!Array.isArray(orbitIntent.signatures) || orbitIntent.signatures.length === 0) {
    return typedFailure(requestHash, REASON_CODES.SchemaValidation);
  }
  const parsedSignatures: CanonicalExecutionInput["execution_request"]["orbit_intent"]["signatures"] = [];
  for (const signature of orbitIntent.signatures) {
    if (!isRecord(signature)) {
      return typedFailure(requestHash, REASON_CODES.SchemaValidation);
    }
    const unknown = rejectUnknownKeys(signature, ["alg", "sig"]);
    if (unknown) {
      return typedFailure(requestHash, unknown);
    }
    const alg = expectString(signature.alg);
    const sig = expectString(signature.sig);
    if (!alg || !sig) {
      return typedFailure(requestHash, REASON_CODES.TypeMismatch);
    }
    parsedSignatures.push({ alg, sig });
  }

  const orbitPayload = orbitIntent.payload;
  if (!isRecord(orbitPayload)) {
    return typedFailure(requestHash, REASON_CODES.SchemaValidation);
  }
  const orbitPayloadReserved = rejectReservedFieldsRecursive(orbitPayload);
  if (orbitPayloadReserved) {
    return typedFailure(requestHash, orbitPayloadReserved);
  }
  const orbitPayloadUnknown = rejectUnknownKeys(orbitPayload, ["tool_calls"]);
  if (orbitPayloadUnknown) {
    return typedFailure(requestHash, orbitPayloadUnknown);
  }
  const parsedOrbitToolCalls = parseToolCalls(orbitPayload.tool_calls);
  if (!parsedOrbitToolCalls.ok) {
    return typedFailure(requestHash, parsedOrbitToolCalls.reason_code);
  }

  const gpuCount = validateInteger(resources.gpu_count, 1, false);
  const hours = validateInteger(resources.hours, 1, false);
  const maxScaleMultiplier = validateInteger(execution.max_scale_multiplier, 1, false);
  const maxRetries = validateInteger(execution.max_retries, 0, true);
  const actualGpuCount = validateInteger(runtimeObservation.actual_gpu_count, 0, true);
  const actualHours = validateInteger(runtimeObservation.actual_hours, 0, true);
  const actualTotalCostCents = validateInteger(runtimeObservation.actual_total_cost_cents, 0, true);
  const maxTotalCostCents = validateInteger(policyRules.max_total_cost_cents, 1, false);
  const maxGpuCount = validateInteger(policyRules.max_gpu_count, 1, false);
  const maxHours = validateInteger(policyRules.max_hours, 1, false);
  const requireManualApprovalAboveCents = validateInteger(policyRules.require_manual_approval_above_cents, 0, true);
  const maxRetryCount = validateInteger(policyRules.max_retry_count, 0, true);
  const gpuHourCents = validateInteger(pricingData.gpu_hour_cents, 1, false);
  const numericChecks = [
    gpuCount,
    hours,
    maxScaleMultiplier,
    gpuHourCents,
    actualGpuCount,
    actualHours,
    actualTotalCostCents,
    maxTotalCostCents,
    maxGpuCount,
    maxHours,
    requireManualApprovalAboveCents,
    maxRetryCount,
    maxRetries
  ];
  let firstNumericReason: string | null = null;
  for (const check of numericChecks) {
    if (!check.ok) {
      if (check.reason_code === REASON_CODES.InvalidJsonNumber) {
        return typedFailure(requestHash, check.reason_code);
      }
      firstNumericReason ??= check.reason_code;
    }
  }
  if (firstNumericReason) {
    return typedFailure(requestHash, firstNumericReason);
  }

  const autoScale = expectBoolean(execution.auto_scale);
  const retryOnFail = expectBoolean(execution.retry_on_fail);
  const alreadyConsumed = expectBoolean(releaseRequest.already_consumed);
  const killSwitchActive = expectBoolean(runtimeObservation.kill_switch_active);
  const allowAutoScale = expectBoolean(policyRules.allow_auto_scale);
  if (autoScale === null || retryOnFail === null || alreadyConsumed === null || killSwitchActive === null || allowAutoScale === null) {
    return typedFailure(requestHash, REASON_CODES.TypeMismatch);
  }

  if (policyVersion !== PINNED_POLICY_VERSION) {
    return typedFailure(requestHash, REASON_CODES.PolicyVersionMismatch);
  }

  if (policyDocument.trust !== undefined) {
    if (!isRecord(policyDocument.trust)) {
      return typedFailure(requestHash, REASON_CODES.InvalidPolicySignature);
    }
    const trustUnknown = rejectUnknownKeys(policyDocument.trust, ["key_version", "key_id", "public_key", "signature"]);
    if (trustUnknown) {
      return typedFailure(requestHash, trustUnknown);
    }
    const keyVersion = expectString(policyDocument.trust.key_version);
    const keyId = expectString(policyDocument.trust.key_id);
    const publicKey = expectString(policyDocument.trust.public_key);
    const signature = expectString(policyDocument.trust.signature);
    if (!keyVersion || !keyId || !publicKey || !signature) {
      return typedFailure(requestHash, REASON_CODES.InvalidPolicySignature);
    }
    const derived = deriveKeyId(publicKey);
    if (derived !== keyId) {
      return typedFailure(requestHash, REASON_CODES.PolicyKeyIdMismatch);
    }
    const payload = canonicalPolicyPayload({
      schema_version: policySchemaVersion,
      policy_version: policyVersion,
      rules: {
        max_total_cost_cents: maxTotalCostCents.value,
        allow_auto_scale: allowAutoScale,
        max_gpu_count: maxGpuCount.value,
        max_hours: maxHours.value,
        require_manual_approval_above_cents: requireManualApprovalAboveCents.value,
        max_retry_count: maxRetryCount.value
      }
    });
    try {
      if (keyVersion !== "ed25519.v1" || !verifyPolicySignature(publicKey, payload, signature)) {
        return typedFailure(requestHash, REASON_CODES.InvalidPolicySignature);
      }
    } catch {
      return typedFailure(requestHash, REASON_CODES.InvalidPolicySignature);
    }
  }

  const built: CanonicalExecutionInput = {
    execution_request: {
      request_id: requestId,
      submitted_region: submittedRegion,
      actor: {
        user_id: userId
      },
      resources: {
        gpu_type: gpuType,
        gpu_count: gpuCount.value,
        hours: hours.value
      },
      execution: {
        auto_scale: autoScale,
        max_scale_multiplier: maxScaleMultiplier.value,
        retry_on_fail: retryOnFail,
        max_retries: maxRetries.value
      },
      tool_calls: parsedToolCalls.value,
      ...(parameters.value === undefined ? {} : { parameters: parameters.value }),
      orbit_intent: {
        orbit_version: orbitVersion,
        action: orbitAction,
        boundary: orbitBoundary,
        payload: {
          tool_calls: parsedOrbitToolCalls.value
        },
        lifecycle_state: lifecycleState,
        signatures: parsedSignatures
      },
      release_request: {
        execution_id: executionId,
        hold_state: holdState as CanonicalExecutionInput["execution_request"]["release_request"]["hold_state"],
        already_consumed: alreadyConsumed
      },
      runtime_observation: {
        kill_switch_active: killSwitchActive,
        actual_gpu_count: actualGpuCount.value,
        actual_hours: actualHours.value,
        actual_total_cost_cents: actualTotalCostCents.value
      },
      ...(budgetToken === undefined ? {} : { budget_token: budgetToken })
    },
    policy_document: {
      schema_version: policySchemaVersion as CanonicalExecutionInput["policy_document"]["schema_version"],
      policy_version: policyVersion,
      ...(policyDocument.trust === undefined
        ? {}
        : {
            trust: {
              key_version: policyDocument.trust.key_version as "ed25519.v1",
              key_id: policyDocument.trust.key_id as string,
              public_key: policyDocument.trust.public_key as string,
              signature: policyDocument.trust.signature as string
            }
          }),
      rules: {
        max_total_cost_cents: maxTotalCostCents.value,
        allow_auto_scale: allowAutoScale,
        max_gpu_count: maxGpuCount.value,
        max_hours: maxHours.value,
        require_manual_approval_above_cents: requireManualApprovalAboveCents.value,
        max_retry_count: maxRetryCount.value
      }
    },
    pricing_data: {
      gpu_hour_cents: gpuHourCents.value
    }
  };

  return {
    raw_input: rawInput,
    canonical_input: canonicalInput,
    request_hash: requestHash,
    policy_hash: policyHash(built.policy_document),
    parsed_input: built
  };
}
