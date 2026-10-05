import type { JsonValue } from "./json.ts";

export const REASON_CODES = {
  SchemaValidation: "ERR_SCHEMA_VALIDATION",
  DuplicateJsonKeys: "ERR_DUPLICATE_JSON_KEYS",
  InvalidJsonSyntax: "ERR_INVALID_JSON_SYNTAX",
  InvalidJsonNumber: "ERR_INVALID_JSON_NUMBER",
  TypeMismatch: "ERR_TYPE_MISMATCH",
  NonDeterministicInput: "ERR_NON_DETERMINISTIC_INPUT",
  PolicyVersionMismatch: "ERR_POLICY_VERSION_MISMATCH",
  PolicyKeyIdMismatch: "ERR_POLICY_KEY_ID_MISMATCH",
  InvalidPolicySignature: "ERR_INVALID_POLICY_SIGNATURE",
  ToolCallSequence: "ERR_TOOL_CALL_SEQUENCE",
  OrbitMultipleActions: "ERR_ORBIT_MULTIPLE_ACTIONS",
  ForbiddenActionInParameters: "ERR_FORBIDDEN_ACTION_IN_PARAMETERS",
  ExecutionIdAlreadyConsumed: "ERR_EXECUTION_ID_ALREADY_CONSUMED",
  ExecutionIdReplayed: "ERR_EXECUTION_ID_REPLAYED",
  BudgetTokenExhausted: "ERR_BUDGET_TOKEN_EXHAUSTED",
  IntegerOverflow: "ERR_INTEGER_OVERFLOW",
  CostLimit: "ERR_COST_LIMIT",
  AutoScaleDenied: "ERR_AUTO_SCALE_DENIED",
  GpuLimit: "ERR_GPU_LIMIT",
  HoursLimit: "ERR_HOURS_LIMIT",
  RetryLimit: "ERR_RETRY_LIMIT",
  ManualApprovalRequired: "ERR_MANUAL_APPROVAL_REQUIRED",
  KillSwitch: "ERR_KILL_SWITCH",
  RuntimeGpuDrift: "ERR_RUNTIME_GPU_DRIFT",
  RuntimeHoursDrift: "ERR_RUNTIME_HOURS_DRIFT",
  RuntimeCostDrift: "ERR_RUNTIME_COST_DRIFT",
  ReceiptSignatureInvalid: "ERR_RECEIPT_SIGNATURE_INVALID",
  ReplayMismatch: "ERR_REPLAY_MISMATCH",
  OkAllow: "OK_ALLOW",
  OkOrbit: "OK_ORBIT",
  OkArm: "OK_ARM",
  OkRamona: "OK_RAM0NA"
} as const;

export type ReasonCode = (typeof REASON_CODES)[keyof typeof REASON_CODES];
export type Decision = "ALLOW" | "REFUSE";

export type ToolCall = {
  tool: string;
  priority: number;
  parameters?: ParameterObject;
};

export type ParameterObject = Record<string, JsonValue>;

export type CanonicalExecutionInput = {
  execution_request: {
    request_id: string;
    submitted_region: string;
    actor: {
      user_id: string;
    };
    resources: {
      gpu_type: string;
      gpu_count: number;
      hours: number;
    };
    execution: {
      auto_scale: boolean;
      max_scale_multiplier: number;
      retry_on_fail: boolean;
      max_retries: number;
    };
    tool_calls: ToolCall[];
    parameters?: ParameterObject;
    orbit_intent: {
      orbit_version: string;
      action: string;
      boundary: string;
      payload: {
        tool_calls: ToolCall[];
      };
      lifecycle_state: string;
      signatures: Array<{
        alg: string;
        sig: string;
      }>;
    };
    release_request: {
      execution_id: string;
      hold_state: "NONE" | "PENDING" | "APPROVED";
      already_consumed: boolean;
    };
    runtime_observation: {
      kill_switch_active: boolean;
      actual_gpu_count: number;
      actual_hours: number;
      actual_total_cost_cents: number;
    };
    budget_token?: string;
  };
  policy_document: {
    schema_version: "ecs.policy.v1";
    policy_version: string;
    trust?: {
      key_version: "ed25519.v1";
      key_id: string;
      public_key: string;
      signature: string;
    };
    rules: {
      max_total_cost_cents: number;
      allow_auto_scale: boolean;
      max_gpu_count: number;
      max_hours: number;
      require_manual_approval_above_cents: number;
      max_retry_count: number;
    };
  };
  pricing_data: {
    gpu_hour_cents: number;
  };
};

export type ParsedEnvelope = {
  raw_input: string;
  canonical_input: string;
  request_hash: string;
  parsed_input: CanonicalExecutionInput;
  policy_hash: string;
};

export type TypedFailure = {
  decision: "REFUSE";
  request_hash: string;
  decision_hash: string;
  reason_code: ReasonCode;
  parse_boundary: true;
};

export type PreflightTrace = {
  layer: "preflight";
  request_hash: string;
  policy_hash: string;
  policy_version: string;
};

export type OrbitTrace = {
  layer: "orbit";
  decision: Decision;
  reason_code: ReasonCode;
  validation_hash: string;
};

export type ArmTrace = {
  layer: "arm";
  decision: Decision;
  reason_code: ReasonCode;
  projected_total_cost_cents: number;
  allowed_cost_cents: number;
  prevented_cost_cents: number;
  execution_id: string;
  budget_token?: string;
};

export type RamonaTrace = {
  layer: "ramona";
  decision: Decision;
  reason_code: ReasonCode;
  runtime_hash: string;
};

export type DecisionOutput = {
  decision: Decision;
  decision_hash: string;
  request_hash: string;
  reason_code: ReasonCode;
  total_cost_usd: string;
  allowed_cost_usd: string;
  prevented_cost_usd: string;
  policy_version: string;
  policy_hash: string;
  execution_id: string;
  key_set_version: string;
};

// ─────────────────────────────────────────────────────────────────────────────
// LEGACY (v1 status: verify-only, feature-frozen).
//
// `ecs.receipt.v2` is the legacy GPU/compute-pipeline receipt. It is emitted ONLY
// under the explicit `MNDE_DECISION_ENGINE=legacy` compatibility profile. It is
// frozen: no new fields or features are added. It remains fully verifiable
// (tools/verify.mjs → kind "pipeline") so historical receipts keep verifying.
//
// The CANONICAL v1 receipt is `mnde.pe.receipt.v1` (src/policy-engine/receipt.mjs),
// optionally wrapped in the `mnde.signed-receipt.v1` custody envelope. New
// development targets those. See docs/receipt-formats.md for the lifecycle table.
// ─────────────────────────────────────────────────────────────────────────────
export type SignedReceiptPayload = {
  schema_version: "ecs.receipt.v2";
  canonical_request: string;
  request_hash: string;
  decision_output: DecisionOutput;
  pipeline_trace: {
    preflight: PreflightTrace;
    orbit: OrbitTrace;
    arm: ArmTrace;
    ramona: RamonaTrace;
  };
};

export type SignedReceipt = SignedReceiptPayload & {
  signature: {
    algorithm: "HMAC-SHA256";
    key_id: string;
    value: string;
  };
  verifiable_signature: {
    algorithm: "ED25519";
    authority_id: string;
    key_id: string;
    public_key_fingerprint: string;
    signed_at: string;
    value: string;
  };
};

export type ExecutionResult = {
  receipt: SignedReceipt;
  receipt_bytes: string;
};
