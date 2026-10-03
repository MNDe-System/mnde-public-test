export type DecisionState = "ALLOW" | "REFUSE" | "HOLD";

export type OrbitIntent = {
  orbit_version: string;
  action: string;
  boundary: string;
  payload: Record<string, unknown>;
  lifecycle_state: string;
  signatures: Array<{
    alg: string;
    sig: string;
  }>;
  ext?: Record<string, unknown>;
};

export type RequestObject = {
  schema_version: "mnde.request.v1";
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
  pricing: {
    gpu_hour_usd: number;
  };
  execution: {
    auto_scale: boolean;
    max_scale_multiplier: number;
    retry_on_fail: boolean;
    max_retries: number;
  };
  orbit_intent: OrbitIntent;
  release_request: {
    execution_id: string;
    hold_state: "NONE" | "PENDING" | "APPROVED";
    already_consumed: boolean;
  };
  runtime_request: {
    kill_switch_active: boolean;
    observed_request_hash: string;
    observed_policy_hash: string;
    actual_gpu_count: number;
    actual_hours: number;
    actual_total_cost_usd: number;
  };
};

export type PolicyObject = {
  schema_version: "mnde.policy.v1";
  policy_version: string;
  allowed_request_keys: string[];
  rules: {
    max_total_cost_usd: number;
    allow_auto_scale: boolean;
    max_gpu_count: number;
    max_hours: number;
    require_manual_approval_above_usd: number;
  };
  trust: {
    key_version: "ed25519.v1";
    key_id: string;
    signing_public_key: string;
    signature: string;
  };
};

export type DecisionObject = {
  schema_version: "mnde.decision.v1";
  decision: DecisionState;
  reasons: string[];
  request_hash: string;
  policy_hash: string;
  decision_hash: string;
  validation_hash: string;
  projected_total_cost_usd: number;
  allowed_cost_usd: number;
  prevented_cost_usd: number;
  policy_version: string;
  release_hash?: string;
  runtime_hash?: string;
};
