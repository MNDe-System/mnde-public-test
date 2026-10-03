// Built-in default-deny system policy.
//
// When the policy engine is the active decision engine (the v1 default) but no
// operator policy is configured, the sidecar evaluates THIS policy rather than
// taking a special "no policy" code path. It is an ordinary, evaluable policy
// with zero rules, so the engine matches no ALLOW rule and returns a normal
// REFUSE (reason_code NO_MATCHING_RULE) wrapped in a normal mnde.pe.receipt.v1
// that replays and verifies offline exactly like any other receipt.
//
// The fact "no policy is configured" is DEPLOYMENT state, not a decision fact:
// it is surfaced through the API response, startup logs, and health — never
// written into the signed receipt. The receipt records what the engine decided
// (NO_MATCHING_RULE) and which policy decided it (mnde.system.default_deny.v1).

export const DEFAULT_DENY_POLICY_ID = "mnde.system.default_deny.v1";

export const DEFAULT_DENY_POLICY = Object.freeze({
  schema_version: "1.0",
  policy_id: DEFAULT_DENY_POLICY_ID,
  version: "1.0.0",
  state: "ACTIVE",
  rules: []
});

// Deployment-state label surfaced operationally (API/logs/health), never in the receipt.
export const POLICY_CONFIGURATION_STATE_NO_POLICY = "NO_POLICY_CONFIGURED";
export const POLICY_SOURCE_BUILTIN = "BUILTIN";
