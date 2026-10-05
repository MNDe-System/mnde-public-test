// Canonical decision-engine signal.
//
// Single source of truth for "which decision engine is selected" and, more
// importantly, for the security property "is policy enforcement enabled". The
// production posture gate must express that *outcome*, not match a specific
// engine name — so when a future enforcement backend is added (e.g. a next-gen
// or enterprise engine), it is registered here ONCE and every caller (the
// sidecar's engine selection and the production gate) follows automatically.
//
// "legacy" is the non-enforced default pipeline; it is intentionally NOT in the
// enforcement set.

// Engines that constitute an enforced policy decision path. Add future
// enforcement backends here — this is the only place that should change.
export const POLICY_ENFORCEMENT_ENGINES = new Set(["policy-engine"]);

// v1 canonical default. The general policy engine is the authority path; the
// legacy GPU/compute pipeline is an explicit opt-in compatibility profile.
export const DEFAULT_ENGINE = "policy-engine";
export const LEGACY_ENGINE = "legacy";
export const KNOWN_ENGINES = new Set(["policy-engine", "legacy"]);

// Resolve MNDE_DECISION_ENGINE to a known engine.
//   unset / empty            -> DEFAULT_ENGINE ("policy-engine")
//   "policy-engine" / "legacy" -> itself
//   any other value          -> null  (the caller MUST fail closed; never silently
//                                       pick an engine for an unrecognized value)
export function resolveDecisionEngine(env = process.env) {
  const raw = env.MNDE_DECISION_ENGINE;
  if (raw === undefined || raw === null || String(raw).trim() === "") return DEFAULT_ENGINE;
  return KNOWN_ENGINES.has(raw) ? raw : null;
}

// The security property the production gate cares about: is an enforced policy
// engine selected? Independent of which specific enforcement engine it is.
export function isPolicyEnforcementEnabled(env = process.env) {
  return POLICY_ENFORCEMENT_ENGINES.has(env.MNDE_DECISION_ENGINE);
}
