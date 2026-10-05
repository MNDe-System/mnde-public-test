// Production posture pre-flight (fail-closed).
//
// The trust-root pre-flight (src/authority-signing/preflight.mjs) guarantees a
// real production *signing* root in MNDE_PROFILE=production. This pre-flight
// closes the complementary gap it does not cover: in production the decision
// endpoint must ALSO require caller authentication AND run an enforced
// (signed-bundle) policy engine. Without it, a production profile can boot with
// caller auth off (MNDE_SIDECAR_AUTH unset) and the legacy engine (no signed
// policy enforcement), then deny or under-enforce silently at request time.
//
// Pure config inspection; no side effects. MNDE_PROFILE is read through the
// canonical parser so a missing/unknown value never silently implies production.

import { parseRuntimeProfile } from "../shared/runtime-profile.mjs";
import { isPolicyEnforcementEnabled } from "../shared/decision-engine.mjs";
import { loadAuthConfig } from "./sidecar-auth/index.mjs";

export const ERR_PRODUCTION_CALLER_AUTH_REQUIRED = "ERR_PRODUCTION_CALLER_AUTH_REQUIRED";
export const ERR_PRODUCTION_POLICY_ENFORCEMENT_REQUIRED = "ERR_PRODUCTION_POLICY_ENFORCEMENT_REQUIRED";

// Evaluate the two production requirements against an env. Returns
// { ok, violations: [{ reason_code, detail }] }. Does NOT consider MNDE_PROFILE —
// it answers "are these settings acceptable for production?" so the checks are
// testable independently of the deployment signal.
export async function evaluateProductionPosture(env) {
  const violations = [];

  // 1. Caller authentication must be enabled AND validly configured.
  const auth = loadAuthConfig(env);
  if (auth.mode !== "bearer") {
    violations.push({
      reason_code: ERR_PRODUCTION_CALLER_AUTH_REQUIRED,
      detail: "MNDE_PROFILE=production requires caller authentication: set MNDE_SIDECAR_AUTH=bearer with MNDE_SIDECAR_AUTH_TOKENS (or MNDE_SIDECAR_AUTH_TOKENS_FILE)"
    });
  } else if (!auth.ok) {
    violations.push({
      reason_code: ERR_PRODUCTION_CALLER_AUTH_REQUIRED,
      detail: `MNDE_SIDECAR_AUTH=bearer is enabled but misconfigured: ${auth.reason}`
    });
  }

  // 2. Policy enforcement must be enabled AND validly configured. We assert the
  //    security outcome ("is an enforced policy engine selected?") via the
  //    canonical decision-engine abstraction, NOT a specific engine name, so a
  //    future enforcement backend is covered without revisiting this gate. Once
  //    enabled, the engine's own production config check (signed bundle) must
  //    pass too, so a broken bundle refuses boot rather than deferring to
  //    per-request denial.
  if (!isPolicyEnforcementEnabled(env)) {
    violations.push({
      reason_code: ERR_PRODUCTION_POLICY_ENFORCEMENT_REQUIRED,
      detail: "MNDE_PROFILE=production requires an enforced policy engine: set MNDE_DECISION_ENGINE=policy-engine with a signed policy bundle (MNDE_PE_POLICY_BUNDLE)"
    });
  } else {
    let pe;
    try {
      const { loadPolicyEngineConfig } = await import("./policy-engine/sidecar-adapter.mjs");
      pe = await loadPolicyEngineConfig(env);
    } catch (error) {
      pe = { ok: false, reason: error instanceof Error ? error.message : String(error) };
    }
    if (!pe.ok) {
      violations.push({
        reason_code: ERR_PRODUCTION_POLICY_ENFORCEMENT_REQUIRED,
        detail: `MNDE_DECISION_ENGINE=policy-engine is selected but its production configuration is invalid: ${pe.reason}`
      });
    }
  }

  return { ok: violations.length === 0, violations };
}

// Pre-flight entry. No-op outside an explicit production profile (a missing or
// unknown MNDE_PROFILE never implies production — the canonical parser handles
// unknown values, and only normalized "production" enforces here). In production,
// returns the first violation so the caller can refuse boot fail-closed.
export async function assertProductionPosture(env) {
  const profile = parseRuntimeProfile(env.MNDE_PROFILE);
  if (!profile.ok || profile.profile !== "production") {
    return { ok: true, profile: profile.profile, enforced: false };
  }
  const result = await evaluateProductionPosture(env);
  if (!result.ok) {
    const first = result.violations[0];
    return { ok: false, profile: "production", enforced: true, reason_code: first.reason_code, detail: first.detail, violations: result.violations };
  }
  return { ok: true, profile: "production", enforced: true };
}
