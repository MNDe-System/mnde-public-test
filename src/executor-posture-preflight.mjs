// Executor production posture pre-flight (fail-closed).
//
// The sidecar has had a production gate for some time: src/authority-signing/preflight.mjs
// refuses to start on dev/demo signing material, and src/production-posture-preflight.mjs
// refuses to start without caller authentication and an enforced signed-bundle
// policy engine. This file is the missing half — the same discipline applied to
// the side that CONSUMES receipts rather than the side that produces them.
//
// Why it is needed. Every verification input the executor takes is optional and
// unset by default: the authority bundle, the pinned root fingerprint, the
// environment id, the expected executor id. Left at defaults, receipt
// verification falls back to the authority bundle that ships inside the package
// and reports REPO_LOCAL_TRUST_SOURCE. That is a real signature check against a
// root nobody chose, and it resolves in an installed package, not only in a
// source checkout. So a production deployment could run with the producer side
// correctly refusing demo key material while the consumer side quietly accepted
// receipts signed by it. Nothing said so, because nothing asked.
//
// What it does NOT do. It does not enable execution, relax anything, or change
// how a receipt is verified. It answers one question at construction time — are
// these settings acceptable for production? — and refuses the executor if they
// are not. Outside an explicit production profile it is inert, so development
// and test behaviour is untouched.
//
// Pure config inspection; no side effects. MNDE_PROFILE is read through the
// canonical parser so a missing or unknown value never silently implies production.

import { parseRuntimeProfile } from "../shared/runtime-profile.mjs";
import { isDevKeyMaterialPath } from "./authority-signing/preflight.mjs";

export const ERR_EXECUTOR_PRODUCTION_TRUST_ROOT_REQUIRED = "ERR_EXECUTOR_PRODUCTION_TRUST_ROOT_REQUIRED";
export const ERR_EXECUTOR_PRODUCTION_DEMO_TRUST_ROOT = "ERR_EXECUTOR_PRODUCTION_DEMO_TRUST_ROOT";
export const ERR_EXECUTOR_PRODUCTION_EXECUTOR_BINDING_REQUIRED = "ERR_EXECUTOR_PRODUCTION_EXECUTOR_BINDING_REQUIRED";

function isConfigured(value) {
  return typeof value === "string" && value.trim().length > 0;
}

// Evaluate the production requirements against resolved executor settings.
// Returns { ok, violations: [{ reason_code, detail }] }. Does NOT consider
// MNDE_PROFILE — it answers "are these settings acceptable for production?", so
// the checks stay testable independently of the deployment signal.
//
// `settings` are the values createMndeExecutor has already resolved from config
// and env, plus `repoRoot`, the directory the receipt verifier would search for
// a repo-local authority bundle.
export function evaluateExecutorPosture(settings = {}) {
  const violations = [];
  const {
    verifyAuthorityBundlePath,
    verifyAuthorityBundleLoaded,
    verifyTrustedRootFingerprint,
    verifyEnvironmentId,
    verifyExpectedExecutorId,
    verifyRequireExecutor,
    repoRoot
  } = settings;

  // 1. A trust root the operator chose. Both halves are required and neither
  //    substitutes for the other: the bundle carries the keys, and the
  //    fingerprint is what proves the bundle is the one that was meant. A bundle
  //    accepted without a pinned root is a bundle whose host decides who signs.
  if (!isConfigured(verifyAuthorityBundlePath)) {
    violations.push({
      reason_code: ERR_EXECUTOR_PRODUCTION_TRUST_ROOT_REQUIRED,
      detail: "MNDE_PROFILE=production requires an explicitly configured authority bundle: set MNDE_VERIFY_AUTHORITY_BUNDLE (or pass verifyAuthorityBundle). Without it receipt verification falls back to the authority bundle shipped in the package."
    });
  } else if (verifyAuthorityBundleLoaded === false) {
    // Configured but unreadable or not JSON. loadVerifyBundle swallows that and
    // returns undefined, which would otherwise look exactly like "unset" and
    // drop the deployment onto the fallback it thought it had replaced.
    violations.push({
      reason_code: ERR_EXECUTOR_PRODUCTION_TRUST_ROOT_REQUIRED,
      detail: `MNDE_VERIFY_AUTHORITY_BUNDLE is set to ${JSON.stringify(verifyAuthorityBundlePath)} but could not be read as JSON. A trust root that failed to load is not a trust root.`
    });
  } else if (isDevKeyMaterialPath(verifyAuthorityBundlePath, repoRoot)) {
    // The demo bundle ships inside the package, so pointing at it is an easy
    // accident rather than an exotic one.
    violations.push({
      reason_code: ERR_EXECUTOR_PRODUCTION_DEMO_TRUST_ROOT,
      detail: `MNDE_VERIFY_AUTHORITY_BUNDLE points at development/demo key material (${verifyAuthorityBundlePath}). Production must verify against a published authority bundle whose root fingerprint was obtained out of band.`
    });
  }

  if (!isConfigured(verifyTrustedRootFingerprint)) {
    violations.push({
      reason_code: ERR_EXECUTOR_PRODUCTION_TRUST_ROOT_REQUIRED,
      detail: "MNDE_PROFILE=production requires the pinned trust root: set MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT (or pass verifyTrustedRootFingerprint) to the sha256 of the root public key, obtained independently of the bundle host."
    });
  }

  // 2. The receipt must be bound to THIS executor. Without an expected executor
  //    id the executor accepts authority-only receipts, which say an action was
  //    authorized but not that it was authorized for the process holding them.
  //    The environment id belongs with it: an executor-bound (v2) receipt cannot
  //    be verified offline without it, so requiring one without the other buys a
  //    refusal rather than a check.
  if (verifyRequireExecutor !== true || !isConfigured(verifyExpectedExecutorId)) {
    violations.push({
      reason_code: ERR_EXECUTOR_PRODUCTION_EXECUTOR_BINDING_REQUIRED,
      detail: "MNDE_PROFILE=production requires executor-bound receipts: set MNDE_VERIFY_EXPECTED_EXECUTOR_ID (or pass verifyExpectedExecutorId) so a receipt that is not bound to this executor is refused."
    });
  }
  if (!isConfigured(verifyEnvironmentId)) {
    violations.push({
      reason_code: ERR_EXECUTOR_PRODUCTION_EXECUTOR_BINDING_REQUIRED,
      detail: "MNDE_PROFILE=production requires the executor environment id: set MNDE_VERIFY_ENVIRONMENT_ID (or pass verifyEnvironmentId) so executor-bound receipts can be verified offline."
    });
  }

  return { ok: violations.length === 0, violations };
}

// Pre-flight entry. No-op outside an explicit production profile: a missing or
// unknown MNDE_PROFILE never implies production, exactly as the sidecar's own
// pre-flight treats it, so every existing local and test caller is unaffected.
// In production, returns the first violation so the caller can refuse fail-closed.
export function assertExecutorPosture(settings = {}, env = process.env) {
  const profile = parseRuntimeProfile(env.MNDE_PROFILE);
  if (!profile.ok || profile.profile !== "production") {
    return { ok: true, profile: profile.profile, enforced: false };
  }
  const result = evaluateExecutorPosture(settings);
  if (!result.ok) {
    const first = result.violations[0];
    return { ok: false, profile: "production", enforced: true, reason_code: first.reason_code, detail: first.detail, violations: result.violations };
  }
  return { ok: true, profile: "production", enforced: true };
}
