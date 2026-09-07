// Sidecar adapter for the policy engine (opt-in decision path).
//
// Loaded by the sidecar ONLY when MNDE_DECISION_ENGINE=policy-engine. Maps an
// incoming decision request to a policy-engine request, evaluates it against the
// sidecar-configured policy, and returns a signed policy-engine receipt.
//
// Trust anchors come ONLY from sidecar configuration (env/flag/file) — NEVER from
// the request body. Signed artifacts (authority grants, approvals) may be attached
// to the request; the keys that vouch for them come from config.

import { readFileSync } from "node:fs";

import { buildPolicyReceipt } from "./receipt.mjs";
import { loadSignedPolicyBundleConfig } from "../policy-bundles/index.mjs";
import { parseRuntimeProfile } from "../../shared/runtime-profile.mjs";
import { DEFAULT_DENY_POLICY, POLICY_CONFIGURATION_STATE_NO_POLICY, POLICY_SOURCE_BUILTIN } from "./default-deny.mjs";

function loadJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function loadOptionalTrustConfig(env) {
  let trustAnchors;
  if (env.MNDE_PE_TRUST_ANCHORS) {
    try {
      trustAnchors = loadJson(env.MNDE_PE_TRUST_ANCHORS);
    } catch (error) {
      return { ok: false, reason: `trust anchors load failed: ${error?.message ?? String(error)}` };
    }
  }
  let approvalTrustAnchors;
  if (env.MNDE_PE_APPROVAL_TRUST_ANCHORS) {
    try {
      approvalTrustAnchors = loadJson(env.MNDE_PE_APPROVAL_TRUST_ANCHORS);
    } catch (error) {
      return { ok: false, reason: `approval trust anchors load failed: ${error?.message ?? String(error)}` };
    }
  }
  return { ok: true, trustAnchors, approvalTrustAnchors };
}

// Load decision-engine config. Fails closed (ok:false) on any malformed/missing
// configured file, so the sidecar can refuse rather than silently run unprotected.
export async function loadPolicyEngineConfig(env) {
  const profileResult = parseRuntimeProfile(env.MNDE_PROFILE);
  if (!profileResult.ok) return { ok: false, reason: profileResult.detail };
  const production = profileResult.profile === "production";
  // Signed bundles are opt-in. The legacy MNDE_PE_POLICY path stays unchanged
  // unless an operator explicitly supplies a bundle path.
  if (env.MNDE_PE_POLICY_BUNDLE) {
    const signed = await loadSignedPolicyBundleConfig(env);
    if (!signed.ok) return signed;
    const trustConfig = loadOptionalTrustConfig(env);
    if (!trustConfig.ok) return trustConfig;
    return {
      ok: true,
      production,
      policy: signed.policy,
      signedPolicyBundle: signed.signedPolicyBundle,
      policyBundleProvenance: signed.policyBundleProvenance,
      trustAnchors: trustConfig.trustAnchors,
      approvalTrustAnchors: trustConfig.approvalTrustAnchors
    };
  }
  if (production) return { ok: false, reason: "ERR_PE_PRODUCTION_REQUIRES_SIGNED_POLICY_BUNDLE" };
  const policyPath = env.MNDE_PE_POLICY;
  if (!policyPath) {
    // Non-production with no configured policy: evaluate the built-in default-deny
    // system policy (a real, evaluable policy → deterministic REFUSE) instead of
    // failing closed unservably. The sidecar stays operational (boot/health/receipts)
    // and refuses every action until a real policy is installed. NO_POLICY_CONFIGURED
    // is surfaced operationally, never in the receipt.
    const trustConfig = loadOptionalTrustConfig(env);
    if (!trustConfig.ok) return trustConfig;
    return {
      ok: true,
      production,
      policy: DEFAULT_DENY_POLICY,
      policy_source: POLICY_SOURCE_BUILTIN,
      policy_configuration_state: POLICY_CONFIGURATION_STATE_NO_POLICY,
      trustAnchors: trustConfig.trustAnchors,
      approvalTrustAnchors: trustConfig.approvalTrustAnchors
    };
  }
  let policy;
  try {
    policy = loadJson(policyPath);
  } catch (error) {
    return { ok: false, reason: `policy load failed: ${error?.message ?? String(error)}` };
  }
  const trustConfig = loadOptionalTrustConfig(env);
  if (!trustConfig.ok) return trustConfig;
  return { ok: true, production, policy, trustAnchors: trustConfig.trustAnchors, approvalTrustAnchors: trustConfig.approvalTrustAnchors };
}

// Accept either a native policy-engine request or the legacy decision envelope.
export function toPolicyEngineRequest(body, now) {
  if (body && body.schema_version === "1.0" && body.tool && typeof body.tool.tool_name === "string") {
    return { ...body, timestamp: typeof body.timestamp === "string" ? body.timestamp : now };
  }
  const er = body?.execution_request ?? {};
  const toolCall = Array.isArray(er.tool_calls) ? er.tool_calls[0] : undefined;
  return {
    schema_version: "1.0",
    request_id: typeof er.request_id === "string" ? er.request_id : (typeof body?.request_id === "string" ? body.request_id : "request"),
    timestamp: now,
    principal: { id: typeof er?.actor?.user_id === "string" ? er.actor.user_id : "unknown" },
    agent: { id: typeof er?.orbit_intent?.boundary === "string" ? er.orbit_intent.boundary : (typeof er?.actor?.user_id === "string" ? er.actor.user_id : "agent") },
    tool: { tool_name: typeof toolCall?.tool === "string" ? toolCall.tool : "unknown" },
    parameters: toolCall && typeof toolCall.parameters === "object" && toolCall.parameters !== null ? toolCall.parameters : {},
    environment: { region: typeof er?.submitted_region === "string" ? er.submitted_region : "unknown" },
    // Containment evidence is supplied by the enforcing executor, included in
    // the canonical request, and checked again by that executor against the
    // signed receipt. A direct caller can submit arbitrary metadata here, but it
    // gains no execution authority because strict executors require an exact
    // match to their operator-owned manifest snapshot.
    context: er?.mnde_containment && typeof er.mnde_containment === "object" && !Array.isArray(er.mnde_containment)
      ? { mnde_containment: er.mnde_containment }
      : {}
  };
}

export function decidePolicyEngine(body, config, options = {}) {
  const now = options.now ?? new Date().toISOString();
  const request = toPolicyEngineRequest(body, now);
  // When the caller is authenticated, the principal comes from the verified
  // token identity — never from the request body.
  if (options.caller && typeof options.caller.id === "string") {
    request.principal = { ...(request.principal ?? {}), id: options.caller.id };
  }
  // Signed artifacts attached to the request. Anchors are config-only (above).
  const authorities = Array.isArray(body?.mnde_authorities) ? body.mnde_authorities : (Array.isArray(body?.authorities) ? body.authorities : []);
  const approvals = Array.isArray(body?.mnde_approvals) ? body.mnde_approvals : (Array.isArray(body?.approvals) ? body.approvals : []);
  const receipt = buildPolicyReceipt(request, config.policy, {
    authorities,
    trustAnchors: config.trustAnchors,
    rejectLegacyAuthorities: config.production,
    approvals,
    approvalTrustAnchors: config.approvalTrustAnchors,
    policyBundleProvenance: config.policyBundleProvenance,
    // The same authenticated caller used to set request.principal.id above is
    // forwarded so scope-bound (mnde.authority_grant.v1) grants can bind their
    // `principal` field against it — never against the request body directly.
    caller: options.caller,
    now
  });
  return {
    decision: receipt.decision_output.decision,
    reason_code: receipt.decision_output.reason_code,
    receipt
  };
}
