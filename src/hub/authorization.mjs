import { readFileSync } from "node:fs";
import { loadPolicyEngineConfig } from "../policy-engine/sidecar-adapter.mjs";
import { buildPolicyReceiptPayload } from "../policy-engine/receipt.mjs";
import { loadSigningConfig, signReceiptForDelivery, LIVE_RECEIPT_SIGNING_MODES } from "../authority-signing/index.mjs";
import { signPolicyPayload } from "../authority-signing/policy-payload.mjs";
import { verifyAnyReceiptObject } from "../../tools/verify.mjs";
import { verifyExecutionAuthority } from "../execution-authority/index.mjs";
import { verifyExecutorCredential } from "../custody/executor-credential.mjs";
import { verifyAuthorityBundle } from "../custody/bundle.mjs";
import { sha256 } from "../crypto/provider.mjs";

export async function openHubAuthorization(env, startup) {
  const config = await loadPolicyEngineConfig(env);
  if (!config.ok || !config.production || !config.signedPolicyBundle) throw new Error("ERR_HUB_POLICY");
  // Required even for policies without approvals: adding approval_required must
  // never silently become inert because an anchor file was omitted.
  if (!config.approvalTrustAnchors) throw new Error("ERR_HUB_APPROVAL_ANCHORS");
  const signing = await loadSigningConfig({ ...env, MNDE_RECEIPT_SIGNING_MODE: "custody", MNDE_KEY_CUSTODY: "file-backed-production" });
  if (!signing.ok || signing.provider.trustedRootFingerprint !== startup.trustedRootFingerprint) throw new Error("ERR_HUB_SIGNING");
  const verificationContext = {
    trustAnchors: config.trustAnchors,
    approvalTrustAnchors: config.approvalTrustAnchors,
    historicalPolicyBundle: JSON.parse(readFileSync(env.MNDE_PE_POLICY_BUNDLE, "utf8")),
    policyAuthorityBundle: JSON.parse(readFileSync(env.MNDE_PE_AUTHORITY_BUNDLE, "utf8")),
    policyTrustedRootFingerprint: env.MNDE_PE_TRUSTED_ROOT_FINGERPRINT
  };
  const verification = {
    ...verificationContext,
    authorityBundle: startup.authorityBundle,
    trustedRootFingerprint: startup.trustedRootFingerprint,
    environmentId: startup.environmentId,
    expectedExecutorId: startup.expectedExecutorId
  };
  const paths = ["MNDE_AUTHORITY_BUNDLE", "MNDE_RECEIPT_SIGNING_KEY", "MNDE_EXECUTOR_PRIVATE_KEY", "MNDE_EXECUTOR_CREDENTIAL",
    "MNDE_PE_POLICY_BUNDLE", "MNDE_PE_AUTHORITY_BUNDLE", "MNDE_PE_APPROVAL_TRUST_ANCHORS", "MNDE_PE_TRUST_ANCHORS"]
    .map(name => env[name]).filter(Boolean);
  const hashes = paths.map(path => sha256(readFileSync(path)));
  async function readiness() {
    try {
      if (paths.some((path, index) => sha256(readFileSync(path)) !== hashes[index])) return false;
      const now = new Date().toISOString();
      if (!(await verifyAuthorityBundle(startup.authorityBundle, { trustedRootFingerprint: startup.trustedRootFingerprint, now })).ok) return false;
      if (!(await verifyAuthorityBundle(verificationContext.policyAuthorityBundle, { trustedRootFingerprint: verificationContext.policyTrustedRootFingerprint, now })).ok) return false;
      if (!(await verifyExecutorCredential(startup.executorIdentity.credential, { ...verification, now, requiredCapability: "sign_execution_receipt" })).ok) return false;
      // Exercise the configured signers without generating an execution grant.
      await signing.provider.signReceipt("mnde-hub-readiness");
      await startup.executorSigner.sign("mnde-hub-readiness");
      return true;
    } catch { return false; }
  }
  async function decide(request, approvals = []) {
    if (!(await readiness())) throw new Error("ERR_HUB_SIGNING");
    const now = new Date().toISOString();
    if (Date.parse(request.expires_at) <= Date.now()) throw new Error("ERR_HUB_EXPIRED");
    const payload = buildPolicyReceiptPayload(request, config.policy, {
      now, executionStatus: null, caller: { id: request.principal.id },
      trustAnchors: config.trustAnchors, rejectLegacyAuthorities: true,
      approvalTrustAnchors: config.approvalTrustAnchors, approvals,
      policyBundleProvenance: config.policyBundleProvenance
    });
    const inner = await signPolicyPayload(payload, signing, startup.authorityBundle, now);
    const signed = await signReceiptForDelivery(inner, signing, {
      now, signingMode: LIVE_RECEIPT_SIGNING_MODES.EXECUTOR_AND_AUTHORITY,
      executorIdentity: startup.executorIdentity, executorSigner: startup.executorSigner
    });
    if (!signed.ok) throw new Error("ERR_HUB_SIGNING");
    const checked = await verifyAnyReceiptObject(signed.receipt, verification);
    if (!checked.verified) throw new Error("ERR_HUB_RECEIPT_VERIFY");
    const decision = payload.decision_output.decision;
    if (decision === "ALLOW" && !(await verifyExecutionAuthority(signed.receipt, verification)).ok) throw new Error("ERR_HUB_AUTHORITY");
    // REVIEW is an API workflow state; the authoritative receipt still says
    // REFUSE / APPROVAL_REQUIRED until the existing approval verifier permits it.
    return {
      decision: decision === "REFUSE" && payload.decision_output.reason_code === "APPROVAL_REQUIRED" ? "REVIEW" : decision,
      receipt: signed.receipt
    };
  }
  return Object.freeze({ decide, verificationContext, readiness });
}
