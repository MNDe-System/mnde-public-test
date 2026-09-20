// Policy Engine receipts.
//
// Wraps a deterministic policy-engine decision into a signed, offline-verifiable
// receipt on the SAME Ed25519 authority chain as every other MNDe receipt (same
// signing key, same authority manifest, same verification primitives). This is
// how the policy engine and the receipt/verification system are combined into a
// single trust surface: one key, one authority, one way to verify.
//
// Verification replays the decision by re-running the deterministic engine on the
// embedded request + policy + authorities, then checks the signature against the
// trusted authority manifest. A tampered request, policy, or decision fails closed.

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalizeJson, parseStrictJson } from "../../shared/json.ts";
import { RECEIPT_SIGNATURE_ALGORITHM, signReceiptPayload, verifyReceiptPayloadSignature } from "../../shared/index.ts";
import { findAuthorityReceiptKey, loadAuthorityBundle, loadAuthorityBundleForReceipt } from "../../shared/authority-manifest.mjs";
import { findBundleKey, fingerprintOf, verifyAuthorityBundle } from "../custody/index.mjs";
import { evaluatePolicyRequest } from "./index.mjs";
import { EXECUTION_STATUS_DISABLED, receiptExecutionStatus } from "../execution-availability/index.mjs";
import { verifyHistoricalPolicyBundleProvenance } from "../policy-bundles/index.mjs";

// Default: relative to this module's own install location (unchanged behavior
// for every source-checkout test/flow). MNDE_HOME overrides it so the packaged
// CLI reads/writes the authority manifest under the caller's own directory,
// never inside node_modules — same override convention as shared/receipt-signing.ts.
const repoRoot = process.env.MNDE_HOME
  ? resolve(process.env.MNDE_HOME)
  : resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SCHEMA = "mnde.pe.receipt.v1";
const SCHEMA_V2 = "mnde.pe.receipt.v2";

// Explicit receipt-schema -> decision-output-schema routing. Verification and
// minting both consult this map by exact schema string; nothing is ever inferred
// from field presence. A receipt schema with no entry here has no decision-shape
// contract and fails closed (unknown/future versions are rejected, never guessed).
//   mnde.pe.receipt.v1 -> decision "1.0" (frozen; no rule_id)
//   mnde.pe.receipt.v2 -> decision "2.0" (rule_id bound into decision_hash)
const RECEIPT_TO_DECISION_SCHEMA = new Map([
  [SCHEMA, "1.0"],
  [SCHEMA_V2, "2.0"]
]);

function canonicalPayloadWithoutSignature(receiptLike) {
  const { verifiable_signature: _omit, ...payload } = receiptLike;
  return canonicalizeJson(payload);
}

function isBundleProvenance(value, policyHash) {
  return value
    && typeof value === "object"
    && !Array.isArray(value)
    && typeof value.bundle_id === "string" && value.bundle_id.length > 0
    && Number.isSafeInteger(value.serial) && value.serial > 0
    && value.policy_hash === policyHash
    && typeof value.signer_key_id === "string" && value.signer_key_id.length > 0
    && value.activation_mode === "enforce"
    && (value.rollback_authorization_id === null || typeof value.rollback_authorization_id === "string");
}

async function verifyReceiptSignatureWithAuthorityBundle(receipt, signature, options = {}) {
  const hasExplicitAuthorityBundle = Object.hasOwn(options, "authorityBundle") && options.authorityBundle !== undefined;
  if (!hasExplicitAuthorityBundle) return null;
  const authorityBundle = options.authorityBundle;
  if (typeof options.trustedRootFingerprint !== "string" || options.trustedRootFingerprint.length === 0) {
    return { verified: false, reason: "MISSING_TRUSTED_ROOT" };
  }
  const authority = await verifyAuthorityBundle(authorityBundle, {
    trustedRootFingerprint: options.trustedRootFingerprint,
    now: options.now ?? signature.signed_at
  });
  if (!authority.ok) return { verified: false, reason: `authority bundle: ${authority.reason}` };
  if (authorityBundle.authority_id !== signature.authority_id) {
    return { verified: false, reason: "AUTHORITY_BUNDLE_MISMATCH" };
  }

  const keyResult = findBundleKey(authorityBundle, "receipt", signature.key_id, signature.signed_at);
  if (!keyResult.ok) return { verified: false, reason: keyResult.reason };
  if (signature.public_key_fingerprint !== fingerprintOf(keyResult.publicKey)) {
    return { verified: false, reason: "fingerprint mismatch" };
  }
  const ok = verifyReceiptPayloadSignature(canonicalPayloadWithoutSignature(receipt), signature.value, keyResult.publicKey);
  return ok
    ? { verified: true, reason: null, trust_source: "ROOT_PINNED_AUTHORITY_BUNDLE" }
    : { verified: false, reason: "signature invalid" };
}

// Build a signed receipt for a policy-engine decision.
export function buildPolicyReceipt(request, policy, options = {}) {
  // Default to the frozen v1 receipt format; v2 is opt-in via options.receiptSchema.
  const receiptSchema = options.receiptSchema ?? SCHEMA;
  const decisionSchemaVersion = RECEIPT_TO_DECISION_SCHEMA.get(receiptSchema);
  if (decisionSchemaVersion === undefined) throw new Error(`ERR_UNSUPPORTED_RECEIPT_SCHEMA: ${receiptSchema}`);
  const authorities = Array.isArray(options.authorities) ? options.authorities : [];
  const trustAnchors = options.trustAnchors;
  const approvalTrustAnchors = options.approvalTrustAnchors;
  const approvalEnforced = Boolean(approvalTrustAnchors);
  const approvals = Array.isArray(options.approvals) ? options.approvals : [];
  const decision = evaluatePolicyRequest(request, policy, {
    authorities,
    now: options.now,
    trustAnchors,
    rejectLegacyAuthorities: options.rejectLegacyAuthorities,
    approvals,
    approvalTrustAnchors,
    caller: options.caller,
    repoRoot: options.repoRoot,
    consumeAuthorityGrants: options.consumeAuthorityGrants,
    decisionSchemaVersion
  });
  const policyBundleProvenance = options.policyBundleProvenance;
  if (policyBundleProvenance !== undefined && !isBundleProvenance(policyBundleProvenance, decision.policy_hash)) {
    throw new Error("ERR_POLICY_BUNDLE_PROVENANCE_INVALID");
  }
  // Defaults to the deployment-wide state. An explicit option exists so tests can
  // build receipts for both postures; it cannot widen authority, because nothing
  // reads this field to decide whether to execute — the executor refuses on its
  // own state, not on anything carried in a receipt.
  // undefined = use the deployment-wide state (production always wants this).
  // null      = explicitly omit the field, i.e. build an execution-enabled receipt.
  const executionStatus = options.executionStatus === undefined
    ? receiptExecutionStatus()
    : options.executionStatus;
  if (executionStatus !== undefined && executionStatus !== null && executionStatus !== EXECUTION_STATUS_DISABLED) {
    throw new Error(`ERR_UNSUPPORTED_EXECUTION_STATUS: ${executionStatus}`);
  }

  const payload = {
    schema_version: receiptSchema,
    canonical_request: canonicalizeJson(request),
    canonical_policy: canonicalizeJson(policy),
    authorities,
    trust_enforced: Boolean(trustAnchors),
    // Embedded only when approval enforcement is active, so non-enforced receipts
    // are unchanged. Approval trust anchors are NOT embedded (verifier-supplied).
    ...(approvalEnforced ? { approval_enforced: true, approvals } : {}),
    request_hash: decision.request_hash,
    policy_hash: decision.policy_hash,
    authority_chain_hash: decision.authority_chain_hash,
    ...(policyBundleProvenance ? { policy_bundle_provenance: structuredClone(policyBundleProvenance) } : {}),
    // Execution availability at decision time. Embedded ONLY while protected
    // execution is unavailable, so receipts issued once dispatch is live are
    // byte-identical to historical ones and no conformance vector moves. It sits
    // inside `payload`, so it is covered by verifiable_signature and cannot be
    // stripped in transit without breaking the signature.
    //
    // Its meaning is narrow and important: this receipt records that policy
    // approved the request, AND that MNDe could not have executed it. An ALLOW
    // carrying execution_status:"DISABLED" is evidence of a decision, never an
    // execution grant. Absence of the field is not permission either — the
    // executor's strict gate is the enforcement point in both cases.
    ...(executionStatus ? { execution_status: executionStatus } : {}),
    decision_output: decision
  };

  const bundle = loadAuthorityBundle(repoRoot, { kind: "local" });
  if (!bundle.ok) throw new Error(`ERR_AUTHORITY_MANIFEST_INVALID: ${bundle.reason}`);
  const activeKey = bundle.manifest.active_keys?.[0];
  if (!activeKey) throw new Error("ERR_AUTHORITY_NO_ACTIVE_KEY");

  return {
    ...payload,
    verifiable_signature: {
      algorithm: RECEIPT_SIGNATURE_ALGORITHM,
      authority_id: bundle.manifest.authority_id,
      key_id: activeKey.key_id,
      public_key_fingerprint: activeKey.public_key_fingerprint,
      signed_at: new Date().toISOString(),
      value: signReceiptPayload(canonicalPayloadWithoutSignature(payload))
    }
  };
}

// Verify a policy-engine receipt: replay the decision and check the signature.
export async function verifyPolicyReceipt(receipt, options = {}) {
  // Explicit version routing. Only receipt schemas with a decision-shape contract
  // in RECEIPT_TO_DECISION_SCHEMA are accepted; any unknown or future version has
  // no mapping and fails closed here (never guessed from field presence).
  const decisionSchemaVersion = receipt ? RECEIPT_TO_DECISION_SCHEMA.get(receipt.schema_version) : undefined;
  if (!receipt || decisionSchemaVersion === undefined) return { verified: false, reason: "unsupported schema" };
  const isV2 = decisionSchemaVersion === "2.0";

  const parsedRequest = parseStrictJson(receipt.canonical_request);
  const parsedPolicy = parseStrictJson(receipt.canonical_policy);
  if (!parsedRequest.ok || !parsedPolicy.ok) return { verified: false, reason: "canonical request/policy parse failed" };

  // A receipt issued under a cryptographic authority chain can only be verified
  // with trust anchors the verifier supplies out of band.
  if (receipt.trust_enforced && !options.trustAnchors) {
    return { verified: false, reason: "trust anchors required to verify a trust-enforced receipt" };
  }
  if (receipt.approval_enforced && !options.approvalTrustAnchors) {
    return { verified: false, reason: "approval trust anchors required to verify an approval-enforced receipt" };
  }

  const original = receipt.decision_output ?? {};
  // Replay re-verifies every scope-bound grant's signature/trust/time/binding
  // exactly as at decision time, but must NEVER touch the durable nonce store —
  // an offline audit run must be idempotent and must not itself decide whether
  // a grant was "used." consumeAuthorityGrants: false skips step 15 only; every
  // other check (steps 1-14) still runs and must still agree with the original
  // decision, or replay fails closed on drift exactly like any other field.
  // The authenticated caller for replay is derived from the embedded request's
  // principal.id, which sidecar-adapter.mjs already sets to the authenticated
  // caller.id before the request is ever signed — see decidePolicyEngine.
  const replayCaller = typeof parsedRequest.value?.principal?.id === "string" ? { id: parsedRequest.value.principal.id } : undefined;
  const replay = evaluatePolicyRequest(parsedRequest.value, parsedPolicy.value, {
    authorities: Array.isArray(receipt.authorities) ? receipt.authorities : [],
    now: original.evaluated_at,
    trustAnchors: receipt.trust_enforced ? options.trustAnchors : undefined,
    approvals: receipt.approval_enforced ? (Array.isArray(receipt.approvals) ? receipt.approvals : []) : undefined,
    approvalTrustAnchors: receipt.approval_enforced ? options.approvalTrustAnchors : undefined,
    caller: replayCaller,
    repoRoot: options.repoRoot,
    consumeAuthorityGrants: false,
    decisionSchemaVersion
  });

  // Cross-version integrity: the embedded decision's own schema_version must
  // match the version the receipt header declares. This prevents a v1 decision
  // body from being accepted under a v2 receipt header (or vice versa) and
  // rejects any malformed cross-version shape before the drift checks run.
  if (original.schema_version !== decisionSchemaVersion) {
    return { verified: false, reason: "decision schema mismatch" };
  }

  // v1 drift fields are frozen and unchanged. v2 additionally verifies rule_id;
  // because rule_id is bound into decision_hash, a v2 receipt whose rule_id was
  // altered fails BOTH the rule_id check and the decision_hash check.
  const driftFields = isV2
    ? ["decision", "reason_code", "rule_id", "request_hash", "policy_hash", "authority_chain_hash", "decision_hash"]
    : ["decision", "reason_code", "request_hash", "policy_hash", "authority_chain_hash", "decision_hash"];
  for (const field of driftFields) {
    if (replay[field] !== original[field]) return { verified: false, reason: `decision drift: ${field}` };
  }
  // authority_grants is audit metadata, not part of decision_hash (like
  // approval), so it needs its own explicit tamper check: a canonical-JSON
  // deep-equality comparison, not `!==` (they're objects, not primitives).
  if (canonicalizeJson(replay.authority_grants ?? null) !== canonicalizeJson(original.authority_grants ?? null)) {
    return { verified: false, reason: "decision drift: authority_grants" };
  }
  if (receipt.request_hash !== original.request_hash || receipt.policy_hash !== original.policy_hash || receipt.authority_chain_hash !== original.authority_chain_hash) {
    return { verified: false, reason: "receipt header hashes do not match decision" };
  }
  if (receipt.policy_bundle_provenance !== undefined && !isBundleProvenance(receipt.policy_bundle_provenance, replay.policy_hash)) {
    return { verified: false, reason: "policy bundle provenance contradicts replayed policy state" };
  }
  if (options.historicalPolicyBundle !== undefined) {
    if (!receipt.policy_bundle_provenance) return { verified: false, reason: "historical policy bundle supplied but receipt has no bundle provenance" };
    const historical = await verifyHistoricalPolicyBundleProvenance({
      bundle: options.historicalPolicyBundle,
      provenance: receipt.policy_bundle_provenance,
      policy: parsedPolicy.value,
      authorityBundle: options.policyAuthorityBundle,
      trustedRootFingerprint: options.policyTrustedRootFingerprint
    });
    if (!historical.ok) return { verified: false, reason: historical.reason };
  }

  const signature = receipt.verifiable_signature;
  if (!signature) return { verified: false, reason: "missing signature" };
  const authorityBundleSignature = await verifyReceiptSignatureWithAuthorityBundle(receipt, signature, options);
  if (authorityBundleSignature) {
    return authorityBundleSignature.verified
      ? {
        verified: true,
        reason: null,
        trust_source: authorityBundleSignature.trust_source,
        decision: original.decision,
        reason_code: original.reason_code,
        ...(receipt.policy_bundle_provenance ? { policy_bundle_provenance: structuredClone(receipt.policy_bundle_provenance) } : {})
      }
      : authorityBundleSignature;
  }
  const bundle = loadAuthorityBundleForReceipt(repoRoot, signature.authority_id);
  if (!bundle.ok) return { verified: false, reason: bundle.reason };
  // validAt MUST be a value covered by the receipt's own signature — never the
  // unsigned verifiable_signature.signed_at (see shared/authority-manifest.mjs).
  // decision_output.evaluated_at is signed (it's part of decision_output, which
  // is inside canonicalPayloadWithoutSignature) and is already produced by
  // evaluatePolicyRequest for every mnde.pe.receipt.v1 receipt.
  const keyResult = findAuthorityReceiptKey(bundle.manifest, { authorityId: signature.authority_id, keyId: signature.key_id, validAt: receipt.decision_output?.evaluated_at });
  if (!keyResult.ok) return { verified: false, reason: keyResult.reason };
  if (signature.public_key_fingerprint !== keyResult.key.public_key_fingerprint) return { verified: false, reason: "fingerprint mismatch" };

  const ok = verifyReceiptPayloadSignature(canonicalPayloadWithoutSignature(receipt), signature.value, keyResult.key.public_key);
  return ok
    ? {
      verified: true,
      reason: null,
      trust_source: "REPO_LOCAL_AUTHORITY",
      decision: original.decision,
      reason_code: original.reason_code,
      ...(receipt.policy_bundle_provenance ? { policy_bundle_provenance: structuredClone(receipt.policy_bundle_provenance) } : {})
    }
    : { verified: false, reason: "signature invalid" };
}

export const POLICY_RECEIPT_SCHEMA = SCHEMA;
export const POLICY_RECEIPT_SCHEMA_V2 = SCHEMA_V2;
