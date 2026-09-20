// Live receipt signing — the integration layer between a deterministic receipt
// builder and a key-custody provider.
//
//   Decision Engine -> Receipt Builder -> [Signing Adapter] -> Custody Provider
//                                              (this module)
//
// Signing is a separate authority concern: decision engines never import custody
// and never sign. A built receipt is handed here; in legacy mode it passes
// through byte-for-byte, in custody mode it is wrapped in an additive envelope
// that carries a production custody attestation. The inner receipt is never
// mutated, so the existing verifier keeps its byte-for-byte guarantees.
//
//   mnde.signed-receipt.v1 = { schema_version, receipt: <inner, untouched>,
//                              custody_attestation: { ... , signature } }
//   mnde.signed-receipt.v2 = { schema_version, signing_mode,
//                              receipt: <inner, untouched>, executor,
//                              custody_attestation: { ... , signature } }
//
// Verification is fully offline against a published authority bundle: the inner
// receipt verifies through the existing unified verifier, AND the custody
// attestation verifies against the bundle (root trust, bundle signature, key
// validity window, revocation, attestation signature).

import { canonicalizeJson } from "../../shared/json.ts";
import { sha256 } from "../crypto/provider.mjs";
import {
  createCustody,
  findBundleKey,
  verifyCanonical,
  verifyAgainstBundle,
  verifyAuthorityBundle,
  createExternalSignerCustody
} from "../custody/index.mjs";
import { verifyExecutorCredential } from "../custody/executor-credential.mjs";
import { EXECUTOR_RECEIPT_CAPABILITY } from "../custody/executor-identity.mjs";

export const LEGACY_SIGNED_RECEIPT_SCHEMA = "mnde.signed-receipt.v1";
export const SIGNED_RECEIPT_SCHEMA = "mnde.signed-receipt.v2";
export const ATTESTATION_SCHEMA = "mnde.custody.attestation.v1";
export const EXECUTOR_ENVELOPE_SCHEMA = "mnde.executor.receipt-envelope.v1";
export const LIVE_RECEIPT_SIGNING_MODES = Object.freeze({
  AUTHORITY_ONLY: "authority_only",
  EXECUTOR_AND_AUTHORITY: "executor_and_authority"
});

export function isSignedReceiptEnvelope(value) {
  return value?.schema_version === SIGNED_RECEIPT_SCHEMA || value?.schema_version === LEGACY_SIGNED_RECEIPT_SCHEMA;
}

function sha256Hex(text) {
  return sha256(text);
}
function decisionOf(receipt) {
  if (typeof receipt?.decision_output?.decision === "string") return receipt.decision_output.decision;
  if (typeof receipt?.decision === "string") return receipt.decision;
  return "UNKNOWN";
}
function versionOf(schema) {
  const match = typeof schema === "string" ? schema.match(/v(\d+)$/) : null;
  return match ? `v${match[1]}` : "v1";
}

// Map low-level custody/bundle/key reasons onto distinct, stable wire codes.
// `custodyCode` is a structured classification from CustodyConfigurationError
// (preferred); `reason` is the sanitized message (text fallback). Passphrase
// codes are resolved FIRST so an encrypted-key failure never collapses into the
// broad SIGNING_KEY / KEY_MISSING classification below (both passphrase messages
// contain "SIGNING_KEY").
function custodyConfigCode(reason, custodyCode) {
  if (custodyCode === "PASSPHRASE_REQUIRED") return "ERR_CUSTODY_KEY_PASSPHRASE_REQUIRED";
  if (custodyCode === "PASSPHRASE_INVALID") return "ERR_CUSTODY_KEY_PASSPHRASE_INVALID";
  const text = String(reason ?? "");
  if (/^custody: MNDE_[A-Z_]+ requires MNDE_[A-Z_]+_PASSPHRASE$/.test(text)) return "ERR_CUSTODY_KEY_PASSPHRASE_REQUIRED";
  if (/^custody: passphrase for MNDE_[A-Z_]+ is invalid$/.test(text)) return "ERR_CUSTODY_KEY_PASSPHRASE_INVALID";
  if (/cannot read MNDE_AUTHORITY_BUNDLE|MNDE_AUTHORITY_BUNDLE not configured/.test(text)) return "ERR_CUSTODY_BUNDLE_MISSING";
  if (/not valid JSON|not an mnde\.authority\.bundle/.test(text)) return "ERR_CUSTODY_BUNDLE_INVALID";
  if (/revoked|KEY_REVOKED/.test(text)) return "ERR_CUSTODY_KEY_REVOKED";
  if (/KEY_EXPIRED|not usable/.test(text)) return "ERR_CUSTODY_KEY_EXPIRED";
  if (/fingerprint mismatch|does not match the bundle key/.test(text)) return "ERR_CUSTODY_KEY_MISMATCH";
  if (/EXTERNAL_.*SIGNER_CMD|external .*signer/.test(text)) return "ERR_CUSTODY_SIGNER_UNAVAILABLE";
  if (/SIGNING_KEY|EXTERNAL_.*SIGNER_PUBLIC_KEY|no published .* key|not configured|not a valid public key/.test(text)) return "ERR_CUSTODY_KEY_MISSING";
  if (/unknown MNDE_KEY_CUSTODY/.test(text)) return "ERR_CUSTODY_MISCONFIGURED";
  return "ERR_CUSTODY_MISCONFIGURED";
}
function bundleCode(reason) {
  return reason === "BUNDLE_STALE" ? "ERR_CUSTODY_BUNDLE_STALE" : "ERR_CUSTODY_BUNDLE_INVALID";
}
function keyCode(reason) {
  if (reason === "KEY_EXPIRED") return "ERR_CUSTODY_KEY_EXPIRED";
  if (reason === "KEY_REVOKED") return "ERR_CUSTODY_KEY_REVOKED";
  return "ERR_CUSTODY_KEY_MISSING";
}

// Resolve signing configuration. Default legacy; custody is opt-in and fails
// closed — a misconfiguration never silently downgrades to legacy.
//
// `options.now` is the evaluation instant for the bundle's validity window.
// Omitted (every production caller) it means "right now", which is the only
// answer a live process may use. It exists so a caller that already reasons at
// a fixed instant — assertTrustRoot with an injected clock, offline
// verification of historical evidence — evaluates every step at that same
// instant instead of half at the fixture's time and half at the wall clock.
export async function loadSigningConfig(env = process.env, options = {}) {
  const requested = env.MNDE_RECEIPT_SIGNING_MODE;
  // Both "custody" (local-demo / file-backed-production) and "external-signer"
  // engage custody signing. Anything else is legacy pass-through.
  if (requested !== "custody" && requested !== "external-signer") return { ok: true, mode: "legacy" };

  let provider;
  if (requested === "external-signer") {
    try {
      provider = createExternalSignerCustody(env);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return { ok: false, mode: "custody", reason_code: custodyConfigCode(detail), detail };
    }
  } else {
    const custody = await createCustody(env);
    if (!custody.ok) return { ok: false, mode: "custody", reason_code: custodyConfigCode(custody.reason, custody.custodyCode), detail: custody.reason };
    provider = custody.provider;
  }

  const bundle = provider.getPublicBundle();
  // `now: undefined` is identical to omitting it — verifyAuthorityBundle
  // resolves `options.now ?? new Date().toISOString()`.
  const check = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: provider.trustedRootFingerprint, now: options.now });
  if (!check.ok) return { ok: false, mode: "custody", reason_code: bundleCode(check.reason), detail: check.reason };

  // mode is normalized to "custody" so signReceiptForDelivery engages; signer_mode
  // records which provider (custody | external-signer) is in use.
  return { ok: true, mode: "custody", signer_mode: provider.mode, provider, fingerprint: provider.trustedRootFingerprint };
}

function freezeCredential(value) {
  if (!value || typeof value !== "object") return value;
  for (const child of Object.values(value)) freezeCredential(child);
  return Object.freeze(value);
}

// Constructed exactly once by the sidecar after startup validation. The private
// key stays behind executorSigner.sign and is never copied into receipts/logs.
export function createLiveReceiptSigningContext(signingConfig, executorReadiness = { configured: false }) {
  if (!signingConfig?.ok) {
    return { ok: false, reason_code: signingConfig?.reason_code ?? "ERR_CUSTODY_UNAVAILABLE" };
  }
  if (!executorReadiness?.configured) {
    const authorityConfig = Object.freeze({ ...signingConfig });
    return {
      ok: true,
      context: Object.freeze({
        mode: LIVE_RECEIPT_SIGNING_MODES.AUTHORITY_ONLY,
        authorityConfig,
        authoritySigner: signingConfig.provider?.signReceipt ?? null,
        executorSigner: null,
        executorIdentity: null
      })
    };
  }
  if (signingConfig.mode !== "custody" || !signingConfig.provider?.signReceipt) {
    return { ok: false, reason_code: "ERR_EXECUTOR_AUTHORITY_SIGNER_REQUIRED" };
  }
  if (typeof executorReadiness.signer?.sign !== "function" || !executorReadiness.credential) {
    return { ok: false, reason_code: "ERR_EXECUTOR_SIGNER_MISSING" };
  }
  const identity = freezeCredential({
    executor_id: executorReadiness.executor_id,
    key_id: executorReadiness.executor_key_id,
    credential_id: executorReadiness.credential_id,
    environment_id: executorReadiness.environment_id,
    credential: structuredClone(executorReadiness.credential)
  });
  const authorityConfig = Object.freeze({ ...signingConfig });
  return {
    ok: true,
    context: Object.freeze({
      mode: LIVE_RECEIPT_SIGNING_MODES.EXECUTOR_AND_AUTHORITY,
      authorityConfig,
      authoritySigner: signingConfig.provider.signReceipt,
      executorSigner: executorReadiness.signer,
      executorIdentity: identity
    })
  };
}

export async function signLiveReceipt(receipt, signingContext, options = {}) {
  if (!signingContext || !Object.isFrozen(signingContext)) {
    return { ok: false, reason_code: "ERR_SIGNING_MODE_INVALID" };
  }
  if (signingContext.mode === LIVE_RECEIPT_SIGNING_MODES.AUTHORITY_ONLY) {
    if (signingContext.authorityConfig.mode === "legacy") {
      return { ok: true, receipt };
    }
    return signReceiptForDelivery(receipt, signingContext.authorityConfig, {
      ...options,
      signingMode: LIVE_RECEIPT_SIGNING_MODES.AUTHORITY_ONLY
    });
  }
  if (signingContext.mode === LIVE_RECEIPT_SIGNING_MODES.EXECUTOR_AND_AUTHORITY) {
    if (!signingContext.executorSigner || !signingContext.executorIdentity || !signingContext.authoritySigner) {
      return { ok: false, reason_code: "ERR_EXECUTOR_BOUND_SIGNING_FAILED" };
    }
    return signReceiptForDelivery(receipt, signingContext.authorityConfig, {
      ...options,
      signingMode: LIVE_RECEIPT_SIGNING_MODES.EXECUTOR_AND_AUTHORITY,
      executorSigner: signingContext.executorSigner,
      executorIdentity: signingContext.executorIdentity
    });
  }
  return { ok: false, reason_code: "ERR_SIGNING_MODE_INVALID" };
}

// Sign a built receipt for delivery. Legacy mode is a pass-through. Custody mode
// preserves the exact v1 authority-only envelope unless executor identity is
// present, in which case it returns v2. Never logs or returns key material.
export async function signReceiptForDelivery(receipt, signingConfig, options = {}) {
  if (!signingConfig || signingConfig.mode !== "custody") return { ok: true, receipt };
  const provider = signingConfig.provider;
  if (!provider) return { ok: false, reason_code: "ERR_CUSTODY_UNAVAILABLE", detail: "no custody provider" };

  const at = options.now ?? new Date().toISOString();
  const bundle = provider.getPublicBundle();
  const signingMode = options.signingMode ?? LIVE_RECEIPT_SIGNING_MODES.AUTHORITY_ONLY;
  if (!Object.values(LIVE_RECEIPT_SIGNING_MODES).includes(signingMode)) {
    return { ok: false, reason_code: "ERR_SIGNING_MODE_INVALID" };
  }

  // Re-validate the bundle at signing time (catches a bundle gone stale).
  const bundleCheck = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: provider.trustedRootFingerprint, now: at });
  if (!bundleCheck.ok) return { ok: false, reason_code: bundleCode(bundleCheck.reason), detail: bundleCheck.reason };

  const receiptType = typeof receipt?.schema_version === "string" ? receipt.schema_version : "unknown";
  const receiptHash = sha256Hex(canonicalizeJson(receipt));
  let executorEnvelope;
  if (signingMode === LIVE_RECEIPT_SIGNING_MODES.EXECUTOR_AND_AUTHORITY) {
    const identity = options.executorIdentity;
    const signer = options.executorSigner;
    if (!identity || typeof signer?.sign !== "function") {
      return { ok: false, reason_code: "ERR_EXECUTOR_BOUND_SIGNING_FAILED" };
    }
    const credentialCheck = await verifyExecutorCredential(identity.credential, {
      authorityBundle: bundle,
      trustedRootFingerprint: provider.trustedRootFingerprint,
      environmentId: identity.environment_id,
      expectedExecutorId: identity.executor_id,
      requiredCapability: EXECUTOR_RECEIPT_CAPABILITY,
      now: at
    });
    if (!credentialCheck.ok) {
      return { ok: false, reason_code: credentialCheck.code, detail: credentialCheck.detail };
    }
    if (
      credentialCheck.key_id !== identity.key_id ||
      credentialCheck.credential_id !== identity.credential_id ||
      credentialCheck.environment_id !== identity.environment_id
    ) {
      return { ok: false, reason_code: "ERR_EXECUTOR_IDENTITY_MISMATCH" };
    }
    try {
      const identityBody = {
        schema_version: EXECUTOR_ENVELOPE_SCHEMA,
        executor_id: identity.executor_id,
        key_id: identity.key_id,
        credential_id: identity.credential_id,
        environment_id: identity.environment_id,
        receipt_schema_version: receiptType,
        receipt_hash: receiptHash
      };
      const value = await signer.sign(canonicalizeJson(identityBody));
      if (typeof value !== "string" || value.length === 0) throw new Error("executor signer returned no signature");
      executorEnvelope = {
        identity: identityBody,
        credential: structuredClone(identity.credential),
        signature: { algorithm: "ED25519", key_id: identity.key_id, value }
      };
    } catch {
      return { ok: false, reason_code: "ERR_EXECUTOR_BOUND_SIGNING_FAILED" };
    }
  }

  const executorBound = signingMode === LIVE_RECEIPT_SIGNING_MODES.EXECUTOR_AND_AUTHORITY;
  const attestationPayload = {
    schema_version: ATTESTATION_SCHEMA,
    ...(executorBound ? { signing_mode: signingMode } : {}),
    receipt_type: receiptType,
    receipt_version: versionOf(receiptType),
    decision: decisionOf(receipt),
    receipt_hash: receiptHash,
    ...(executorEnvelope ? { executor_envelope_hash: sha256Hex(canonicalizeJson(executorEnvelope)) } : {}),
    authority_bundle_fingerprint: provider.trustedRootFingerprint,
    // Activation binding (mnde.activation.v1): the preflight-verified id of the
    // active authority transition this decision was produced under. Part of the
    // signed attestation payload — tampering breaks the attestation signature.
    // The inner receipt stays byte-for-byte untouched.
    ...(typeof signingConfig.activation_id === "string" && signingConfig.activation_id.length > 0
      ? { activation_id: signingConfig.activation_id }
      : {}),
    signed_at: at
  };

  let signed;
  try {
    signed = await provider.signReceipt(canonicalizeJson(attestationPayload));
  } catch (error) {
    // error.message comes from custody — paths/reasons only, never key bytes.
    return {
      ok: false,
      reason_code: signingMode === LIVE_RECEIPT_SIGNING_MODES.EXECUTOR_AND_AUTHORITY
        ? "ERR_EXECUTOR_BOUND_SIGNING_FAILED"
        : "ERR_CUSTODY_SIGNING_FAILED",
      detail: error?.message ?? String(error)
    };
  }

  // The key that actually signed must be valid in the published bundle.
  const keyCheck = findBundleKey(bundle, "receipt", signed.key_id, at);
  if (!keyCheck.ok) return { ok: false, reason_code: keyCode(keyCheck.reason), detail: keyCheck.reason };

  return {
    ok: true,
    receipt: {
      schema_version: executorBound ? SIGNED_RECEIPT_SCHEMA : LEGACY_SIGNED_RECEIPT_SCHEMA,
      ...(executorBound ? { signing_mode: signingMode } : {}),
      receipt,
      ...(executorEnvelope ? { executor: executorEnvelope } : {}),
      custody_attestation: {
        ...attestationPayload,
        signing_key_id: signed.key_id,
        signature: { algorithm: "ED25519", value: signed.value }
      }
    }
  };
}

// Verify ONLY the custody attestation of an envelope against a published bundle.
// Offline; no network. The inner receipt is verified separately by the caller
// (the unified verifier) so this stays a focused production-trust interface.
export async function verifyCustodyAttestation(envelope, options = {}) {
  if (!isSignedReceiptEnvelope(envelope)) {
    return { ok: false, reason: "not a custody-signed receipt" };
  }
  const attestation = envelope.custody_attestation;
  const inner = envelope.receipt;
  if (!attestation || !inner) return { ok: false, reason: "malformed signed receipt" };

  const bundle = options.authorityBundle;
  if (!bundle) return { ok: false, reason: "authority bundle required to verify a custody-signed receipt" };

  const now = options.now ?? new Date().toISOString();
  const legacyEnvelope = envelope.schema_version === LEGACY_SIGNED_RECEIPT_SCHEMA;
  const signingMode = legacyEnvelope ? LIVE_RECEIPT_SIGNING_MODES.AUTHORITY_ONLY : envelope.signing_mode;
  if (!legacyEnvelope && signingMode === undefined) return { ok: false, reason: "ERR_SIGNING_MODE_MISSING", reason_code: "ERR_SIGNING_MODE_MISSING" };
  if (!Object.values(LIVE_RECEIPT_SIGNING_MODES).includes(signingMode)) {
    return { ok: false, reason: "ERR_SIGNING_MODE_INVALID", reason_code: "ERR_SIGNING_MODE_INVALID" };
  }
  if (!legacyEnvelope && attestation.signing_mode !== signingMode) {
    return { ok: false, reason: "ERR_SIGNING_MODE_INVALID", reason_code: "ERR_SIGNING_MODE_INVALID" };
  }

  // 1) Trust the bundle (root anchor out of band, bundle signature, staleness).
  const bundleCheck = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: options.trustedRootFingerprint, now, maxAgeMs: options.maxAgeMs });
  if (!bundleCheck.ok) return { ok: false, reason: `bundle: ${bundleCheck.reason}` };

  // 2) The receipt must be bound to THIS bundle.
  if (attestation.authority_bundle_fingerprint !== bundle.root_key?.fingerprint) {
    return { ok: false, reason: "authority fingerprint mismatch" };
  }

  // 3) The inner receipt must be byte-identical to what was attested.
  if (sha256Hex(canonicalizeJson(inner)) !== attestation.receipt_hash) {
    return { ok: false, reason: "receipt hash mismatch", reason_code: "ERR_RECEIPT_SIGNATURE_INVALID" };
  }
  // The attestation and its hashed inner receipt are one authorization. Even a
  // correctly signed envelope is invalid if its signed decision/schema metadata
  // disagrees with the exact receipt it attests; accepting split-brain evidence
  // would let downstream gates select whichever layer was more permissive.
  if (attestation.decision !== decisionOf(inner)) {
    return { ok: false, reason: "ERR_RECEIPT_DECISION_MISMATCH", reason_code: "ERR_RECEIPT_DECISION_MISMATCH" };
  }
  if (attestation.receipt_type !== inner.schema_version || attestation.receipt_version !== versionOf(inner.schema_version)) {
    return { ok: false, reason: "ERR_RECEIPT_SCHEMA_MISMATCH", reason_code: "ERR_RECEIPT_SCHEMA_MISMATCH" };
  }

  let executorId = null;
  if (signingMode === LIVE_RECEIPT_SIGNING_MODES.AUTHORITY_ONLY) {
    if (envelope.executor || attestation.executor_envelope_hash) {
      return { ok: false, reason: "ERR_SIGNING_MODE_INVALID", reason_code: "ERR_SIGNING_MODE_INVALID" };
    }
    if (options.requireExecutor) return { ok: false, reason: "ERR_EXECUTOR_REQUIRED", reason_code: "ERR_EXECUTOR_REQUIRED" };
  } else {
    const executor = envelope.executor;
    if (!executor || typeof executor !== "object") {
      return { ok: false, reason: "ERR_EXECUTOR_ENVELOPE_MISSING", reason_code: "ERR_EXECUTOR_ENVELOPE_MISSING" };
    }
    if (!executor.signature?.value) {
      return { ok: false, reason: "ERR_EXECUTOR_SIGNATURE_MISSING", reason_code: "ERR_EXECUTOR_SIGNATURE_MISSING" };
    }
    if (!executor.credential || !executor.identity) {
      return { ok: false, reason: "ERR_EXECUTOR_CREDENTIAL_INVALID", reason_code: "ERR_EXECUTOR_CREDENTIAL_INVALID" };
    }
    if (sha256Hex(canonicalizeJson(executor)) !== attestation.executor_envelope_hash) {
      return { ok: false, reason: "ERR_RECEIPT_SIGNATURE_INVALID", reason_code: "ERR_RECEIPT_SIGNATURE_INVALID" };
    }
    const expectedEnvironment = options.environmentId;
    if (typeof expectedEnvironment !== "string" || expectedEnvironment.length === 0) {
      return { ok: false, reason: "ERR_EXECUTOR_ENVIRONMENT_MISMATCH", reason_code: "ERR_EXECUTOR_ENVIRONMENT_MISMATCH" };
    }
    const credentialCheck = await verifyExecutorCredential(executor.credential, {
      authorityBundle: bundle,
      trustedRootFingerprint: options.trustedRootFingerprint,
      environmentId: expectedEnvironment,
      expectedExecutorId: options.expectedExecutorId ?? executor.identity.executor_id,
      requiredCapability: EXECUTOR_RECEIPT_CAPABILITY,
      // Executor authorization is historical evidence: validate it at the
      // authority-authenticated receipt event time. Runtime signing separately
      // validates the same credential against the current signing timestamp.
      now: attestation.signed_at
    });
    if (!credentialCheck.ok) return { ok: false, reason: credentialCheck.code, reason_code: credentialCheck.code };
    if (
      executor.identity.schema_version !== EXECUTOR_ENVELOPE_SCHEMA ||
      executor.identity.executor_id !== credentialCheck.executor_id ||
      executor.identity.key_id !== credentialCheck.key_id ||
      executor.identity.credential_id !== credentialCheck.credential_id ||
      executor.identity.environment_id !== expectedEnvironment ||
      executor.identity.receipt_schema_version !== inner.schema_version ||
      executor.identity.receipt_hash !== attestation.receipt_hash ||
      executor.signature.key_id !== credentialCheck.key_id
    ) {
      return { ok: false, reason: "ERR_EXECUTOR_IDENTITY_MISMATCH", reason_code: "ERR_EXECUTOR_IDENTITY_MISMATCH" };
    }
    const executorSignatureOk = await verifyCanonical(
      canonicalizeJson(executor.identity),
      executor.signature.value,
      credentialCheck.public_key
    );
    if (!executorSignatureOk) {
      return { ok: false, reason: "ERR_EXECUTOR_SIGNATURE_INVALID", reason_code: "ERR_EXECUTOR_SIGNATURE_INVALID" };
    }
    executorId = credentialCheck.executor_id;
  }

  // 4) Verify the attestation signature against the bundle's receipt key
  //    (key lookup honors validity window + revocation).
  const { signing_key_id, signature, ...signedFields } = attestation;
  const sigValue = signature?.value;
  if (typeof sigValue !== "string") return { ok: false, reason: "missing attestation signature", reason_code: "ERR_AUTHORITY_SIGNATURE_MISSING" };
  const check = await verifyAgainstBundle(canonicalizeJson(signedFields), sigValue, "receipt", signing_key_id, signedFields.signed_at, bundle);
  if (!check.ok) return { ok: false, reason: check.reason, reason_code: "ERR_AUTHORITY_SIGNATURE_INVALID" };

  return {
    ok: true,
    state: signingMode === LIVE_RECEIPT_SIGNING_MODES.EXECUTOR_AND_AUTHORITY
      ? "executor_and_authority_verified"
      : "authority_only_verified",
    signing_mode: signingMode,
    executor_id: executorId,
    decision: attestation.decision,
    signing_key_id,
    authority_fingerprint: attestation.authority_bundle_fingerprint,
    trust_source: "ROOT_PINNED_AUTHORITY_BUNDLE",
    signed_at: attestation.signed_at,
    receipt_hash: attestation.receipt_hash,
    // Activation binding, when the producing runtime was activation-bound.
    // Covered by the attestation signature verified above.
    activation_id: typeof attestation.activation_id === "string" ? attestation.activation_id : null
  };
}
