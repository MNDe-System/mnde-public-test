// Signed Policy Bundle activation boundary.
//
// This module runs before a policy reaches the deterministic policy engine. It
// verifies a policy-key signature against an independently trusted authority
// bundle, enforces a persisted per-policy serial floor, and records activation
// outcomes. It does not participate in execution, receipt signing, or replay.

import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

import { canonicalizeJson } from "../../shared/json.ts";
import { sha256 } from "../crypto/provider.mjs";
import { signCanonical, verifyAgainstBundle, verifyAuthorityBundle } from "../custody/index.mjs";

export const POLICY_BUNDLE_SCHEMA = "mnde.policy.bundle.v1";
export const POLICY_BUNDLE_STATE_SCHEMA = "mnde.policy.bundle.state.v1";

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isTimestamp(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value) && !Number.isNaN(Date.parse(value));
}

function withoutSignature(value) {
  const { signature: _signature, rollback_authorization: _rollbackAuthorization, ...unsigned } = value;
  return unsigned;
}

function canonicalUnsignedBundle(bundle) {
  return canonicalizeJson(withoutSignature(bundle));
}

function bundleDigest(bundle) {
  return sha256(canonicalUnsignedBundle(bundle));
}

function policyHash(policyDocument) {
  return `sha256:${sha256(canonicalizeJson(policyDocument))}`;
}

function validPolicyIdentity(bundle) {
  return isObject(bundle.policy_document)
    && typeof bundle.policy_id === "string"
    && bundle.policy_id.length > 0
    && bundle.policy_document.policy_id === bundle.policy_id;
}

function validateBundleShape(bundle) {
  if (!isObject(bundle) || bundle.schema_version !== POLICY_BUNDLE_SCHEMA) return "POLICY_BUNDLE_UNSUPPORTED";
  if (!validPolicyIdentity(bundle) || typeof bundle.bundle_id !== "string" || bundle.bundle_id.length === 0) return "POLICY_BUNDLE_MALFORMED";
  if (!Number.isSafeInteger(bundle.serial) || bundle.serial < 1) return "POLICY_BUNDLE_MALFORMED";
  if (!isTimestamp(bundle.issued_at)) return "POLICY_BUNDLE_MALFORMED";
  if (bundle.policy_hash !== policyHash(bundle.policy_document)) return "POLICY_BUNDLE_POLICY_HASH_MISMATCH";
  if (typeof bundle.signing_key_id !== "string" || bundle.signing_key_id.length === 0) return "POLICY_BUNDLE_MALFORMED";
  if (!isObject(bundle.signature) || bundle.signature.algorithm !== "ED25519" || typeof bundle.signature.value !== "string") return "POLICY_BUNDLE_UNSIGNED";
  if (bundle.allow_rollback !== undefined && bundle.allow_rollback !== true) return "POLICY_BUNDLE_MALFORMED";
  return null;
}

function defaultState() {
  return { schema_version: POLICY_BUNDLE_STATE_SCHEMA, mode: "enforce", serial_floors: {}, serial_digests: {}, consumed_rollback_authorizations: [], activation_events: [] };
}

function loadState(statePath) {
  if (typeof statePath !== "string" || statePath.length === 0) return { ok: false, reason: "POLICY_BUNDLE_STATE_PATH_REQUIRED" };
  if (!existsSync(statePath)) return { ok: true, state: defaultState() };
  let state;
  try {
    state = JSON.parse(readFileSync(statePath, "utf8"));
  } catch {
    return { ok: false, reason: "POLICY_BUNDLE_STATE_INVALID" };
  }
  if (!isObject(state) || state.schema_version !== POLICY_BUNDLE_STATE_SCHEMA || state.mode !== "enforce" || !isObject(state.serial_floors) || !isObject(state.serial_digests) || !Array.isArray(state.activation_events)) {
    return { ok: false, reason: "POLICY_BUNDLE_STATE_MODE_MISMATCH" };
  }
  if (Object.values(state.serial_floors).some((serial) => !Number.isSafeInteger(serial) || serial < 1)) return { ok: false, reason: "POLICY_BUNDLE_STATE_INVALID" };
  if (Object.values(state.serial_digests).some((bySerial) => !isObject(bySerial) || Object.entries(bySerial).some(([serial, digest]) => !/^\d+$/.test(serial) || typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest)))) return { ok: false, reason: "POLICY_BUNDLE_STATE_INVALID" };
  // Migration-safe (L1): older v1 state files predate single-use rollback
  // tracking. An absent list is treated as empty; a present list must be an
  // array of non-empty authorization ids.
  if (state.consumed_rollback_authorizations !== undefined && (!Array.isArray(state.consumed_rollback_authorizations) || state.consumed_rollback_authorizations.some((id) => typeof id !== "string" || id.length === 0))) {
    return { ok: false, reason: "POLICY_BUNDLE_STATE_INVALID" };
  }
  if (!Array.isArray(state.consumed_rollback_authorizations)) state.consumed_rollback_authorizations = [];
  return { ok: true, state };
}

function writeState(statePath, state) {
  try {
    mkdirSync(dirname(statePath), { recursive: true });
    const temporary = `${statePath}.tmp-${process.pid}`;
    writeFileSync(temporary, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    try { renameSync(temporary, statePath); }
    catch {
      // Windows cannot always replace an existing destination. The old file has
      // already been fully parsed; remove only after the replacement is written.
      try { unlinkSync(statePath); } catch { /* absent is fine */ }
      renameSync(temporary, statePath);
    }
    return { ok: true };
  } catch {
    return { ok: false, reason: "POLICY_BUNDLE_STATE_WRITE_FAILED" };
  }
}

async function rollbackAuthorized(bundle, floor, authorityBundle, now) {
  if (bundle.allow_rollback !== true) return { ok: false, reason: "POLICY_BUNDLE_SERIAL_ROLLBACK_REFUSED" };
  const grant = bundle.rollback_authorization;
  if (!isObject(grant) || !isObject(grant.signature) || typeof grant.signing_key_id !== "string" || typeof grant.authorization_id !== "string" || grant.authorization_id.length === 0 || !isTimestamp(grant.issued_at) || !isTimestamp(grant.expires_at)) {
    return { ok: false, reason: "POLICY_BUNDLE_ROLLBACK_AUTH_INVALID" };
  }
  if (grant.policy_id !== bundle.policy_id || grant.from_serial !== floor || grant.to_serial !== bundle.serial || Date.parse(grant.issued_at) > Date.parse(now) || Date.parse(grant.expires_at) <= Date.parse(now)) {
    return { ok: false, reason: "POLICY_BUNDLE_ROLLBACK_AUTH_INVALID" };
  }
  const verification = await verifyAgainstBundle(canonicalizeJson(withoutSignature(grant)), grant.signature.value, "approval", grant.signing_key_id, grant.issued_at, authorityBundle);
  return verification.ok ? { ok: true, authorization_id: grant.authorization_id } : { ok: false, reason: "POLICY_BUNDLE_ROLLBACK_AUTH_INVALID" };
}

async function verifyHistoricalRollbackAuthorization(bundle, provenance, authorityBundle) {
  const rollbackId = provenance.rollback_authorization_id;
  const grant = bundle.rollback_authorization;
  if (rollbackId === null) {
    return grant === undefined ? { ok: true } : { ok: false, reason: "POLICY_BUNDLE_ROLLBACK_PROVENANCE_MISMATCH" };
  }
  if (!isObject(grant) || grant.authorization_id !== rollbackId || !isObject(grant.signature) || typeof grant.signing_key_id !== "string" || !isTimestamp(grant.issued_at) || !isTimestamp(grant.expires_at)) {
    return { ok: false, reason: "POLICY_BUNDLE_ROLLBACK_PROVENANCE_MISMATCH" };
  }
  if (grant.policy_id !== bundle.policy_id || grant.to_serial !== bundle.serial || !Number.isSafeInteger(grant.from_serial) || grant.from_serial <= bundle.serial || Date.parse(grant.issued_at) > Date.parse(bundle.issued_at) || Date.parse(grant.expires_at) <= Date.parse(bundle.issued_at)) {
    return { ok: false, reason: "POLICY_BUNDLE_ROLLBACK_PROVENANCE_MISMATCH" };
  }
  const verified = await verifyAgainstBundle(canonicalizeJson(withoutSignature(grant)), grant.signature.value, "approval", grant.signing_key_id, grant.issued_at, authorityBundle);
  return verified.ok ? { ok: true } : { ok: false, reason: "POLICY_BUNDLE_ROLLBACK_AUTH_INVALID" };
}

// Verify that signed receipt provenance names this exact historical policy
// bundle. This is an optional offline check; execution and deterministic replay
// intentionally do not load policy bundles or consult wall-clock state.
export async function verifyHistoricalPolicyBundleProvenance({ bundle, provenance, policy, authorityBundle, trustedRootFingerprint }) {
  const shapeError = validateBundleShape(bundle);
  if (shapeError) return { ok: false, reason: shapeError };
  if (!isObject(provenance) || typeof trustedRootFingerprint !== "string" || trustedRootFingerprint.length === 0) {
    return { ok: false, reason: "POLICY_BUNDLE_TRUST_INPUT_INVALID" };
  }
  const authority = await verifyAuthorityBundle(authorityBundle, { trustedRootFingerprint, now: bundle.issued_at });
  if (!authority.ok) return { ok: false, reason: `POLICY_BUNDLE_AUTHORITY_${authority.reason}` };
  const signature = await verifyAgainstBundle(canonicalUnsignedBundle(bundle), bundle.signature.value, "policy", bundle.signing_key_id, bundle.issued_at, authorityBundle);
  if (!signature.ok) return { ok: false, reason: `POLICY_BUNDLE_${signature.reason}` };
  if (provenance.bundle_id !== bundle.bundle_id || provenance.serial !== bundle.serial || provenance.policy_hash !== bundle.policy_hash || provenance.signer_key_id !== bundle.signing_key_id || provenance.activation_mode !== "enforce") {
    return { ok: false, reason: "POLICY_BUNDLE_PROVENANCE_MISMATCH" };
  }
  try {
    if (canonicalizeJson(policy) !== canonicalizeJson(bundle.policy_document)) return { ok: false, reason: "POLICY_BUNDLE_POLICY_DOCUMENT_MISMATCH" };
  } catch {
    return { ok: false, reason: "POLICY_BUNDLE_POLICY_DOCUMENT_MISMATCH" };
  }
  return verifyHistoricalRollbackAuthorization(bundle, provenance, authorityBundle);
}

export async function signPolicyBundle(input, { keyId, privateKeyPem }) {
  const unsigned = {
    schema_version: POLICY_BUNDLE_SCHEMA,
    bundle_id: input.bundle_id,
    policy_id: input.policy_id,
    serial: input.serial,
    issued_at: input.issued_at,
    policy_document: input.policy_document,
    policy_hash: policyHash(input.policy_document),
    ...(input.allow_rollback === true ? { allow_rollback: true } : {}),
    signing_key_id: keyId
  };
  return { ...unsigned, signature: { algorithm: "ED25519", value: await signCanonical(canonicalizeJson(unsigned), privateKeyPem) } };
}

export async function signRollbackAuthorization(input, { keyId, privateKeyPem }) {
  const unsigned = {
    schema_version: "mnde.policy.rollback.v1",
    authorization_id: input.authorization_id,
    policy_id: input.policy_id,
    from_serial: input.from_serial,
    to_serial: input.to_serial,
    issued_at: input.issued_at,
    expires_at: input.expires_at,
    signing_key_id: keyId
  };
  return { ...unsigned, signature: { algorithm: "ED25519", value: await signCanonical(canonicalizeJson(unsigned), privateKeyPem) } };
}

export async function activateSignedPolicyBundle({ bundle, authorityBundle, trustedRootFingerprint, statePath, now }) {
  const shapeError = validateBundleShape(bundle);
  if (shapeError) return { ok: false, reason: shapeError };
  if (!isTimestamp(now)) return { ok: false, reason: "POLICY_BUNDLE_INVALID_NOW" };

  const authority = await verifyAuthorityBundle(authorityBundle, { trustedRootFingerprint, now });
  if (!authority.ok) return { ok: false, reason: `POLICY_BUNDLE_AUTHORITY_${authority.reason}` };

  const signature = await verifyAgainstBundle(canonicalUnsignedBundle(bundle), bundle.signature.value, "policy", bundle.signing_key_id, bundle.issued_at, authorityBundle);
  if (!signature.ok) return { ok: false, reason: `POLICY_BUNDLE_${signature.reason}` };

  const loaded = loadState(statePath);
  if (!loaded.ok) return loaded;
  const state = loaded.state;
  const floor = state.serial_floors[bundle.policy_id] ?? 0;
  const digest = bundleDigest(bundle);
  const recordedDigest = state.serial_digests[bundle.policy_id]?.[String(bundle.serial)];
  if (recordedDigest && recordedDigest !== digest) return { ok: false, reason: "POLICY_BUNDLE_SERIAL_REUSE_REFUSED" };
  let rollbackAuthorizationId = null;
  if (bundle.serial < floor) {
    const rollback = await rollbackAuthorized(bundle, floor, authorityBundle, now);
    if (!rollback.ok) return rollback;
    // L1: a rollback authorization is single-use. Once consumed it can never
    // authorize another rollback, even within its validity window.
    if ((state.consumed_rollback_authorizations ?? []).includes(rollback.authorization_id)) {
      return { ok: false, reason: "POLICY_BUNDLE_ROLLBACK_AUTH_REUSED" };
    }
    rollbackAuthorizationId = rollback.authorization_id;
  }

  const next = structuredClone(state);
  if (rollbackAuthorizationId !== null) {
    next.consumed_rollback_authorizations = [...(next.consumed_rollback_authorizations ?? []), rollbackAuthorizationId];
  }
  // The high-water mark is monotonic even when an explicitly authorized rollback
  // temporarily activates an older policy.
  next.serial_floors[bundle.policy_id] = Math.max(floor, bundle.serial);
  next.serial_digests[bundle.policy_id] ??= {};
  next.serial_digests[bundle.policy_id][String(bundle.serial)] = digest;
  next.activation_events.push({ policy_id: bundle.policy_id, serial: bundle.serial, bundle_issued_at: bundle.issued_at, activated_at: now, result: "ACTIVATED" });
  if (next.activation_events.length > 100) next.activation_events = next.activation_events.slice(-100);
  const stored = writeState(statePath, next);
  if (!stored.ok) return stored;
  return {
    ok: true,
    policy: structuredClone(bundle.policy_document),
    serial: bundle.serial,
    policy_id: bundle.policy_id,
    policyBundleProvenance: {
      bundle_id: bundle.bundle_id,
      serial: bundle.serial,
      policy_hash: bundle.policy_hash,
      signer_key_id: bundle.signing_key_id,
      activation_mode: "enforce",
      rollback_authorization_id: rollbackAuthorizationId
    },
    state: next
  };
}

export async function loadSignedPolicyBundleConfig(env) {
  const bundlePath = env.MNDE_PE_POLICY_BUNDLE;
  const authorityPath = env.MNDE_PE_AUTHORITY_BUNDLE;
  const statePath = env.MNDE_PE_POLICY_BUNDLE_STATE;
  const trustedRootFingerprint = env.MNDE_PE_TRUSTED_ROOT_FINGERPRINT;
  if (!bundlePath || !authorityPath || !statePath || !trustedRootFingerprint) return { ok: false, reason: "signed policy bundle requires MNDE_PE_POLICY_BUNDLE, MNDE_PE_AUTHORITY_BUNDLE, MNDE_PE_POLICY_BUNDLE_STATE, and MNDE_PE_TRUSTED_ROOT_FINGERPRINT" };
  let bundle;
  let authorityBundle;
  try {
    bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
    authorityBundle = JSON.parse(readFileSync(authorityPath, "utf8"));
  } catch {
    return { ok: false, reason: "signed policy bundle configuration could not be read" };
  }
  const result = await activateSignedPolicyBundle({ bundle, authorityBundle, trustedRootFingerprint, statePath, now: env.MNDE_PE_BUNDLE_NOW ?? new Date().toISOString() });
  return result.ok ? {
    ok: true,
    policy: result.policy,
    signedPolicyBundle: { policy_id: result.policy_id, serial: result.serial },
    policyBundleProvenance: result.policyBundleProvenance
  } : result;
}
