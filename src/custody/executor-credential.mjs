// Executor credential `mnde.executor.credential.v1` + fixed one-hop verifier.
//
// Phase 0 (Design A): the EXISTING custody authority bundle is the ONLY issuing
// authority. An executor credential is a short-lived, authority-signed statement
// binding a stable executor_id to that executor's own Ed25519 public key. It is
// how MNDe answers "which agent instance signed this execution" WITHOUT creating
// a parallel CA, a second trust root, or a new identity framework.
//
// Trust chain is FIXED and one hop only:
//
//   trusted root fingerprint (out of band)
//     -> authority bundle root_key            (verifyAuthorityBundle)
//       -> executor credential                (issuer_signature by the root key)
//
// There is no path building, no nested intermediates, no executor-issued
// credentials, and no ignored optional fields. A credential carrying any key
// outside the allow-list below fails closed.
//
// Issuance is an AUTHORITY-SIDE operation: it needs the root PRIVATE key, which
// production custody deliberately never loads into the running decision server.
// Credentials are minted by offline authority tooling (or local-demo in tests)
// and the resulting PUBLIC credential is deployed beside the executor's private
// key. Verification is fully offline and reuses the bundle's own primitives.

import { sha256 } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";
import {
  fingerprintOf,
  verifyAuthorityBundle,
  verifyCanonical
} from "./bundle.mjs";
import { createFileRootSigner, signWithRootSigner } from "./root-signer.mjs";

export const EXECUTOR_CREDENTIAL_SCHEMA = "mnde.executor.credential.v1";

// The single migration epoch for this phase. A credential from any other epoch
// is rejected — there is no general epoch machinery in Phase 0.
export const EXECUTOR_TRUST_EPOCH = "executor-identity-v1";

// Stable, documented error codes. Part of the credential contract. Trust
// failures are never collapsed into a generic internal error.
export const EXECUTOR_CREDENTIAL_ERRORS = Object.freeze({
  MISSING: "ERR_EXECUTOR_CREDENTIAL_MISSING",
  INVALID: "ERR_EXECUTOR_CREDENTIAL_INVALID",
  EXPIRED: "ERR_EXECUTOR_CREDENTIAL_EXPIRED",
  IDENTITY_MISMATCH: "ERR_EXECUTOR_IDENTITY_MISMATCH",
  ENVIRONMENT_MISMATCH: "ERR_EXECUTOR_ENVIRONMENT_MISMATCH",
  KEY_MISMATCH: "ERR_EXECUTOR_KEY_MISMATCH",
  CAPABILITY_DENIED: "ERR_EXECUTOR_CAPABILITY_DENIED"
});

// Exact set of keys a credential may carry. Anything else is a signed-object
// smuggling attempt and fails closed (hostile: "unknown fields inserted").
const ALLOWED_CREDENTIAL_KEYS = Object.freeze([
  "schema_version",
  "credential_id",
  "executor_id",
  "key_id",
  "public_key",
  "issuer_id",
  "issuer_key_id",
  "environment_id",
  "issued_at",
  "not_before",
  "expires_at",
  "capabilities",
  "trust_epoch",
  "signature_algorithm",
  "issuer_signature"
]);

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isValidTimestamp(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}
function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

// Deterministic executor key id derived from the public key. Changes when (and
// only when) the key changes; the executor_id stays stable across rotation.
export function executorKeyId(publicKeyPem) {
  return `mnde-exk:${fingerprintOf(publicKeyPem).slice(0, 32)}`;
}

// Deterministic credential id over the credential body EXCLUDING credential_id
// and issuer_signature. Binds the id to the content; recomputed on verify.
function computeCredentialId(bodyWithoutIdAndSignature) {
  return `mnde-cred:${sha256(canonicalizeJson(bodyWithoutIdAndSignature)).slice(0, 32)}`;
}

function bodyForId(credentialLike) {
  const { credential_id: _id, issuer_signature: _sig, ...rest } = credentialLike;
  return rest;
}
function bodyForSignature(credentialLike) {
  const { issuer_signature: _sig, ...rest } = credentialLike;
  return rest;
}

// Issue (authority-side). Signs the credential with the bundle ROOT capability.
//
// options:
//   authorityBundle  loaded mnde.authority.bundle.v1 (public material)
//   rootSigner       root-signing capability (production callers resolve it via
//                    resolveRootSigner so external-root mode cannot use a PEM)
//   rootPrivatePem   Ed25519 private key PEM for authorityBundle.root_key
//   executorId       stable executor id (e.g. mnde:local:prod:executor:codex:01)
//   publicPem        the executor's OWN Ed25519 public key PEM
//   environmentId    environment scope string
//   capabilities     array of capability strings (sorted for determinism)
//   issuedAt/notBefore/expiresAt  ISO-8601 timestamps (short-lived)
export async function issueExecutorCredential(options) {
  const {
    authorityBundle,
    rootSigner,
    rootPrivatePem,
    executorId,
    publicPem,
    environmentId,
    capabilities,
    issuedAt,
    notBefore,
    expiresAt
  } = options ?? {};

  if (!isObject(authorityBundle) || !isObject(authorityBundle.root_key)) {
    throw new Error("issueExecutorCredential: authorityBundle with root_key is required");
  }
  if (!rootSigner && !isNonEmptyString(rootPrivatePem)) throw new Error("issueExecutorCredential: rootPrivatePem or rootSigner is required");
  if (!isNonEmptyString(executorId)) throw new Error("issueExecutorCredential: executorId is required");
  if (!isNonEmptyString(publicPem)) throw new Error("issueExecutorCredential: publicPem is required");
  if (!isNonEmptyString(environmentId)) throw new Error("issueExecutorCredential: environmentId is required");
  if (!isValidTimestamp(issuedAt) || !isValidTimestamp(notBefore) || !isValidTimestamp(expiresAt)) {
    throw new Error("issueExecutorCredential: issuedAt, notBefore, expiresAt must be valid timestamps");
  }
  if (Date.parse(expiresAt) <= Date.parse(notBefore)) {
    throw new Error("issueExecutorCredential: expiresAt must be after notBefore");
  }
  const caps = Array.isArray(capabilities) ? [...capabilities] : [];
  if (!caps.every(isNonEmptyString)) throw new Error("issueExecutorCredential: capabilities must be non-empty strings");
  caps.sort();

  const core = {
    schema_version: EXECUTOR_CREDENTIAL_SCHEMA,
    executor_id: executorId,
    key_id: executorKeyId(publicPem),
    public_key: publicPem,
    issuer_id: authorityBundle.authority_id,
    issuer_key_id: authorityBundle.root_key.key_id,
    environment_id: environmentId,
    issued_at: issuedAt,
    not_before: notBefore,
    expires_at: expiresAt,
    capabilities: caps,
    trust_epoch: EXECUTOR_TRUST_EPOCH,
    signature_algorithm: "ED25519"
  };
  const credential_id = computeCredentialId(core);
  const signedBody = { ...core, credential_id };
  const root = {
    keyId: authorityBundle.root_key.key_id,
    publicPem: authorityBundle.root_key.public_key,
    fingerprint: authorityBundle.root_key.fingerprint
  };
  // Production callers must pass a capability obtained from resolveRootSigner;
  // the inline PEM adapter remains for backward-compatible offline tooling.
  const signer = rootSigner ?? createFileRootSigner({
    keyId: root.keyId,
    publicKeyPem: root.publicPem,
    privateKeyPem: rootPrivatePem
  });
  const signature = await signWithRootSigner(signer, canonicalizeJson(signedBody), root);
  return { ...signedBody, issuer_signature: signature.value };
}

function fail(code, detail) {
  return { ok: false, code, detail };
}

// Verify (fixed one-hop). Every field carried in the credential is validated;
// none is decorative. Returns { ok:true, executor_id, key_id, credential_id,
// public_key, capabilities, environment_id, trust_epoch } or { ok:false, code }.
//
// options:
//   authorityBundle        the issuing bundle (its root_key is the one hop)
//   trustedRootFingerprint out-of-band anchor; the bundle is not self-trusted
//   environmentId          required environment match
//   expectedExecutorId     optional exact executor_id the caller expects
//   requiredCapability     optional capability that must be granted
//   now                    ISO-8601 verification time (defaults to wall clock)
export async function verifyExecutorCredential(credential, options = {}) {
  if (credential === null || credential === undefined) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.MISSING, "no credential supplied");
  }
  if (!isObject(credential)) return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "credential is not an object");

  // 0) Strict shape: exact schema, no unknown keys, required fields well-typed.
  if (credential.schema_version !== EXECUTOR_CREDENTIAL_SCHEMA) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "unsupported schema_version");
  }
  for (const key of Object.keys(credential)) {
    if (!ALLOWED_CREDENTIAL_KEYS.includes(key)) {
      return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, `unknown credential field: ${key}`);
    }
  }
  for (const key of ALLOWED_CREDENTIAL_KEYS) {
    if (!(key in credential)) return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, `missing credential field: ${key}`);
  }
  if (
    !isNonEmptyString(credential.credential_id) ||
    !isNonEmptyString(credential.executor_id) ||
    !isNonEmptyString(credential.key_id) ||
    !isNonEmptyString(credential.public_key) ||
    !isNonEmptyString(credential.issuer_id) ||
    !isNonEmptyString(credential.issuer_key_id) ||
    !isNonEmptyString(credential.environment_id) ||
    !isNonEmptyString(credential.issuer_signature)
  ) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "malformed credential field");
  }
  if (credential.signature_algorithm !== "ED25519") {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "unsupported signature_algorithm");
  }
  if (!Array.isArray(credential.capabilities) || !credential.capabilities.every(isNonEmptyString)) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "malformed capabilities");
  }

  // 1) The one hop: the bundle's root must be the trusted anchor and the bundle
  //    itself must verify (root fingerprint, root signature, freshness).
  const bundle = options.authorityBundle;
  if (!isObject(bundle) || !isObject(bundle.root_key)) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "issuing bundle unavailable");
  }
  const bundleOk = await verifyAuthorityBundle(bundle, {
    trustedRootFingerprint: options.trustedRootFingerprint,
    now: options.now
  });
  if (!bundleOk.ok) return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, `issuing bundle untrusted: ${bundleOk.reason}`);

  // 2) Issuer binding: the credential must name THIS bundle's authority + root.
  if (credential.issuer_id !== bundle.authority_id) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "issuer_id does not match authority bundle");
  }
  if (credential.issuer_key_id !== bundle.root_key.key_id) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "issuer_key_id does not match bundle root key");
  }

  // 3) Environment + executor identity.
  if (isNonEmptyString(options.environmentId) && credential.environment_id !== options.environmentId) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.ENVIRONMENT_MISMATCH, "credential environment does not match runtime");
  }
  if (isNonEmptyString(options.expectedExecutorId) && credential.executor_id !== options.expectedExecutorId) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.IDENTITY_MISMATCH, "credential executor_id does not match expected");
  }

  // 4) Epoch.
  if (credential.trust_epoch !== EXECUTOR_TRUST_EPOCH) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "unexpected trust_epoch");
  }

  // 5) key_id must derive from the carried public key.
  let derivedKeyId;
  try {
    derivedKeyId = executorKeyId(credential.public_key);
  } catch {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "public_key is not a valid Ed25519 public key");
  }
  if (derivedKeyId !== credential.key_id) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.KEY_MISMATCH, "key_id does not derive from public_key");
  }

  // 6) credential_id must be the deterministic hash of the body.
  if (computeCredentialId(bodyForId(credential)) !== credential.credential_id) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "credential_id does not match body");
  }

  // 7) Validity window.
  if (!isValidTimestamp(credential.issued_at) || !isValidTimestamp(credential.not_before) || !isValidTimestamp(credential.expires_at)) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "malformed credential timestamps");
  }
  const nowIso = options.now ?? new Date().toISOString();
  if (!isValidTimestamp(nowIso)) return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "invalid now");
  const nowMs = Date.parse(nowIso);
  if (nowMs < Date.parse(credential.not_before)) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.EXPIRED, "credential is not yet valid");
  }
  if (nowMs >= Date.parse(credential.expires_at)) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.EXPIRED, "credential has expired");
  }

  // 8) Capability.
  if (isNonEmptyString(options.requiredCapability) && !credential.capabilities.includes(options.requiredCapability)) {
    return fail(EXECUTOR_CREDENTIAL_ERRORS.CAPABILITY_DENIED, `capability not granted: ${options.requiredCapability}`);
  }

  // 9) Issuer signature over the full body (credential_id included), by the root.
  const signatureValid = await verifyCanonical(
    canonicalizeJson(bodyForSignature(credential)),
    credential.issuer_signature,
    bundle.root_key.public_key
  );
  if (!signatureValid) return fail(EXECUTOR_CREDENTIAL_ERRORS.INVALID, "issuer signature invalid");

  return {
    ok: true,
    executor_id: credential.executor_id,
    key_id: credential.key_id,
    credential_id: credential.credential_id,
    public_key: credential.public_key,
    capabilities: [...credential.capabilities],
    environment_id: credential.environment_id,
    trust_epoch: credential.trust_epoch
  };
}
