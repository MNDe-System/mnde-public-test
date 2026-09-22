// Signed execution evidence for the git.push typed effect.
//
// WHY THIS IS NOT A RECEIPT. A decision receipt answers "was this exact action
// authorized?". It is signed before anything happens, and it stays true whether
// or not the effect was ever attempted. This answers a different question:
// "what protected effect did the executor actually observe?" — and it can only
// be produced after the attempt. Collapsing the two would let an authorization
// be read as proof of execution, which is the confusion the whole project
// exists to prevent, so the two carry different schema strings and nothing
// accepts one where the other is required.
//
// WHAT IT BINDS. Every field a verifier needs to decide what happened, and
// nothing else. The authorization it descends from (execution id, grant id, the
// receipt's own hash and the authenticated authority digest), the executor that
// acted (id, environment, key, credential), the exact effect that was approved
// (repository, remote, target ref, expected old SHA, approved new SHA), what was
// actually seen (the remote's ref before and after), whether the single-use
// authority was claimed, and the outcome. Mutating any of them breaks the
// signature, because the signature is over the canonical form of the whole body.
//
// WHAT IT DOES NOT CARRY. No secrets, no private key material, no credentials
// from the transport environment, and no captured stderr — git writes remote
// URLs and occasionally credential-helper chatter to stderr, so it stays in the
// local unsigned record and out of the signed, portable one.
//
// EXECUTED IS A CLAIM ABOUT THE REMOTE, NOT ABOUT A PROCESS. Evidence may only
// say EXECUTED when the ref was read back and equals the approved new SHA. That
// rule is enforced when the body is built AND again when it is verified, so a
// body that says EXECUTED while its own observed SHA disagrees is refused even
// though its signature is intact. A correct signature over an incoherent claim
// is not evidence.
//
// OFFLINE. Verification needs the envelope, the authority bundle and the pinned
// root fingerprint. It reaches no network and consults no clock it was not
// given. The executor's public key arrives inside the credential, which is
// itself signed by the root, so the chain is root -> credential -> evidence.

import { canonicalizeJson } from "../../../shared/json.ts";
import { sha256 } from "../../crypto/provider.mjs";
import { verifyCanonical } from "../../custody/bundle.mjs";
import { verifyExecutorCredential } from "../../custody/executor-credential.mjs";
import { EXECUTOR_RECEIPT_CAPABILITY } from "../../custody/executor-identity.mjs";
import { GIT_PUSH_ACTION } from "./validate.mjs";

export const EXECUTION_EVIDENCE_SCHEMA = "mnde.git-push-execution-evidence.v1";
export const EXECUTION_EVIDENCE_ENVELOPE_SCHEMA = "mnde.git-push-execution-evidence-envelope.v1";

// The outcomes evidence may report. Kept identical to the executor's own
// vocabulary so a record never has to be translated between the two.
export const EVIDENCE_OUTCOME = Object.freeze({
  EXECUTED: "EXECUTED",
  REFUSED: "REFUSED",
  RECONCILED_NOT_APPLIED: "RECONCILED_NOT_APPLIED",
  INDETERMINATE: "INDETERMINATE"
});

export const EVIDENCE_ERRORS = Object.freeze({
  INVALID: "ERR_EVIDENCE_INVALID",
  SCHEMA: "ERR_EVIDENCE_SCHEMA_UNSUPPORTED",
  SIGNATURE_INVALID: "ERR_EVIDENCE_SIGNATURE_INVALID",
  CREDENTIAL_INVALID: "ERR_EVIDENCE_CREDENTIAL_INVALID",
  IDENTITY_MISMATCH: "ERR_EVIDENCE_IDENTITY_MISMATCH",
  INCOHERENT: "ERR_EVIDENCE_INCOHERENT",
  SIGNING_FAILED: "ERR_EVIDENCE_SIGNING_FAILED"
});

// Exact key sets. An unknown key is a refusal rather than something ignored:
// a field a verifier does not understand is a field it cannot have checked.
const BODY_KEYS = Object.freeze([
  "action",
  "approved_new_sha",
  "authority_bundle_fingerprint",
  "authority_digest",
  "authorization_receipt_hash",
  "claim",
  "credential_id",
  "effect_attempted",
  "environment_id",
  "execution_id",
  "executor_id",
  "expected_old_sha",
  "grant_id",
  "key_id",
  "observed_after_sha",
  "observed_before_sha",
  "outcome",
  "reason_code",
  "recorded_at",
  "remote",
  "remote_url",
  "repository",
  "schema_version",
  "target_ref"
]);

const CLAIM_KEYS = Object.freeze(["decision", "namespace", "record_digest"]);
const ENVELOPE_KEYS = Object.freeze(["credential", "evidence", "schema_version", "signature"]);
const SIGNATURE_KEYS = Object.freeze(["algorithm", "key_id", "value"]);

const FULL_SHA = /^[0-9a-f]{40}$/;

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function fail(reason_code, detail) {
  return Object.freeze({ ok: false, reason_code, detail });
}

function exactKeys(value, allowed, label) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) return `unknown ${label} field: ${key}`;
  }
  for (const key of allowed) {
    if (!(key in value)) return `missing ${label} field: ${key}`;
  }
  return null;
}

// The one rule that makes EXECUTED mean something. Applied when the body is
// built and again when it is verified, so neither side is trusted to have done
// it. `observed_after_sha` may be null when the remote could not be read, and a
// null observation can never support EXECUTED.
function outcomeContradictsObservation(body) {
  if (body.outcome === EVIDENCE_OUTCOME.EXECUTED) {
    if (body.observed_after_sha !== body.approved_new_sha) {
      return "outcome is EXECUTED but the observed final SHA is not the approved new SHA";
    }
    if (body.effect_attempted !== true) {
      return "outcome is EXECUTED but the effect was not attempted";
    }
  }
  if (body.outcome === EVIDENCE_OUTCOME.REFUSED && body.effect_attempted !== false) {
    return "outcome is REFUSED but the effect was attempted";
  }
  if (body.outcome !== EVIDENCE_OUTCOME.REFUSED && body.effect_attempted !== true) {
    return `outcome is ${body.outcome} but the effect was not attempted`;
  }
  return null;
}

// Build the signable body. Pure: no clock, no filesystem, no network — the
// caller supplies `recorded_at` so the same inputs always produce the same
// bytes, which is what makes the evidence reproducible from a stored record.
export function buildExecutionEvidenceBody(input = {}) {
  if (!isObject(input)) return fail(EVIDENCE_ERRORS.INVALID, "input must be an object");

  const body = {
    schema_version: EXECUTION_EVIDENCE_SCHEMA,
    action: GIT_PUSH_ACTION,

    // Which authorization this descends from.
    execution_id: input.execution_id ?? null,
    grant_id: input.grant_id ?? null,
    authorization_receipt_hash: input.authorization_receipt_hash ?? null,
    authority_digest: input.authority_digest ?? null,

    // Who acted, and under which trust root.
    executor_id: input.executor_id ?? null,
    environment_id: input.environment_id ?? null,
    key_id: input.key_id ?? null,
    credential_id: input.credential_id ?? null,
    authority_bundle_fingerprint: input.authority_bundle_fingerprint ?? null,

    // The exact effect that was approved.
    repository: input.repository ?? null,
    remote: input.remote ?? null,
    remote_url: input.remote_url ?? null,
    target_ref: input.target_ref ?? null,
    expected_old_sha: input.expected_old_sha ?? null,
    approved_new_sha: input.approved_new_sha ?? null,

    // What the executor actually saw.
    observed_before_sha: input.observed_before_sha ?? null,
    observed_after_sha: input.observed_after_sha ?? null,

    // Whether the single-use authority was consumed, and for which record.
    claim: {
      decision: input.claim?.decision ?? null,
      namespace: input.claim?.namespace ?? null,
      record_digest: input.claim?.record_digest ?? null
    },

    effect_attempted: input.effect_attempted === true,
    outcome: input.outcome ?? null,
    reason_code: input.reason_code ?? null,
    recorded_at: input.recorded_at ?? null
  };

  const shape = exactKeys(body, BODY_KEYS, "evidence");
  if (shape) return fail(EVIDENCE_ERRORS.INVALID, shape);

  for (const field of ["execution_id", "grant_id", "executor_id", "environment_id", "recorded_at"]) {
    if (!isNonEmptyString(body[field])) {
      return fail(EVIDENCE_ERRORS.INVALID, `${field} must be a non-empty string`);
    }
  }
  if (!Object.values(EVIDENCE_OUTCOME).includes(body.outcome)) {
    return fail(EVIDENCE_ERRORS.INVALID, `unsupported outcome: ${String(body.outcome)}`);
  }
  for (const field of ["expected_old_sha", "approved_new_sha"]) {
    if (!FULL_SHA.test(String(body[field]))) {
      return fail(EVIDENCE_ERRORS.INVALID, `${field} must be a full lowercase 40-hex SHA`);
    }
  }
  for (const field of ["observed_before_sha", "observed_after_sha"]) {
    const value = body[field];
    if (value !== null && !FULL_SHA.test(String(value))) {
      return fail(EVIDENCE_ERRORS.INVALID, `${field} must be null or a full lowercase 40-hex SHA`);
    }
  }

  const incoherent = outcomeContradictsObservation(body);
  if (incoherent) return fail(EVIDENCE_ERRORS.INCOHERENT, incoherent);

  return Object.freeze({ ok: true, body: Object.freeze(body) });
}

// Sign a built body with the executor's own key. The private key never leaves
// the caller's signer; only the signature comes back.
export async function signExecutionEvidence(body, { identity, signer } = {}) {
  if (!isObject(body)) return fail(EVIDENCE_ERRORS.INVALID, "body must be an object");
  if (!isObject(identity)) return fail(EVIDENCE_ERRORS.INVALID, "no executor identity supplied");
  if (typeof signer?.sign !== "function") return fail(EVIDENCE_ERRORS.INVALID, "no executor signer supplied");

  // The body must already name the identity that is about to sign it, or the
  // signature would attest to an executor the body does not claim.
  if (
    body.executor_id !== identity.executor_id ||
    body.key_id !== identity.key_id ||
    body.credential_id !== identity.credential_id ||
    body.environment_id !== identity.environment_id
  ) {
    return fail(EVIDENCE_ERRORS.IDENTITY_MISMATCH, "evidence body does not name the signing executor");
  }

  let value;
  try {
    value = await signer.sign(canonicalizeJson(body));
  } catch {
    return fail(EVIDENCE_ERRORS.SIGNING_FAILED, "the executor signer threw");
  }
  if (!isNonEmptyString(value)) {
    return fail(EVIDENCE_ERRORS.SIGNING_FAILED, "the executor signer returned no signature");
  }

  return Object.freeze({
    ok: true,
    envelope: Object.freeze({
      schema_version: EXECUTION_EVIDENCE_ENVELOPE_SCHEMA,
      evidence: body,
      credential: structuredClone(identity.credential),
      signature: { algorithm: "ED25519", key_id: identity.key_id, value }
    })
  });
}

// Verify an envelope offline. Fail-closed at every step: anything unrecognized,
// malformed, mismatched or merely unproven is a refusal, never a pass.
export async function verifyExecutionEvidence(envelope, options = {}) {
  if (!isObject(envelope)) return fail(EVIDENCE_ERRORS.INVALID, "envelope is not an object");
  if (envelope.schema_version !== EXECUTION_EVIDENCE_ENVELOPE_SCHEMA) {
    return fail(EVIDENCE_ERRORS.SCHEMA, "unsupported envelope schema_version");
  }
  const envelopeShape = exactKeys(envelope, ENVELOPE_KEYS, "envelope");
  if (envelopeShape) return fail(EVIDENCE_ERRORS.INVALID, envelopeShape);

  const body = envelope.evidence;
  if (!isObject(body)) return fail(EVIDENCE_ERRORS.INVALID, "evidence is not an object");
  if (body.schema_version !== EXECUTION_EVIDENCE_SCHEMA) {
    return fail(EVIDENCE_ERRORS.SCHEMA, "unsupported evidence schema_version");
  }
  const bodyShape = exactKeys(body, BODY_KEYS, "evidence");
  if (bodyShape) return fail(EVIDENCE_ERRORS.INVALID, bodyShape);
  if (!isObject(body.claim)) return fail(EVIDENCE_ERRORS.INVALID, "claim is not an object");
  const claimShape = exactKeys(body.claim, CLAIM_KEYS, "claim");
  if (claimShape) return fail(EVIDENCE_ERRORS.INVALID, claimShape);

  // This evidence type describes one action and refuses to speak for any other.
  if (body.action !== GIT_PUSH_ACTION) {
    return fail(EVIDENCE_ERRORS.INVALID, `evidence action is not ${GIT_PUSH_ACTION}`);
  }
  if (!Object.values(EVIDENCE_OUTCOME).includes(body.outcome)) {
    return fail(EVIDENCE_ERRORS.INVALID, `unsupported outcome: ${String(body.outcome)}`);
  }

  const signature = envelope.signature;
  if (!isObject(signature)) return fail(EVIDENCE_ERRORS.INVALID, "signature is not an object");
  const signatureShape = exactKeys(signature, SIGNATURE_KEYS, "signature");
  if (signatureShape) return fail(EVIDENCE_ERRORS.INVALID, signatureShape);
  if (signature.algorithm !== "ED25519") {
    return fail(EVIDENCE_ERRORS.INVALID, `unsupported signature algorithm: ${String(signature.algorithm)}`);
  }
  if (!isNonEmptyString(signature.value)) return fail(EVIDENCE_ERRORS.INVALID, "signature value is empty");

  // A body that contradicts itself is refused before any cryptography runs. A
  // valid signature over an incoherent claim would otherwise read as proof.
  const incoherent = outcomeContradictsObservation(body);
  if (incoherent) return fail(EVIDENCE_ERRORS.INCOHERENT, incoherent);

  // The credential is what carries the executor's public key, and it is signed
  // by the root, so this is where the chain is anchored.
  const credentialCheck = await verifyExecutorCredential(envelope.credential, {
    authorityBundle: options.authorityBundle,
    trustedRootFingerprint: options.trustedRootFingerprint,
    environmentId: body.environment_id,
    expectedExecutorId: body.executor_id,
    requiredCapability: EXECUTOR_RECEIPT_CAPABILITY,
    now: options.now
  });
  if (!credentialCheck.ok) {
    return fail(EVIDENCE_ERRORS.CREDENTIAL_INVALID, credentialCheck.detail ?? credentialCheck.code ?? "credential rejected");
  }

  // The credential, the body and the signature must all name one executor.
  if (
    credentialCheck.key_id !== body.key_id ||
    credentialCheck.key_id !== signature.key_id ||
    credentialCheck.credential_id !== body.credential_id ||
    credentialCheck.environment_id !== body.environment_id ||
    credentialCheck.executor_id !== body.executor_id
  ) {
    return fail(EVIDENCE_ERRORS.IDENTITY_MISMATCH, "credential, evidence and signature do not name one executor");
  }

  // Optional pinning by the caller: a verifier that knows which executor and
  // environment it will accept says so, rather than accepting any valid one.
  if (isNonEmptyString(options.expectedExecutorId) && options.expectedExecutorId !== body.executor_id) {
    return fail(EVIDENCE_ERRORS.IDENTITY_MISMATCH, "evidence was signed by a different executor than expected");
  }
  if (isNonEmptyString(options.expectedEnvironmentId) && options.expectedEnvironmentId !== body.environment_id) {
    return fail(EVIDENCE_ERRORS.IDENTITY_MISMATCH, "evidence names a different environment than expected");
  }

  let signatureValid = false;
  try {
    signatureValid = await verifyCanonical(canonicalizeJson(body), signature.value, credentialCheck.public_key);
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) return fail(EVIDENCE_ERRORS.SIGNATURE_INVALID, "evidence signature does not verify");

  return Object.freeze({
    ok: true,
    evidence: body,
    executed: body.outcome === EVIDENCE_OUTCOME.EXECUTED,
    executor_id: body.executor_id,
    evidence_digest: sha256(canonicalizeJson(body))
  });
}
