// Activation authority — `mnde.activation.v1` (docs/activation-authority-v1.md).
//
// An activation record is the customer-side authority transition that grants a
// verified release execution authority. It is signed by an `activation` role key
// in the customer's mnde.authority.bundle.v1 — never by the vendor. The vendor
// proves what it shipped (release manifest); the customer proves what they
// allowed (this record); receipts prove what executed (activation_id binding).
//
// Core invariant: no execution may proceed until the active authority
// transition has been verified.
//
// The record is deterministic and self-verifying: `activation_id` is the
// SHA-256 of the canonical record with `activation_id` and `signature` removed,
// and the Ed25519 signature covers that same canonical payload. Tampering with
// any field breaks the id, the signature, or both.

import { sha256 } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";
import {
  evaluateRevocation,
  findBundleKey,
  signCanonical,
  verifyAuthorityBundle,
  verifyCanonical
} from "../custody/bundle.mjs";

export const ACTIVATION_SCHEMA = "mnde.activation.v1";
export const ACTIVATION_KINDS = Object.freeze(["genesis", "upgrade", "rollback", "reinstall"]);

const HEX64 = /^[0-9a-f]{64}$/;

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}
function isValidTimestamp(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}
function invalid(detail) {
  return { ok: false, reason_code: "ERR_ACTIVATION_INVALID", detail };
}
function untrusted(detail) {
  return { ok: false, reason_code: "ERR_ACTIVATION_UNTRUSTED", detail };
}
function chainError(reason_code, detail) {
  return { ok: false, reason_code, detail };
}

// Canonical payload = record with activation_id and signature removed.
// activation_id is derived from this payload, so it cannot be part of it;
// the signature covers the same payload for the same reason.
function canonicalActivationPayload(record) {
  const { activation_id: _id, signature: _sig, ...payload } = record;
  return canonicalizeJson(payload);
}

export function computeActivationId(record) {
  return sha256(canonicalActivationPayload(record));
}

// Structural validation only — no authority bundle required. Used by the local
// runtime profile (custody never loads there) and as step one of full
// verification. A structurally invalid record fails in EVERY profile.
export function validateActivationStructure(record) {
  if (!isObject(record)) return invalid("activation record is not an object");
  if (record.schema_version !== ACTIVATION_SCHEMA) return invalid(`schema_version must be ${ACTIVATION_SCHEMA}`);
  if (!ACTIVATION_KINDS.includes(record.kind)) return invalid(`kind must be one of ${ACTIVATION_KINDS.join(", ")}`);

  if (record.kind === "genesis") {
    if (record.previous_activation_id !== null) return invalid("genesis requires previous_activation_id: null");
  } else if (!HEX64.test(String(record.previous_activation_id ?? ""))) {
    return invalid(`kind '${record.kind}' requires a previous_activation_id (64 hex)`);
  }

  for (const field of ["authority_id", "release_version", "vendor_authority_id"]) {
    if (!isNonEmptyString(record[field])) return invalid(`missing or empty ${field}`);
  }
  for (const field of ["artifact_hash", "release_manifest_hash"]) {
    if (!HEX64.test(String(record[field] ?? ""))) return invalid(`${field} must be 64 lowercase hex characters`);
  }
  if (!isValidTimestamp(record.activated_at)) return invalid("activated_at must be an RFC 3339 timestamp");

  const v = record.verification;
  if (!isObject(v)) return invalid("missing verification block");
  // A record whose verification block reports anything but success must not
  // exist — activation is refused instead of recorded-as-failed. Enforced here
  // so a hand-edited record cannot smuggle an unverified release in.
  if (v.manifest_signature !== "VERIFIED") return invalid("verification.manifest_signature must be VERIFIED");
  if (v.artifact_hash_match !== "VERIFIED") return invalid("verification.artifact_hash_match must be VERIFIED");
  if (v.revocation_status_at_activation !== "NOT_REVOKED") return invalid("verification.revocation_status_at_activation must be NOT_REVOKED");
  if (!HEX64.test(String(v.vendor_root_fingerprint ?? ""))) return invalid("verification.vendor_root_fingerprint must be 64 lowercase hex characters");
  if (!isNonEmptyString(v.verifier_version)) return invalid("missing verification.verifier_version");

  const sig = record.signature;
  if (!isObject(sig)) return invalid("missing signature block");
  if (sig.algorithm !== "ED25519") return invalid("signature.algorithm must be ED25519");
  if (!isNonEmptyString(sig.key_id)) return invalid("missing signature.key_id");
  if (!HEX64.test(String(sig.public_key_fingerprint ?? ""))) return invalid("signature.public_key_fingerprint must be 64 lowercase hex characters");
  if (!isValidTimestamp(sig.signed_at)) return invalid("signature.signed_at must be an RFC 3339 timestamp");
  if (!isNonEmptyString(sig.value)) return invalid("missing signature.value");

  const recomputed = computeActivationId(record);
  if (record.activation_id !== recomputed) return invalid("activation_id does not match the canonical record hash");

  return { ok: true, activation_id: record.activation_id };
}

// Build and sign an activation record with an `activation` role key from the
// customer's authority bundle. The verification block is caller-supplied
// evidence of what was checked BEFORE this call; callers must refuse to build a
// record for anything that did not verify (this function enforces that too).
export async function buildActivationRecord(input) {
  const {
    bundle,
    signingKeyId,
    signingPrivateKeyPem,
    authorityId,
    kind,
    previousActivationId = null,
    releaseVersion,
    artifactHash,
    releaseManifestHash,
    vendorAuthorityId,
    verification,
    channel,
    activatedAt
  } = input;

  if (!isObject(bundle) || !isNonEmptyString(signingKeyId) || !isNonEmptyString(signingPrivateKeyPem)) {
    throw new Error("buildActivationRecord: bundle, signingKeyId, and signingPrivateKeyPem are required");
  }

  const keyResult = findBundleKey(bundle, "activation", signingKeyId, activatedAt);
  if (!keyResult.ok) throw new Error(`buildActivationRecord: activation key not usable: ${keyResult.reason}`);
  if (keyResult.revoked_now) throw new Error("buildActivationRecord: activation key is revoked; refusing to sign a new transition");

  const entry = bundle.keys.activation.find((k) => k.key_id === signingKeyId);

  const body = {
    schema_version: ACTIVATION_SCHEMA,
    authority_id: authorityId,
    kind,
    previous_activation_id: kind === "genesis" ? null : previousActivationId,
    release_version: releaseVersion,
    artifact_hash: artifactHash,
    release_manifest_hash: releaseManifestHash,
    vendor_authority_id: vendorAuthorityId,
    verification,
    ...(channel !== undefined ? { channel } : {}),
    activated_at: activatedAt
  };

  const canonical = canonicalizeJson(body);
  const record = {
    ...body,
    activation_id: sha256(canonical),
    signature: {
      algorithm: "ED25519",
      key_id: signingKeyId,
      public_key_fingerprint: entry.fingerprint,
      signed_at: activatedAt,
      value: await signCanonical(canonical, signingPrivateKeyPem)
    }
  };

  const check = validateActivationStructure(record);
  if (!check.ok) throw new Error(`buildActivationRecord: produced record failed validation: ${check.detail}`);
  return record;
}

// Full offline verification of one activation record against the customer's
// authority bundle (docs/activation-authority-v1.md §13). Fail closed; INVALID
// (structure/hash/signature/chain) is distinct from UNTRUSTED (bundle, key,
// revocation-as-of-event).
//
// options:
//   authorityBundle        — customer mnde.authority.bundle.v1
//   trustedRootFingerprint — out-of-band trust anchor for the bundle
//   previousRecord         — optional: the prior record in the chain
//   now                    — optional: verification-time timestamp
export async function verifyActivationRecord(record, options = {}) {
  const { authorityBundle, trustedRootFingerprint, previousRecord, now } = options;

  const structure = validateActivationStructure(record);
  if (!structure.ok) return structure;

  const bundleCheck = await verifyAuthorityBundle(authorityBundle, { trustedRootFingerprint, now });
  if (!bundleCheck.ok) return untrusted(`authority bundle: ${bundleCheck.reason}`);

  if (record.authority_id !== authorityBundle.authority_id) {
    return untrusted(`record authority_id '${record.authority_id}' does not match bundle authority '${authorityBundle.authority_id}'`);
  }

  const signedAt = record.signature.signed_at;
  const key = findBundleKey(authorityBundle, "activation", record.signature.key_id, signedAt, now);
  if (!key.ok) return untrusted(`activation key '${record.signature.key_id}': ${key.reason}`);

  const signatureOk = await verifyCanonical(canonicalActivationPayload(record), record.signature.value, key.publicKey);
  if (!signatureOk) return invalid("activation signature does not verify");

  // Genesis constraints (§10.1): the genesis record is the first authorized act
  // of a newly created authority — it cannot predate the authority itself.
  if (record.kind === "genesis" && isValidTimestamp(authorityBundle.issued_at)
    && Date.parse(signedAt) < Date.parse(authorityBundle.issued_at)) {
    return invalid("genesis signed_at predates the authority bundle issued_at");
  }

  // Chain linkage against the supplied previous record (§10).
  if (previousRecord !== undefined && previousRecord !== null) {
    if (record.kind === "genesis") {
      return chainError("ERR_ACTIVATION_CHAIN_FORK", "a genesis record cannot follow an existing record");
    }
    if (record.previous_activation_id !== previousRecord.activation_id) {
      return chainError("ERR_ACTIVATION_CHAIN", "previous_activation_id does not match the prior record in the chain");
    }
  }

  // Release revocation — both verdicts (§11). Revoked-as-of-activation makes
  // the activation itself untrustworthy; revoked-now is advisory.
  const releaseRevocation = evaluateRevocation(
    authorityBundle.revocation,
    { artifact_hash: record.artifact_hash, release_version: record.release_version },
    record.activated_at,
    now
  );
  if (releaseRevocation.revoked_as_of_event) {
    return untrusted("release was revoked as of the activation time (REVOKED_AS_OF_EVENT)");
  }

  return {
    ok: true,
    activation_id: record.activation_id,
    authority_id: record.authority_id,
    release_version: record.release_version,
    artifact_hash: record.artifact_hash,
    // Advisory verdicts — the evidence verifies; the operator may still need to act.
    revoked_now: releaseRevocation.revoked_now || key.revoked_now === true
  };
}

// Verify an ordered activation chain (§10): exactly one genesis, first; every
// later record links to its predecessor by activation_id. Structural only —
// callers verify individual record signatures via verifyActivationRecord.
export function verifyActivationChain(records) {
  if (!Array.isArray(records) || records.length === 0) {
    return chainError("ERR_ACTIVATION_CHAIN", "activation chain is empty");
  }
  let genesisCount = 0;
  for (let i = 0; i < records.length; i += 1) {
    const record = records[i];
    const structure = validateActivationStructure(record);
    if (!structure.ok) return chainError("ERR_ACTIVATION_CHAIN", `record ${i}: ${structure.detail}`);
    if (record.kind === "genesis") {
      genesisCount += 1;
      if (i !== 0) return chainError("ERR_ACTIVATION_CHAIN_FORK", `record ${i}: genesis after the chain started`);
    } else if (i === 0) {
      return chainError("ERR_ACTIVATION_CHAIN", "chain does not begin with a genesis record");
    } else if (record.previous_activation_id !== records[i - 1].activation_id) {
      return chainError("ERR_ACTIVATION_CHAIN", `record ${i}: previous_activation_id does not match record ${i - 1}`);
    }
  }
  if (genesisCount !== 1) {
    return chainError("ERR_ACTIVATION_CHAIN_FORK", `expected exactly one genesis record, found ${genesisCount}`);
  }
  return { ok: true, head_activation_id: records[records.length - 1].activation_id, length: records.length };
}
