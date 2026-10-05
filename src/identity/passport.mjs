// Passport subject derivation for mnde.execution_passport.v1.
//
// Derives a stable, cross-run identifier for "who was executing" from the
// fields that OIDC verification actually proved — not from caller-supplied
// executor metadata like executor.id, runner id, hostname, or container id.
//
// Formula:
//   passport_subject_id = "sha256:" + sha256(canonicalize({
//     schema:           "mnde.passport_subject.v1",
//     issuer:           identity_issuer from assertion,
//     verified_identity: verified_identity from assertion,
//     authority_scope:   authority_chain_id from the signed result envelope
//   }))
//
// Stability contract:
//   - STABLE across: multiple runs, executor restart, key rotation, container
//     recreation, workflow run ID change, runner ID change, timestamp change.
//   - CHANGES when: verified_identity changes (different repo/branch/actor),
//     issuer changes (GitHub vs GitLab vs anything else), or authority_scope
//     changes (different MNDe authority chain).
//
// executor.id must NOT be used as the Passport subject. It is caller-supplied,
// can change every run, and has no verified provenance. Record it as
// executor_instance_id evidence under the passport, never as the passport key.

import { sha256 } from "../crypto/provider.mjs";

import { canonicalizeJson } from "../../shared/json.ts";

export const PASSPORT_SUBJECT_SCHEMA = "mnde.passport_subject.v1";

// Derive passport_subject_id from its three verified inputs.
//
// issuer           — token issuer URL (from identity_assertion.identity_issuer)
// verified_identity — verified JWT subject (from identity_assertion.verified_identity)
// authority_scope  — authority_chain_id from the signed result envelope
//
// Returns "sha256:<64-hex>".
export function computePassportSubjectId({ issuer, verified_identity, authority_scope }) {
  if (typeof issuer !== "string" || issuer.length === 0) {
    throw new Error("computePassportSubjectId: issuer must be a non-empty string");
  }
  if (typeof verified_identity !== "string" || verified_identity.length === 0) {
    throw new Error("computePassportSubjectId: verified_identity must be a non-empty string");
  }
  if (typeof authority_scope !== "string" || authority_scope.length === 0) {
    throw new Error("computePassportSubjectId: authority_scope must be a non-empty string");
  }

  const subject = {
    schema: PASSPORT_SUBJECT_SCHEMA,
    authority_scope,
    issuer,
    verified_identity
  };

  return "sha256:" + sha256(canonicalizeJson(subject));
}

// Derive passport_subject_id from a verified identity_assertion and the
// authority_chain_id from the signed result envelope.
//
// Returns "sha256:<64-hex>", or null if assertion is absent/null.
// Does NOT re-verify the assertion — callers must already have verified it.
export function derivePassportSubjectId(identityAssertion, authorityScope) {
  if (identityAssertion == null) return null;
  return computePassportSubjectId({
    issuer: identityAssertion.identity_issuer,
    verified_identity: identityAssertion.verified_identity,
    authority_scope: authorityScope
  });
}
