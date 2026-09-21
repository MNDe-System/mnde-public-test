// Durable single-use claim protocol — MNDe's answer to F-001.
//
// F-001 in one sentence: a verified receipt is a signature, and a signature can
// be presented twice. Nothing in a receipt makes it single-use, so after a crash,
// a restart, or a restore of executor-local files the same authentic ALLOW would
// authorize the same effect again. The answer is not another signature check. It
// is to SPEND the authority somewhere the executor cannot rewind, before the
// effect happens.
//
// This file is the protocol half. The store half is src/freshness/postgres_claim.mjs
// and deployment/freshness/postgres.sql, which were run against a real PostgreSQL
// primary in docs/F001-CLAIM-STORE-PROOF.md — 22 of 22, including the case F-001
// names (a fresh execution id reusing a spent grant id is refused).
//
// Promoted out of experiments/exp-001-stage2/src/freshness.mjs, which was written
// against that experiment's merge-specific declaration. The protocol is unchanged;
// what changed is that the claim record is now derived from the action-agnostic
// authority minted by src/execution-authority/index.mjs, so a second typed effect
// reuses this file untouched.
//
// THE SAFETY GOAL IS AT-MOST-ONCE ATTEMPT, NOT EXACTLY-ONCE EFFECT. A claim made
// immediately before a crash consumes the authority without producing the effect.
// That is a deliberate fail-closed outcome: an authority that might have been used
// is treated as used. The alternative — re-spending on uncertainty — is F-001.

import { isProductionExecutionAuthority } from "../execution-authority/index.mjs";

export const DISPATCH = Object.freeze({
  CLAIMED: "CLAIMED",                       // fresh: proceed to exactly one dispatch
  SPENT: "SPENT",                           // already claimed: refuse, never re-send
  UNKNOWN: "UNKNOWN",                       // claim uncertain: send nothing, no retry
  NO_BACKEND: "NO_BACKEND",                 // no durable backend: fail closed (F-001)
  BACKEND_UNAVAILABLE: "BACKEND_UNAVAILABLE",
  NO_NAMESPACE: "NO_NAMESPACE"
});

export const ERR_NOT_PRODUCTION_VERIFIED = "ERR_NOT_PRODUCTION_VERIFIED";
export const ERR_NAMESPACE_MISMATCH = "ERR_NAMESPACE_MISMATCH";
export const ERR_AUTHORITY_IDENTITY = "ERR_AUTHORITY_IDENTITY";
export const ERR_NO_EXECUTION_ID = "ERR_NO_EXECUTION_ID";

// The exact column set the deployed schema accepts. Ordering is irrelevant; the
// set is not — the adapter refuses a record with an extra or missing field, so a
// change here without a schema migration fails closed rather than silently
// widening what a claim covers.
const CLAIM_FIELDS = Object.freeze(["grant_id", "subject", "executor_id", "receipt_hash", "aplus_digest"]);

// Build the claim record from a verified authority.
//
// The namespace is TRUSTED CONFIG and never an agent-supplied field: it is the
// server-side identity the executor login is bound to, and letting a request
// choose it would let one executor spend another's authority.
export function deriveClaimRecord(authority, { namespace } = {}) {
  if (typeof namespace !== "string" || namespace.length === 0) return { ok: false, reason: DISPATCH.NO_NAMESPACE };
  // The brand, not a field. An object literal claiming `ok: true` cannot get here.
  if (!isProductionExecutionAuthority(authority)) return { ok: false, reason: ERR_NOT_PRODUCTION_VERIFIED };
  if (authority.trust?.namespace !== null && authority.trust?.namespace !== namespace) {
    return { ok: false, reason: ERR_NAMESPACE_MISMATCH };
  }

  const record = Object.freeze({
    namespace,
    execution_id: typeof authority.execution_id === "string" ? authority.execution_id : null,
    grant_id: authority.grant_id ?? null,
    subject: typeof authority.subject === "string" ? authority.subject : null,
    executor_id: authority.executor_id ?? null,
    receipt_hash: authority.receipt_hash,
    // Historical column name, kept because the schema is deployed and proven.
    // It carries the digest of the whole authenticated action, so a claim is
    // bound to WHAT was authorized, not merely to its id.
    aplus_digest: authority.authority_digest
  });

  for (const field of CLAIM_FIELDS) {
    if (typeof record[field] !== "string" || !record[field]) return { ok: false, reason: ERR_AUTHORITY_IDENTITY };
  }
  if (!record.execution_id) return { ok: false, reason: ERR_NO_EXECUTION_ID };
  return { ok: true, record };
}

// Attempt the durable claim. NEVER retries; on uncertainty returns UNKNOWN and
// the caller sends nothing.
export async function claimAuthority(backend, record) {
  if (!backend) return { decision: DISPATCH.NO_BACKEND };

  let health;
  try { health = await backend.health(); } catch { return { decision: DISPATCH.BACKEND_UNAVAILABLE }; }
  if (!health || health.ok !== true) return { decision: DISPATCH.BACKEND_UNAVAILABLE };

  let res;
  try {
    res = await backend.claim(record);
  } catch {
    // The claim submission failed, timed out, or the acknowledgement was lost.
    // Do ONE consistent lookup. If the claim is durably present it is SPENT and
    // must never be re-sent. Otherwise the outcome is genuinely UNKNOWN and we
    // send nothing — no blind claim-and-dispatch.
    try {
      const look = await backend.lookup(record);
      if (look?.found === true && look.record?.namespace === record.namespace
        && (look.record.execution_id === record.execution_id || look.record.grant_id === record.grant_id)) {
        return { decision: DISPATCH.SPENT, claim: look.record, note: "claim-ack-lost-but-durably-present" };
      }
    } catch { /* the lookup is uncertain too; fall through to UNKNOWN */ }
    return { decision: DISPATCH.UNKNOWN };
  }

  if (!res || typeof res.status !== "string") return { decision: DISPATCH.UNKNOWN, note: "contradictory-backend" };
  if (res.status === "CLAIMED") {
    // A status flag without an exact durable acknowledgement is not authority.
    if (!res.record || Object.keys(record).some((k) => res.record[k] !== record[k])) {
      return { decision: DISPATCH.UNKNOWN, note: "inconsistent-ack" };
    }
    return { decision: DISPATCH.CLAIMED, claim: res.record };
  }
  if (res.status === "ALREADY_SPENT") {
    return { decision: DISPATCH.SPENT, claim: res.prior ?? null, collided_on: res.collided_on ?? null };
  }
  return { decision: DISPATCH.UNKNOWN, note: "unrecognized-claim-status" };
}
