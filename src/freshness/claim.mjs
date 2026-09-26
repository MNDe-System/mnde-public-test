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
import { isExecutorClaimBackend } from "./postgres_claim.mjs";

// THE CLAIM TICKET — why the raw push cannot run without a durable claim.
//
// A CLAIMED decision is a value, and a value can be forged or reused. So a claim
// made through a backend the executor's own startup opened (never one a caller
// built) also mints a ticket: an opaque object whose only meaning is membership
// in this module-private map. The push primitive in src/effects/git-push/
// transport.mjs redeems it and refuses without it. A ticket
//   - exists only after the durable store acknowledged a FRESH claim;
//   - is bound to the digest of the exact effect it was minted for;
//   - is spent by its first redemption, matching or not.
// Importing the transport directly, or calling claimAuthority with a stub
// backend, therefore yields no push: the stub is not in the adapter's opened set,
// so no ticket is minted.
const CLAIM_TICKETS = new WeakMap();

export const ERR_CLAIM_TICKET = "ERR_CLAIM_TICKET";

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
// the caller sends nothing. `effectDigest` names the one effect a resulting
// ticket may start; without it, or through a backend the executor did not open,
// a CLAIMED decision carries no ticket.
export async function claimAuthority(backend, record, { effectDigest = null } = {}) {
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
    if (!isExecutorClaimBackend(backend) || typeof effectDigest !== "string" || !effectDigest) {
      return { decision: DISPATCH.CLAIMED, claim: res.record, ticket: null };
    }
    const ticket = Object.freeze(Object.create(null));
    CLAIM_TICKETS.set(ticket, Object.freeze({ record: res.record, effect_digest: effectDigest }));
    return { decision: DISPATCH.CLAIMED, claim: res.record, ticket };
  }
  if (res.status === "ALREADY_SPENT") {
    return { decision: DISPATCH.SPENT, claim: res.prior ?? null, collided_on: res.collided_on ?? null };
  }
  return { decision: DISPATCH.UNKNOWN, note: "unrecognized-claim-status" };
}

// Spend a ticket. The entry is deleted before it is compared, so a mismatched
// redemption burns the ticket too: there is no second try with different effect.
export function redeemClaimTicket(ticket, effectDigest) {
  const entry = ticket !== null && typeof ticket === "object" ? CLAIM_TICKETS.get(ticket) : undefined;
  if (!entry) return { ok: false, reason: ERR_CLAIM_TICKET, detail: "no unspent durable claim ticket was presented" };
  CLAIM_TICKETS.delete(ticket);
  if (typeof effectDigest !== "string" || entry.effect_digest !== effectDigest) {
    return { ok: false, reason: ERR_CLAIM_TICKET, detail: "the claim ticket was minted for a different effect" };
  }
  return { ok: true, record: entry.record };
}
