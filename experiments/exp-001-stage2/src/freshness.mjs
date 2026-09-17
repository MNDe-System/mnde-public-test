import { isProductionVerified } from "./declaration.mjs";
// EXP-001 Stage 2 — freshness: derive the claim identity from a verified
// declaration and perform the at-most-once durable claim before dispatch.
//
// Safety goal: one verified execution authority causes AT MOST ONE protected
// dispatch attempt, even across process restart or restoration of executor-local
// files. This is at-most-once ATTEMPT, not exactly-once effect: a claim made just
// before a crash may consume authority without an effect — an acceptable
// fail-closed outcome.

import { CLAIM } from "./claim_store.mjs";

export const DISPATCH = Object.freeze({
  CLAIMED: "CLAIMED",                 // fresh: proceed to exactly one dispatch
  SPENT: "SPENT",                     // already claimed: refuse, never re-send
  UNKNOWN: "UNKNOWN",                 // claim uncertain: send nothing, no retry
  NO_BACKEND: "NO_BACKEND",           // no durable backend configured: fail closed (F-001)
  BACKEND_UNAVAILABLE: "BACKEND_UNAVAILABLE",
  NO_NAMESPACE: "NO_NAMESPACE"
});

// Build the claim record. The namespace is TRUSTED CONFIG, never an agent field.
// Every identity component is taken from the verified declaration (authenticated
// A⁺ + executor identity + receipt hash).
export function deriveClaimRecord(decl, { namespace } = {}) {
  if (typeof namespace !== "string" || namespace.length === 0) return { ok: false, reason: DISPATCH.NO_NAMESPACE };
  if (!isProductionVerified(decl)) return { ok: false, reason: "ERR_NOT_PRODUCTION_VERIFIED" };
  if (decl.trust.namespace !== null && decl.trust.namespace !== namespace) return { ok: false, reason: "ERR_NAMESPACE_MISMATCH" };
  const d = decl.declaration;
  const record = Object.freeze({
    namespace,
    execution_id: typeof d.executionId === "string" ? d.executionId : null,
    grant_id: d.grant_id ?? null,
    subject: typeof d.subject === "string" ? d.subject : null,
    executor_id: decl?.trust?.executor_id ?? null,
    receipt_hash: decl.receiptHash,
    aplus_digest: decl.aplusDigest
  });
  for (const field of ["grant_id", "subject", "executor_id", "receipt_hash", "aplus_digest"]) {
    if (typeof record[field] !== "string" || !record[field]) return { ok: false, reason: "ERR_AUTHORITY_IDENTITY" };
  }
  if (!record.execution_id) return { ok: false, reason: "ERR_NO_EXECUTION_ID" };
  return { ok: true, record };
}

// Attempt the durable claim. Never retries; on uncertainty returns UNKNOWN.
export async function claimAuthority(backend, record) {
  if (!backend) return { decision: DISPATCH.NO_BACKEND };
  let health;
  try { health = await backend.health(); } catch { return { decision: DISPATCH.BACKEND_UNAVAILABLE }; }
  if (!health || health.ok !== true) return { decision: DISPATCH.BACKEND_UNAVAILABLE };

  let res;
  try {
    res = await backend.claim(record);
  } catch {
    // Claim submission failed / timed out / ack lost. Do ONE consistent lookup.
    // If the claim is durably present, it is SPENT (never re-send). Otherwise the
    // outcome is genuinely UNKNOWN and we send nothing — no blind claim+dispatch.
    try {
      const look = await backend.lookup(record);
      if (look?.found === true && look.record?.namespace === record.namespace
        && (look.record.execution_id === record.execution_id || look.record.grant_id === record.grant_id)) return { decision: DISPATCH.SPENT, claim: look.record, note: "claim-ack-lost-but-durably-present" };
    } catch { /* lookup also uncertain */ }
    return { decision: DISPATCH.UNKNOWN };
  }
  if (!res || typeof res.status !== "string") return { decision: DISPATCH.UNKNOWN, note: "contradictory-backend" };
  if (res.status === CLAIM.CLAIMED) {
    // A status flag without an exact durable acknowledgement is not authority.
    if (!res.record || Object.keys(record).some(k => res.record[k] !== record[k])) return { decision: DISPATCH.UNKNOWN, note: "inconsistent-ack" };
    return { decision: DISPATCH.CLAIMED, claim: res.record };
  }
  if (res.status === CLAIM.ALREADY_SPENT) return { decision: DISPATCH.SPENT, claim: res.prior ?? null, collided_on: res.collided_on ?? null };
  return { decision: DISPATCH.UNKNOWN, note: "unrecognized-claim-status" };
}
