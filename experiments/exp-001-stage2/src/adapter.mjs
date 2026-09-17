// EXP-001 Stage 2 — Unit 3: adapter skeleton with ONE stubbed merge call site.
//
// The adapter builds the fixed request (Unit 1) from a verified declaration and
// dispatches it through an INJECTED transport exactly once. The adapter itself
// opens no network connection — the transport is the only egress, and in the
// future live adapter process it (and only it) would hold the write credential.
// Agent code and the declaration cannot supply a token or a URL.
//
// The adapter returns an ATTEMPT RECORD, never "effect confirmed". A missing
// reply/timeout is UNKNOWN and never triggers an automatic second merge; outcome
// classification is the observer + validator's job (Unit 2).

import { buildMergeRequest } from "./build_request.mjs";
import { isProductionVerified } from "./declaration.mjs";
import { deriveClaimRecord, claimAuthority, DISPATCH } from "./freshness.mjs";

export const ATTEMPT = Object.freeze({ RESPONDED: "RESPONDED", UNKNOWN: "UNKNOWN", REFUSED_BEFORE_DISPATCH: "REFUSED_BEFORE_DISPATCH" });

// Strip anything token-like from a transport response before recording it.
function sanitizeResponse(resp) {
  if (!resp || typeof resp !== "object") return { httpStatus: null, body: null };
  const headers = {};
  for (const [k, v] of Object.entries(resp.headers ?? {})) {
    if (/^(authorization|proxy-authorization|cookie|set-cookie|x-.*-token)$/i.test(k)) continue;
    headers[k] = v;
  }
  return {
    httpStatus: typeof resp.status === "number" ? resp.status : null,
    body: resp.body ?? null,
    providerRequestId: resp.headers?.["x-github-request-id"] ?? resp.providerRequestId ?? null,
    headers
  };
}

// config: { owner, repo, target_ref }  — pins the adapter; holds NO token field.
// transport: async ({ method, path, body }) => { status, body, headers }  — the
//   ONLY egress. A test transport records the request and returns a simulated
//   response; it must not be a real network client in this offline build.
// beforeDispatch (TEST-ONLY): async () => void, awaited after the request is
//   frozen and before dispatch, so a fixture can mutate the MODELLED external
//   head. It receives nothing that can change the action or URL.
// config: { owner, repo, target_ref, namespace }  — namespace is TRUSTED config,
//   used to scope durable claims; it is never taken from an agent field.
// claimBackend: the durable, out-of-rollback-domain claim service (§ claim_store).
//   REQUIRED for the protected path. Absent/unhealthy => refuse (F-001 fail-closed).
export function createAdapter({ config, transport, beforeDispatch, claimBackend } = {}) {
  if (typeof transport !== "function") throw new Error("adapter requires an injected transport (offline: a recording stub)");
  if (config && "token" in config) throw new Error("ERR_TOKEN_IN_CONFIG: the adapter config must not carry a credential");

  let dispatched = 0;
  const refused = (error, extra = {}) => Object.freeze({
    outcome: ATTEMPT.REFUSED_BEFORE_DISPATCH, error, dispatched: false, request: null, at: new Date().toISOString(), ...extra
  });

  async function attemptMerge(verifiedDeclaration) {
    // 1) AUTHORIZATION BOUNDARY: dispatch requires the exact-action production
    //    brand (verified executor-bound v2). A wiring brand, the test-only
    //    fixture, or a {verified:true} object never reaches the claim or transport.
    if (!isProductionVerified(verifiedDeclaration)) return refused("ERR_NOT_PRODUCTION_VERIFIED");

    // 2) Build + freeze the request from the signed A⁺ BEFORE any await.
    let request;
    try {
      request = buildMergeRequest(verifiedDeclaration, config);
    } catch (error) {
      return refused(error.code ?? String(error?.message ?? error));
    }

    // 3) FRESHNESS: atomically claim the authority in the durable, out-of-domain
    //    backend BEFORE any transport. The adapter derives the claim itself from
    //    the verified declaration + trusted namespace — it never trusts a
    //    caller-supplied "claimed" flag.
    const derived = deriveClaimRecord(verifiedDeclaration, { namespace: config?.namespace });
    if (!derived.ok) return refused(derived.reason);
    const claim = await claimAuthority(claimBackend, derived.record);

    if (claim.decision === DISPATCH.NO_BACKEND) return refused("ERR_NO_CLAIM_BACKEND", { claim });
    if (claim.decision === DISPATCH.BACKEND_UNAVAILABLE) return refused("ERR_CLAIM_BACKEND_UNAVAILABLE", { claim });
    if (claim.decision === DISPATCH.SPENT) return refused("ERR_AUTHORITY_SPENT", { claim }); // prior is for inspection only
    if (claim.decision === DISPATCH.UNKNOWN) {
      // Claim outcome unknown → send NOTHING, no retry. Operator reconciliation.
      return Object.freeze({ outcome: ATTEMPT.UNKNOWN, error: "ERR_CLAIM_UNKNOWN", dispatched: false, request: null, claim, at: new Date().toISOString() });
    }
    // claim.decision === CLAIMED → proceed to exactly one dispatch.

    if (typeof beforeDispatch === "function") {
      await beforeDispatch(); // test-only; cannot alter the frozen `request`
    }

    // 4) Exactly one dispatch. No retry on failure/timeout, and NO re-claim.
    dispatched += 1;
    const at = new Date().toISOString();
    let resp;
    try {
      resp = await transport({ method: request.method, path: request.path, body: request.body });
    } catch (error) {
      // Lost provider response: UNKNOWN. Do NOT auto-retry and do NOT re-claim —
      // the authority is already spent. Observation + operator reconciliation.
      return Object.freeze({
        outcome: ATTEMPT.UNKNOWN, error: String(error?.message ?? error),
        dispatched: true, dispatchCount: dispatched, request, claim, at
      });
    }
    const s = sanitizeResponse(resp);
    return Object.freeze({
      outcome: ATTEMPT.RESPONDED,
      dispatched: true, dispatchCount: dispatched,
      request, claim,
      httpStatus: s.httpStatus,
      responseBodySanitized: s.body,
      providerRequestId: s.providerRequestId ?? null,
      at
    });
  }

  return { attemptMerge, get dispatchCount() { return dispatched; } };
}
