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
export function createAdapter({ config, transport, beforeDispatch } = {}) {
  if (typeof transport !== "function") throw new Error("adapter requires an injected transport (offline: a recording stub)");
  if (config && "token" in config) throw new Error("ERR_TOKEN_IN_CONFIG: the adapter config must not carry a credential");

  let dispatched = 0;

  async function attemptMerge(verifiedDeclaration) {
    // AUTHORIZATION BOUNDARY: dispatch requires a declaration that passed the REAL
    // receipt verifier (production brand). A JavaScript brand from the test-only
    // fixture, or a plain {verified:true} object, is NOT sufficient and never
    // reaches the transport.
    if (!isProductionVerified(verifiedDeclaration)) {
      return Object.freeze({
        outcome: ATTEMPT.REFUSED_BEFORE_DISPATCH,
        error: "ERR_NOT_PRODUCTION_VERIFIED",
        dispatched: false, request: null, at: new Date().toISOString()
      });
    }
    // Build + freeze the request BEFORE any await, so a post-verification mutation
    // or the test hook cannot change what is dispatched.
    let request;
    try {
      request = buildMergeRequest(verifiedDeclaration, config);
    } catch (error) {
      return Object.freeze({
        outcome: ATTEMPT.REFUSED_BEFORE_DISPATCH,
        error: error.code ?? String(error?.message ?? error),
        dispatched: false, request: null, at: new Date().toISOString()
      });
    }

    if (typeof beforeDispatch === "function") {
      await beforeDispatch(); // test-only; cannot alter the frozen `request`
    }

    // Exactly one dispatch. No retry on failure/timeout.
    dispatched += 1;
    const at = new Date().toISOString();
    let resp;
    try {
      resp = await transport({ method: request.method, path: request.path, body: request.body });
    } catch (error) {
      // Missing reply / timeout: UNKNOWN. Do NOT auto-retry — a second merge could
      // be a second effect. The observer decides what actually happened.
      return Object.freeze({
        outcome: ATTEMPT.UNKNOWN,
        error: String(error?.message ?? error),
        dispatched: true, dispatchCount: dispatched, request, at
      });
    }
    const s = sanitizeResponse(resp);
    return Object.freeze({
      outcome: ATTEMPT.RESPONDED,
      dispatched: true, dispatchCount: dispatched,
      request,
      httpStatus: s.httpStatus,
      responseBodySanitized: s.body,
      providerRequestId: s.providerRequestId ?? null,
      at
    });
  }

  return { attemptMerge, get dispatchCount() { return dispatched; } };
}
