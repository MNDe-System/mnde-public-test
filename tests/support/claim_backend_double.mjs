// TEST SUPPORT ONLY — stands in for src/freshness/postgres_claim.mjs.
//
// The git.push executor opens its own durable claim store; no caller can hand it
// one. That leaves tests two choices: run a real PostgreSQL primary (the
// deployment proof does, see deployment/freshness/claim-store-proof.mjs), or
// replace the adapter MODULE for the whole test process. This file is that
// replacement. ./claim_backend_hooks.mjs redirects every import of
// src/freshness/postgres_claim.mjs here, so the executor, claim.mjs and the
// transport all see this module and nothing else, exactly as in production they
// all see the real one.
//
// It is loaded only through `node --import ./tests/support/claim_backend_hooks.mjs`.
// Nothing shipped imports tests/ (test_git_push_reachability.mjs, layer 5), and a
// process started without the hook gets the real adapter, which refuses without
// MNDE_CLAIM_CONFIG — so forgetting the hook fails closed, never open.

const INSTALLED = Symbol.for("mnde.test.claim-backend-double.installed");
const OPENED = new WeakSet();

// The backend the next executor constructed in this process will open. `null`
// models a deployment with no claim store configured.
export function installClaimBackend(backend) {
  globalThis[INSTALLED] = backend ?? null;
}

export async function openExecutorClaimBackend() {
  if (arguments.length) throw new Error("ERR_BACKEND_SUBSTITUTION");
  const backend = globalThis[INSTALLED] ?? null;
  if (!backend) throw new Error("ERR_CLAIM_CONFIG");
  OPENED.add(backend);
  return backend;
}

export function isExecutorClaimBackend(value) {
  return value !== null && typeof value === "object" && OPENED.has(value);
}
