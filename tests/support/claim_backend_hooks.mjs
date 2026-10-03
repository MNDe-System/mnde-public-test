// TEST SUPPORT ONLY — preload with `node --import ./tests/support/claim_backend_hooks.mjs`.
//
// Redirects src/freshness/postgres_claim.mjs to ./claim_backend_double.mjs for
// the whole process. It has to be a preload: ESM links the entire static import
// graph before evaluating any of it, so a hook registered from inside a test
// file would be too late for that file's own imports.

import { registerHooks } from "node:module";

const REAL = "/src/freshness/postgres_claim.mjs";
const DOUBLE = new URL("./claim_backend_double.mjs", import.meta.url).href;

registerHooks({
  resolve(specifier, context, nextResolve) {
    const resolved = nextResolve(specifier, context);
    if (resolved.url.startsWith("file:") && resolved.url.endsWith(REAL)) {
      return { ...resolved, url: DOUBLE, shortCircuit: true };
    }
    return resolved;
  }
});
