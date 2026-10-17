// TEST SUPPORT ONLY — preload: `node --import ./tests/support/witness_hooks.mjs`.
// Everything claim_backend_hooks.mjs does, plus redirecting src/freshness/spend_witness.mjs to
// ./witness_double.mjs for the whole process (see that file).
import "./claim_backend_hooks.mjs";
import { registerHooks } from "node:module";

const REAL = "/src/freshness/spend_witness.mjs";
const DOUBLE = new URL("./witness_double.mjs", import.meta.url).href;

registerHooks({
  resolve(specifier, context, nextResolve) {
    const resolved = nextResolve(specifier, context);
    if (resolved.url.startsWith("file:") && resolved.url.endsWith(REAL)) return { ...resolved, url: DOUBLE, shortCircuit: true };
    return resolved;
  }
});
