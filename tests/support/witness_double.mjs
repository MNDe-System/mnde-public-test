// TEST SUPPORT ONLY — loaded in place of src/freshness/spend_witness.mjs by witness_hooks.mjs.
// Everything real is re-exported unchanged; only the executor's entry point
// (openExecutorSpendWitness) can be handed a client over an in-process transport, because the
// executor itself refuses to be handed a witness by its caller (the same rule as the claim store).
import * as real from "../../src/freshness/spend_witness.mjs?real";
export * from "../../src/freshness/spend_witness.mjs?real";

const KEY = Symbol.for("mnde.test.installedSpendWitness");

// undefined => behave as production (read MNDE_WITNESS_CONFIG); null => no witness; client => that client.
export function installWitnessClient(client) {
  if (client === undefined) delete globalThis[KEY]; else globalThis[KEY] = client;
}

export function openExecutorSpendWitness(env, options) {
  return Object.hasOwn(globalThis, KEY) ? globalThis[KEY] : real.openExecutorSpendWitness(env, options);
}
