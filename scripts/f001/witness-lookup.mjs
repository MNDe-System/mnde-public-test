#!/usr/bin/env node
// witness-lookup — read-only reconciliation against the spend witness, with the EXECUTOR's own configuration.
//
//   MNDE_WITNESS_CONFIG=/abs/witness-client.json node scripts/f001/witness-lookup.mjs \
//     --namespace <ns> --grant-id <id> --execution-id <id>
//
// Prints one JSON line: FOUND (the authorization is consumed: never reuse it), NOT_FOUND (the witness has no record;
// the authority may still be spent locally, so issue a NEW authorization), or UNKNOWN (the answer could not be verified).
// It consumes nothing and changes nothing. The answer is signed by the witness and verified against the pinned key.
import { openExecutorSpendWitness } from "../../src/freshness/spend_witness.mjs";

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, v, i, all) => (v.startsWith("--") ? [...acc, [v.slice(2), all[i + 1]]] : acc), []));
if (!args.namespace || !args["grant-id"] || !args["execution-id"]) {
  process.stderr.write("usage: witness-lookup --namespace <ns> --grant-id <id> --execution-id <id>   (MNDE_WITNESS_CONFIG must be set)\n");
  process.exit(2);
}
let witness;
try { witness = openExecutorSpendWitness(process.env); } catch (error) { process.stdout.write(`${JSON.stringify({ decision: "UNKNOWN", detail: String(error.message) })}\n`); process.exit(1); }
if (!witness) { process.stdout.write(`${JSON.stringify({ decision: "UNKNOWN", detail: "MNDE_WITNESS_CONFIG is not set" })}\n`); process.exit(1); }
const result = await witness.lookup({ namespace: args.namespace, grant_id: args["grant-id"], execution_id: args["execution-id"] });
process.stdout.write(`${JSON.stringify(result)}\n`);
process.exit(result.decision === "FOUND" || result.decision === "NOT_FOUND" ? 0 : 1);
