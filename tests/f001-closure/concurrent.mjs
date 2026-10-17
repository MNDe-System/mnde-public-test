// TEST SUPPORT ONLY — concurrency probes for the F-001 closure harness.
//
//   node tests/f001-closure/concurrent.mjs claims <N>             N concurrent claims, real adapter + real PostgreSQL
//   node tests/f001-closure/concurrent.mjs execute <N> <request>  N concurrent executeGitPush() of ONE authorization
//
// Environment is the production operator environment (see closure.mjs). Prints one
// JSON line of counts; the parent measures the remote independently.
import { readFileSync } from "node:fs";

import { createGitPushExecutor } from "../../src/effects/git-push/index.mjs";
import { loadGitPushStartup } from "../../src/effects/git-push/startup.mjs";
import { openExecutorClaimBackend } from "../../src/freshness/postgres_claim.mjs";

const [mode, countArg, requestPath] = process.argv.slice(2);
const count = Number(countArg);
const tally = (values) => values.reduce((acc, v) => { acc[v] = (acc[v] ?? 0) + 1; return acc; }, {});

if (mode === "claims") {
  const backend = await openExecutorClaimBackend();
  const namespace = JSON.parse(readFileSync(process.env.MNDE_CLAIM_CONFIG, "utf8")).namespace;
  const unique = `c${Date.now()}${Math.random().toString(16).slice(2)}`;
  const results = await Promise.all(Array.from({ length: count }, (_, i) => backend.claim({
    namespace, execution_id: `${unique}-exec-${i}`, grant_id: `${unique}-grant`, subject: "s",
    executor_id: "e", receipt_hash: "r".repeat(64), aplus_digest: "a".repeat(64)
  }).then((r) => r.status, (e) => `THROW:${e.message}`)));
  console.log(JSON.stringify({ mode, count, tally: tally(results) }));
} else if (mode === "witness") {
  const { openExecutorSpendWitness } = await import("../../src/freshness/spend_witness.mjs");
  const witness = openExecutorSpendWitness(process.env);
  const unique = `w${Date.now()}${Math.random().toString(16).slice(2)}`;
  const namespace = JSON.parse(readFileSync(process.env.MNDE_CLAIM_CONFIG, "utf8")).namespace;
  const results = await Promise.all(Array.from({ length: count }, (_, i) => witness.consume({
    namespace, grant_id: `${unique}-grant`, execution_id: `${unique}-exec-${i}`, executor_id: process.env.MNDE_EXECUTOR_ID,
    receipt_hash: "r".repeat(64), aplus_digest: "a".repeat(64)
  }).then((r) => r.decision, (e) => `THROW:${e.message}`)));
  console.log(JSON.stringify({ mode, count, tally: tally(results) }));
} else if (mode === "execute") {
  const loaded = await loadGitPushStartup(process.env);
  if (!loaded.ok) { console.log(JSON.stringify({ mode, startup_failed: loaded.reason_code ?? loaded.detail })); process.exit(4); }
  const executor = createGitPushExecutor(loaded.startup);
  const request = JSON.parse(readFileSync(requestPath, "utf8"));
  const results = await Promise.all(Array.from({ length: count }, () => executor.executeGitPush(request).then((r) => `${r.outcome}${r.reason_code ? `:${r.reason_code}` : ""}`, (e) => `THROW:${e.message}`)));
  console.log(JSON.stringify({ mode, count, tally: tally(results) }));
  loaded.signer.destroy?.();
} else {
  console.error("usage: concurrent.mjs claims <N> | execute <N> <request.json>");
  process.exit(2);
}
