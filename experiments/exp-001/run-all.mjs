// EXP-001 Stage 1 runner. Executes each attack script as its own process,
// aggregates the per-conjunct evidence into results.json, and pins the commit +
// environment under test. Deterministic order; no network.
//
//   node experiments/exp-001/run-all.mjs

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const expRoot = resolve(dirname(fileURLToPath(import.meta.url)));
const repoRoot = resolve(expRoot, "..", "..");
const evidenceDir = join(expRoot, "evidence");

const SCRIPTS = [
  ["A-encoding", "attacks/a_encoding.mjs", "A_encoding.json"],
  ["C-binding", "attacks/c_binding.mjs", "C_binding.json"],
  ["D-freshness", "attacks/d_freshness.mjs", "D_freshness.json"],
  ["crypto-custody", "attacks/e_crypto_custody.mjs", "E_crypto_custody.json"]
];

function git(args) {
  try { return execFileSync("git", args, { cwd: repoRoot, encoding: "utf8" }).trim(); } catch { return null; }
}

const commit = git(["rev-parse", "HEAD"]);
const branch = git(["rev-parse", "--abbrev-ref", "HEAD"]);
// Dirtiness of everything EXCEPT this experiment package — proves MNDe source is
// untouched regardless of the (untracked) experiment files.
const dirty = git(["status", "--porcelain", "--", ".", ":(exclude)experiments/exp-001"]) ? true : false;

const conjuncts = [];
for (const [name, rel, evidence] of SCRIPTS) {
  process.stdout.write(`\n=== ${name} (${rel}) ===\n`);
  try {
    execFileSync(process.execPath, [join(expRoot, rel)], { cwd: repoRoot, stdio: "inherit" });
  } catch (e) {
    process.stdout.write(`  (script exited non-zero: ${e.status})\n`);
  }
  const data = JSON.parse(readFileSync(join(evidenceDir, evidence), "utf8"));
  conjuncts.push({ name, evidence, ...data });
}

function tally(pred) { return conjuncts.flatMap((c) => c.results).filter(pred).length; }
const allResults = conjuncts.flatMap((c) => c.results);

const results = {
  experiment_id: "MNDE-EXP-001",
  stage: 1,
  title: "Exact Approval Binding — MNDe as-is (no GitHub adapter)",
  mnde_commit: commit,
  branch,
  working_tree_dirty_excluding_experiment: dirty,
  node_version: process.version,
  platform: process.platform,
  run_at: new Date().toISOString(),
  scope: "Tests MNDe's actual claim: exact binding of a declared action to a verified, request-bound, single-use receipt gating a local run() call. No GitHub machinery added; no MNDe source modified.",
  totals: {
    tests: allResults.length,
    pass: tally((r) => r.verdict === "PASS"),
    fail: tally((r) => r.verdict === "FAIL"),
    inconclusive: tally((r) => r.verdict === "INCONCLUSIVE")
  },
  per_conjunct: conjuncts.map((c) => ({
    conjunct: c.name,
    total: c.results.length,
    pass: c.results.filter((r) => r.verdict === "PASS").length,
    fail: c.results.filter((r) => r.verdict === "FAIL").length,
    inconclusive: c.results.filter((r) => r.verdict === "INCONCLUSIVE").length
  })),
  conjuncts
};

writeFileSync(join(expRoot, "results.json"), `${JSON.stringify(results, null, 2)}\n`, "utf8");
process.stdout.write(`\n=== TOTALS ===\n`);
process.stdout.write(`${JSON.stringify(results.totals)} @ ${commit?.slice(0, 10)}\n`);
for (const c of results.per_conjunct) process.stdout.write(`  ${c.conjunct}: ${c.pass}P/${c.fail}F/${c.inconclusive}I of ${c.total}\n`);
