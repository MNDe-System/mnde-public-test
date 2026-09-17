// EXP-001 Stage 2 offline test runner.
//
// Runs ONLY the Stage 2 tests, each in its own process with the network guard
// pre-imported (`--import tests/_guard.mjs`) so any accidental real network call
// fails immediately. Does NOT touch experiments/exp-001/ (the frozen baseline).
//
//   node experiments/exp-001-stage2/run-tests.mjs

import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = resolve(dirname(fileURLToPath(import.meta.url)));
// --import needs a file:// URL on Windows (absolute C:\ paths are rejected).
const guard = pathToFileURL(join(here, "tests", "_guard.mjs")).href;
const TESTS = [
  "tests/test_build_request.mjs",
  "tests/test_evidence.mjs",
  "tests/test_adapter.mjs",
  "tests/test_verify_failclosed.mjs",
  "tests/test_verify_positive.mjs",
  "tests/test_freshness.mjs"
];

let failures = 0;
for (const t of TESTS) {
  process.stdout.write(`\n=== ${t} ===\n`);
  try {
    execFileSync(process.execPath, ["--import", guard, join(here, t)], { stdio: "inherit" });
  } catch {
    failures += 1;
  }
}
process.stdout.write(`\n=== Stage 2 offline units: ${failures === 0 ? "ALL FILES PASS" : `${failures} FILE(S) FAILED`} ===\n`);
process.exit(failures === 0 ? 0 : 1);
