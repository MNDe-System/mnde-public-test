#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const claimHook = "./tests/support/claim_backend_hooks.mjs";
const hubHook = "./tests/support/hub_observation_hooks.mjs";
const suites = [
  ["hub", "test_hub", hubHook],
  ["git-push-cli", "test_git_push_cli"],
  ["git-push-credential-custody", "test_git_push_credential_custody"],
  ["git-push-effect", "test_git_push_effect", claimHook],
  ["git-push-execution-evidence", "test_git_push_execution_evidence", claimHook],
  ["git-push-first-run", "test_git_push_first_run"],
  ["git-push-isolation", "test_git_push_isolation", claimHook],
  ["git-push-reachability", "test_git_push_reachability"],
  ["git-push-single-route", "test_git_push_single_route", claimHook],
  ["authenticated-approvals", "test_authenticated_approvals"],
  ["policy-engine", "test_policy_engine"],
  ["policy-receipt", "test_policy_receipt"],
  ["policy-trust", "test_policy_trust"],
  ["signed-policy-bundle", "test_signed_policy_bundle"],
  ["policy-bundle-provenance", "test_policy_bundle_provenance"],
  ["historical-policy-bundle-verification", "test_historical_policy_bundle_verification"],
  ["conformance-vectors", "test_conformance_vectors"],
  ["pe-receipt-v2", "test_pe_receipt_v2"],
  ["executor-readiness", "test_executor_readiness"],
  ["executor-key-path-security", "test_executor_key_path_security"],
  ["crypto-provider", "test_crypto_provider"],
  ["receipt-signing-key-status", "test_receipt_signing_key_status"],
  ["executor-credential", "test_executor_credential"],
  ["custody", "test_custody"],
  ["authority-init", "test_authority_init"],
  ["release-boundary", "test_release_boundary"]
];

let passed = 0;
const failures = [];
for (const [name, file, preload] of suites) {
  process.stdout.write(`\n=== ${name} ===\n`);
  const args = [...(preload ? ["--import", preload] : []), `./tests/${file}.mjs`];
  const result = spawnSync(process.execPath, args, { cwd: root, encoding: "utf8", maxBuffer: 20 * 1024 * 1024 });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.status === 0) passed += 1;
  else failures.push({ name, status: result.status, error: result.error?.message ?? null });
}
process.stdout.write(`\nRelease suites: ${passed}/${suites.length} passed, ${failures.length} failed, 0 skipped\n`);
if (failures.length) {
  for (const failure of failures) process.stderr.write(`${failure.name}: ${failure.status ?? failure.error}\n`);
  process.exitCode = 1;
}
