#!/usr/bin/env node
// verify-git-push-evidence — check a signed git.push execution evidence file
// offline, against a published authority bundle and a root fingerprint obtained
// out of band. Reads no keys and needs no network, claim store or repository.
//
//   node scripts/verify-git-push-evidence.mjs <git-push-….signed.json> \
//     --authority-bundle <authority.bundle.json> \
//     --root-fingerprint <sha256 hex> \
//     [--expected-executor-id <id>] [--expected-environment-id <id>]
//
// Prints one line of JSON and exits 0 only when the evidence verifies. What a
// verified record means, and what it does not, is in
// src/effects/git-push/evidence.mjs.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyExecutionEvidence } from "../src/effects/git-push/evidence.mjs";

const KNOWN = new Set(["authority-bundle", "root-fingerprint", "expected-executor-id", "expected-environment-id"]);
const USAGE = "usage: node scripts/verify-git-push-evidence.mjs <evidence.signed.json> --authority-bundle <path> --root-fingerprint <hex> [--expected-executor-id <id>] [--expected-environment-id <id>]\n";

async function main() {
  const [evidencePath, ...rest] = process.argv.slice(2);
  const args = {};
  for (let i = 0; i < rest.length; i += 2) {
    if (!rest[i]?.startsWith("--") || rest[i + 1] === undefined) { process.stderr.write(USAGE); process.exit(2); }
    args[rest[i].slice(2)] = rest[i + 1];
  }
  if (!evidencePath || Object.keys(args).some((key) => !KNOWN.has(key)) || !args["authority-bundle"] || !args["root-fingerprint"]) {
    process.stderr.write(USAGE);
    process.exit(2);
  }
  let envelope;
  let bundle;
  try {
    envelope = JSON.parse(readFileSync(evidencePath, "utf8"));
    bundle = JSON.parse(readFileSync(args["authority-bundle"], "utf8"));
  } catch (error) {
    process.stdout.write(`${JSON.stringify({ ok: false, reason: `could not read input (${error?.code ?? error?.name ?? "error"})` })}\n`);
    process.exit(1);
  }
  const verdict = await verifyExecutionEvidence(envelope, {
    authorityBundle: bundle,
    trustedRootFingerprint: args["root-fingerprint"],
    expectedExecutorId: args["expected-executor-id"],
    expectedEnvironmentId: args["expected-environment-id"]
  });
  const evidence = verdict.ok ? envelope.evidence : null;
  process.stdout.write(`${JSON.stringify({
    ok: verdict.ok === true,
    reason_code: verdict.ok ? null : (verdict.reason_code ?? null),
    detail: verdict.ok ? null : (verdict.detail ?? null),
    outcome: evidence?.outcome ?? null,
    execution_id: evidence?.execution_id ?? null,
    executor_id: evidence?.executor_id ?? null,
    grant_id: evidence?.grant_id ?? null,
    repository: evidence?.repository ?? null,
    target_ref: evidence?.target_ref ?? null,
    expected_old_sha: evidence?.expected_old_sha ?? null,
    approved_new_sha: evidence?.approved_new_sha ?? null,
    observed_before_sha: evidence?.observed_before_sha ?? null,
    observed_after_sha: evidence?.observed_after_sha ?? null
  })}\n`);
  process.exit(verdict.ok ? 0 : 1);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    process.stderr.write(`verify-git-push-evidence: ${error?.message ?? String(error)}\n`);
    process.exit(1);
  });
}
