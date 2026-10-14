#!/usr/bin/env node
// mnde-git-push-doctor — read-only readiness diagnosis for the git.push executor.
//
//   mnde-git-push-doctor            human-readable report
//   mnde-git-push-doctor --json     one line of JSON (schema mnde.git-push-doctor.v1)
//
// Run it in the shell where you would run mnde-git-push. It runs the executor's
// own startup checks and its claim-store health query, and reports what would
// stop a push. It cannot push, claim, request a credential or write a file; see
// src/effects/git-push/doctor.mjs for the exact boundary.
//
// Exit codes:
//   0  local checks passed (this is NOT a claim that the repository is protected)
//   1  not ready: at least one check FAILED or is NOT_CONFIGURED
//   3  usage error
//   5  internal error

import { renderGitPushDoctor, runGitPushDoctor, VERDICT } from "../src/effects/git-push/doctor.mjs";

const args = process.argv.slice(2);
const json = args.includes("--json");
if (args.some((arg) => arg !== "--json")) {
  process.stderr.write("usage: mnde-git-push-doctor [--json]\n");
  process.exit(3);
}

try {
  const report = await runGitPushDoctor(process.env);
  process.stdout.write(json ? `${JSON.stringify(report)}\n` : renderGitPushDoctor(report));
  process.exitCode = report.verdict === VERDICT.NOT_READY ? 1 : 0;
} catch (error) {
  process.stderr.write(`mnde-git-push-doctor: internal error (${error?.code ?? error?.name ?? "error"})\n`);
  process.exitCode = 5;
}
