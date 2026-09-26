// TEST SUPPORT ONLY — one git.push attempt in its own OS process, so the parent
// test can crash or kill it at an exact point in the claim -> start -> push
// window. Real repositories, real production verifier, real signing; the only
// seam is the claim store module, replaced for the whole process by
// claim_backend_hooks.mjs (the parent starts this runner with it preloaded).
//
//   node tests/support/git_push_crash_runner.mjs <mode> <caseDir>
//
// modes:
//   crash-after-claim   the claim is recorded, then the process exits (99)
//                       before the execution start is written or anything sent
//   hang-in-push        the remote's pre-receive hook blocks until the parent
//                       releases it, so the parent can kill this process while
//                       the push is genuinely in flight
//
// Before executing, the runner writes <caseDir>/info.json with the paths and ids
// the parent needs to inspect the aftermath.

import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { createGitPushExecutor } from "../../src/effects/git-push/index.mjs";
import { installClaimBackend } from "./claim_backend_double.mjs";
import {
  ENVIRONMENT_ID,
  EXECUTOR_ID,
  gitPushAuthorization,
  inMemoryClaimBackend,
  makeRepositories,
  productionTrust,
  pushParameters
} from "./git_push_fixtures.mjs";

const [mode, caseDir] = process.argv.slice(2);
process.env.MNDE_PROFILE = "production";

const NAMESPACE = "mnde-git-push-crash-namespace";
const trust = await productionTrust(caseDir);
const repos = makeRepositories(join(caseDir, "repos"));

const inner = inMemoryClaimBackend({ namespace: NAMESPACE });
const claimBackend = mode === "crash-after-claim"
  ? { ...inner, async claim(record) { const r = await inner.claim(record); if (r.status === "CLAIMED") process.exit(99); return r; } }
  : inner;

if (mode === "hang-in-push") {
  const reached = join(caseDir, "REACHED").replace(/\\/g, "/");
  const release = join(caseDir, "RELEASE").replace(/\\/g, "/");
  writeFileSync(join(repos.barePath, "hooks", "pre-receive"),
    `#!/bin/sh\n: > "${reached}"\ni=0\nwhile [ ! -f "${release}" ] && [ $i -lt 600 ]; do sleep 0.1; i=$((i+1)); done\nexit 1\n`,
    { mode: 0o755 });
}

const evidenceDir = join(caseDir, "evidence");
installClaimBackend(claimBackend);
const executor = createGitPushExecutor({
  repoPath: repos.localPath,
  namespace: NAMESPACE,
  authorityBundle: trust.bundle,
  authorityBundlePath: trust.bundlePath,
  trustedRootFingerprint: trust.fingerprint,
  environmentId: ENVIRONMENT_ID,
  expectedExecutorId: EXECUTOR_ID,
  allowedSchemes: ["file"],
  evidenceDir,
  executorIdentity: trust.executor.identity,
  executorSigner: trust.executor.signer
});

const executionId = `exec-crash-${mode}`;
const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
const authorization = await gitPushAuthorization(trust, parameters, { executionId });

writeFileSync(join(caseDir, "info.json"), JSON.stringify({
  evidenceDir, barePath: repos.barePath, remoteUrl: repos.remoteUrl, commits: repos.commits, executionId
}));

const result = await executor.executeGitPush({
  repository: parameters.repository,
  remote: parameters.remote,
  remoteUrl: parameters.remote_url,
  sourceCommit: parameters.source_commit,
  targetRef: parameters.target_ref,
  expectedOldSha: parameters.expected_old_sha,
  authorization
});
writeFileSync(join(caseDir, "result.json"), JSON.stringify({ outcome: result.outcome, reason_code: result.reason_code }));
