// TEST SUPPORT ONLY — runs with the REAL src/freshness/postgres_claim.mjs, i.e.
// without claim_backend_hooks.mjs preloaded, so the parent can show what the
// shipped wiring does when no claim store is configured.
//
//   node tests/support/git_push_real_store_runner.mjs <caseDir>

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { createGitPushExecutor } from "../../src/effects/git-push/index.mjs";
import { buildPushArgv, buildTransportEnv, performPush, pushEffectDigest } from "../../src/effects/git-push/transport.mjs";
import { claimAuthority } from "../../src/freshness/claim.mjs";
import {
  ENVIRONMENT_ID,
  EXECUTOR_ID,
  gitPushAuthorization,
  inMemoryClaimBackend,
  makeRepositories,
  productionTrust,
  pushParameters
} from "./git_push_fixtures.mjs";

const [caseDir] = process.argv.slice(2);
mkdirSync(caseDir, { recursive: true });
const NAMESPACE = "mnde-git-push-real-store-namespace";
const trust = await productionTrust(caseDir);
const repos = makeRepositories(join(caseDir, "repos"));
const remoteBefore = repos.remoteSha();

// Is the test double loaded? With the hooks preloaded, the adapter's specifier
// resolves to the double instead; here it must resolve to the real file.
const doubleLoaded = import.meta.resolve("../../src/freshness/postgres_claim.mjs").endsWith("claim_backend_double.mjs");

// A stub claim store, called directly, then its "ticket" handed to the push.
const argv = buildPushArgv({ remoteUrl: repos.remoteUrl, sourceCommit: repos.commits[1], targetRef: "refs/heads/main", expectedOldSha: repos.commits[0] });
const stub = await claimAuthority(inMemoryClaimBackend({ namespace: NAMESPACE }), {
  namespace: NAMESPACE, execution_id: "exec-stub", grant_id: "grant-stub", subject: "s",
  executor_id: EXECUTOR_ID, receipt_hash: "r".repeat(64), aplus_digest: "a".repeat(64)
}, { effectDigest: pushEffectDigest(argv) });
const direct = await performPush(argv, { repoPath: repos.localPath, cwd: repos.localPath, env: buildTransportEnv({}).env, timeoutMs: 30_000 }, stub.ticket);

// The executor, configured for production in every respect except the claim store.
const executor = createGitPushExecutor({
  repoPath: repos.localPath,
  namespace: NAMESPACE,
  authorityBundle: trust.bundle,
  authorityBundlePath: trust.bundlePath,
  trustedRootFingerprint: trust.fingerprint,
  environmentId: ENVIRONMENT_ID,
  expectedExecutorId: EXECUTOR_ID,
  allowedSchemes: ["file"],
  evidenceDir: join(caseDir, "evidence"),
  executorIdentity: trust.executor.identity,
  executorSigner: trust.executor.signer
});
const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
const result = await executor.executeGitPush({
  repository: parameters.repository,
  remote: parameters.remote,
  remoteUrl: parameters.remote_url,
  sourceCommit: parameters.source_commit,
  targetRef: parameters.target_ref,
  expectedOldSha: parameters.expected_old_sha,
  authorization: await gitPushAuthorization(trust, parameters)
});

writeFileSync(join(caseDir, "result.json"), JSON.stringify({
  double_loaded: doubleLoaded,
  stub_ticket: stub.ticket ?? null,
  direct_push_reason: direct.reason ?? null,
  outcome: result.outcome,
  reason_code: result.reason_code,
  claim_decision: result.evidence?.claim?.decision ?? null,
  claim_note: result.evidence?.claim?.note ?? null,
  remote_before: remoteBefore,
  remote_after: repos.remoteSha()
}));
