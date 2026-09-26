// git.push — isolation from the local repository, and the claim -> push window.
//
//   npm run test:git-push-isolation
//
// Two properties the typed effect needs and test_git_push_effect.mjs does not
// cover:
//
// 1. THE LOCAL REPOSITORY CANNOT STEER THE EFFECT. The agent that produced the
//    commits can write the local repository's `.git/config`. Git honours that file
//    for every command run inside the repository, so if the push ran there, two
//    lines of config — an `ext::` url rewrite plus `protocol.ext.allow` — start an
//    arbitrary program inside a correctly authorized push, and `pushInsteadOf`
//    sends the approved commits to a different remote. Against the pre-fix build
//    the command-execution case below runs the payload. The effect now runs in an
//    executor-owned staging repository that reads the local objects and none of
//    the local configuration.
//
// 2. A CRASH BETWEEN THE CLAIM AND THE OUTCOME IS CLASSIFIABLE. The authority is
//    spent before the push, so "spent, never sent" and "sent, outcome never
//    recorded" both leave a consumed grant and no outcome record. The durable
//    execution-start record separates them; both crash cases below run in a real
//    child process that dies at the exact point.
//
// Everything is real: repositories on disk pushed over file://, executor-bound
// signed authorizations through the production verifier, real signing. The claim
// backend is the suite's in-memory one (see test_git_push_effect.mjs for why).

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";

import {
  classifyGitPushExecution,
  createGitPushExecutor,
  ERR_EXECUTION_START_NOT_RECORDED,
  ERR_REMOTE_MISMATCH,
  OUTCOME
} from "../src/effects/git-push/index.mjs";
import {
  ENVIRONMENT_ID,
  EXECUTOR_ID,
  gitPushAuthorization,
  inMemoryClaimBackend,
  makeRepositories,
  productionTrust,
  pushParameters,
  readJson
} from "./support/git_push_fixtures.mjs";
import { installClaimBackend } from "./support/claim_backend_double.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const RUNNER = join(HERE, "support", "git_push_crash_runner.mjs");
const HOOKS = pathToFileURL(join(HERE, "support", "claim_backend_hooks.mjs")).href;
const NAMESPACE = "mnde-git-push-isolation-namespace";

let passed = 0;
let failed = 0;
const pendingCleanup = [];
function cleanUp() {
  while (pendingCleanup.length) {
    const d = pendingCleanup.pop();
    try { rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* best effort */ }
  }
}
async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    cleanUp();
  }
}

function git(args, cwd) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}
function refAt(bare, ref = "refs/heads/main") {
  try { return git(["--git-dir", bare, "rev-parse", "--verify", "--quiet", ref]); } catch { return null; }
}
const stagingDirs = () => readdirSync(tmpdir()).filter((n) => n.startsWith("mnde-git-push-stage-"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(pred, ms, what) {
  const end = Date.now() + ms;
  while (!pred()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(25);
  }
}

async function main() {
  process.env.MNDE_PROFILE = "production";
  const dir = mkdtempSync(join(tmpdir(), "mnde-git-push-isolation-"));
  const trust = await productionTrust(dir);

  let caseIndex = 0;
  function fixture(startupOverrides = {}) {
    caseIndex += 1;
    const caseDir = join(dir, `case-${caseIndex}`);
    pendingCleanup.push(caseDir);
    const repos = makeRepositories(caseDir);
    const evidenceDir = join(caseDir, "evidence");
    installClaimBackend(inMemoryClaimBackend({ namespace: NAMESPACE }));
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
      executorSigner: trust.executor.signer,
      ...startupOverrides
    });
    return { repos, executor, caseDir, evidenceDir };
  }
  async function pushOnce({ repos, executor }, extra = {}) {
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters, extra);
    return executor.executeGitPush({
      repository: parameters.repository, remote: parameters.remote, remoteUrl: parameters.remote_url,
      sourceCommit: parameters.source_commit, targetRef: parameters.target_ref,
      expectedOldSha: parameters.expected_old_sha, authorization
    });
  }
  // A second bare repository the attacker controls, seeded at the approved old
  // SHA so that a redirected lease WOULD match there and the commits would land.
  function attackerRemote(fx) {
    const evil = join(fx.caseDir, "attacker.git");
    mkdirSync(evil);
    git(["init", "--quiet", "--bare", "--initial-branch=main", "."], evil);
    git(["push", "--quiet", pathToFileURL(evil).href, `${fx.repos.commits[0]}:refs/heads/main`], fx.repos.localPath);
    return evil;
  }

  console.log("── 1. the local repository's config cannot steer the effect ──");

  await test("an ext:: pushInsteadOf rewrite in the local repo does not run a program; the approved push lands", async () => {
    const fx = fixture();
    const marker = join(fx.caseDir, "PAYLOAD-RAN");
    const payload = join(fx.caseDir, "payload.mjs");
    writeFileSync(payload, `(await import("node:fs")).writeFileSync(${JSON.stringify(marker)}, "x");\n`);
    const esc = (s) => s.replace(/\\/g, "/").replace(/ /g, "% ");
    git(["config", "protocol.ext.allow", "always"], fx.repos.localPath);
    git(["config", `url.ext::${esc(process.execPath)} ${esc(payload)}.pushInsteadOf`, fx.repos.remoteUrl], fx.repos.localPath);
    const result = await pushOnce(fx);
    assert.equal(existsSync(marker), false, "a program configured by the local repository ran inside the authorized push");
    assert.equal(result.outcome, OUTCOME.EXECUTED, `${result.outcome}: ${result.reason_code} ${result.detail}`);
    assert.equal(fx.repos.remoteSha(), fx.repos.commits[1]);
  });

  await test("a pushInsteadOf redirect in the local repo cannot send the approved commits elsewhere", async () => {
    const fx = fixture();
    const evil = attackerRemote(fx);
    git(["config", `url.${pathToFileURL(evil).href}.pushInsteadOf`, fx.repos.remoteUrl], fx.repos.localPath);
    const result = await pushOnce(fx);
    assert.equal(result.outcome, OUTCOME.EXECUTED, `${result.outcome}: ${result.reason_code} ${result.detail}`);
    assert.equal(fx.repos.remoteSha(), fx.repos.commits[1], "the approved remote must receive the push");
    assert.equal(refAt(evil), fx.repos.commits[0], "the attacker's remote must receive nothing");
  });

  await test("an insteadOf redirect of the approved URL is refused before anything is claimed or sent", async () => {
    const fx = fixture();
    const evil = attackerRemote(fx);
    git(["config", `url.${pathToFileURL(evil).href}.insteadOf`, fx.repos.remoteUrl], fx.repos.localPath);
    const result = await pushOnce(fx);
    assert.equal(result.outcome, OUTCOME.REFUSED);
    assert.equal(result.reason_code, ERR_REMOTE_MISMATCH);
    assert.equal(fx.repos.remoteSha(), fx.repos.commits[0]);
    assert.equal(refAt(evil), fx.repos.commits[0]);
  });

  await test("local hooks, fsmonitor and ssh/credential programs configured in the local repo never run", async () => {
    const fx = fixture();
    const marker = join(fx.caseDir, "PAYLOAD-RAN");
    const cmd = `"${process.execPath.replace(/\\/g, "/")}" -e "require('fs').writeFileSync('${marker.replace(/\\/g, "/")}','x')"`;
    const hooks = join(fx.caseDir, "agent-hooks");
    mkdirSync(hooks);
    for (const h of ["pre-push", "reference-transaction", "post-checkout"]) writeFileSync(join(hooks, h), `#!/bin/sh\n${cmd}\n`, { mode: 0o755 });
    git(["config", "core.hooksPath", hooks], fx.repos.localPath);
    git(["config", "core.fsmonitor", cmd], fx.repos.localPath);
    git(["config", "core.sshCommand", cmd], fx.repos.localPath);
    git(["config", "credential.helper", `!${cmd}`], fx.repos.localPath);
    const result = await pushOnce(fx);
    assert.equal(result.outcome, OUTCOME.EXECUTED, `${result.outcome}: ${result.reason_code} ${result.detail}`);
    assert.equal(existsSync(marker), false, "a local-repository program ran during the effect");
  });

  await test("the staging repository is removed after every attempt", async () => {
    const before = stagingDirs().length;
    const fx = fixture();
    const ok = await pushOnce(fx);
    assert.equal(ok.outcome, OUTCOME.EXECUTED);
    const replay = await pushOnce(fixture());
    assert.equal(replay.outcome, OUTCOME.EXECUTED);
    assert.equal(stagingDirs().length, before, "a staging repository was left behind");
  });

  console.log("\n── 2. the claim -> outcome window is classifiable ──");

  await test("a completed push leaves a durable start record and classifies as EXECUTED", async () => {
    const fx = fixture();
    const result = await pushOnce(fx, { executionId: "exec-iso-complete" });
    assert.equal(result.outcome, OUTCOME.EXECUTED);
    const start = readJson(join(fx.evidenceDir, "git-push-exec-iso-complete.started.json"));
    assert.equal(start.execution_id, "exec-iso-complete");
    assert.equal(start.authorized.source_commit, fx.repos.commits[1]);
    const c = classifyGitPushExecution({ evidenceDir: fx.evidenceDir, executionId: "exec-iso-complete" });
    assert.equal(c.condition, OUTCOME.EXECUTED);
    assert.equal(c.retry_permitted, false);
  });

  await test("if the start cannot be recorded, nothing is sent", async () => {
    // The evidence directory is an existing FILE, so no record can be created in it.
    caseIndex += 1;
    const blocker = join(dir, `evidence-is-a-file-${caseIndex}`);
    writeFileSync(blocker, "not a directory");
    const fx = fixture({ evidenceDir: blocker });
    const result = await pushOnce(fx);
    assert.equal(result.outcome, OUTCOME.REFUSED);
    assert.equal(result.reason_code, ERR_EXECUTION_START_NOT_RECORDED);
    assert.equal(fx.repos.remoteSha(), fx.repos.commits[0], "a push was sent without a durable start record");
  });

  await test("process dies right after the claim -> NOT_STARTED, remote untouched (real child process)", async () => {
    caseIndex += 1;
    const caseDir = join(dir, `crash-after-claim-${caseIndex}`);
    mkdirSync(caseDir);
    pendingCleanup.push(caseDir);
    const child = spawn(process.execPath, ["--no-warnings", "--import", HOOKS, RUNNER, "crash-after-claim", caseDir], { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (d) => { stderr += d; });
    const code = await new Promise((r) => child.on("exit", (c) => r(c)));
    assert.equal(code, 99, `the runner should die right after its claim (exit ${code}): ${stderr}`);
    const info = readJson(join(caseDir, "info.json"));
    const c = classifyGitPushExecution({ evidenceDir: info.evidenceDir, executionId: info.executionId });
    assert.equal(c.condition, "NOT_STARTED");
    assert.equal(c.retry_permitted, false);
    assert.equal(refAt(info.barePath), info.commits[0], "nothing may have been pushed");
  });

  await test("process killed while the push is in flight -> INDETERMINATE, review required (real child process)", async () => {
    caseIndex += 1;
    const caseDir = join(dir, `killed-in-push-${caseIndex}`);
    mkdirSync(caseDir);
    pendingCleanup.push(caseDir);
    const child = spawn(process.execPath, ["--no-warnings", "--import", HOOKS, RUNNER, "hang-in-push", caseDir], { stdio: ["ignore", "ignore", "pipe"] });
    let exited = false;
    child.on("exit", () => { exited = true; });
    try {
      await waitFor(() => existsSync(join(caseDir, "REACHED")) || exited, 60000, "the push to reach the remote");
      assert.equal(exited, false, "the runner exited before its push reached the remote");
      child.kill("SIGKILL");
      await waitFor(() => exited, 10000, "the runner to die");
    } finally {
      writeFileSync(join(caseDir, "RELEASE"), "go"); // let the orphaned receive-pack finish (it rejects)
    }
    const info = readJson(join(caseDir, "info.json"));
    assert.equal(existsSync(join(caseDir, "result.json")), false, "a killed process cannot have recorded an outcome");
    const c = classifyGitPushExecution({ evidenceDir: info.evidenceDir, executionId: info.executionId });
    assert.equal(c.condition, OUTCOME.INDETERMINATE, JSON.stringify(c));
    assert.equal(c.review_required, true);
    assert.equal(c.retry_permitted, false);
    await sleep(1500); // the orphaned push completes its rejection before cleanup
  });

  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  const total = passed + failed;
  if (failed === 0) console.log(`\nPASS git.push isolation (${passed}/${total})`);
  else { console.error(`\nFAIL git.push isolation (${passed}/${total})`); process.exitCode = 1; }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
