// git.push — the production CLI is a front door, not a second path.
//
//   npm run test:git-push-cli
//
// bin/mnde-git-push.mjs is the supported production caller of the typed git.push
// executor. This suite runs that file as a separate OS process, exactly as an
// operator would, and checks that it adds nothing of its own: every push goes
// through createGitPushExecutor(), each invocation calls executeGitPush() at most
// once, request input can never reach startup configuration, and every outcome
// other than an observed EXECUTED exits non-zero.
//
// Three things are measured from outside the CLI rather than from what it prints:
//   - the remote's ref, read with git;
//   - every push the remote RECEIVED, logged by a post-receive hook in the bare
//     repository, so "no push" means the remote saw nothing, not merely that the
//     ref ended where it started;
//   - every executor construction and executeGitPush() call, logged by a
//     test-only preload (tests/support/git_push_cli_counting_hooks.mjs).
//
// The claim store here is a test double that keeps claims as files so a replay
// can be a second process (tests/support/git_push_cli_claim_store.mjs). It proves
// the CLI reaches the claim; it proves nothing about durability. The cases with
// no or bad claim configuration run WITHOUT the double, against the real adapter.

import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, normalize, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { verifyExecutionEvidence } from "../src/effects/git-push/evidence.mjs";
import { classifyGitPushExecution } from "../src/effects/git-push/index.mjs";
import {
  ENVIRONMENT_ID,
  EXECUTOR_ID,
  gitPushAuthorization,
  makeRepositories,
  productionTrust,
  pushParameters,
  writeCredentialConfig
} from "./support/git_push_fixtures.mjs";
import { issueExecutorCredential } from "../src/custody/executor-credential.mjs";
import { EXECUTOR_RECEIPT_CAPABILITY } from "../src/custody/executor-identity.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const SOURCE_CLI = join(ROOT, "bin", "mnde-git-push.mjs");
const COUNTING = pathToFileURL(join(HERE, "support", "git_push_cli_counting_hooks.mjs")).href;
const CLAIM_DOUBLE = pathToFileURL(join(HERE, "support", "git_push_cli_claim_store.mjs")).href;
const NAMESPACE = "mnde-git-push-cli-namespace";

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  [PASS] ${name}`); }
  catch (error) { failed += 1; console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.stack : String(error)}`); }
}

const dir = mkdtempSync(join(tmpdir(), "mnde-git-push-cli-"));
const trust = await productionTrust(dir);

// Operator files, outside the repository, as a deployment would have them.
const operatorDir = join(dir, "operator");
mkdirSync(operatorDir, { recursive: true });
const keyPath = join(operatorDir, "executor-key.pem");
writeFileSync(keyPath, trust.executor.keys.privatePem, { encoding: "utf8", mode: 0o600 });
const credentialPath = join(operatorDir, "executor-credential.json");
writeFileSync(credentialPath, `${JSON.stringify(trust.executor.credential, null, 2)}\n`, "utf8");
// Present so the CLI's startup check passes. The claim-store double replaces the
// adapter that would read it; the real adapter rejects its shape.
const doubleClaimConfigPath = join(operatorDir, "claim-config.test-double.json");
writeFileSync(doubleClaimConfigPath, `${JSON.stringify({ note: "replaced by the test claim double" })}\n`, "utf8");

function git(args, cwd) {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

// Every push the remote receives appends one line per updated ref. When the file
// `move-away` exists, the hook then moves the ref to the SHA it names, which
// makes the pusher's read-back see a third SHA: an ambiguous outcome.
const POST_RECEIVE = `#!/bin/sh
cat >> received.log
if [ -f move-away ]; then git update-ref refs/heads/main "$(cat move-away)"; fi
`;

let caseIndex = 0;
function newCase() {
  caseIndex += 1;
  const caseDir = join(dir, `case-${caseIndex}`);
  const repos = makeRepositories(caseDir);
  writeFileSync(join(repos.barePath, "hooks", "post-receive"), POST_RECEIVE, { encoding: "utf8", mode: 0o755 });
  const claimDir = join(caseDir, "claims");
  mkdirSync(claimDir, { recursive: true });
  return {
    caseDir,
    repos,
    claimDir,
    evidenceDir: join(caseDir, "evidence"),
    callLog: join(caseDir, "calls.log"),
    received: () => {
      const path = join(repos.barePath, "received.log");
      return existsSync(path) ? readFileSync(path, "utf8").split("\n").filter(Boolean).length : 0;
    }
  };
}

function operatorEnv(c, overrides = {}) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) if (!key.startsWith("MNDE_")) env[key] = value;
  Object.assign(env, {
    MNDE_PROFILE: "production",
    MNDE_CLAIM_CONFIG: doubleClaimConfigPath,
    MNDE_GIT_CREDENTIAL_CONFIG: c.repos.credentialConfigPath,
    MNDE_GIT_PUSH_REPO_PATH: c.repos.localPath,
    MNDE_GIT_PUSH_NAMESPACE: NAMESPACE,
    MNDE_GIT_PUSH_EVIDENCE_DIR: c.evidenceDir,
    MNDE_GIT_PUSH_ALLOWED_SCHEMES: "file",
    MNDE_VERIFY_AUTHORITY_BUNDLE: trust.bundlePath,
    MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT: trust.fingerprint,
    MNDE_VERIFY_ENVIRONMENT_ID: ENVIRONMENT_ID,
    MNDE_VERIFY_EXPECTED_EXECUTOR_ID: EXECUTOR_ID,
    MNDE_EXECUTOR_ID: EXECUTOR_ID,
    MNDE_EXECUTOR_PRIVATE_KEY: keyPath,
    MNDE_EXECUTOR_CREDENTIAL: credentialPath,
    MNDE_EXECUTOR_ENVIRONMENT: ENVIRONMENT_ID,
    MNDE_TEST_CLAIM_STORE: c.claimDir,
    MNDE_TEST_CLI_CALL_LOG: c.callLog
  });
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
  return env;
}

function calls(c) {
  const lines = existsSync(c.callLog) ? readFileSync(c.callLog, "utf8").split("\n").filter(Boolean) : [];
  return { construct: lines.filter((l) => l === "construct").length, execute: lines.filter((l) => l === "execute").length };
}

// Run the CLI once. stdout must be exactly one JSON line whatever happens.
function runCli(c, args, { env = {}, claimDouble = true, cli = SOURCE_CLI } = {}) {
  rmSync(c.callLog, { force: true });
  const receivedBefore = c.received();
  const preloads = claimDouble ? [COUNTING, CLAIM_DOUBLE] : [COUNTING];
  const run = spawnSync(process.execPath, [...preloads.flatMap((p) => ["--import", p]), cli, ...args], {
    cwd: c.caseDir,
    env: operatorEnv(c, env),
    encoding: "utf8",
    timeout: 120_000
  });
  if (run.error) throw run.error;
  const lines = run.stdout.split("\n").filter(Boolean);
  assert.equal(lines.length, 1, `stdout must be exactly one JSON line; got:\n${run.stdout}\nstderr:\n${run.stderr}`);
  const out = JSON.parse(lines[0]);
  assert.equal(out.schema, "mnde.git-push-cli-result.v1");
  assert.equal(out.exit_code, run.status, "the printed exit_code must be the process exit status");
  return { status: run.status, out, stderr: run.stderr, calls: calls(c), pushesReceived: c.received() - receivedBefore };
}

function requestFor(parameters, authorization) {
  return {
    repository: parameters.repository,
    remote: parameters.remote,
    remoteUrl: parameters.remote_url,
    sourceCommit: parameters.source_commit,
    targetRef: parameters.target_ref,
    expectedOldSha: parameters.expected_old_sha,
    authorization
  };
}

let requestIndex = 0;
function writeRequest(c, body) {
  requestIndex += 1;
  const path = join(c.caseDir, `request-${requestIndex}.json`);
  writeFileSync(path, typeof body === "string" ? body : `${JSON.stringify(body, null, 2)}\n`, "utf8");
  return path;
}

// A valid request for commits[0] -> commits[1] on this case's remote.
async function validRequest(c, options = {}) {
  const parameters = pushParameters(c.repos, { from: c.repos.commits[0], to: c.repos.commits[1] });
  const authorization = await gitPushAuthorization(trust, parameters, options);
  return { parameters, authorization, path: writeRequest(c, requestFor(parameters, authorization)) };
}

function claimFiles(c) {
  const names = readdirSync(c.claimDir);
  return { execution: names.filter((n) => n.startsWith("execution-")).length, grant: names.filter((n) => n.startsWith("grant-")).length };
}

function assertNothingSent(c, run, label) {
  assert.equal(run.pushesReceived, 0, `${label}: the remote must receive no push`);
  assert.equal(c.repos.remoteSha(), c.repos.commits[0], `${label}: the remote must not move`);
}

function assertOneCall(run, label) {
  assert.deepEqual(run.calls, { construct: 1, execute: 1 }, `${label}: exactly one executor and one executeGitPush()`);
}

function assertNoExecutor(run, label) {
  assert.deepEqual(run.calls, { construct: 0, execute: 0 }, `${label}: the executor must never be constructed`);
}

async function executeOnce(c, options = {}) {
  const request = await validRequest(c, options);
  const run = runCli(c, [request.path]);
  assert.equal(run.status, 0, `the authorized push must execute: ${JSON.stringify(run.out)}`);
  assert.equal(c.repos.remoteSha(), c.repos.commits[1]);
  return { request, run };
}

// ── Static helpers (same rules as tests/test_git_push_reachability.mjs) ──────
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
}
function specifiers(src) {
  const re = /(?:import|export)\s[^'"`;]*?from\s*["']([^"']+)["']|import\s*\(\s*["']([^"']+)["']\s*\)|require\s*\(\s*["']([^"']+)["']\s*\)|import\s+["']([^"']+)["']/g;
  return [...stripComments(src).matchAll(re)].map((m) => m[1] ?? m[2] ?? m[3] ?? m[4]);
}
const posix = (p) => p.split(sep).join("/");

async function main() {
  console.log("git.push production CLI (bin/mnde-git-push.mjs, run as a child process)\n");

  for (const fault of ["write", "file-sync", "close", "directory-sync"]) {
    await test(`start durability: ${fault} failure consumes authority but sends nothing`, async () => {
      const c = newCase();
      const request = await validRequest(c);
      const run = runCli(c, [request.path], { env: { MNDE_TEST_START_FAULT: fault } });
      assert.equal(run.status, 1, JSON.stringify(run.out));
      assert.equal(run.out.reason_code, "ERR_GIT_PUSH_EXECUTION_START_NOT_RECORDED");
      assert.equal(run.out.executed, false);
      assert.equal(run.out.effect_attempted, false);
      assert.equal(run.out.claim.decision, "CLAIMED");
      assertOneCall(run, fault);
      assertNothingSent(c, run, fault);
      assert.match(readFileSync(c.callLog, "utf8"), new RegExp(`start-fault:${fault}`));
      assert.deepEqual(claimFiles(c), { execution: 1, grant: 1 });
      assert.equal(readdirSync(c.evidenceDir).filter((f) => f.endsWith(".started.json")).length, 1, "never delete the marker on failure");
      const replay = runCli(c, [request.path]);
      assert.equal(replay.out.reason_code, "ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT");
      assertNothingSent(c, replay, "replay after start persistence failure");
    });
  }

  await test("start durability: successful file-close-directory sequence precedes exactly one push", async () => {
    const c = newCase();
    const request = await validRequest(c);
    // The remote itself rejects the push unless the full sequence was logged.
    writeFileSync(join(c.repos.barePath, "hooks", "pre-receive"),
      `#!/bin/sh\ngrep -q 'start:directory-close' '${posix(c.callLog)}' || exit 1\n`, { mode: 0o755 });
    const run = runCli(c, [request.path], { env: { MNDE_TEST_START_FAULT: "observe" } });
    assert.equal(run.status, 0, JSON.stringify(run.out));
    assert.equal(run.pushesReceived, 1);
    assert.equal(c.repos.remoteSha(), c.repos.commits[1]);
    assert.deepEqual(readFileSync(c.callLog, "utf8").trim().split("\n").filter((s) => s.startsWith("start:")),
      ["start:create", "start:write", "start:file-sync", "start:close", "start:directory-sync", "start:directory-close"]);
    const startPath = readdirSync(c.evidenceDir).find((f) => f.endsWith(".started.json"));
    assert.equal(JSON.parse(readFileSync(join(c.evidenceDir, startPath), "utf8")).execution_id, run.out.execution_id);
  });

  await test("start durability: kill after directory flush before push retains marker and spent authority", async () => {
    const c = newCase();
    const request = await validRequest(c);
    const child = spawn(process.execPath, ["--import", COUNTING, "--import", CLAIM_DOUBLE, SOURCE_CLI, request.path], {
      cwd: c.caseDir, env: operatorEnv(c, { MNDE_TEST_START_FAULT: "kill-before-push" }), stdio: ["ignore", "ignore", "pipe"]
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    const ended = new Promise((resolve, reject) => { child.once("exit", resolve); child.once("error", reject); });
    try {
      const deadline = Date.now() + 60_000;
      while (!(existsSync(c.callLog) && readFileSync(c.callLog, "utf8").includes("start:directory-close"))) {
        assert.equal(child.exitCode, null, stderr);
        assert.ok(Date.now() < deadline, `start durability wait timed out: ${stderr}`);
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    } finally {
      child.kill("SIGKILL");
      await ended;
    }
    assert.equal(c.received(), 0);
    assert.equal(c.repos.remoteSha(), c.repos.commits[0]);
    assert.deepEqual(claimFiles(c), { execution: 1, grant: 1 });
    const startPath = readdirSync(c.evidenceDir).find((f) => f.endsWith(".started.json"));
    const start = JSON.parse(readFileSync(join(c.evidenceDir, startPath), "utf8"));
    const recovery = classifyGitPushExecution({ evidenceDir: c.evidenceDir, executionId: start.execution_id });
    assert.equal(recovery.condition, "INDETERMINATE");
    assert.equal(recovery.retry_permitted, false);
    const replay = runCli(c, [request.path]);
    assert.equal(replay.out.reason_code, "ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT");
    assertNothingSent(c, replay, "replay after killed durable start");
    assert.ok(existsSync(join(c.evidenceDir, startPath)), "replay must retain the start marker");
  });

  for (const fault of ["signer", "write", "file-sync", "rename", "directory-sync"]) {
    await test(`evidence completion: ${fault} fails after one confirmed effect, exits 7, never retries`, async () => {
      const c = newCase();
      const request = await validRequest(c);
      const run = runCli(c, [request.path], { env: { MNDE_TEST_EVIDENCE_FAULT: fault } });
      assert.equal(run.status, 7, JSON.stringify(run.out));
      assert.equal(run.out.outcome, "EFFECT_EXECUTED_EVIDENCE_FAILURE");
      assert.equal(run.out.ok, false);
      assert.equal(run.out.executed, true);
      assert.equal(run.out.effect_attempted, true);
      assert.equal(run.out.claim.decision, "CLAIMED");
      assert.deepEqual(run.out.observed, { before: c.repos.commits[0], after: c.repos.commits[1] });
      assert.equal(c.repos.remoteSha(), c.repos.commits[1]);
      assert.equal(run.pushesReceived, 1);
      assertOneCall(run, fault);
      assert.match(readFileSync(c.callLog, "utf8"), /evidence-fault/, "fault must actually fire");
      assert.equal(run.out.reason_code, fault === "signer" ? "ERR_GIT_PUSH_EVIDENCE_GENERATION" : "ERR_GIT_PUSH_EVIDENCE_PERSISTENCE");
      assert.equal(run.out.evidence_error.stage, fault === "signer" ? "generation" : "persistence");
      assert.equal(run.out.signed_evidence_path, null);
      const local = JSON.parse(readFileSync(run.out.evidence_path, "utf8"));
      assert.equal(local.outcome, "EFFECT_EXECUTED_EVIDENCE_FAILURE");
      assert.equal(local.evidence_persisted, false);
      assert.equal(local.executed, true);
      const recovery = classifyGitPushExecution({ evidenceDir: c.evidenceDir, executionId: run.out.execution_id });
      assert.equal(recovery.condition, "EFFECT_EXECUTED_EVIDENCE_FAILURE");
      assert.equal(recovery.review_required, true);
      assert.equal(recovery.retry_permitted, false);
      const files = readdirSync(c.evidenceDir);
      assert.ok(!files.some((f) => f.endsWith(".tmp")), "failed temporary writes are cleaned up");
      const published = files.filter((f) => f.endsWith(".signed.json"));
      assert.equal(published.length, fault === "directory-sync" ? 1 : 0);
      if (fault === "directory-sync") {
        const envelope = JSON.parse(readFileSync(join(c.evidenceDir, published[0]), "utf8"));
        assert.equal((await verifyExecutionEvidence(envelope, { authorityBundle: trust.bundle, trustedRootFingerprint: trust.fingerprint })).ok, true);
        assert.equal(envelope.evidence.outcome, "EXECUTED", "valid observed-effect evidence is not a durable completion acknowledgement");
      }
      // Even evidence failure cannot unspend authority. Resetting the disposable
      // remote ensures this tests the claim, not merely the pre-state guard.
      c.repos.setRemoteTo(c.repos.commits[0]);
      const replay = runCli(c, [request.path]);
      assert.equal(replay.out.reason_code, "ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT");
      assertNothingSent(c, replay, "replay after evidence failure");
    });
  }

  for (const outcome of ["INDETERMINATE", "RECONCILED_NOT_APPLIED"]) {
    await test(`evidence completion: signer failure preserves ${outcome}`, async () => {
      const c = newCase();
      const request = await validRequest(c);
      if (outcome === "INDETERMINATE") {
        git(["push", "--quiet", c.repos.remoteUrl, `${c.repos.divergent}:refs/heads/divergent`], c.repos.localPath);
        writeFileSync(join(c.repos.barePath, "move-away"), `${c.repos.divergent}\n`);
      } else writeFileSync(join(c.repos.barePath, "hooks", "pre-receive"), "#!/bin/sh\nexit 1\n", { mode: 0o755 });
      const run = runCli(c, [request.path], { env: { MNDE_TEST_EVIDENCE_FAULT: "signer" } });
      assert.equal(run.out.outcome, outcome, JSON.stringify(run.out));
      assert.equal(run.status, outcome === "INDETERMINATE" ? 2 : 6);
      assert.equal(run.out.executed, outcome === "INDETERMINATE" ? null : false);
      assert.equal(run.out.evidence_error.stage, "generation");
      assert.equal(c.repos.remoteSha(), outcome === "INDETERMINATE" ? c.repos.divergent : c.repos.commits[0]);
      assert.equal(run.pushesReceived, outcome === "INDETERMINATE" ? 1 : 0);
      assertOneCall(run, outcome);
    });
  }

  await test("A: a valid authorized request reaches the typed executor and executes exactly once", async () => {
    const c = newCase();
    const ids = { executionId: `exec-cli-${caseIndex}`, grantId: `grant-cli-${caseIndex}` };
    const { run } = await executeOnce(c, ids);
    assert.equal(run.out.outcome, "EXECUTED");
    assert.equal(run.out.ok, true);
    assert.equal(run.out.executed, true);
    assert.equal(run.out.execution_id, ids.executionId);
    assert.equal(run.out.grant_id, ids.grantId);
    assert.deepEqual(run.out.observed, { before: c.repos.commits[0], after: c.repos.commits[1] });
    assert.equal(run.pushesReceived, 1, "the remote received exactly one push");
    assertOneCall(run, "A");
    assert.equal(run.out.claim.decision, "CLAIMED");
    assert.equal(run.out.claim.backend_kind, "test-file-claim-store");
    assert.deepEqual(claimFiles(c), { execution: 1, grant: 1 }, "one consumed authority in the claim store");
    assert.ok(run.out.signed_evidence_path && existsSync(run.out.signed_evidence_path), "signed evidence was written");
    assert.equal(run.out.evidence_error, null);
    assert.equal(JSON.parse(readFileSync(run.out.evidence_path, "utf8")).evidence_persisted, true);
    const envelope = JSON.parse(readFileSync(run.out.signed_evidence_path, "utf8"));
    assert.deepEqual(envelope, run.out.signed_evidence, "stdout carries the same signed evidence that was written");
    const verdict = await verifyExecutionEvidence(envelope, { authorityBundle: trust.bundle, trustedRootFingerprint: trust.fingerprint });
    assert.equal(verdict.ok, true, `signed evidence verifies offline: ${JSON.stringify(verdict)}`);
    assert.equal(envelope.evidence.outcome, "EXECUTED");
    assert.equal(envelope.evidence.observed_after_sha, c.repos.commits[1]);
    assert.doesNotMatch(JSON.stringify(run.out), /PRIVATE KEY/, "no key material on stdout");
    assert.equal(run.stderr, "", "stderr stays empty on success");
  });

  await test("B: replaying the same request after resetting the remote is refused by the claim, nothing sent", async () => {
    const c = newCase();
    const { request } = await executeOnce(c);
    c.repos.setRemoteTo(c.repos.commits[0]); // the lease alone would now allow the push again
    const run = runCli(c, [request.path]);
    assert.equal(run.status, 1);
    assert.equal(run.out.outcome, "REFUSED");
    assert.equal(run.out.reason_code, "ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT");
    assert.equal(run.out.claim.decision, "SPENT", "refused by the claim, not the remote state");
    assert.equal(run.out.observed.before, c.repos.commits[0], "the remote was in the approved pre-state");
    assert.equal(run.out.effect_attempted, false);
    assertNothingSent(c, run, "B");
    assertOneCall(run, "B");
    assert.deepEqual(claimFiles(c), { execution: 1, grant: 1 });
  });

  await test("C: a fresh execution id on a spent grant is refused, nothing sent", async () => {
    const c = newCase();
    const grantId = `grant-cli-${caseIndex}`;
    await executeOnce(c, { executionId: `exec-cli-${caseIndex}-a`, grantId });
    c.repos.setRemoteTo(c.repos.commits[0]);
    const again = await validRequest(c, { executionId: `exec-cli-${caseIndex}-b`, grantId });
    const run = runCli(c, [again.path]);
    assert.equal(run.status, 1);
    assert.equal(run.out.reason_code, "ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT");
    assert.equal(run.out.claim.decision, "SPENT");
    assertNothingSent(c, run, "C");
    assertOneCall(run, "C");
  });

  await test("D: a spent execution id under a new grant is refused, nothing sent", async () => {
    const c = newCase();
    const executionId = `exec-cli-${caseIndex}`;
    await executeOnce(c, { executionId, grantId: `grant-cli-${caseIndex}-a` });
    c.repos.setRemoteTo(c.repos.commits[0]);
    const again = await validRequest(c, { executionId, grantId: `grant-cli-${caseIndex}-b` });
    const run = runCli(c, [again.path]);
    assert.equal(run.status, 1);
    assert.equal(run.out.reason_code, "ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT");
    assert.equal(run.out.claim.decision, "SPENT");
    assertNothingSent(c, run, "D");
    assertOneCall(run, "D");
  });

  await test("E: without MNDE_CLAIM_CONFIG the CLI refuses at startup, before any executor exists", async () => {
    const c = newCase();
    const request = await validRequest(c);
    const run = runCli(c, [request.path], { env: { MNDE_CLAIM_CONFIG: undefined }, claimDouble: false });
    assert.equal(run.status, 4);
    assert.equal(run.out.outcome, "STARTUP_FAILED");
    assert.equal(run.out.reason_code, "ERR_GIT_PUSH_CLI_CONFIG");
    assert.match(run.out.detail, /MNDE_CLAIM_CONFIG/);
    assertNoExecutor(run, "E");
    assertNothingSent(c, run, "E");
    assert.equal(existsSync(c.evidenceDir), false, "no evidence: no executor ran");
  });

  await test("F1: a claim config that does not exist refuses at startup, before any executor or fallback backend exists", async () => {
    const c = newCase();
    const request = await validRequest(c);
    const run = runCli(c, [request.path], { env: { MNDE_CLAIM_CONFIG: join(operatorDir, "no-such-claim-config.json") }, claimDouble: false });
    assert.equal(run.status, 4, JSON.stringify(run.out));
    assert.equal(run.out.reason_code, "ERR_GIT_PUSH_CLI_CONFIG");
    assert.match(run.out.detail, /MNDE_CLAIM_CONFIG cannot be read \(ENOENT\)/);
    assertNothingSent(c, run, "F1");
    assertNoExecutor(run, "F1");
  });

  await test("F2: a well-formed claim config pointing at unreachable storage fails closed, no fallback", async () => {
    const c = newCase();
    const request = await validRequest(c);
    const caFile = join(operatorDir, "unreachable-ca.pem");
    const passwordFile = join(operatorDir, "unreachable-password");
    writeFileSync(caFile, "-----BEGIN CERTIFICATE-----\nnot a real certificate\n-----END CERTIFICATE-----\n", "utf8");
    writeFileSync(passwordFile, "not-a-real-password\n", { encoding: "utf8", mode: 0o600 });
    const configPath = join(operatorDir, "unreachable-claim-config.json");
    writeFileSync(configPath, JSON.stringify({
      host: "127.0.0.1", port: 1, database: "mnde", user: "mnde_executor", namespace: NAMESPACE, passwordFile, caFile
    }), "utf8");
    const run = runCli(c, [request.path], { env: { MNDE_CLAIM_CONFIG: configPath }, claimDouble: false });
    assert.equal(run.status, 1);
    assert.equal(run.out.reason_code, "ERR_GIT_PUSH_CLAIM_NOT_ESTABLISHED");
    assert.ok(["NO_BACKEND", "BACKEND_UNAVAILABLE"].includes(run.out.claim.decision), run.out.claim.decision);
    assert.notEqual(run.out.claim.backend_kind, "test-file-claim-store");
    assertNothingSent(c, run, "F2");
    assertOneCall(run, "F2");
  });

  await test("G: invalid JSON is refused before the executor exists", async () => {
    const c = newCase();
    const run = runCli(c, [writeRequest(c, "{ \"repository\": ")]);
    assert.equal(run.status, 3);
    assert.equal(run.out.reason_code, "ERR_GIT_PUSH_CLI_REQUEST_NOT_JSON");
    assertNoExecutor(run, "G");
    assertNothingSent(c, run, "G");
  });

  await test("H: a missing request file, or no argument at all, is refused before the executor exists", async () => {
    const c = newCase();
    for (const args of [[join(c.caseDir, "no-such-request.json")], [], ["a.json", "b.json"], ["--help"]]) {
      const run = runCli(c, args);
      assert.equal(run.status, 3, `args ${JSON.stringify(args)}`);
      assert.equal(run.out.outcome, "INVALID_INPUT");
      assertNoExecutor(run, `H ${JSON.stringify(args)}`);
      assertNothingSent(c, run, "H");
    }
  });

  await test("I: extra, missing or malformed request fields are refused; nothing sent", async () => {
    const c = newCase();
    const { parameters, authorization } = await validRequest(c);
    const base = requestFor(parameters, authorization);

    for (const [label, body] of [
      ["extra force flag", { ...base, force: true }],
      ["missing expectedOldSha", Object.fromEntries(Object.entries(base).filter(([k]) => k !== "expectedOldSha"))],
      ["array", [base]],
      ["null", null]
    ]) {
      const run = runCli(c, [writeRequest(c, body)]);
      assert.equal(run.status, 3, label);
      assert.equal(run.out.outcome, "INVALID_INPUT", label);
      assertNoExecutor(run, label);
      assertNothingSent(c, run, label);
    }

    // Right keys, wrong value: an abbreviated SHA is not expanded or coerced; the
    // executor refuses it against the signed authorization.
    const abbreviated = runCli(c, [writeRequest(c, { ...base, sourceCommit: base.sourceCommit.slice(0, 12) })]);
    assert.equal(abbreviated.status, 1);
    assert.equal(abbreviated.out.outcome, "REFUSED");
    assert.equal(abbreviated.out.effect_attempted, false);
    assertOneCall(abbreviated, "abbreviated SHA");
    assertNothingSent(c, abbreviated, "abbreviated SHA");
    assert.deepEqual(claimFiles(c), { execution: 0, grant: 0 }, "a refused request spends nothing");
  });

  await test("J: startup security settings named in request.json are refused, never read", async () => {
    const c = newCase();
    const { parameters, authorization } = await validRequest(c);
    const base = requestFor(parameters, authorization);
    const injected = {
      claimBackend: { kind: "in-memory" },
      executorSigner: { sign: "attacker" },
      executorIdentity: { executor_id: "attacker" },
      trustedRootFingerprint: "0".repeat(64),
      authorityBundlePath: join(operatorDir, "attacker-bundle.json"),
      MNDE_CLAIM_CONFIG: join(operatorDir, "attacker-claim-config.json"),
      MNDE_PROFILE: "local",
      allowedSchemes: ["file", "ext"],
      namespace: "attacker-namespace",
      evidenceDir: join(c.caseDir, "attacker-evidence")
    };
    for (const [key, value] of [...Object.entries(injected), ["all of them", null]]) {
      const body = key === "all of them" ? { ...base, ...injected } : { ...base, [key]: value };
      const run = runCli(c, [writeRequest(c, body)]);
      assert.equal(run.status, 3, key);
      assert.equal(run.out.reason_code, "ERR_GIT_PUSH_CLI_REQUEST_FIELDS", key);
      assertNoExecutor(run, key);
      assertNothingSent(c, run, key);
    }
    assert.equal(existsSync(join(c.caseDir, "attacker-evidence")), false);
    // And the unmodified request still executes with the operator's settings.
    const ok = runCli(c, [writeRequest(c, base)]);
    assert.equal(ok.status, 0);
    assert.equal(ok.out.claim.namespace, NAMESPACE);
  });

  await test("K: the CLI reaches git.push only through createGitPushExecutor (static)", () => {
    const cli = readFileSync(SOURCE_CLI, "utf8");
    const startup = readFileSync(join(ROOT, "src", "effects", "git-push", "startup.mjs"), "utf8");
    assert.deepEqual(specifiers(cli).sort(), ["../src/effects/git-push/index.mjs", "../src/effects/git-push/startup.mjs", "node:fs"]);
    assert.deepEqual(specifiers(startup).sort(), ["../../../shared/runtime-profile.mjs", "../../custody/bundle.mjs", "../../custody/executor-readiness.mjs", "./secret-files.mjs", "node:fs", "node:path", "node:url"]);

    const forbidden = /child_process|node:cluster|worker_threads|\bspawn|\bexecFile|\bexecSync|\bfetch\s*\(|performPush|buildPushArgv|claimAuthority|redeemClaimTicket|openExecutorClaimBackend|claimBackend|postgres_claim|freshness\/|transport\.mjs|api\.github\.com|["'`]git["'`]/;
    for (const [name, src] of [["bin/mnde-git-push.mjs", cli], ["src/effects/git-push/startup.mjs", startup]]) {
      const hit = forbidden.exec(stripComments(src));
      assert.equal(hit, null, `${name} must not reach below the executor: found '${hit?.[0]}'`);
    }

    const code = stripComments(cli);
    assert.equal((code.match(/createGitPushExecutor\s*\(/g) ?? []).length, 1, "exactly one construction site");
    assert.equal((code.match(/\.executeGitPush\s*\(/g) ?? []).length, 1, "exactly one execution call site");

    // Outside tests, only the executor itself and this CLI name the constructor.
    const files = execFileSync("git", ["ls-files", "-co", "--exclude-standard", "-z"], { cwd: ROOT, encoding: "utf8" })
      .split("\0").filter((f) => /\.(mjs|js|cjs|ts)$/.test(f) && !f.startsWith("tests/") && !f.startsWith("dist/") && !f.startsWith("node_modules/"));
    const callers = files.filter((f) => /createGitPushExecutor/.test(stripComments(readFileSync(join(ROOT, f), "utf8"))));
    assert.deepEqual(callers.sort(), ["bin/mnde-git-push.mjs", "src/effects/git-push/index.mjs"]);
  });

  await test("L: one invocation constructs one executor and calls executeGitPush() once, success or refusal", async () => {
    const c = newCase();
    const { request, run } = await executeOnce(c);
    assertOneCall(run, "executed");
    c.repos.setRemoteTo(c.repos.commits[0]);
    const refused = runCli(c, [request.path]);
    assert.equal(refused.status, 1);
    assertOneCall(refused, "refused");
  });

  await test("M1: an uncertain claim is never retried: one attempt, nothing sent, non-zero", async () => {
    const c = newCase();
    const request = await validRequest(c);
    const run = runCli(c, [request.path], { env: { MNDE_TEST_CLAIM_MODE: "throw-on-claim" } });
    assert.equal(run.status, 1);
    assert.equal(run.out.reason_code, "ERR_GIT_PUSH_CLAIM_NOT_ESTABLISHED");
    assert.equal(run.out.claim.decision, "UNKNOWN");
    assertOneCall(run, "M1");
    assertNothingSent(c, run, "M1");
  });

  await test("M2: a claim whose acknowledgement was lost is treated as spent: one attempt, nothing sent, ever", async () => {
    const c = newCase();
    const request = await validRequest(c);
    const run = runCli(c, [request.path], { env: { MNDE_TEST_CLAIM_MODE: "ack-lost" } });
    assert.equal(run.status, 1);
    assert.equal(run.out.reason_code, "ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT");
    assert.equal(run.out.claim.note, "claim-ack-lost-but-durably-present");
    assertOneCall(run, "M2");
    assertNothingSent(c, run, "M2");
    const later = runCli(c, [request.path]);
    assert.equal(later.status, 1, "the consumed authority stays consumed");
    assert.equal(later.out.reason_code, "ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT");
    assertNothingSent(c, later, "M2 later");
  });

  await test("M3: an ambiguous transport outcome exits INDETERMINATE after exactly one push, and is never retried", async () => {
    const c = newCase();
    git(["push", "--quiet", c.repos.remoteUrl, `${c.repos.divergent}:refs/heads/divergent`], c.repos.localPath);
    writeFileSync(join(c.repos.barePath, "move-away"), `${c.repos.divergent}\n`, "utf8");
    const request = await validRequest(c);
    const run = runCli(c, [request.path]);
    assert.equal(run.status, 2, JSON.stringify(run.out));
    assert.equal(run.out.outcome, "INDETERMINATE");
    assert.equal(run.out.executed, null);
    assert.equal(run.out.effect_attempted, true);
    assert.equal(run.pushesReceived, 1, "exactly one push reached the remote");
    assert.equal(c.repos.remoteSha(), c.repos.divergent);
    assertOneCall(run, "M3");
    // An operator re-running it is refused; and once the remote is put back in
    // the approved pre-state, it is the claim, not the remote, that refuses.
    const again = runCli(c, [request.path]);
    assert.equal(again.status, 1, "re-running the same authority is refused");
    assert.equal(again.pushesReceived, 0);
    rmSync(join(c.repos.barePath, "move-away"));
    c.repos.setRemoteTo(c.repos.commits[0]);
    const reset = runCli(c, [request.path]);
    assert.equal(reset.status, 1);
    assert.equal(reset.out.reason_code, "ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT");
    assert.equal(reset.out.claim.decision, "SPENT");
    assertNothingSent(c, reset, "M3 after reset");
  });

  await test("P1: no MNDE_GIT_CREDENTIAL_CONFIG is a startup failure, whatever ambient credentials exist", async () => {
    const c = newCase();
    const request = await validRequest(c);
    const run = runCli(c, [request.path], { env: { MNDE_GIT_CREDENTIAL_CONFIG: undefined, GITHUB_TOKEN: "ghp_ambient", GH_TOKEN: "gho_ambient", SSH_AUTH_SOCK: join(c.caseDir, "agent.sock") } });
    assert.equal(run.status, 4);
    assert.match(run.out.detail, /MNDE_GIT_CREDENTIAL_CONFIG/);
    assertNoExecutor(run, "P1");
    assertNothingSent(c, run, "P1");
  });

  await test("P2: a credential scoped to another repository refuses before the claim; the same authority then executes", async () => {
    const c = newCase();
    const request = await validRequest(c);
    const elsewhere = writeCredentialConfig(c.caseDir, { kind: "none", repositories: ["file:/srv/some/other/repo"] }, "elsewhere.json");
    const refused = runCli(c, [request.path], { env: { MNDE_GIT_CREDENTIAL_CONFIG: elsewhere } });
    assert.equal(refused.status, 1, JSON.stringify(refused.out));
    assert.equal(refused.out.reason_code, "ERR_GIT_CREDENTIAL_SCOPE");
    assertNothingSent(c, refused, "P2 refused");
    assert.deepEqual(claimFiles(c), { execution: 0, grant: 0 }, "a credential refusal must not spend the authority");
    const ok = runCli(c, [request.path]);
    assert.equal(ok.status, 0, JSON.stringify(ok.out));
    assert.equal(ok.out.push_credential.credential_provider_kind, "none");
    assert.equal(ok.out.push_credential.credential_scope, request.parameters.repository);
    assert.equal(ok.pushesReceived, 1);
  });

  await test("P3: ambient credentials, askpass, ssh settings, HOME and injected git config never reach the push", async () => {
    const c = newCase();
    // The remote records the environment the push arrived with: receive-pack
    // runs as a child of the executor's git, so this is the push's own env.
    writeFileSync(join(c.repos.barePath, "hooks", "pre-receive"), "#!/bin/sh\nenv > push-env.txt\n", { encoding: "utf8", mode: 0o755 });
    const decoy = join(c.caseDir, "decoy.git");
    git(["init", "--quiet", "--bare", decoy], c.caseDir);
    const hostileHome = join(c.caseDir, "hostile-home");
    mkdirSync(hostileHome, { recursive: true });
    const decoyUrl = pathToFileURL(decoy).href;
    writeFileSync(join(hostileHome, ".gitconfig"), `[url "${decoyUrl}"]\n\tpushInsteadOf = ${c.repos.remoteUrl}\n[credential]\n\thelper = store\n`, "utf8");
    const request = await validRequest(c);
    const run = runCli(c, [request.path], {
      env: {
        GITHUB_TOKEN: "ghp_ambient_token_value",
        GH_TOKEN: "gho_ambient_token_value",
        GIT_ASKPASS: "/bin/echo",
        SSH_ASKPASS: "/bin/echo",
        SSH_AUTH_SOCK: join(c.caseDir, "agent.sock"),
        GIT_SSH_COMMAND: "ssh -i /home/founder/.ssh/id_ed25519",
        GIT_CONFIG_GLOBAL: join(hostileHome, ".gitconfig"),
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: `url.${decoyUrl}.pushInsteadOf`,
        GIT_CONFIG_VALUE_0: c.repos.remoteUrl,
        GIT_DIR: decoy,
        HOME: hostileHome,
        XDG_CONFIG_HOME: hostileHome
      }
    });
    assert.equal(run.status, 0, JSON.stringify(run.out));
    assert.equal(c.repos.remoteSha(), c.repos.commits[1], "the push landed on the authorized remote");
    assert.equal(git(["for-each-ref"], decoy), "", "the decoy received nothing");
    const pushEnv = readFileSync(join(c.repos.barePath, "push-env.txt"), "utf8");
    for (const leaked of ["ghp_ambient_token_value", "gho_ambient_token_value", "agent.sock", "id_ed25519", "hostile-home", "pushInsteadOf"]) {
      assert.ok(!pushEnv.includes(leaked), `${leaked} reached the push environment`);
    }
    assert.match(pushEnv, /^GIT_ALLOW_PROTOCOL=file$/m, "the push may use exactly the configured protocol");
    assert.doesNotMatch(pushEnv, /^GIT_ASKPASS=.+$/m);
  });

  await test("P4: MNDe's shipped demo root, a demo-named authority, or an executor key that is also an authority key refuse startup", async () => {
    const c = newCase();
    const request = await validRequest(c);
    const demoRoot = runCli(c, [request.path], { env: { MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT: "6e987c47fe1144c9a9e957b1c9f45f50e37df8892e2f0b3ad80b6d2a20ec4efa" } });
    assert.equal(demoRoot.status, 4);
    assert.equal(demoRoot.out.reason_code, "ERR_GIT_PUSH_DEMO_TRUST_MATERIAL");
    assertNoExecutor(demoRoot, "P4 demo root");

    const demoTrust = await productionTrust(c.caseDir, { authorityId: "acme-demo-authority" });
    const demoNamed = runCli(c, [request.path], { env: { MNDE_VERIFY_AUTHORITY_BUNDLE: demoTrust.bundlePath, MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT: demoTrust.fingerprint } });
    assert.equal(demoNamed.status, 4);
    assert.equal(demoNamed.out.reason_code, "ERR_GIT_PUSH_DEMO_TRUST_MATERIAL");

    // An executor credential issued for the authority's own receipt-signing key.
    const reused = await issueExecutorCredential({
      authorityBundle: trust.bundle,
      rootPrivatePem: trust.root.privatePem,
      executorId: EXECUTOR_ID,
      publicPem: trust.receipt.publicPem,
      environmentId: ENVIRONMENT_ID,
      capabilities: [EXECUTOR_RECEIPT_CAPABILITY],
      issuedAt: "2026-06-14T00:00:00.000Z",
      notBefore: "2026-01-01T00:00:00.000Z",
      expiresAt: "2099-01-01T00:00:00.000Z"
    });
    const reusedKey = join(operatorDir, "reused-key.pem");
    writeFileSync(reusedKey, trust.receipt.privatePem, { encoding: "utf8", mode: 0o600 });
    const reusedCredential = join(operatorDir, "reused-credential.json");
    writeFileSync(reusedCredential, JSON.stringify(reused), "utf8");
    const roleReuse = runCli(c, [request.path], { env: { MNDE_EXECUTOR_PRIVATE_KEY: reusedKey, MNDE_EXECUTOR_CREDENTIAL: reusedCredential } });
    assert.equal(roleReuse.status, 4, JSON.stringify(roleReuse.out));
    assert.equal(roleReuse.out.reason_code, "ERR_GIT_PUSH_TRUST_ROLE_REUSE");
    assertNoExecutor(roleReuse, "P4 role reuse");
    assertNothingSent(c, roleReuse, "P4");
  });

  await test("P5: a trust file inside the local repository, or (POSIX) writable by others, refuses startup", async () => {
    const c = newCase();
    const request = await validRequest(c);
    const planted = join(c.repos.localPath, "authority-bundle.json");
    writeFileSync(planted, readFileSync(trust.bundlePath, "utf8"), "utf8");
    const inRepo = runCli(c, [request.path], { env: { MNDE_VERIFY_AUTHORITY_BUNDLE: planted } });
    assert.equal(inRepo.status, 4);
    assert.equal(inRepo.out.reason_code, "ERR_GIT_PUSH_TRUST_FILE_INSECURE");
    assertNoExecutor(inRepo, "P5 in repo");
    if (process.platform !== "win32") {
      const loose = join(operatorDir, "world-writable-bundle.json");
      writeFileSync(loose, readFileSync(trust.bundlePath, "utf8"), "utf8");
      chmodSync(loose, 0o666);
      const writable = runCli(c, [request.path], { env: { MNDE_VERIFY_AUTHORITY_BUNDLE: loose } });
      assert.equal(writable.status, 4);
      assert.equal(writable.out.reason_code, "ERR_GIT_PUSH_TRUST_FILE_INSECURE");
      const openKey = join(operatorDir, "group-readable-key.pem");
      writeFileSync(openKey, trust.executor.keys.privatePem, "utf8");
      chmodSync(openKey, 0o640);
      const readable = runCli(c, [request.path], { env: { MNDE_EXECUTOR_PRIVATE_KEY: openKey } });
      assert.equal(readable.status, 4);
      assert.equal(readable.out.reason_code, "ERR_GIT_PUSH_TRUST_FILE_INSECURE");
    }
    assertNothingSent(c, inRepo, "P5");
  });

  await test("N: the built package ships the CLI, runs it end to end, and ships no test code", async () => {
    execFileSync(process.execPath, [join(ROOT, "build", "build-package.mjs")], { cwd: ROOT, stdio: "pipe" });
    const dist = join(ROOT, "dist");
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
    assert.equal(pkg.bin["mnde-git-push"], "./dist/bin/mnde-git-push.mjs");
    assert.ok(pkg.files.includes("dist"));
    const distCli = join(dist, "bin", "mnde-git-push.mjs");
    for (const rel of ["bin/mnde-git-push.mjs", "src/effects/git-push/startup.mjs", "src/effects/git-push/index.mjs"]) {
      assert.ok(existsSync(join(dist, rel)), `${rel} must ship`);
    }
    assert.equal(existsSync(join(dist, "tests")), false, "tests/ must not ship");

    const offenders = [];
    const walk = (d) => {
      for (const entry of readdirSync(d)) {
        const full = join(d, entry);
        if (statSync(full).isDirectory()) { walk(full); continue; }
        if (!/\.(mjs|js|cjs)$/.test(entry)) continue;
        for (const spec of specifiers(readFileSync(full, "utf8"))) {
          if (!spec.startsWith(".")) continue;
          const target = posix(relative(ROOT, normalize(join(dirname(full), spec))));
          if (!target.startsWith("dist/")) offenders.push(`${posix(relative(ROOT, full))} -> ${spec}`);
        }
      }
    };
    walk(dist);
    assert.deepEqual(offenders, [], "no shipped file may import outside the package (tests/, experiments/)");

    const c = newCase();
    const request = await validRequest(c);
    const run = runCli(c, [request.path], { cli: distCli });
    assert.equal(run.status, 0, JSON.stringify(run.out));
    assert.equal(run.out.outcome, "EXECUTED");
    assertOneCall(run, "packaged CLI");
    assert.equal(run.pushesReceived, 1);
  });

  console.log(`\n${failed === 0 ? "PASS" : "FAIL"} git.push production CLI (${passed}/${passed + failed})`);
  try { rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* best effort */ }
  if (failed > 0) process.exit(1);
}

await main();
