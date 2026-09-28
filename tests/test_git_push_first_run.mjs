// git.push — the operator path from nothing to one executed push.
//
//   npm run test:git-push-first-run
//
// docs/FIRST-PRODUCTION-GIT-PUSH.md takes an operator from no trust material to
// one real push with three scripts. This suite runs those scripts as an operator
// would and checks what each one hands to the next:
//
//   scripts/prepare-git-push-trust.mjs    fresh authority + executor, env files
//   scripts/authorize-git-push.mjs        one executor-bound authorization
//   bin/mnde-git-push.mjs                 the production CLI, unchanged
//   scripts/verify-git-push-evidence.mjs  offline check of what it signed
//
// The remote is a real bare repository over file://. The claim store is the
// file-backed test double the CLI suite uses (tests/support/
// git_push_cli_claim_store.mjs); it proves the claim is reached and a replay is
// refused by it, not durability. The same flow was run by hand against a real
// PostgreSQL 16 claim store over verified TLS; see the runbook.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { verifyExecutionAuthority, isProductionExecutionAuthority } from "../src/execution-authority/index.mjs";
import { REQUIRED_STARTUP_ENV } from "../src/effects/git-push/startup.mjs";
import { authorizeGitPush } from "../scripts/authorize-git-push.mjs";
import { makeRepositories, pushParameters, writeCredentialConfig } from "./support/git_push_fixtures.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const PREPARE = join(ROOT, "scripts", "prepare-git-push-trust.mjs");
const AUTHORIZE = join(ROOT, "scripts", "authorize-git-push.mjs");
const VERIFY = join(ROOT, "scripts", "verify-git-push-evidence.mjs");
const CLI = join(ROOT, "bin", "mnde-git-push.mjs");
const CLAIM_DOUBLE = pathToFileURL(join(HERE, "support", "git_push_cli_claim_store.mjs")).href;
const DEMO_ROOT = "6e987c47fe1144c9a9e957b1c9f45f50e37df8892e2f0b3ad80b6d2a20ec4efa";
const EXECUTOR_ID = "mnde:firstrun:prod:executor:gitpush:01";

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  [PASS] ${name}`); }
  catch (error) { failed += 1; console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.stack : String(error)}`); }
}

function cleanEnv(extra = {}) {
  const env = {};
  for (const [key, value] of Object.entries(process.env)) if (!key.startsWith("MNDE_")) env[key] = value;
  return { ...env, ...extra };
}

function run(script, args, env, preloads = []) {
  return spawnSync(process.execPath, [...preloads.flatMap((p) => ["--import", p]), script, ...args], { encoding: "utf8", env });
}

// The POSIX env file is `export NAME='value'` per line; read it back the way a
// shell would for these literal values.
function readEnvFile(path) {
  const vars = {};
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const match = /^export ([A-Z0-9_]+)='([^']*)'$/.exec(line);
    if (match) vars[match[1]] = match[2];
  }
  return vars;
}

function prepare(dir, authorityId = "mnde-firstrun-prod") {
  const out = join(dir, "trust");
  const result = run(PREPARE, ["--out", out, "--authority-id", authorityId, "--executor-id", EXECUTOR_ID], cleanEnv());
  return { out, result };
}

const dir = mkdtempSync(join(tmpdir(), "mnde-git-push-first-run-"));
const { out: trustDir, result: prepared } = prepare(dir);
const trustEnv = existsSync(join(trustDir, "mnde-git-push.env.sh")) ? readEnvFile(join(trustDir, "mnde-git-push.env.sh")) : {};

console.log("git.push first production run: prepare -> authorize -> execute -> verify");

await test("prepare writes fresh trust outside the repository and an env file naming every startup variable", async () => {
  assert.equal(prepared.status, 0, prepared.stderr);
  const summary = JSON.parse(prepared.stdout);
  assert.notEqual(summary.root_fingerprint, DEMO_ROOT);
  for (const path of Object.values(summary.files)) assert.ok(existsSync(path), `missing ${path}`);
  for (const name of REQUIRED_STARTUP_ENV) assert.ok(Object.hasOwn(trustEnv, name), `env file does not set ${name}`);
  for (const name of ["MNDE_AUTHORITY_BUNDLE", "MNDE_RECEIPT_SIGNING_KEY"]) assert.ok(Object.hasOwn(trustEnv, name), `env file does not set ${name}`);
  assert.equal(trustEnv.MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT, summary.root_fingerprint);
  assert.equal(trustEnv.MNDE_EXECUTOR_ID, trustEnv.MNDE_VERIFY_EXPECTED_EXECUTOR_ID);
  assert.equal(trustEnv.MNDE_EXECUTOR_ENVIRONMENT, trustEnv.MNDE_VERIFY_ENVIRONMENT_ID);
  // Nothing secret is printed.
  assert.doesNotMatch(prepared.stdout + prepared.stderr, /PRIVATE KEY/);
  // The PowerShell file sets the same variables.
  const ps1 = readFileSync(join(trustDir, "mnde-git-push.env.ps1"), "utf8");
  for (const name of Object.keys(trustEnv)) assert.match(ps1, new RegExp(`^\\$env:${name} = '`, "m"));
});

await test("prepare refuses an output directory inside the repository, and a directory already prepared", async () => {
  const inside = run(PREPARE, ["--out", join(ROOT, "tmp-trust-must-not-exist"), "--authority-id", "mnde-x-prod", "--executor-id", EXECUTOR_ID], cleanEnv());
  assert.notEqual(inside.status, 0);
  assert.equal(existsSync(join(ROOT, "tmp-trust-must-not-exist")), false);
  const again = run(PREPARE, ["--out", trustDir, "--authority-id", "mnde-firstrun-prod", "--executor-id", EXECUTOR_ID], cleanEnv());
  assert.notEqual(again.status, 0);
});

// One repository pair and credential config shared by the cases below.
const repoDir = join(dir, "repos");
mkdirSync(repoDir, { recursive: true });
const repos = makeRepositories(repoDir);
const approve = (overrides = {}) => ({
  remoteUrl: repos.remoteUrl,
  targetRef: "refs/heads/main",
  expectedOldSha: repos.commits[0],
  sourceCommit: repos.commits[1],
  subject: "operator-under-test",
  ...overrides
});
const authorizeEnv = { ...trustEnv, MNDE_GIT_PUSH_ALLOWED_SCHEMES: "file" };

await test("authorize produces an authorization the executor's own verifier accepts at both layers", async () => {
  const result = await authorizeGitPush(approve(), authorizeEnv);
  assert.equal(result.ok, true, result.detail);
  const bundle = JSON.parse(readFileSync(trustEnv.MNDE_VERIFY_AUTHORITY_BUNDLE, "utf8"));
  const authority = await verifyExecutionAuthority(result.request.authorization, {
    authorityBundle: bundle,
    trustedRootFingerprint: trustEnv.MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT,
    environmentId: trustEnv.MNDE_VERIFY_ENVIRONMENT_ID,
    expectedExecutorId: trustEnv.MNDE_VERIFY_EXPECTED_EXECUTOR_ID
  });
  assert.equal(authority.ok, true, authority.reason);
  assert.equal(isProductionExecutionAuthority(authority), true);
  assert.equal(authority.action, "git.push");
  assert.deepEqual({ ...authority.parameters }, pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] }));
  // The inner decision is signed by the operator's authority, not the demo one.
  assert.equal(result.request.authorization.receipt.verifiable_signature.authority_id, bundle.authority_id);
  // It is an executable receipt, not a decision-only one.
  assert.equal(Object.hasOwn(result.request.authorization.receipt, "execution_status"), false);
  assert.deepEqual(Object.keys(result.request).sort(),
    ["authorization", "expectedOldSha", "remote", "remoteUrl", "repository", "sourceCommit", "targetRef"]);
});

await test("authorize refuses demo trust, a pin that does not match the bundle, and another authority's receipt key", async () => {
  const demo = await authorizeGitPush(approve(), { ...authorizeEnv, MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT: DEMO_ROOT });
  assert.equal(demo.ok, false);
  assert.match(demo.detail, /demo root/);

  const wrongPin = await authorizeGitPush(approve(), { ...authorizeEnv, MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT: "ab".repeat(32) });
  assert.equal(wrongPin.ok, false);
  assert.match(wrongPin.detail, /does not match/);

  const other = prepare(join(dir, "other"), "mnde-other-prod");
  assert.equal(other.result.status, 0, other.result.stderr);
  const otherEnv = readEnvFile(join(other.out, "mnde-git-push.env.sh"));
  const mixed = await authorizeGitPush(approve(), { ...authorizeEnv, MNDE_RECEIPT_SIGNING_KEY: otherEnv.MNDE_RECEIPT_SIGNING_KEY });
  assert.equal(mixed.ok, false);

  const missing = await authorizeGitPush(approve(), { ...authorizeEnv, MNDE_RECEIPT_SIGNING_KEY: undefined });
  assert.equal(missing.ok, false);
});

await test("authorize refuses a push the executor would never build", async () => {
  for (const overrides of [
    { expectedOldSha: "0".repeat(40) },
    { sourceCommit: repos.commits[0] },
    { expectedOldSha: repos.commits[0].slice(0, 12) },
    { targetRef: "main" },
    { remoteUrl: "https://user:secret@example.invalid/org/repo.git" }
  ]) {
    const result = await authorizeGitPush(approve(overrides), { ...trustEnv });
    assert.equal(result.ok, false, `accepted ${JSON.stringify(overrides)}`);
  }
  // Without MNDE_GIT_PUSH_ALLOWED_SCHEMES the executor default applies: file:// is refused.
  assert.equal((await authorizeGitPush(approve(), trustEnv)).ok, false);
});

await test("the CLI executes the authorization once, a replay is refused by the claim, and the evidence verifies offline", async () => {
  const claimDir = join(dir, "claims");
  mkdirSync(claimDir, { recursive: true });
  const claimConfig = join(trustDir, "claim-config.json");
  writeFileSync(claimConfig, `${JSON.stringify({ note: "replaced by the test claim double" })}\n`, { mode: 0o600 });
  writeCredentialConfig(trustDir, { kind: "none", repositories: [pushParameters(repos, {}).repository] }, "git-credential.json");

  const request = join(dir, "request.json");
  const issued = run(AUTHORIZE, [
    "--remote-url", repos.remoteUrl,
    "--target-ref", "refs/heads/main",
    "--expected-old-sha", repos.commits[0],
    "--source-commit", repos.commits[1],
    "--out", request
  ], cleanEnv(authorizeEnv));
  assert.equal(issued.status, 0, issued.stderr);
  assert.doesNotMatch(issued.stdout, /PRIVATE KEY/);
  // It never overwrites a request file.
  assert.notEqual(run(AUTHORIZE, ["--remote-url", repos.remoteUrl, "--target-ref", "refs/heads/main",
    "--expected-old-sha", repos.commits[0], "--source-commit", repos.commits[1], "--out", request], cleanEnv(authorizeEnv)).status, 0);

  const cliEnv = cleanEnv({
    ...trustEnv,
    MNDE_GIT_PUSH_REPO_PATH: repos.localPath,
    MNDE_GIT_PUSH_ALLOWED_SCHEMES: "file",
    MNDE_TEST_CLAIM_STORE: claimDir
  });
  const first = run(CLI, [request], cliEnv, [CLAIM_DOUBLE]);
  const result = JSON.parse(first.stdout);
  assert.equal(first.status, 0, first.stdout);
  assert.equal(result.outcome, "EXECUTED");
  assert.equal(repos.remoteSha(), repos.commits[1]);

  // Put the remote back in the approved pre-state: only the claim stands between
  // the same authorization and a second push.
  repos.setRemoteTo(repos.commits[0]);
  const replay = JSON.parse(run(CLI, [request], cliEnv, [CLAIM_DOUBLE]).stdout);
  assert.equal(replay.outcome, "REFUSED");
  assert.equal(replay.reason_code, "ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT");
  assert.equal(repos.remoteSha(), repos.commits[0]);

  const verified = run(VERIFY, [result.signed_evidence_path,
    "--authority-bundle", trustEnv.MNDE_VERIFY_AUTHORITY_BUNDLE,
    "--root-fingerprint", trustEnv.MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT,
    "--expected-executor-id", EXECUTOR_ID], cleanEnv());
  assert.equal(verified.status, 0, verified.stdout);
  const verdict = JSON.parse(verified.stdout);
  assert.equal(verdict.outcome, "EXECUTED");
  assert.equal(verdict.observed_after_sha, repos.commits[1]);

  const otherRoot = run(VERIFY, [result.signed_evidence_path,
    "--authority-bundle", trustEnv.MNDE_VERIFY_AUTHORITY_BUNDLE,
    "--root-fingerprint", DEMO_ROOT], cleanEnv());
  assert.notEqual(otherRoot.status, 0);
});

const total = passed + failed;
if (failed === 0) console.log(`\nPASS git.push first production run (${passed}/${total})`);
else { console.error(`\nFAIL git.push first production run (${passed}/${total})`); process.exitCode = 1; }
