// git.push doctor — a read-only diagnosis that cannot become a way to push.
//
//   npm run test:git-push-doctor
//
// bin/mnde-git-push-doctor.mjs runs as a separate OS process, exactly as an
// operator would run it, against real components: the real startup loader (trust
// files, root, executor identity), the real executor constructor (push-credential
// configuration) and the real executor readiness query.
//
// What is NOT real, and where: the READY cases substitute the claim store with
// the file-backed test double from tests/support (the same one test_git_push_cli
// uses), because CI has no PostgreSQL. Those cases prove doctor reports what the
// executor's readiness() says; they say nothing about PostgreSQL. The
// unreachable-store case runs WITHOUT the double, against the real adapter.
//
// Measured from outside doctor, not from what it prints:
//   - every executor construction and executeGitPush() call (test-only preload),
//     which must be exactly one construction and zero executions;
//   - every push the remote received (post-receive hook);
//   - the claim directory, the evidence directory and the working tree, which must
//     hold no new file afterwards.

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { issueExecutorCredential } from "../src/custody/executor-credential.mjs";
import { EXECUTOR_RECEIPT_CAPABILITY } from "../src/custody/executor-identity.mjs";
import { renderGitPushDoctor, runGitPushDoctor } from "../src/effects/git-push/doctor.mjs";
import { ENVIRONMENT_ID, EXECUTOR_ID, makeRepositories, productionTrust } from "./support/git_push_fixtures.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const DOCTOR = join(ROOT, "bin", "mnde-git-push-doctor.mjs");
const COUNTING = pathToFileURL(join(HERE, "support", "git_push_cli_counting_hooks.mjs")).href;
const CLAIM_DOUBLE = pathToFileURL(join(HERE, "support", "git_push_cli_claim_store.mjs")).href;
const NAMESPACE = "mnde-git-push-doctor-namespace";
const DEMO_ROOT = "6e987c47fe1144c9a9e957b1c9f45f50e37df8892e2f0b3ad80b6d2a20ec4efa";
const PASSWORD_MARKER = "doctor-test-password-must-never-print";

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  [PASS] ${name}`); }
  catch (error) { failed += 1; console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.stack : String(error)}`); }
}

const dir = mkdtempSync(join(tmpdir(), "mnde-git-push-doctor-"));
const trust = await productionTrust(dir);

const operatorDir = join(dir, "operator");
mkdirSync(operatorDir, { recursive: true });
const keyPath = join(operatorDir, "executor-key.pem");
writeFileSync(keyPath, trust.executor.keys.privatePem, { encoding: "utf8", mode: 0o600 });
const credentialPath = join(operatorDir, "executor-credential.json");
writeFileSync(credentialPath, `${JSON.stringify(trust.executor.credential, null, 2)}\n`, "utf8");
const doubleClaimConfigPath = join(operatorDir, "claim-config.test-double.json");
writeFileSync(doubleClaimConfigPath, `${JSON.stringify({ note: "replaced by the test claim double" })}\n`, "utf8");

const POST_RECEIVE = "#!/bin/sh\ncat >> received.log\n";

let caseIndex = 0;
function newCase() {
  caseIndex += 1;
  const caseDir = join(dir, `case-${caseIndex}`);
  const repos = makeRepositories(caseDir);
  writeFileSync(join(repos.barePath, "hooks", "post-receive"), POST_RECEIVE, { encoding: "utf8", mode: 0o755 });
  const claimDir = join(caseDir, "claims");
  const evidenceDir = join(caseDir, "evidence");
  mkdirSync(claimDir, { recursive: true });
  mkdirSync(evidenceDir, { recursive: true });
  return {
    caseDir, repos, claimDir, evidenceDir,
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

function snapshot(c) {
  return JSON.stringify({
    claims: readdirSync(c.claimDir),
    evidence: readdirSync(c.evidenceDir),
    work: readdirSync(c.repos.localPath).sort(),
    remote: c.repos.remoteSha()
  });
}

function runDoctor(c, args = ["--json"], { env = {}, claimDouble = true, env0 = null } = {}) {
  const before = snapshot(c);
  const preloads = claimDouble ? [COUNTING, CLAIM_DOUBLE] : [COUNTING];
  const run = spawnSync(process.execPath, [...preloads.flatMap((p) => ["--import", p]), DOCTOR, ...args], {
    cwd: c.caseDir,
    env: env0 ?? operatorEnv(c, env),
    encoding: "utf8",
    timeout: 120_000
  });
  if (run.error) throw run.error;
  const report = args.includes("--json") && run.stdout.trim() ? JSON.parse(run.stdout.trim().split("\n").at(-1)) : null;
  return {
    status: run.status, stdout: run.stdout, stderr: run.stderr, report, calls: calls(c),
    pushesReceived: c.received(), unchanged: snapshot(c) === before
  };
}

const byId = (report, id) => report.checks.find((x) => x.id === id);
const OUTPUT_FORBIDDEN = [
  PASSWORD_MARKER,
  "BEGIN PRIVATE KEY",
  "BEGIN PUBLIC KEY",
  ...trust.executor.keys.privatePem.split("\n").filter((l) => l.length > 20)
];
function assertNoSecrets(run, label) {
  for (const text of [run.stdout, run.stderr]) {
    for (const needle of OUTPUT_FORBIDDEN) assert.ok(!text.includes(needle), `${label}: output contains secret material`);
  }
}
function assertNoSideEffects(c, run, label) {
  assert.equal(run.calls.execute, 0, `${label}: doctor must never call executeGitPush()`);
  assert.equal(run.pushesReceived, 0, `${label}: the remote must receive no push`);
  assert.ok(run.unchanged, `${label}: no claim, evidence, working-tree or remote change`);
  assert.equal(c.repos.remoteSha(), c.repos.commits[0], `${label}: the remote must not move`);
}

// Static helpers (same rules as tests/test_git_push_reachability.mjs).
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
}
function specifiers(src) {
  const re = /(?:import|export)\s[^'"`;]*?from\s*["']([^"']+)["']|import\s*\(\s*["']([^"']+)["']\s*\)|require\s*\(\s*["']([^"']+)["']\s*\)|import\s+["']([^"']+)["']/g;
  return [...stripComments(src).matchAll(re)].map((m) => m[1] ?? m[2] ?? m[3] ?? m[4]);
}

console.log("git.push doctor (bin/mnde-git-push-doctor.mjs, run as a child process)\n");

await test("A: an unconfigured shell is NOT_CONFIGURED with the first step named; dependents are SKIPPED, not READY", () => {
  const c = newCase();
  const run = runDoctor(c, ["--json"], { env0: { PATH: process.env.PATH } });
  assert.equal(run.status, 1, run.stderr);
  assert.equal(run.report.schema, "mnde.git-push-doctor.v1");
  assert.equal(run.report.verdict, "NOT_READY");
  const config = byId(run.report, "config.environment");
  assert.equal(config.status, "NOT_CONFIGURED");
  assert.match(config.fix, /FIRST-PRODUCTION-GIT-PUSH\.md/);
  for (const id of ["startup.trust", "executor.construct", "claim.store"]) assert.equal(byId(run.report, id).status, "SKIPPED", id);
  assert.equal(run.calls.construct, 0, "no executor without configuration");
  assertNoSideEffects(c, run, "A");
});

await test("B: a complete configuration passes the local checks, says what it did not verify, and changes nothing", () => {
  const c = newCase();
  const run = runDoctor(c);
  assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
  assert.equal(run.report.verdict, "LOCAL_CHECKS_PASSED");
  for (const id of ["runtime.node", "runtime.git", "config.environment", "startup.trust", "executor.credential_expiry", "executor.construct", "claim.store", "repo.path", "evidence.dir"]) {
    assert.equal(byId(run.report, id).status, "READY", `${id}: ${byId(run.report, id).evidence}`);
  }
  assert.ok(run.report.not_verified.includes("credential.live"));
  assert.ok(run.report.not_verified.includes("enforcement.sole_credential"));
  for (const id of run.report.not_verified) assert.equal(byId(run.report, id).status, "NOT_VERIFIED");
  assert.deepEqual(run.report.side_effects, { push_attempted: false, claim_written: false, credential_requested: false, files_written: false });
  assert.deepEqual(run.calls, { construct: 1, execute: 0 }, "one construction for the readiness check, zero executions");
  assertNoSideEffects(c, run, "B");
  assertNoSecrets(run, "B");
});

await test("B2: the text report uses words not colour, names what is unverified, and never says 'protected' or 'secure'", () => {
  const c = newCase();
  const run = runDoctor(c, []);
  assert.equal(run.status, 0, run.stderr);
  assert.match(run.stdout, /\[READY\]/);
  assert.match(run.stdout, /\[NOT_VERIFIED\]/);
  assert.match(run.stdout, /NOT a statement that your repository is protected/);
  assert.match(run.stdout, /Nothing was pushed, no claim was written, no credential was requested, no file was written\./);
  assert.doesNotMatch(run.stdout, /\bsecure\b/i);
  assert.doesNotMatch(run.stdout, /\u001b\[/, "no terminal colour codes");
  assertNoSideEffects(c, run, "B2");
  assertNoSecrets(run, "B2");
});

await test("C: a credential close to expiry is ATTENTION with the fix, and still exits 0", async () => {
  const c = newCase();
  const soon = await issueExecutorCredential({
    authorityBundle: trust.bundle,
    rootPrivatePem: trust.root.privatePem,
    executorId: EXECUTOR_ID,
    publicPem: trust.executor.keys.publicPem,
    environmentId: ENVIRONMENT_ID,
    capabilities: [EXECUTOR_RECEIPT_CAPABILITY],
    issuedAt: new Date(Date.now() - 60_000).toISOString(),
    notBefore: new Date(Date.now() - 60_000).toISOString(),
    expiresAt: new Date(Date.now() + 24 * 3_600_000).toISOString()
  });
  const soonPath = join(operatorDir, "expiring-credential.json");
  writeFileSync(soonPath, `${JSON.stringify(soon)}\n`, "utf8");
  const run = runDoctor(c, ["--json"], { env: { MNDE_EXECUTOR_CREDENTIAL: soonPath } });
  assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
  assert.equal(run.report.verdict, "LOCAL_CHECKS_PASSED_WITH_ATTENTION");
  const expiry = byId(run.report, "executor.credential_expiry");
  assert.equal(expiry.status, "ATTENTION");
  assert.match(expiry.fix, /trust-enroll-executor/);
  assertNoSideEffects(c, run, "C");
});

await test("D: the shipped demo root is FAILED with the reason code and the fix; nothing later is reported READY", () => {
  const c = newCase();
  const run = runDoctor(c, ["--json"], { env: { MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT: DEMO_ROOT } });
  assert.equal(run.status, 1);
  const trustCheck = byId(run.report, "startup.trust");
  assert.equal(trustCheck.status, "FAILED");
  assert.match(trustCheck.evidence, /ERR_GIT_PUSH_DEMO_TRUST_MATERIAL/);
  assert.match(trustCheck.fix, /prepare-git-push-trust/);
  for (const id of ["executor.credential_expiry", "executor.construct", "claim.store"]) assert.equal(byId(run.report, id).status, "SKIPPED", id);
  assert.equal(run.calls.construct, 0);
  assertNoSideEffects(c, run, "D");
});

if (process.platform !== "win32") {
  await test("E: a group-readable executor key is FAILED with the permission fix, and the key is not printed", () => {
    const c = newCase();
    const openKey = join(operatorDir, "group-readable-key.pem");
    writeFileSync(openKey, trust.executor.keys.privatePem, "utf8");
    chmodSync(openKey, 0o640);
    const run = runDoctor(c, ["--json"], { env: { MNDE_EXECUTOR_PRIVATE_KEY: openKey } });
    assert.equal(run.status, 1);
    const trustCheck = byId(run.report, "startup.trust");
    assert.equal(trustCheck.status, "FAILED");
    assert.match(trustCheck.evidence, /ERR_GIT_PUSH_TRUST_FILE_INSECURE/);
    assert.match(trustCheck.fix, /chmod 600/);
    assertNoSideEffects(c, run, "E");
    assertNoSecrets(run, "E");
  });
}

await test("F: a missing push-credential configuration fails at construction and skips the claim check", () => {
  const c = newCase();
  const run = runDoctor(c, ["--json"], { env: { MNDE_GIT_CREDENTIAL_CONFIG: join(operatorDir, "no-such-credential-config.json") } });
  assert.equal(run.status, 1, run.stdout);
  assert.equal(byId(run.report, "startup.trust").status, "READY");
  const construct = byId(run.report, "executor.construct");
  assert.equal(construct.status, "FAILED");
  assert.equal(byId(run.report, "claim.store").status, "SKIPPED");
  assert.equal(run.calls.construct, 1);
  assertNoSideEffects(c, run, "F");
});

await test("G: against the REAL claim adapter, an unreachable store is FAILED with a fix; construction alone is not reported as ready", () => {
  const c = newCase();
  const caFile = join(operatorDir, "unreachable-ca.pem");
  const passwordFile = join(operatorDir, "unreachable-password");
  writeFileSync(caFile, "-----BEGIN CERTIFICATE-----\nnot a real certificate\n-----END CERTIFICATE-----\n", "utf8");
  writeFileSync(passwordFile, `${PASSWORD_MARKER}\n`, { encoding: "utf8", mode: 0o600 });
  const configPath = join(operatorDir, "unreachable-claim-config.json");
  writeFileSync(configPath, JSON.stringify({
    host: "127.0.0.1", port: 1, database: "mnde", user: "mnde_executor", namespace: NAMESPACE, passwordFile, caFile
  }), "utf8");
  const run = runDoctor(c, ["--json"], { env: { MNDE_CLAIM_CONFIG: configPath }, claimDouble: false });
  assert.equal(run.status, 1, run.stdout);
  assert.equal(byId(run.report, "executor.construct").status, "READY");
  const claim = byId(run.report, "claim.store");
  assert.equal(claim.status, "FAILED");
  assert.match(claim.fix, /pg/);
  assert.equal(run.report.verdict, "NOT_READY");
  assert.deepEqual(run.calls, { construct: 1, execute: 0 });
  assertNoSideEffects(c, run, "G");
  assertNoSecrets(run, "G");
});

await test("H: a missing evidence directory is ATTENTION; a staging path that is not a repository is FAILED", () => {
  const c = newCase();
  const noEvidence = runDoctor(c, ["--json"], { env: { MNDE_GIT_PUSH_EVIDENCE_DIR: join(c.caseDir, "not-yet") } });
  assert.equal(byId(noEvidence.report, "evidence.dir").status, "ATTENTION");
  assert.equal(noEvidence.status, 0);
  assert.equal(existsSync(join(c.caseDir, "not-yet")), false, "doctor must not create the directory");

  const notRepo = join(c.caseDir, "plain-dir");
  mkdirSync(notRepo);
  const bad = runDoctor(c, ["--json"], { env: { MNDE_GIT_PUSH_REPO_PATH: notRepo } });
  assert.equal(byId(bad.report, "repo.path").status, "FAILED");
  assert.equal(bad.status, 1);
});

await test("I: usage errors exit 3 before reading any configuration", () => {
  const c = newCase();
  const run = runDoctor(c, ["--bogus"]);
  assert.equal(run.status, 3);
  assert.match(run.stderr, /usage: mnde-git-push-doctor/);
  assert.deepEqual(run.calls, { construct: 0, execute: 0 });
});

await test("J: the library renders a report without colour and without inventing a READY for an unverified check", async () => {
  const report = await runGitPushDoctor({ PATH: process.env.PATH ?? "" });
  assert.equal(report.verdict, "NOT_READY");
  assert.ok(report.checks.every((x) => x.status !== "READY" || !/unverified|not verified/i.test(x.evidence)));
  assert.doesNotMatch(renderGitPushDoctor(report), /\u001b\[/);
});

await test("K: doctor reaches the executor only to construct it and read readiness (static)", () => {
  const lib = readFileSync(join(ROOT, "src", "effects", "git-push", "doctor.mjs"), "utf8");
  const bin = readFileSync(DOCTOR, "utf8");
  assert.deepEqual(specifiers(lib).sort(), ["./index.mjs", "./startup.mjs", "node:fs", "node:path"]);
  assert.deepEqual(specifiers(bin).sort(), ["../src/effects/git-push/doctor.mjs"]);
  const forbidden = /child_process|node:cluster|worker_threads|\bspawn|\bexecFile|\bexecSync|\bfetch\s*\(|performPush|buildPushArgv|claimAuthority|redeemClaimTicket|openExecutorClaimBackend|postgres_claim|freshness\/|transport\.mjs|credential-provider|api\.github\.com|writeFile|mkdirSync|appendFile|renameSync|unlinkSync|rmSync|\.executeGitPush\b/;
  // "git" as a bare literal is allowed: doctor looks for the executable on PATH
  // with fs.statSync and never runs it, which the child_process/spawn ban proves.
  for (const [name, src] of [["doctor.mjs", lib], ["mnde-git-push-doctor.mjs", bin]]) {
    const hit = forbidden.exec(stripComments(src));
    assert.equal(hit, null, `${name} must not reach below the executor or write: found '${hit?.[0]}'`);
  }
  assert.equal((stripComments(lib).match(/createGitPushExecutor\s*\(/g) ?? []).length, 1, "exactly one construction site");
  assert.equal((stripComments(lib).match(/\.readiness\s*\(/g) ?? []).length, 1, "exactly one readiness call");
});

const total = passed + failed;
if (failed === 0) console.log(`\nPASS git.push doctor (${passed}/${total})`);
else { console.error(`\nFAIL git.push doctor (${passed}/${total})`); process.exitCode = 1; }
