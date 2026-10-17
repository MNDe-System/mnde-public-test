// F-001 closure harness — real PostgreSQL, real production CLI, real SIGKILLs.
//
//   F001_PG_DIR=/var/tmp/mnde-pg node tests/f001-closure/closure.mjs [case-id ...]
//
// NOT part of `npm test`: it needs a provisioned disposable PostgreSQL primary
// (docs/F001-CLOSURE-REPORT.md "Reproducing"), the `pg` driver, and it writes
// claim rows that the executor login cannot delete. Everything here runs the
// production entry point (bin/mnde-git-push.mjs) as a separate OS process with the
// real claim adapter. The remote is a local bare repository reached over file://;
// it is NOT GitHub. Cases that need GitHub, a GitHub App, a human approver or an
// OS/VM crash are not simulated here and are reported BLOCKED in the closure report.
//
// Environment:
//   F001_PG_DIR   cluster directory (default /var/tmp/mnde-pg): claim-config.json, ca.crt, data/, snap/
//   F001_SRC      tree whose bin/mnde-git-push.mjs is executed (default: this tree). Point it at a
//                 checkout of the pre-remediation commit to reproduce the vulnerability (control run).
//   F001_OUT      output directory for results.json and per-case artifacts

import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { classifyGitPushExecution } from "../../src/effects/git-push/index.mjs";
import { canonicalRepositoryIdentity } from "../../src/effects/git-push/validate.mjs";
import { startEmulator } from "./ghemu.mjs";
import {
  ENVIRONMENT_ID, EXECUTOR_ID, gitPushAuthorization, makeRepositories, productionTrust, pushParameters
} from "../support/git_push_fixtures.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..");
const SRC = resolve(process.env.F001_SRC ?? ROOT);
const PG = resolve(process.env.F001_PG_DIR ?? "/var/tmp/mnde-pg");
const OUT = resolve(process.env.F001_OUT ?? join(ROOT, "docs", "evidence", "f001", "2026-10-17-closure"));
const CLI = join(SRC, "bin", "mnde-git-push.mjs");
const FAULTS = pathToFileURL(join(HERE, "faults.mjs")).href;
const PG_BIN = "/usr/lib/postgresql/16/bin";
const claimConfig = JSON.parse(readFileSync(join(PG, "claim-config.json"), "utf8"));
const only = new Set(process.argv.slice(2));
mkdirSync(OUT, { recursive: true });

// ── result recording ────────────────────────────────────────────────────────
const results = [];
async function scenario(id, title, expected, fn) {
  if (only.size && !only.has(id)) return;
  const entry = { id, title, expected, status: "FAIL", observed: null };
  try {
    entry.observed = await fn();
    entry.status = "PASS";
  } catch (error) {
    entry.status = error?.blocked ? "BLOCKED" : "FAIL";
    entry.observed = { error: String(error?.message ?? error).slice(0, 1500), ...(error?.observed ?? {}) };
  }
  results.push(entry);
  console.log(`[${entry.status}] ${id} ${title}`);
  if (entry.status !== "PASS") console.log(`        ${JSON.stringify(entry.observed).slice(0, 700)}`);
}

// ── database helpers (owner role; the executor login cannot read the table) ─
const ownerEnv = { ...process.env, PGPASSWORD: "ownerpw", PGSSLMODE: "verify-full", PGSSLROOTCERT: join(PG, "ca.crt") };
function sql(query, db = claimConfig.database) {
  return execFileSync("psql", ["-h", "127.0.0.1", "-p", String(claimConfig.port), "-U", "owner", "-d", db, "-At", "-c", query],
    { env: ownerEnv, encoding: "utf8" }).trim();
}
const claimRows = (grantId) => Number(sql(`select count(*) from mnde_claim.claims where grant_id = '${grantId}'`));
const pgCtl = (...args) => spawnSync("su", ["postgres", "-c", `${PG_BIN}/pg_ctl -D ${PG}/data ${args.join(" ")}`], { encoding: "utf8" });

// ── world ───────────────────────────────────────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), "mnde-f001-closure-"));
const trust = await productionTrust(dir);
const operatorDir = join(dir, "operator");
mkdirSync(operatorDir, { recursive: true });
const keyPath = join(operatorDir, "executor-key.pem");
writeFileSync(keyPath, trust.executor.keys.privatePem, { encoding: "utf8", mode: 0o600 });
const credentialPath = join(operatorDir, "executor-credential.json");
writeFileSync(credentialPath, `${JSON.stringify(trust.executor.credential, null, 2)}\n`, "utf8");

const git = (args, cwd) => execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
const PRE_RECEIVE = `#!/bin/sh
cat >> attempts.log
if [ -f hold-pre-receive ]; then : > pre-receive-reached; i=0
  while [ ! -f release-pre-receive ] && [ $i -lt 1200 ]; do sleep 0.1; i=$((i+1)); done; exit 1; fi
`;
const POST_RECEIVE = `#!/bin/sh
cat >> received.log
if [ -f hold-post-receive ]; then : > post-receive-reached; i=0
  while [ ! -f release-post-receive ] && [ $i -lt 1200 ]; do sleep 0.1; i=$((i+1)); done; fi
`;

let caseIndex = 0;
function newCase(label) {
  caseIndex += 1;
  const caseDir = join(dir, `${String(caseIndex).padStart(2, "0")}-${label}`);
  const repos = makeRepositories(caseDir);
  writeFileSync(join(repos.barePath, "hooks", "pre-receive"), PRE_RECEIVE, { mode: 0o755 });
  writeFileSync(join(repos.barePath, "hooks", "post-receive"), POST_RECEIVE, { mode: 0o755 });
  const count = (name) => { const p = join(repos.barePath, name); return existsSync(p) ? readFileSync(p, "utf8").split("\n").filter(Boolean).length : 0; };
  return { caseDir, repos, label, evidenceDir: join(caseDir, "evidence"), log: join(caseDir, "fault.log"),
    attempts: () => count("attempts.log"), received: () => count("received.log"),
    flag: (name) => join(repos.barePath, name) };
}

function operatorEnv(c, overrides = {}) {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith("MNDE_") && !k.startsWith("PG")) env[k] = v;
  Object.assign(env, {
    MNDE_PROFILE: "production",
    MNDE_CLAIM_CONFIG: join(PG, "claim-config.json"),
    MNDE_GIT_CREDENTIAL_CONFIG: c.repos.credentialConfigPath,
    MNDE_GIT_PUSH_REPO_PATH: c.repos.localPath,
    MNDE_GIT_PUSH_NAMESPACE: claimConfig.namespace,
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
    MNDE_F001_LOG: c.log
  });
  for (const [k, v] of Object.entries(overrides)) { if (v === undefined) delete env[k]; else env[k] = v; }
  return env;
}

// Start the production CLI. Resolves with what the OS reports, plus parsed stdout when there is one.
function startCli(c, requestPath, { fault = "", env = {} } = {}) {
  const child = spawn(process.execPath, ["--no-warnings", "--import", FAULTS, CLI, requestPath],
    { cwd: c.caseDir, env: operatorEnv(c, { MNDE_F001_FAULT: fault, ...env }), stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "", stderr = "";
  child.stdout.on("data", (d) => { stdout += d; });
  child.stderr.on("data", (d) => { stderr += d; });
  const done = new Promise((res) => child.on("close", (code, signal) => {
    const line = stdout.split("\n").filter(Boolean)[0];
    let out = null;
    try { out = line ? JSON.parse(line) : null; } catch { out = null; }
    res({ code, signal, out, stderr: stderr.slice(0, 600) });
  }));
  return { child, done };
}
const runCli = (c, requestPath, options) => startCli(c, requestPath, options).done;

async function waitFor(path, ms = 30000) {
  const end = Date.now() + ms;
  while (!existsSync(path)) { if (Date.now() > end) throw new Error(`timed out waiting for ${path}`); await new Promise((r) => setTimeout(r, 50)); }
}

let requestIndex = 0;
async function authorize(c, { from = 0, to = 1, grantId = `grant-${randomUUID()}`, executionId = `exec-${randomUUID()}`, now, expiresAt, overrides } = {}) {
  const parameters = pushParameters(c.repos, { from: c.repos.commits[from], to: c.repos.commits[to], overrides });
  const options = { grantId, executionId, ...(now ? { now } : {}), ...(expiresAt ? { expiresAt } : {}) };
  const authorization = await gitPushAuthorization(trust, parameters, options);
  requestIndex += 1;
  const path = join(c.caseDir, `request-${requestIndex}.json`);
  const body = (p) => ({ repository: p.repository, remote: p.remote, remoteUrl: p.remote_url, sourceCommit: p.source_commit,
    targetRef: p.target_ref, expectedOldSha: p.expected_old_sha, authorization });
  writeFileSync(path, `${JSON.stringify(body(parameters), null, 2)}\n`);
  return { parameters, authorization, path, grantId, executionId, bodyFor: body };
}

function signedEvidenceFiles(c) {
  return existsSync(c.evidenceDir) ? readdirSync(c.evidenceDir).filter((n) => n.endsWith(".signed.json")).map((n) => join(c.evidenceDir, n)) : [];
}
function verifyOffline(file) {
  const run = spawnSync(process.execPath, [join(ROOT, "scripts", "verify-git-push-evidence.mjs"), file,
    "--authority-bundle", trust.bundlePath, "--root-fingerprint", trust.fingerprint,
    "--expected-executor-id", EXECUTOR_ID, "--expected-environment-id", ENVIRONMENT_ID], { encoding: "utf8" });
  return { exit: run.status, ...JSON.parse(run.stdout.split("\n").filter(Boolean)[0] ?? "{}") };
}
function executionId(c) {
  const f = existsSync(c.evidenceDir) ? readdirSync(c.evidenceDir).find((n) => n.endsWith(".started.json")) : null;
  return f ? f.replace(/^git-push-/, "").replace(/\.started\.json$/, "") : null;
}
// Operator reconciliation: read-only. Compares the remote with the approved states and never pushes.
function reconcile(c, a) {
  const remote = c.repos.remoteSha();
  const p = a.parameters;
  return remote === p.source_commit ? "REMOTE_AT_APPROVED_SHA" : remote === p.expected_old_sha ? "REMOTE_AT_PRE_STATE" : `REMOTE_DIVERGED:${remote}`;
}
function classify(c, a, exec) {
  const id = exec ?? executionId(c);
  return id ? classifyGitPushExecution({ evidenceDir: c.evidenceDir, executionId: id }) : { condition: "NO_EXECUTION_RECORD" };
}
const reason = (r) => r.out?.reason_code ?? null;
const SPENT = "ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT";

// ═══════════════════════════════════════════════════════════════════════════
await scenario("T01", "authorized push succeeds once; claim, ledger, start record and signed evidence all exist",
  "EXECUTED, remote at approved SHA, 1 DB row, ledger entry, start record, evidence verifies offline", async () => {
    const c = newCase("baseline");
    const a = await authorize(c);
    const r = await runCli(c, a.path);
    assert.equal(r.code, 0, JSON.stringify(r.out ?? r.stderr));
    assert.equal(r.out.outcome, "EXECUTED");
    assert.equal(c.repos.remoteSha(), a.parameters.source_commit);
    assert.equal(c.received(), 1);
    const files = signedEvidenceFiles(c);
    assert.equal(files.length, 1);
    const v = verifyOffline(files[0]);
    assert.equal(v.ok, true, JSON.stringify(v));
    assert.equal(claimRows(r.out.grant_id), 1);
    const ledger = readdirSync(join(c.evidenceDir, "spent-ledger"));
    assert.ok(ledger.includes("LEDGER.json") && ledger.filter((n) => n.startsWith("grant-")).length === 1 && ledger.filter((n) => n.startsWith("exec-")).length === 1);
    assert.ok(readdirSync(c.evidenceDir).some((n) => n.endsWith(".started.json")));
    cpSync(files[0], join(OUT, "T01-evidence.signed.json"));
    return { outcome: r.out.outcome, db_rows: 1, ledger_entries: ledger, offline_verify: v, evidence_copy: "T01-evidence.signed.json",
      push_credential: r.out.push_credential };
  });

await scenario("T02", "repeated execution of a consumed authorization fails, three times, with the remote reset so only the claim can stop it",
  "every replay REFUSED already-spent; remote receives zero further pushes", async () => {
    const c = newCase("replay");
    const a = await authorize(c);
    const first = await runCli(c, a.path);
    assert.equal(first.code, 0);
    c.repos.setRemoteTo(a.parameters.expected_old_sha); // an administrator reverts the branch: the pre-state check would now pass
    const before = c.received();
    const replays = [];
    for (let i = 0; i < 3; i += 1) replays.push(await runCli(c, a.path));
    for (const r of replays) assert.equal(r.out.reason_code, SPENT, JSON.stringify(r.out));
    assert.equal(c.received(), before, "the remote received another push");
    assert.equal(c.repos.remoteSha(), a.parameters.expected_old_sha);
    return { replays: replays.map((r) => ({ exit: r.code, outcome: r.out.outcome, reason: r.out.reason_code })), remote_pushes_after_first: c.received() - before };
  });

await scenario("T03", "100 concurrent claims of one grant against real PostgreSQL",
  "exactly one CLAIMED", async () => {
    const c = newCase("claims100");
    const run = spawnSync(process.execPath, [join(HERE, "concurrent.mjs"), "claims", "100"], { env: operatorEnv(c), encoding: "utf8", timeout: 180000 });
    const out = JSON.parse(run.stdout.split("\n").filter(Boolean).pop());
    assert.equal(out.tally.CLAIMED, 1, JSON.stringify(out));
    return out;
  });

await scenario("T04", "100 concurrent executeGitPush() calls of one authorization in one executor, then 12 concurrent CLI processes of another",
  "exactly one push reaches the remote in each", async () => {
    const c = newCase("race-inproc");
    const a = await authorize(c);
    const run = spawnSync(process.execPath, ["--no-warnings", join(HERE, "concurrent.mjs"), "execute", "100", a.path], { env: operatorEnv(c), encoding: "utf8", timeout: 280000 });
    const inproc = JSON.parse(run.stdout.split("\n").filter(Boolean).pop());
    assert.equal(inproc.tally.EXECUTED, 1, JSON.stringify(inproc));
    assert.equal(c.received(), 1, `remote received ${c.received()} pushes`);
    const d = newCase("race-procs");
    const b = await authorize(d);
    const runs = await Promise.all(Array.from({ length: 12 }, () => runCli(d, b.path)));
    const executed = runs.filter((r) => r.out?.outcome === "EXECUTED").length;
    assert.equal(executed, 1, JSON.stringify(runs.map((r) => r.out?.reason_code ?? r.out?.outcome)));
    assert.equal(d.received(), 1);
    const tally = {};
    for (const r of runs) { const k = r.out?.reason_code ?? r.out?.outcome ?? "NO_OUTPUT"; tally[k] = (tally[k] ?? 0) + 1; }
    return { in_process_100: inproc.tally, remote_pushes_in_process: c.received(), processes_12: tally, remote_pushes_processes: d.received() };
  });

// ── crash matrix ────────────────────────────────────────────────────────────
// retryAllowed: the fault happens before the authority is consumed, so a retry is a first execution, not a reuse.
async function crashCase(id, title, fault, { expectRetryExecutes = false, hold = null, expectRemote }) {
  await scenario(id, title, expectRetryExecutes
    ? "SIGKILL; authority not consumed; one retry executes once; a further retry is refused"
    : "SIGKILL; authority consumed; recovery refuses reuse and sends nothing", async () => {
      const c = newCase(id.toLowerCase());
      const a = await authorize(c);
      let killed;
      if (hold) {
        writeFileSync(c.flag(`hold-${hold}`), "");
        const run = startCli(c, a.path);
        await waitFor(c.flag(`${hold}-reached`));
        run.child.kill("SIGKILL");
        killed = await run.done;
        writeFileSync(c.flag(`release-${hold}`), ""); // let the orphaned hook finish; the executor is already dead
      } else {
        killed = await runCli(c, a.path, { fault });
      }
      assert.equal(killed.signal, "SIGKILL", `expected SIGKILL, got ${JSON.stringify(killed)}`);
      const faultLog = existsSync(c.log) ? readFileSync(c.log, "utf8").trim() : "(held hook; parent killed child)";
      const grantRows = Number(sql(`select count(*) from mnde_claim.claims where execution_id = '${a.executionId}'`));
      const remoteAfterCrash = reconcile(c, a);
      assert.equal(remoteAfterCrash, expectRemote, `remote state after crash: ${remoteAfterCrash}`);
      const classification = classify(c, a, a.executionId);
      const attemptsAfterCrash = c.attempts();
      const recovery = await runCli(c, a.path);
      const observed = { fault_log: faultLog, db_claim_rows_after_crash: grantRows, remote_after_crash: remoteAfterCrash,
        classification: classification.condition, retry_permitted: classification.retry_permitted ?? null,
        recovery: { exit: recovery.code, outcome: recovery.out?.outcome, reason: recovery.out?.reason_code } };
      if (expectRetryExecutes) {
        assert.equal(recovery.out.outcome, "EXECUTED", JSON.stringify(recovery.out));
        assert.equal(c.received(), 1);
        const again = await runCli(c, a.path);
        assert.notEqual(again.out.outcome, "EXECUTED");
        observed.second_retry = { reason: again.out.reason_code };
        assert.equal(c.received(), 1, "a second push was sent");
      } else {
        assert.equal(recovery.out.outcome, "REFUSED", JSON.stringify(recovery.out));
        assert.equal(recovery.out.reason_code, SPENT, JSON.stringify(recovery.out));
        assert.equal(c.attempts(), attemptsAfterCrash, "recovery contacted the remote's receive-pack");
        observed.remote_pushes_total = c.received();
        observed.reconciliation = reconcile(c, a);
        assert.equal(observed.reconciliation, expectRemote);
        assert.ok(c.received() <= 1);
      }
      return observed;
    });
}
const AT_OLD = "REMOTE_AT_PRE_STATE";
await crashCase("C1", "crash BEFORE claiming (died before first_claim was sent)", "sql-before-claim", { expectRetryExecutes: true, expectRemote: AT_OLD });
await crashCase("C2", "crash DURING claim commit, transaction open and COMMIT not yet sent", "sql-before-commit", { expectRetryExecutes: true, expectRemote: AT_OLD });
await scenario("C2b", "crash DURING claim commit: COMMIT written to the socket, process killed before the reply",
  "either the claim committed (recovery refuses) or it did not (retry executes once); never both", async () => {
    const c = newCase("c2b");
    const a = await authorize(c);
    const killed = await runCli(c, a.path, { fault: "sql-during-commit" });
    assert.equal(killed.signal, "SIGKILL");
    await new Promise((r) => setTimeout(r, 500));
    const committed = Number(sql(`select count(*) from mnde_claim.claims where execution_id = '${a.executionId}'`)) === 1;
    const recovery = await runCli(c, a.path);
    if (committed) {
      assert.equal(recovery.out.reason_code, SPENT);
      assert.equal(c.received(), 0);
    } else {
      assert.equal(recovery.out.outcome, "EXECUTED", JSON.stringify({ committed, out: recovery.out }));
      assert.equal(c.received(), 1);
    }
    return { claim_committed_before_death: committed, recovery: { outcome: recovery.out.outcome, reason: recovery.out.reason_code }, remote_pushes: c.received() };
  });
await crashCase("C3", "crash AFTER claim commit was acknowledged", "sql-after-commit", { expectRemote: AT_OLD });
await scenario("C3b", "SIMULATED (not a crash): COMMIT acknowledged but the reply reported lost",
  "claim found durably present by lookup; nothing sent; replay refused", async () => {
    const c = newCase("c3b");
    const a = await authorize(c);
    const r = await runCli(c, a.path, { fault: "sql-lost-ack" });
    assert.equal(r.out.outcome, "REFUSED", JSON.stringify(r.out));
    assert.equal(c.received(), 0);
    const replay = await runCli(c, a.path);
    assert.equal(replay.out.reason_code, SPENT);
    return { first: { outcome: r.out.outcome, reason: r.out.reason_code, claim: r.out.claim }, replay: replay.out.reason_code, remote_pushes: c.received() };
  });
await crashCase("C4", "crash after claim, BEFORE the executor-local ledger entry", "fs-before-ledger", { expectRemote: AT_OLD });
await crashCase("C5", "crash BEFORE execution-start persistence (ledger entry written)", "fs-before-start-record", { expectRemote: AT_OLD });
await crashCase("C6", "crash AFTER execution-start persistence (file and directory fsynced)", "fs-after-start-record", { expectRemote: AT_OLD });
await crashCase("C6b", "crash immediately before `git push` is spawned", "exec-before-push", { expectRemote: AT_OLD });
await crashCase("C7", "crash DURING the GitHub-side push (receive-pack blocked in pre-receive; client SIGKILLed)", null, { hold: "pre-receive", expectRemote: AT_OLD });
await crashCase("C8", "crash AFTER remote success, before any local evidence (post-receive blocked; client SIGKILLed)", null, { hold: "post-receive", expectRemote: "REMOTE_AT_APPROVED_SHA" });
await crashCase("C9", "crash DURING evidence persistence: signed evidence fsynced as *.tmp, not renamed", "fs-evidence-before-rename", { expectRemote: "REMOTE_AT_APPROVED_SHA" });
await crashCase("C9b", "crash DURING evidence persistence: renamed, directory not yet fsynced", "fs-evidence-after-rename", { expectRemote: "REMOTE_AT_APPROVED_SHA" });
await crashCase("C10", "crash BEFORE the client response (evidence durable)", "stdout-before-response", { expectRemote: "REMOTE_AT_APPROVED_SHA" });

await scenario("C11", "executor restart: a new process, same state directories, after a completed push",
  "refuses; classification is EXECUTED", async () => {
    const c = newCase("restart");
    const a = await authorize(c);
    const first = await runCli(c, a.path);
    assert.equal(first.code, 0);
    const restarted = await runCli(c, a.path);
    assert.equal(restarted.out.reason_code, SPENT);
    const k = classify(c, a, a.executionId);
    assert.equal(k.condition, "EXECUTED");
    return { restarted: restarted.out.reason_code, classification: k.condition, remote_pushes: c.received() };
  });

// ── binding / staleness ─────────────────────────────────────────────────────
await scenario("B1", "wrong ref, wrong repository, changed target SHA, stale authorization: refused before any claim, authority stays usable",
  "each REFUSED with no DB row and no push; the genuine request then still executes once", async () => {
    const c = newCase("binding");
    const a = await authorize(c);
    const good = JSON.parse(readFileSync(a.path, "utf8"));
    const variants = {
      wrong_ref: { ...good, targetRef: "refs/heads/other" },
      wrong_repository: { ...good, repository: "https:github.com/attacker/other" },
      changed_target_sha: { ...good, sourceCommit: c.repos.commits[2] },
      changed_expected_old_sha: { ...good, expectedOldSha: c.repos.commits[1] },
      wrong_remote_url: { ...good, remoteUrl: `${good.remoteUrl}.evil` }
    };
    const seen = {};
    for (const [name, body] of Object.entries(variants)) {
      const path = join(c.caseDir, `variant-${name}.json`);
      writeFileSync(path, JSON.stringify(body));
      const r = await runCli(c, path);
      assert.equal(r.out.outcome, "REFUSED", `${name}: ${JSON.stringify(r.out)}`);
      seen[name] = r.out.reason_code;
    }
    const stale = await authorize(c, { expiresAt: "2026-06-14T00:05:00.000Z" }); // expired months ago
    const rs = await runCli(c, stale.path);
    assert.equal(rs.out.outcome, "REFUSED", JSON.stringify(rs.out));
    seen.stale_authorization = rs.out.reason_code;
    assert.equal(c.attempts(), 0);
    assert.equal(Number(sql(`select count(*) from mnde_claim.claims where execution_id = '${a.executionId}'`)), 0);
    const genuine = await runCli(c, a.path);
    assert.equal(genuine.out.outcome, "EXECUTED");
    return { refusal_reasons: seen, db_rows_before_genuine: 0, genuine_then_executed_once: true, remote_pushes: c.received() };
  });

await scenario("B2", "ledger lost: spent-ledger directory removed next to existing start records",
  "fails closed (ERR_LEDGER_UNAVAILABLE), never re-initializes", async () => {
    const c = newCase("ledger-lost");
    const a = await authorize(c);
    assert.equal((await runCli(c, a.path)).code, 0);
    rmSync(join(c.evidenceDir, "spent-ledger"), { recursive: true, force: true });
    const b = await authorize(c, { from: 1, to: 2 });
    const r = await runCli(c, b.path);
    assert.equal(r.out.outcome, "REFUSED");
    assert.equal(r.out.reason_code, "ERR_LEDGER_UNAVAILABLE", JSON.stringify(r.out));
    assert.equal(c.received(), 1);
    return { reason: r.out.reason_code, remote_pushes: c.received() };
  });

// ── database rollback ───────────────────────────────────────────────────────
await scenario("R1", "restore a PostgreSQL snapshot taken BEFORE the authorization was consumed, then replay it",
  SRC === ROOT ? "REFUSED (rollback detected, quarantined); zero further pushes; a different fresh authorization also refused while quarantined"
    : "CONTROL against the pre-remediation tree: the replay is expected to EXECUTE a second time (the vulnerability)", async () => {
    const c = newCase("rollback");
    const snap = join(PG, "snap");
    rmSync(snap, { recursive: true, force: true });
    const base = spawnSync(`${PG_BIN}/pg_basebackup`, ["-h", "127.0.0.1", "-p", String(claimConfig.port), "-U", "owner", "-D", snap, "-Fp", "-X", "fetch", "-c", "fast"],
      { env: ownerEnv, encoding: "utf8" });
    assert.equal(base.status, 0, base.stderr);
    spawnSync("chown", ["-R", "postgres", snap]); spawnSync("chmod", ["700", snap]);
    const a = await authorize(c);
    const first = await runCli(c, a.path);
    assert.equal(first.code, 0, JSON.stringify(first.out));
    const consumed = claimRows(first.out.grant_id);
    assert.equal(consumed, 1);
    // An administrator who may legitimately move the branch puts it back, so the remote pre-state check
    // would pass for a replay: only the authority record can stop it.
    c.repos.setRemoteTo(a.parameters.expected_old_sha);
    const pushesBefore = c.received();
    // The database administrator restores the older state. Executor files and signing keys are untouched.
    rmSync(join(PG, "data.after-claim"), { recursive: true, force: true });
    assert.equal(pgCtl("stop", "-m", "fast", "-w").status, 0);
    try {
      renameSync(join(PG, "data"), join(PG, "data.after-claim"));
      renameSync(snap, join(PG, "data"));
    } finally {
      const started = pgCtl("start", "-w", "-l", join(PG, "log"));
      assert.equal(started.status, 0, started.stderr + started.stdout);
    }
    const afterRestore = claimRows(first.out.grant_id);
    assert.equal(afterRestore, 0, "the restore did not roll the claim back");
    // Replay shape 1 (the F-001 case): a re-issued authorization — fresh execution id, same spent grant.
    const reissued = await authorize(c, { grantId: a.grantId });
    const replay1 = await runCli(c, reissued.path);
    const pushes1 = c.received() - pushesBefore;
    c.repos.setRemoteTo(a.parameters.expected_old_sha);
    const pushesMid = c.received();
    // Replay shape 2: the very same signed authorization presented again.
    const replay2 = await runCli(c, a.path);
    const observed = { rows_before_restore: consumed, rows_after_restore: afterRestore,
      replay_new_execution_id_same_grant: { exit: replay1.code, outcome: replay1.out?.outcome, reason: replay1.out?.reason_code, detail: replay1.out?.detail, pushes_received_by_remote: pushes1 },
      replay_same_authorization: { exit: replay2.code, outcome: replay2.out?.outcome, reason: replay2.out?.reason_code, detail: replay2.out?.detail, pushes_received_by_remote: c.received() - pushesMid },
      remote_after_replays: reconcile(c, a) };
    if (SRC === ROOT) {
      assert.equal(replay1.out.reason_code, "ERR_LEDGER_ROLLBACK_DETECTED", JSON.stringify(replay1.out));
      assert.equal(pushes1, 0, "the rolled-back grant pushed again");
      assert.equal(replay2.out.outcome, "REFUSED");
      assert.equal(c.received() - pushesMid, 0);
      const fresh = await authorize(c);
      const rf = await runCli(c, fresh.path);
      observed.fresh_authorization_while_quarantined = { outcome: rf.out.outcome, reason: rf.out.reason_code };
      assert.equal(rf.out.outcome, "REFUSED");
      assert.equal(rf.out.reason_code, "ERR_LEDGER_QUARANTINED");
      rmSync(join(c.evidenceDir, "spent-ledger", "QUARANTINE.json")); // explicit operator action after investigation
      const afterClear = await runCli(c, fresh.path);
      observed.fresh_after_operator_clears_quarantine = afterClear.out.outcome;
      assert.equal(afterClear.out.outcome, "EXECUTED");
    } else {
      // Control: documents what the pre-remediation tree does. Failing to reproduce is itself a finding.
      observed.control_vulnerability_reproduced = replay1.out.outcome === "EXECUTED";
      assert.equal(replay1.out.outcome, "EXECUTED", `control expected a second execution: ${JSON.stringify(observed)}`);
      assert.equal(pushes1, 1);
    }
    return observed;
  });

// ── GitHub-App credential path, against a local EMULATOR (not GitHub) ───────
const wantsEmulator = !only.size || [...only].some((id) => id.startsWith("G"));
let emu = null;
let emuState = null;
let gh = null;
if (wantsEmulator) {
  emuState = join(dir, "emulator");
  mkdirSync(emuState, { recursive: true });
  const root = join(emuState, "root", "acme");
  mkdirSync(root, { recursive: true });
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const appKeyPath = join(operatorDir, "github-app.pem");
  writeFileSync(appKeyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  emu = await startEmulator({ stateDir: emuState, projectRoot: join(emuState, "root"), cert: readFileSync(join(PG, "server.crt")),
    key: readFileSync(join(PG, "server.key")), appId: 424242, appPublicPem: publicKey.export({ type: "spki", format: "pem" }),
    installationId: 777, repoFullName: "acme/widgets" });
  gh = { appKeyPath, remoteUrl: `https://localhost:${emu.port}/acme/widgets.git`, root, ca: join(PG, "ca.crt") };
  const transportEnvPath = join(operatorDir, "transport-env.json");
  writeFileSync(transportEnvPath, JSON.stringify({ GIT_SSL_CAINFO: gh.ca }));
  gh.transportEnvPath = transportEnvPath;
}
const setFlag = (name, on = true) => { const p = join(emuState, name); if (on) writeFileSync(p, ""); else rmSync(p, { force: true }); };
const mints = (fromIndex = 0) => emu.events().slice(fromIndex);
function newGhCase(label) {
  const c = newCase(label);
  // The bare repository is served at /acme/widgets.git; the local clone's `origin` is the https URL.
  rmSync(join(gh.root, "widgets.git"), { force: true });
  symlinkSync(c.repos.barePath, join(gh.root, "widgets.git"));
  git(["remote", "set-url", "origin", gh.remoteUrl], c.repos.localPath);
  const configPath = join(c.caseDir, "git-credential-config.app.json");
  writeFileSync(configPath, JSON.stringify({ schema: "mnde.git-credential-config.v1", kind: "github-app", app_id: 424242, installation_id: 777,
    private_key_file: gh.appKeyPath, api_base_url: `https://localhost:${emu.port}`, repositories: [canonicalRepositoryIdentity(gh.remoteUrl)] }), { mode: 0o600 });
  c.env = { MNDE_GIT_CREDENTIAL_CONFIG: configPath, MNDE_GIT_PUSH_ALLOWED_SCHEMES: "https", MNDE_GIT_PUSH_TRANSPORT_ENV: gh.transportEnvPath, NODE_EXTRA_CA_CERTS: gh.ca };
  return c;
}
async function ghAuthorize(c, options = {}) {
  return authorize(c, { ...options, overrides: { remote_url: gh.remoteUrl, repository: canonicalRepositoryIdentity(gh.remoteUrl) } });
}
const ghRun = (c, path, fault = "") => runCli(c, path, { fault, env: c.env });
const countEv = (events, e, access) => events.filter((x) => x.e === e && (access === undefined || x.access === access)).length;

await scenario("G1", "[emulator] authorized push with the github-app credential: read token for the pre-state, write token only after the claim",
  "EXECUTED; mint order read then write; both revoked; evidence verifies offline", async () => {
    const c = newGhCase("gh-happy");
    const a = await ghAuthorize(c);
    const r = await ghRun(c, a.path);
    assert.equal(r.code, 0, JSON.stringify(r.out ?? r.stderr));
    const ev = emu.events().filter((x) => x.e === "minted" || x.e === "revoked");
    assert.deepEqual(ev.map((x) => `${x.e}:${x.access}`).slice(0, 4).sort(), ["minted:read", "minted:write", "revoked:read", "revoked:write"]);
    assert.equal(ev.find((x) => x.e === "minted").access, "read", "the first token minted must be the read token");
    assert.equal(c.repos.remoteSha(), a.parameters.source_commit);
    const files = signedEvidenceFiles(c);
    const v = verifyOffline(files[0]);
    assert.equal(v.ok, true, JSON.stringify(v));
    cpSync(files[0], join(OUT, "G1-evidence.signed.json"));
    return { mint_sequence: ev.map((x) => `${x.e}:${x.access}`), push_credential: r.out.push_credential, offline_verify: v, emulator_pushes_applied: countEv(emu.events(), "push-applied") >= 1 };
  });

await scenario("G2", "[emulator] 12 concurrent presentations of one authorization: write tokens minted == claim winners",
  "exactly 1 write token minted, 1 push applied; losers never held a write-capable token", async () => {
    const c = newGhCase("gh-race");
    const a = await ghAuthorize(c);
    const from = emu.events().length;
    const runs = await Promise.all(Array.from({ length: 12 }, () => ghRun(c, a.path)));
    const ev = emu.events().slice(from);
    const writeMints = countEv(ev, "minted", "write"), readMints = countEv(ev, "minted", "read");
    const executed = runs.filter((r) => r.out?.outcome === "EXECUTED").length;
    const observed = { executed, read_tokens_minted: readMints, write_tokens_minted: writeMints, pushes_applied: countEv(ev, "push-applied"),
      refusal_reasons: runs.filter((r) => r.out?.outcome !== "EXECUTED").map((r) => r.out?.reason_code ?? r.out?.outcome) };
    if (SRC === ROOT) {
      assert.equal(executed, 1, JSON.stringify(observed));
      assert.equal(writeMints, 1, `write tokens minted: ${writeMints}`);
      assert.equal(observed.pushes_applied, 1);
    } else {
      // Control (pre-remediation tree): documents the defect. Every racing process got a write token.
      observed.control_write_tokens_exceed_winners = writeMints > executed;
      assert.ok(writeMints > 1, `control expected >1 write tokens; got ${writeMints}`);
    }
    return observed;
  });

await scenario("G3", "[emulator] GitHub App credential failure (token endpoint answers 500) before execution",
  "REFUSED, nothing sent, authority NOT spent; after the fault clears the same authorization executes once", async () => {
    const c = newGhCase("gh-credfail");
    const a = await ghAuthorize(c);
    setFlag("api-fail-read");
    const r = await ghRun(c, a.path);
    setFlag("api-fail-read", false);
    assert.equal(r.out.outcome, "REFUSED");
    assert.equal(claimRows(a.grantId), 0);
    assert.equal(countEv(emu.events(), "push-applied") >= 0, true);
    assert.equal(c.repos.remoteSha(), a.parameters.expected_old_sha);
    const retry = await ghRun(c, a.path);
    assert.equal(retry.out.outcome, "EXECUTED", JSON.stringify(retry.out));
    return { first: { outcome: r.out.outcome, reason: r.out.reason_code }, db_rows_after_failure: 0, retry_after_fault_cleared: retry.out.outcome };
  });

await scenario("G4", "[emulator] GitHub API timeout BEFORE execution (token endpoint never answers)",
  "REFUSED after the 10 s HTTP timeout; authority NOT spent; retry after recovery executes once", async () => {
    const c = newGhCase("gh-timeout-pre");
    const a = await ghAuthorize(c);
    setFlag("api-hang-read");
    const t0 = Date.now();
    const r = await ghRun(c, a.path);
    setFlag("api-hang-read", false);
    assert.equal(r.out.outcome, "REFUSED", JSON.stringify(r.out));
    assert.equal(claimRows(a.grantId), 0);
    const retry = await ghRun(c, a.path);
    assert.equal(retry.out.outcome, "EXECUTED", JSON.stringify(retry.out));
    return { first: { outcome: r.out.outcome, reason: r.out.reason_code, seconds: Math.round((Date.now() - t0) / 1000) }, db_rows_after_failure: 0, retry: retry.out.outcome };
  });

await scenario("G5", "[emulator] write-token mint fails AFTER the claim (read mint ok, write mint 500)",
  "REFUSED, nothing sent, authority SPENT; replay refused; classification NOT_STARTED", async () => {
    const c = newGhCase("gh-writefail");
    const a = await ghAuthorize(c);
    setFlag("api-fail-write");
    const from = emu.events().length;
    const r = await ghRun(c, a.path);
    setFlag("api-fail-write", false);
    assert.equal(r.out.outcome, "REFUSED", JSON.stringify(r.out));
    assert.equal(claimRows(a.grantId), 1);
    assert.equal(countEv(emu.events().slice(from), "push-applied"), 0);
    assert.equal(c.repos.remoteSha(), a.parameters.expected_old_sha);
    const replay = await ghRun(c, a.path);
    assert.equal(replay.out.reason_code, SPENT);
    const k = classify(c, a, a.executionId);
    assert.equal(k.condition, "NOT_STARTED");
    return { first: { outcome: r.out.outcome, reason: r.out.reason_code }, db_rows: 1, replay: replay.out.reason_code, classification: k.condition };
  });

await scenario("G6", "[emulator] transport timeout AFTER a possibly-applied push (receive-pack response held past the 30 s executor timeout)",
  "remote read-back decides: ref at approved SHA => EXECUTED; replay refused; no second push", async () => {
    const c = newGhCase("gh-timeout-post");
    const a = await ghAuthorize(c);
    setFlag("delay-receive-pack-response");
    const from = emu.events().length;
    const r = await ghRun(c, a.path);
    setFlag("delay-receive-pack-response", false);
    const applied = countEv(emu.events().slice(from), "push-applied");
    assert.equal(applied, 1);
    assert.equal(r.out.outcome, "EXECUTED", JSON.stringify(r.out));
    assert.notEqual(r.out.push_credential, undefined);
    const replay = await ghRun(c, a.path);
    assert.equal(replay.out.reason_code, SPENT);
    assert.equal(countEv(emu.events().slice(from), "push-applied"), 1);
    return { outcome: r.out.outcome, exit_code_of_git_push_in_evidence: r.out.claim ? "see evidence" : null, pushes_applied: applied, replay: replay.out.reason_code };
  });

await scenario("G7", "[emulator] push applied, then the remote becomes unreachable so the read-back fails (unknown outcome)",
  "INDETERMINATE (exit 2), authority SPENT, replay refused, operator reconciliation shows the ref at the approved SHA; no second push", async () => {
    const c = newGhCase("gh-indeterminate");
    const a = await ghAuthorize(c);
    setFlag("down-after-push-armed");
    const from = emu.events().length;
    const r = await ghRun(c, a.path);
    setFlag("down-after-push-armed", false);
    setFlag("down", false);
    assert.equal(r.out.outcome, "INDETERMINATE", JSON.stringify(r.out));
    assert.equal(r.code, 2);
    const replay = await ghRun(c, a.path);
    assert.equal(replay.out.reason_code, SPENT);
    assert.equal(countEv(emu.events().slice(from), "push-applied"), 1);
    const k = classify(c, a, a.executionId);
    const files = signedEvidenceFiles(c);
    const v = files.length ? verifyOffline(files[0]) : null;
    return { outcome: r.out.outcome, exit: r.code, classification: k.condition, review_required: k.review_required, reconciliation: reconcile(c, a),
      signed_evidence_outcome: v?.outcome ?? null, offline_verify_ok: v?.ok ?? null, pushes_applied: 1, replay: replay.out.reason_code };
  });

await scenario("G8", "[emulator] direct `git push` by a holder of no push credential",
  "denied (401); the remote does not move. Says nothing about GitHub rulesets or a real agent environment", async () => {
    const c = newGhCase("gh-direct");
    const head = c.repos.commits[1];
    const env = { ...process.env, GIT_SSL_CAINFO: gh.ca, GIT_TERMINAL_PROMPT: "0", GIT_CONFIG_NOSYSTEM: "1", HOME: c.caseDir };
    // Async: the emulator runs in this process and must keep answering while git talks to it.
    const direct = await new Promise((res) => {
      const child = spawn("git", ["push", gh.remoteUrl, `${head}:refs/heads/main`], { cwd: c.repos.localPath, env, stdio: ["ignore", "pipe", "pipe"] });
      let stderr = "";
      child.stderr.on("data", (d) => { stderr += d; });
      child.on("close", (status) => res({ status, stderr }));
    });
    assert.notEqual(direct.status, 0);
    assert.equal(c.repos.remoteSha(), c.repos.commits[0]);
    return { direct_push_exit: direct.status, remote_unchanged: true, stderr_tail: direct.stderr.trim().split("\n").slice(-2).join(" | ").slice(0, 200) };
  });

if (emu) await emu.close();

// ── report ──────────────────────────────────────────────────────────────────
const file = join(OUT, SRC === ROOT ? "results.json" : `results-control-preremediation-${[...only].join("-") || "all"}.json`);
let head = "";
try { head = git(["rev-parse", "HEAD"], SRC); } catch { head = "unknown"; }
writeFileSync(file, `${JSON.stringify({ generated_at: new Date().toISOString(), tree: SRC, tree_head: head, node: process.version,
  postgres: sql("show server_version"), results }, null, 2)}\n`);
const failed = results.filter((r) => r.status !== "PASS");
console.log(`\n${failed.length ? "FAIL" : "PASS"} f001 closure (${results.length - failed.length}/${results.length}) -> ${file}`);
rmSync(dir, { recursive: true, force: true });
process.exit(failed.length ? 1 : 0);
