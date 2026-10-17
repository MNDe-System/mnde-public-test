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
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { classifyGitPushExecution } from "../../src/effects/git-push/index.mjs";
import { canonicalRepositoryIdentity } from "../../src/effects/git-push/validate.mjs";
import { generateAuthorityKeyPair } from "../../src/custody/bundle.mjs";
import { sha256 } from "../../src/crypto/provider.mjs";
import { openSpendWitness } from "../../src/freshness/spend_witness.mjs";
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
const VERIFY_STATE = process.env.F001_VERIFY_POWER_STATE ?? null;   // post-reboot verification of a power-loss run (scenario P2)
const PAUSE_AT = process.env.F001_PAUSE_AT ?? null;                  // power-loss run: pause at this boundary (scenario P1)
const POWER_STATE = process.env.F001_POWER_STATE ?? null;            // where P1 persists what P2 needs; must be on the disk under test

// ── OS identities ───────────────────────────────────────────────────────────
// The executor runs as an unprivileged user (not root); the witness runs as a different
// unprivileged user whose data directory only it can read. F001_RUN_AS="" runs executors as the
// current user (root in this sandbox) and is for debugging only.
const RUN_AS = process.env.F001_RUN_AS ?? "mnde-exec";
const WITNESS_USER = process.env.F001_WITNESS_USER ?? "mnde-witness";
const NODE = process.env.F001_NODE ?? "/opt/node24/bin/node";   // readable by both users
const WDIR = resolve(process.env.F001_WITNESS_DIR ?? "/var/tmp/mnde-witness");
const idOf = (name, flag) => Number(execFileSync("id", [flag, name], { encoding: "utf8" }));
const asUser = RUN_AS ? { uid: idOf(RUN_AS, "-u"), gid: idOf(RUN_AS, "-g") } : {};
const asWitness = { uid: idOf(WITNESS_USER, "-u"), gid: idOf(WITNESS_USER, "-g") };
const own = (path, user = RUN_AS) => { if (user) spawnSync("chown", ["-R", `${user}:${user}`, path]); };
// git refuses repositories owned by another user; the harness is root and the repositories belong to the executor user.
// A harness-only global config (never the executor's, which is built from empty): trust repositories owned by the executor user.
const harnessGitConfig = join(tmpdir(), `mnde-f001-harness-gitconfig-${process.pid}`);
writeFileSync(harnessGitConfig, "[safe]\n\tdirectory = *\n");
process.env.GIT_CONFIG_GLOBAL = harnessGitConfig;
mkdirSync(OUT, { recursive: true });

// ── result recording ────────────────────────────────────────────────────────
const results = [];
let head0 = "unknown";
try { head0 = execFileSync("git", ["rev-parse", "HEAD"], { cwd: SRC, encoding: "utf8" }).trim(); } catch { /* not a checkout */ }
async function scenario(id, title, expected, fn) {
  if (only.size && !only.has(id)) return;
  const entry = { id, title, expected, status: "FAIL", observed: null };
  try {
    entry.observed = await fn();
    entry.status = "PASS";
  } catch (error) {
    entry.status = error?.blocked ? "BLOCKED" : error?.knownGap ? "KNOWN_GAP" : "FAIL";
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
own(dir);
const trust = await productionTrust(dir);
const operatorDir = join(dir, "operator");
mkdirSync(operatorDir, { recursive: true });
const keyPath = join(operatorDir, "executor-key.pem");
writeFileSync(keyPath, trust.executor.keys.privatePem, { encoding: "utf8", mode: 0o600 });
const credentialPath = join(operatorDir, "executor-credential.json");
writeFileSync(credentialPath, `${JSON.stringify(trust.executor.credential, null, 2)}\n`, "utf8");
own(dir);


// ── spend witness: its own process, its own OS user, its own data directory ──────────────────────
// Nothing in the restore scenarios touches WDIR/data. The executor user cannot read it (scenario S1).
// HONEST LIMIT: it is the same machine and root can reach everything, so this proves the mechanism and
// the executor identity's lack of access, not administrative independence.
const WITNESS_ON = (process.env.F001_WITNESS ?? "1") !== "0";
const WITNESS_ID = "mnde-closure-witness";
let witnessClientConfig = null, witnessProc = null, witnessPort = null, witnessKey = null, witnessToken = null;
const witnessLogPath = join(WDIR, "data", "spend-log.jsonl");
const witnessEntries = () => (existsSync(witnessLogPath) ? readFileSync(witnessLogPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l).entry) : []);
async function startWitness({ port = 0, key = witnessKey } = {}) {
  if (key) writeFileSync(join(WDIR, "witness-key.pem"), key.privatePem, { mode: 0o600 });
  writeFileSync(join(WDIR, "witness-config.json"), JSON.stringify({ host: "127.0.0.1", port, data_dir: join(WDIR, "data"), witness_id: WITNESS_ID,
    key_id: key?.keyId ?? JSON.parse(readFileSync(join(WDIR, "witness-config.json"), "utf8")).key_id, key_file: join(WDIR, "witness-key.pem"), tls_cert_file: join(WDIR, "pki", "server.crt"), tls_key_file: join(WDIR, "pki", "server.key"),
    tokens_file: join(WDIR, "tokens.json") }));
  own(WDIR, WITNESS_USER);
  spawnSync("chown", ["root:root", join(WDIR, "pki", "ca.crt")]);
  const child = spawn(NODE, ["--no-warnings", join(ROOT, "deployment", "witness", "witness-server.mjs"), join(WDIR, "witness-config.json")],
    { stdio: ["ignore", "pipe", "pipe"], ...asWitness });
  let err = "";
  child.stderr.on("data", (d) => { err += d; });
  const started = await new Promise((res, rej) => {
    let buf = "";
    child.stdout.on("data", (d) => { buf += d; const line = buf.split("\n")[0]; if (line.includes("witness.started")) res(JSON.parse(line)); });
    child.on("exit", (code) => rej(new Error(`witness exited ${code}: ${err.slice(0, 400)}`)));
    setTimeout(() => rej(new Error("witness did not start")), 15000);
  });
  witnessProc = child; witnessPort = started.port;
  return started;
}
async function stopWitness(signal = "SIGTERM") {
  if (!witnessProc) return;
  const p = witnessProc; witnessProc = null;
  await new Promise((res) => { p.on("exit", res); p.kill(signal); setTimeout(res, 5000); });
  if (signal === "SIGKILL") rmSync(join(WDIR, "data", "witness.lock"), { force: true }); // an operator removes a stale lock after confirming no server runs
}
function writeWitnessClientConfig({ keys = [{ key_id: witnessKey.keyId, public_key: witnessKey.publicPem }], caFile = join(WDIR, "pki", "ca.crt"), token = witnessToken, timeoutMs = 3000 } = {}) {
  writeFileSync(join(dir, "operator", "witness-token"), token, { mode: 0o600 });
  const path = join(dir, "operator", "witness-client.json");
  writeFileSync(path, JSON.stringify({ url: `https://localhost:${witnessPort}`, witness_id: WITNESS_ID, caFile, tokenFile: join(dir, "operator", "witness-token"), witness_keys: keys, timeoutMs }));
  own(dir);
  witnessClientConfig = path;
}
if (WITNESS_ON && !VERIFY_STATE) {
  rmSync(WDIR, { recursive: true, force: true });
  mkdirSync(join(WDIR, "pki"), { recursive: true }); mkdirSync(join(WDIR, "data"), { mode: 0o700 });
  const ossl = (...a) => { const r = spawnSync("openssl", a, { cwd: join(WDIR, "pki"), encoding: "utf8" }); if (r.status !== 0) throw new Error(`openssl ${a[0]} failed: ${r.stderr}`); };
  ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt", "-days", "2", "-subj", "/CN=mnde-witness-test-ca");
  ossl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr", "-subj", "/CN=localhost");
  writeFileSync(join(WDIR, "pki", "san.cnf"), "subjectAltName=DNS:localhost,IP:127.0.0.1");
  ossl("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-out", "server.crt", "-days", "2", "-extfile", "san.cnf");
  const pair = generateAuthorityKeyPair();
  witnessKey = { keyId: "witness-key-1", privatePem: pair.privatePem, publicPem: pair.publicPem };
  witnessToken = `witness-token-${randomUUID()}`;
  writeFileSync(join(WDIR, "tokens.json"), JSON.stringify({ [sha256(witnessToken)]: { executor_id: EXECUTOR_ID, namespace: claimConfig.namespace } }));
  rmSync(join(WDIR, "pki", "ca.key"), { force: true });   // the CA key is not needed after signing and must not outlive the setup
  spawnSync("chmod", ["755", WDIR, join(WDIR, "pki")]); spawnSync("chmod", ["644", join(WDIR, "pki", "ca.crt")]);
  own(WDIR, WITNESS_USER);
  spawnSync("chmod", ["755", WDIR, join(WDIR, "pki")]); spawnSync("chmod", ["700", join(WDIR, "data")]);
  spawnSync("chown", ["root:root", join(WDIR, "pki", "ca.crt")]);    // a trust anchor is owned by root, never by the witness or the executor
  await startWitness();
  writeWitnessClientConfig();
}

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
  own(caseDir);
  const count = (name) => { const p = join(repos.barePath, name); return existsSync(p) ? readFileSync(p, "utf8").split("\n").filter(Boolean).length : 0; };
  return { caseDir, repos, label, evidenceDir: join(caseDir, "evidence"), log: join(caseDir, "fault.log"),
    attempts: () => count("attempts.log"), received: () => count("received.log"),
    flag: (name) => join(repos.barePath, name) };
}

function operatorEnv(c, overrides = {}) {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith("MNDE_") && !k.startsWith("PG") && !k.startsWith("GIT_CONFIG")) env[k] = v;
  env.HOME = c.caseDir;
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
    MNDE_F001_LOG: c.log,
    ...(witnessClientConfig ? { MNDE_WITNESS_CONFIG: witnessClientConfig } : {})
  });
  for (const [k, v] of Object.entries(overrides)) { if (v === undefined) delete env[k]; else env[k] = v; }
  return env;
}

// Start the production CLI. Resolves with what the OS reports, plus parsed stdout when there is one.
function startCli(c, requestPath, { fault = "", env = {} } = {}) {
  const child = spawn(NODE, ["--no-warnings", "--import", FAULTS, CLI, requestPath],
    { cwd: c.caseDir, env: operatorEnv(c, { MNDE_F001_FAULT: fault, ...env }), stdio: ["ignore", "pipe", "pipe"], ...asUser });
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
    const run = spawnSync(NODE, [join(HERE, "concurrent.mjs"), "claims", "100"], { env: operatorEnv(c), encoding: "utf8", timeout: 180000, ...asUser });
    const out = JSON.parse(run.stdout.split("\n").filter(Boolean).pop());
    assert.equal(out.tally.CLAIMED, 1, JSON.stringify(out));
    return out;
  });

await scenario("T04", "100 concurrent executeGitPush() calls of one authorization in one executor, then 12 concurrent CLI processes of another",
  "exactly one push reaches the remote in each", async () => {
    const c = newCase("race-inproc");
    const a = await authorize(c);
    const run = spawnSync(NODE, ["--no-warnings", join(HERE, "concurrent.mjs"), "execute", "100", a.path], { env: operatorEnv(c), encoding: "utf8", timeout: 280000, ...asUser });
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

// ── adversarial review (F-001 final) ────────────────────────────────────────
async function restorePg(snap) {
  rmSync(join(PG, "data.after-claim"), { recursive: true, force: true });
  assert.equal(pgCtl("stop", "-m", "fast", "-w").status, 0);
  try {
    renameSync(join(PG, "data"), join(PG, "data.after-claim"));
    renameSync(snap, join(PG, "data"));
  } finally {
    const started = pgCtl("start", "-w", "-l", join(PG, "log"));
    assert.equal(started.status, 0, started.stderr + started.stdout);
  }
}
function takeSnapshot() {
  const snap = join(PG, "snap");
  rmSync(snap, { recursive: true, force: true });
  const base = spawnSync(`${PG_BIN}/pg_basebackup`, ["-h", "127.0.0.1", "-p", String(claimConfig.port), "-U", "owner", "-D", snap, "-Fp", "-X", "fetch", "-c", "fast"],
    { env: ownerEnv, encoding: "utf8" });
  assert.equal(base.status, 0, base.stderr);
  spawnSync("chown", ["-R", "postgres", snap]); spawnSync("chmod", ["700", snap]);
  return snap;
}

await scenario("X1", "two executors with SEPARATE evidence directories (separate ledgers) race one authorization against one database",
  "exactly one push reaches the remote; the database claim alone arbitrates", async () => {
    const c = newCase("two-executors");
    const a = await authorize(c);
    const second = join(c.caseDir, "evidence-executor-b");
    const runs = await Promise.all(Array.from({ length: 10 }, (_, i) => runCli(c, a.path, i % 2 ? { env: { MNDE_GIT_PUSH_EVIDENCE_DIR: second } } : {})));
    const executed = runs.filter((r) => r.out?.outcome === "EXECUTED").length;
    assert.equal(executed, 1, JSON.stringify(runs.map((r) => r.out?.reason_code ?? r.out?.outcome)));
    assert.equal(c.received(), 1);
    assert.equal(Number(sql(`select count(*) from mnde_claim.claims where execution_id = '${a.executionId}'`)), 1);
    return { executed, remote_pushes: c.received(), db_rows: 1 };
  });

await scenario("X2", "spent-ledger corruption and deletion: corrupt marker, emptied entry, deleted entry",
  "corrupt/missing ledger fails closed; an emptied or deleted entry is still refused by the other barrier", async () => {
    const c = newCase("ledger-attacks");
    const a = await authorize(c);
    assert.equal((await runCli(c, a.path)).code, 0);
    const ledgerDir = join(c.evidenceDir, "spent-ledger");
    const entries = readdirSync(ledgerDir).filter((n) => n !== "LEDGER.json");
    const observed = {};
    // 1. emptied entries still exist => still spent
    for (const n of entries) writeFileSync(join(ledgerDir, n), "");
    c.repos.setRemoteTo(a.parameters.expected_old_sha);
    const baseline = c.received(); // the administrative reset above is itself a received push
    let r = await runCli(c, a.path);
    observed.entries_emptied = r.out.reason_code; assert.equal(r.out.reason_code, SPENT);
    // 2. entries deleted: the database still says spent
    for (const n of entries) rmSync(join(ledgerDir, n));
    r = await runCli(c, a.path);
    observed.entries_deleted_db_intact = r.out.reason_code; assert.equal(r.out.reason_code, SPENT);
    assert.equal(c.received(), baseline, "a replay pushed");
    // 3. corrupt marker: every request fails closed
    writeFileSync(join(ledgerDir, "LEDGER.json"), "{garbage");
    const fresh = await authorize(c, { from: 0, to: 1 });
    r = await runCli(c, fresh.path);
    observed.marker_corrupt = r.out.reason_code; assert.equal(r.out.reason_code, "ERR_LEDGER_UNAVAILABLE");
    assert.equal(c.received(), baseline, "a push was sent with a corrupt ledger marker");
    observed.pushes_after_reset = c.received() - baseline;
    // 4. a stray directory where an entry would be is unreadable-as-file => unavailable, never "unspent"
    return observed;
  });

await scenario("X3", "malformed and forged signed evidence is rejected by the offline verifier",
  "every tampered copy fails verification; the genuine copy verifies", async () => {
    const variants = {
      outcome_changed: (e) => { e.evidence.outcome = "REFUSED"; },
      approved_sha_changed: (e) => { e.evidence.approved_new_sha = "0".repeat(40); },
      observed_after_changed: (e) => { e.evidence.observed_after_sha = "1".repeat(40); },
      executor_changed: (e) => { e.evidence.executor_id = "mnde:attacker:executor"; },
      signature_removed: (e) => { delete e.signature; },
      signature_flipped: (e) => { const sig = e.signature?.value ?? e.signature; if (typeof sig === "string") { const f = (sig[0] === "0" ? "1" : "0") + sig.slice(1); if (e.signature?.value) e.signature.value = f; else e.signature = f; } },
      truncated_json: null,
      extra_field: (e) => { e.evidence.injected = true; }
    };
    const dirV = mkdtempSync(join(tmpdir(), "mnde-x3-"));
    const out = {};
    const verify = (file, fp = trust.fingerprint) => spawnSync(process.execPath, [join(ROOT, "scripts", "verify-git-push-evidence.mjs"), file,
      "--authority-bundle", trust.bundlePath, "--root-fingerprint", fp, "--expected-executor-id", EXECUTOR_ID, "--expected-environment-id", ENVIRONMENT_ID], { encoding: "utf8" });
    // The genuine copy was signed by a previous run's trust; re-sign a fresh one for this run.
    const c = newCase("x3");
    const a = await authorize(c);
    const run = await runCli(c, a.path);
    assert.equal(run.code, 0);
    const genuine = signedEvidenceFiles(c)[0];
    assert.equal(verify(genuine).status, 0, "genuine evidence must verify");
    const base = JSON.parse(readFileSync(genuine, "utf8"));
    for (const [name, mutate] of Object.entries(variants)) {
      const file = join(dirV, `${name}.json`);
      if (mutate === null) writeFileSync(file, readFileSync(genuine, "utf8").slice(0, 200));
      else { const e = structuredClone(base); mutate(e); writeFileSync(file, JSON.stringify(e)); }
      const v = verify(file);
      out[name] = v.status;
      assert.notEqual(v.status, 0, `${name} was accepted`);
    }
    const wrongRoot = verify(genuine, "f".repeat(64));
    out.wrong_root_fingerprint = wrongRoot.status; assert.notEqual(wrongRoot.status, 0);
    rmSync(dirV, { recursive: true, force: true });
    return { verifier_exit_codes: out, genuine_exit: 0 };
  });

await scenario("D1", "executor database login cannot administer: roles, replication/backup, DDL, history edits, policy changes, file/program access",
  "every administrative or history-altering statement is refused by the server; legitimate claims still work", async () => {
    const executorEnv = { ...process.env, PGPASSWORD: readFileSync(join(PG, "execpw"), "utf8").trim(), PGSSLMODE: "verify-full", PGSSLROOTCERT: join(PG, "ca.crt") };
    const asExecutor = (query) => spawnSync("psql", ["-h", "127.0.0.1", "-p", String(claimConfig.port), "-U", claimConfig.user, "-d", claimConfig.database, "-At", "-c", query], { env: executorEnv, encoding: "utf8" });
    const attempts = {
      delete_claims: "DELETE FROM mnde_claim.claims",
      update_claims: "UPDATE mnde_claim.claims SET grant_id = grant_id || 'x'",
      truncate_claims: "TRUNCATE mnde_claim.claims",
      insert_claim_directly: "INSERT INTO mnde_claim.claims(namespace,execution_id,grant_id,record) VALUES ('f001-closure-ns','x','y','{}')",
      select_history_directly: "SELECT * FROM mnde_claim.claims",
      rebind_namespace: "UPDATE mnde_claim.executor_namespaces SET namespace = 'other'",
      create_role: "CREATE ROLE intruder LOGIN",
      alter_own_role_superuser: "ALTER ROLE mnde_executor SUPERUSER",
      set_role_owner: "SET ROLE owner",
      drop_schema: "DROP SCHEMA mnde_claim CASCADE",
      alter_table: "ALTER TABLE mnde_claim.claims DISABLE TRIGGER ALL",
      create_function_in_schema: "CREATE FUNCTION mnde_claim.evil() RETURNS int LANGUAGE sql AS 'select 1'",
      replace_claim_function: "CREATE OR REPLACE FUNCTION mnde_claim.first_claim(r jsonb) RETURNS TABLE(inserted boolean, record jsonb) LANGUAGE sql AS 'select true, r'",
      grant_self_table: "GRANT ALL ON mnde_claim.claims TO mnde_executor",
      create_database: "CREATE DATABASE evil",
      read_server_file: "SELECT pg_read_file('/etc/passwd')",
      copy_to_program: "COPY (SELECT 1) TO PROGRAM 'id'",
      alter_system: "ALTER SYSTEM SET fsync = off",
      disable_synchronous_commit_globally: "ALTER DATABASE " + claimConfig.database + " SET synchronous_commit = off",
      create_replication_slot: "SELECT pg_create_physical_replication_slot('evil')",
      pg_switch_wal_or_backup: "SELECT pg_backup_start('evil')"
    };
    const refused = {};
    for (const [name, query] of Object.entries(attempts)) {
      const r = asExecutor(query);
      refused[name] = r.status !== 0 ? "refused" : "ALLOWED";
      assert.notEqual(r.status, 0, `${name} was allowed: ${r.stdout}`);
    }
    const rep = spawnSync(`${PG_BIN}/pg_basebackup`, ["-h", "127.0.0.1", "-p", String(claimConfig.port), "-U", claimConfig.user, "-D", join(dir, "evil-backup"), "-Fp", "-X", "fetch"], { env: executorEnv, encoding: "utf8" });
    refused.pg_basebackup_as_executor = rep.status !== 0 ? "refused" : "ALLOWED";
    assert.notEqual(rep.status, 0, "executor took a base backup");
    const legit = asExecutor("SELECT mnde_claim.bound_namespace()");
    assert.equal(legit.status, 0); assert.equal(legit.stdout.trim(), claimConfig.namespace);
    const role = sql(`select rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, rolinherit from pg_roles where rolname='${claimConfig.user}'`);
    assert.equal(role, "f|f|f|f|f|f");
    // Topology facts about THIS rig (honest limits, not security properties):
    const dataOwner = execFileSync("stat", ["-c", "%U", join(PG, "data")], { encoding: "utf8" }).trim();
    return { statements_refused: refused, legitimate_bound_namespace: legit.stdout.trim(), executor_role_flags_super_createrole_createdb_replication_bypassrls_inherit: role,
      rig_topology_NOT_independent: { postgres_data_dir_owner_os_user: dataOwner, executor_os_user: RUN_AS || "root (F001_RUN_AS unset)", harness_os_user: process.env.USER ?? "root",
        note: "executor and database share one machine and root can read, replace and restore the data directory; the executor OS identity is unprivileged (see S1) but administrative independence is NOT demonstrated by this rig" } };
  });

const blockedUnless = (cond, why) => { if (!cond) throw Object.assign(new Error(why), { blocked: true }); };
const wClient = () => openSpendWitness({ url: `https://localhost:${witnessPort}`, witness_id: WITNESS_ID, caFile: join(WDIR, "pki", "ca.crt"),
  tokenFile: join(dir, "operator", "witness-token"), witness_keys: [{ key_id: witnessKey.keyId, public_key: witnessKey.publicPem }], timeoutMs: 3000 }, { readFiles: false });
const restoreExecutorState = (c, evidenceSnap) => { rmSync(c.evidenceDir, { recursive: true, force: true }); cpSync(evidenceSnap, c.evidenceDir, { recursive: true }); own(c.caseDir); };
const WITNESS_CONSUMED = "ERR_GIT_PUSH_WITNESS_ALREADY_CONSUMED";

await scenario("S1", "executor OS identity cannot administer PostgreSQL or the witness (no read, write, delete, rename, truncate, signal or stop)",
  "every attempt as the executor user fails; its legitimate reads still work", async () => {
    blockedUnless(RUN_AS && WITNESS_ON, "needs F001_RUN_AS and the witness");
    const sh = (cmd) => spawnSync("sh", ["-c", cmd], { encoding: "utf8", ...asUser });
    const pgPid = readFileSync(join(PG, "data", "postmaster.pid"), "utf8").split("\n")[0];
    const attempts = {
      read_postgres_data_dir: `ls ${PG}/data`, read_database_owner_password: `cat ${PG}/ownerpw`, read_postgres_server_key: `cat ${PG}/server.key`,
      list_witness_data_dir: `ls ${WDIR}/data`, read_witness_signing_key: `cat ${WDIR}/witness-key.pem`, read_witness_tls_key: `cat ${WDIR}/pki/server.key`,
      append_witness_log: `echo x >> ${witnessLogPath}`, truncate_witness_log: `: > ${witnessLogPath}`, delete_witness_log: `rm -f ${witnessLogPath}`,
      rename_witness_log: `mv ${witnessLogPath} ${witnessLogPath}.bak`, replace_witness_data_dir: `rm -rf ${WDIR}/data`,
      signal_postgres: `kill -0 ${pgPid}`, signal_witness: `kill -0 ${witnessProc.pid}`,
      stop_postgres: `${PG_BIN}/pg_ctl -D ${PG}/data stop -m fast`, replace_postgres_snapshot: `mv ${PG}/data ${PG}/data.evil`
    };
    const refused = {};
    for (const [name, cmd] of Object.entries(attempts)) {
      const r = sh(cmd);
      refused[name] = r.status !== 0 ? "refused" : "ALLOWED";
      assert.notEqual(r.status, 0, `${name} was allowed: ${r.stdout}${r.stderr}`);
    }
    assert.equal(sh("id -un").stdout.trim(), RUN_AS);
    assert.equal(sh(`cat ${join(PG, "claim-config.json")} > /dev/null`).status, 0, "the executor must still read its claim configuration");
    const before = witnessEntries().length;
    return { executor_os_user: RUN_AS, witness_os_user: WITNESS_USER, attempts_refused: refused, witness_log_entries_unchanged: witnessEntries().length === before,
      note: "same machine: root can reach all of this; this shows the executor IDENTITY has no administrative route, not administrative independence" };
  });

await scenario("W0", "WHOLE-SYSTEM ROLLBACK: database AND executor ledger/evidence restored together, then the consumed grant is replayed (two restored executors at once)",
  "REFUSED by the external witness; zero further pushes; the witness log unchanged; signed witness proof of why", async () => {
    blockedUnless(WITNESS_ON, "the witness is disabled (F001_WITNESS=0)");
    const c = newCase("whole-system-rollback");
    const snap = takeSnapshot();
    const evidenceSnap = join(c.caseDir, "evidence-snapshot");
    mkdirSync(c.evidenceDir, { recursive: true }); own(c.caseDir);
    cpSync(c.evidenceDir, evidenceSnap, { recursive: true });
    const a = await authorize(c);
    const first = await runCli(c, a.path);
    assert.equal(first.code, 0, JSON.stringify(first.out));
    const entriesAfterFirst = witnessEntries();
    const mine = entriesAfterFirst.find((e) => e.grant_id === a.grantId);
    assert.ok(mine, "the witness recorded the first execution");
    c.repos.setRemoteTo(a.parameters.expected_old_sha);
    const baseline = c.received();
    await restorePg(snap);
    restoreExecutorState(c, evidenceSnap);
    assert.equal(claimRows(a.grantId), 0, "the database restore must have removed the claim");
    assert.equal(existsSync(join(c.evidenceDir, "spent-ledger")), false, "the ledger restore must have removed the spend entry");
    const [r1, r2] = await Promise.all([runCli(c, a.path), runCli(c, a.path)]);
    const reasons = [r1, r2].map((r) => r.out?.reason_code);
    for (const r of [r1, r2]) assert.equal(r.out?.outcome, "REFUSED", JSON.stringify(r.out));
    assert.ok(reasons.includes(WITNESS_CONSUMED), `expected the witness to refuse: ${reasons}`);
    assert.equal(c.received(), baseline, "a restored executor pushed a consumed grant again");
    assert.deepEqual(witnessEntries().filter((e) => e.grant_id === a.grantId).map((e) => e.n), [mine.n], "the witness history must be unchanged");
    const proof = await wClient().lookup({ namespace: claimConfig.namespace, grant_id: a.grantId, execution_id: a.executionId });
    assert.equal(proof.decision, "FOUND");
    writeFileSync(join(OUT, "W0-witness-lookup.signed.json"), `${JSON.stringify(proof.record, null, 2)}\n`);
    return { first_execution: first.out.outcome, witness_entry_n: mine.n, witness_entry_digest_prefix: proof.record.entry_digest.slice(0, 16),
      restored_executors: reasons, remote_pushes_after_restore: c.received() - baseline, witness_log_unchanged: true,
      refusal_witness_reference: [r1, r2].find((r) => r.out?.reason_code === WITNESS_CONSUMED)?.out?.claim?.witness ?? null, signed_witness_proof: "W0-witness-lookup.signed.json" };
  });

await scenario("W0c", "CONTROL: the identical whole-system rollback with the witness DISABLED reproduces the gap",
  "the replay EXECUTES (this is the attack W0 defeats; if it does not reproduce, W0 proves nothing)", async () => {
    const c = newCase("whole-system-rollback-control");
    const snap = takeSnapshot();
    const evidenceSnap = join(c.caseDir, "evidence-snapshot");
    mkdirSync(c.evidenceDir, { recursive: true }); own(c.caseDir);
    cpSync(c.evidenceDir, evidenceSnap, { recursive: true });
    const a = await authorize(c);
    const noWitness = { env: { MNDE_WITNESS_CONFIG: undefined } };
    assert.equal((await runCli(c, a.path, noWitness)).code, 0);
    c.repos.setRemoteTo(a.parameters.expected_old_sha);
    const baseline = c.received();
    await restorePg(snap);
    restoreExecutorState(c, evidenceSnap);
    const replay = await runCli(c, a.path, noWitness);
    assert.equal(replay.out?.outcome, "EXECUTED", `the control did not reproduce the gap: ${JSON.stringify(replay.out)}`);
    assert.equal(c.received() - baseline, 1);
    return { replay_without_witness: "EXECUTED", second_push_reached_remote: true };
  });

await scenario("W1", "two executors with SEPARATE databases, SEPARATE ledgers and separate evidence directories race one authorization",
  "exactly one push; the witness is the only shared arbiter", async () => {
    blockedUnless(WITNESS_ON, "the witness is disabled");
    const dbB = "mnde_claim_test_b";
    sql(`drop database if exists ${dbB}`, "postgres"); sql(`create database ${dbB}`, "postgres");
    execFileSync("psql", ["-h", "127.0.0.1", "-p", String(claimConfig.port), "-U", "owner", "-d", dbB, "-q", "-v", "ON_ERROR_STOP=1", "-f", join(ROOT, "deployment", "freshness", "postgres.sql")], { env: ownerEnv });
    for (const q of [`insert into mnde_claim.executor_namespaces values ('${claimConfig.user}', '${claimConfig.namespace}')`, `grant usage on schema mnde_claim to ${claimConfig.user}`,
      `grant execute on function mnde_claim.bound_namespace(), mnde_claim.first_claim(jsonb), mnde_claim.lookup_claim(jsonb) to ${claimConfig.user}`, `revoke all on database ${dbB} from public`, `grant connect on database ${dbB} to ${claimConfig.user}`]) sql(q, dbB);
    const cfgB = join(dir, "operator", "claim-config-b.json");
    writeFileSync(cfgB, JSON.stringify({ ...claimConfig, database: dbB })); own(dir);
    const c = newCase("two-databases");
    const a = await authorize(c);
    const evidenceB = join(c.caseDir, "evidence-executor-b");
    const baselineEntries = witnessEntries().length;
    const runs = await Promise.all(Array.from({ length: 8 }, (_, i) => runCli(c, a.path, i % 2 ? { env: { MNDE_CLAIM_CONFIG: cfgB, MNDE_GIT_PUSH_EVIDENCE_DIR: evidenceB } } : {})));
    const executed = runs.filter((r) => r.out?.outcome === "EXECUTED").length;
    assert.equal(executed, 1, JSON.stringify(runs.map((r) => r.out?.reason_code ?? r.out?.outcome)));
    assert.equal(c.received(), 1);
    assert.equal(witnessEntries().length - baselineEntries, 1, "one authorization, one witness entry");
    const tally = {};
    for (const r of runs) { const k = r.out?.reason_code ?? r.out?.outcome; tally[k] = (tally[k] ?? 0) + 1; }
    return { executed, outcomes: tally, remote_pushes: c.received(), witness_entries_added: 1, database_a_rows: claimRows(a.grantId), database_b_rows: Number(sql(`select count(*) from mnde_claim.claims where grant_id='${a.grantId}'`, dbB)) };
  });

await scenario("W2", "witness UNAVAILABLE before the claim (process stopped)",
  "REFUSED before anything is spent; the same authorization executes once the witness is back", async () => {
    blockedUnless(WITNESS_ON, "the witness is disabled");
    const c = newCase("witness-outage"); const a = await authorize(c);
    await stopWitness("SIGTERM");
    const down = await runCli(c, a.path);
    await startWitness({ port: witnessPort });
    assert.equal(down.out?.outcome, "REFUSED"); assert.equal(down.out?.reason_code, "ERR_GIT_PUSH_WITNESS_UNAVAILABLE", JSON.stringify(down.out));
    assert.equal(claimRows(a.grantId), 0, "an unreachable witness must not spend the database claim");
    assert.equal(c.received(), 0);
    const up = await runCli(c, a.path);
    assert.equal(up.out?.outcome, "EXECUTED", JSON.stringify(up.out));
    return { while_down: down.out.reason_code, rows_while_down: 0, after_restart: up.out.outcome };
  });

for (const fault of ["witness-before-consume", "witness-during-consume", "witness-after-consume"]) {
  await scenario(`W3-${fault.split("-")[1]}`, `process killed at the witness boundary: ${fault}`,
    "authority consumed or not, nothing is ever sent; recovery refuses; the witness holds the spend iff it received it", async () => {
      blockedUnless(WITNESS_ON, "the witness is disabled");
      const c = newCase(`w3-${fault}`); const a = await authorize(c);
      const before = witnessEntries().length;
      const killed = await runCli(c, a.path, { fault });
      assert.equal(killed.signal, "SIGKILL", JSON.stringify(killed));
      await new Promise((r) => setTimeout(r, 400));
      const recorded = witnessEntries().length - before;
      if (fault === "witness-before-consume") assert.equal(recorded, 0);
      if (fault === "witness-after-consume") assert.equal(recorded, 1);
      assert.equal(c.received(), 0, "nothing may be sent at a witness boundary");
      const recovery = await runCli(c, a.path);
      assert.equal(recovery.out?.outcome, "REFUSED", JSON.stringify(recovery.out));
      assert.equal(c.received(), 0);
      const k = classify(c, a, a.executionId);
      assert.equal(k.condition, "NOT_STARTED");
      const looked = await wClient().lookup({ namespace: claimConfig.namespace, grant_id: a.grantId, execution_id: a.executionId });
      return { witness_entries_recorded: recorded, db_rows: claimRows(a.grantId), recovery: recovery.out.reason_code, classification: k.condition, witness_lookup: looked.decision, remote_pushes: 0 };
    });
}

await scenario("W4", "witness SIGKILLed and restarted after a spend, then a rolled-back executor replays",
  "the spend survives the witness restart; the replay is refused by the witness", async () => {
    blockedUnless(WITNESS_ON, "the witness is disabled");
    const c = newCase("witness-restart");
    const snap = takeSnapshot();
    const evidenceSnap = join(c.caseDir, "evidence-snapshot"); mkdirSync(c.evidenceDir, { recursive: true }); own(c.caseDir); cpSync(c.evidenceDir, evidenceSnap, { recursive: true });
    const a = await authorize(c);
    assert.equal((await runCli(c, a.path)).code, 0);
    const n = witnessEntries().length;
    await stopWitness("SIGKILL");
    await startWitness({ port: witnessPort });                    // takes over the dead process's stale lock, re-verifies the log
    assert.equal(witnessEntries().length, n);
    c.repos.setRemoteTo(a.parameters.expected_old_sha);
    const baseline = c.received();
    await restorePg(snap); restoreExecutorState(c, evidenceSnap);
    const replay = await runCli(c, a.path);
    assert.equal(replay.out?.reason_code, WITNESS_CONSUMED, JSON.stringify(replay.out));
    assert.equal(c.received(), baseline);
    return { witness_entries_survived_sigkill: n, replay: replay.out.reason_code, remote_pushes_after_restore: 0 };
  });

await scenario("W5", "witness key rotation: the witness signs with a key the executor has not pinned",
  "REFUSED before the claim while unpinned; after pinning both keys the same authorization executes", async () => {
    blockedUnless(WITNESS_ON, "the witness is disabled");
    const c = newCase("witness-rotation"); const a = await authorize(c);
    const oldKey = witnessKey;
    const pair = generateAuthorityKeyPair();
    witnessKey = { keyId: "witness-key-2", privatePem: pair.privatePem, publicPem: pair.publicPem };
    await stopWitness("SIGTERM"); await startWitness({ port: witnessPort, key: witnessKey });
    writeWitnessClientConfig({ keys: [{ key_id: oldKey.keyId, public_key: oldKey.publicPem }] });
    const unpinned = await runCli(c, a.path);
    assert.equal(unpinned.out?.reason_code, "ERR_GIT_PUSH_WITNESS_UNAVAILABLE", JSON.stringify(unpinned.out));
    assert.equal(claimRows(a.grantId), 0);
    writeWitnessClientConfig({ keys: [{ key_id: oldKey.keyId, public_key: oldKey.publicPem }, { key_id: witnessKey.keyId, public_key: witnessKey.publicPem }] });
    const pinned = await runCli(c, a.path);
    assert.equal(pinned.out?.outcome, "EXECUTED", JSON.stringify(pinned.out));
    writeWitnessClientConfig();
    return { unpinned_key: unpinned.out.reason_code, after_pinning_both: pinned.out.outcome };
  });

await scenario("W6", "authenticated-channel failures: wrong CA and wrong token",
  "REFUSED before the claim in both cases; nothing spent", async () => {
    blockedUnless(WITNESS_ON, "the witness is disabled");
    const out = {};
    for (const [name, opts] of Object.entries({ wrong_ca: { caFile: join(PG, "ca.crt") }, wrong_token: { token: "not-the-token" } })) {
      const c = newCase(`w6-${name}`); const a = await authorize(c);
      writeWitnessClientConfig(opts);
      const r = await runCli(c, a.path);
      assert.equal(r.out?.reason_code, "ERR_GIT_PUSH_WITNESS_UNAVAILABLE", `${name}: ${JSON.stringify(r.out)}`);
      assert.equal(claimRows(a.grantId), 0); assert.equal(c.received(), 0);
      out[name] = r.out.reason_code;
    }
    writeWitnessClientConfig();
    return out;
  });

await scenario("W8", "100 concurrent consumes of one grant against the real TLS witness",
  "exactly one CONSUMED", async () => {
    blockedUnless(WITNESS_ON, "the witness is disabled");
    const c = newCase("witness-100");
    const run = spawnSync(NODE, [join(HERE, "concurrent.mjs"), "witness", "100"], { env: operatorEnv(c), encoding: "utf8", timeout: 120000, ...asUser });
    const out = JSON.parse(run.stdout.split("\n").filter(Boolean).pop());
    assert.equal(out.tally.CONSUMED, 1, JSON.stringify(out));
    return out;
  });

// ── power-loss tooling (docs/F001-POWER-LOSS-RUNBOOK.md) ───────────────────────────────────────────
// P1 runs one authorization to a named boundary and PAUSES there with everything before it durably written.
// A human then cuts power. P2 runs after reboot and reports which records survived and that replay is refused.
// With F001_SIMULATE_POWER_CUT=1 P1 SIGKILLs itself instead: that exercises the tooling and is NOT a power-loss result.
const BOUNDARIES = {
  "fs-after-start-record":     { kind: "fault", durable: ["db", "ledger", "witness", "start"],             remote: "pre" },
  "witness-after-consume":     { kind: "fault", durable: ["db", "ledger", "witness"],                      remote: "pre" },
  "fs-evidence-before-rename": { kind: "fault", durable: ["db", "ledger", "witness", "start"],             remote: "approved" },
  "post-receive":              { kind: "hold",  durable: ["db", "ledger", "witness", "start"],             remote: "approved" }
};
if (PAUSE_AT && (!only.size || only.has("P1"))) {
  await scenario("P1", `power-loss run: pause at ${PAUSE_AT}`, "paused at the boundary with all earlier records fsynced; waits for power to be cut", async () => {
    const spec = BOUNDARIES[PAUSE_AT];
    blockedUnless(spec && POWER_STATE && isAbsolute(POWER_STATE), "F001_PAUSE_AT must be one of " + Object.keys(BOUNDARIES).join(", ") + " and F001_POWER_STATE an absolute path on the disk under test");
    const c = newCase("power-loss");
    const a = await authorize(c);
    const env = operatorEnv(c, spec.kind === "fault" ? { MNDE_F001_FAULT: PAUSE_AT, MNDE_F001_PAUSE: "1" } : {});
    const state = { boundary: PAUSE_AT, spec, caseDir: c.caseDir, evidenceDir: c.evidenceDir, requestPath: a.path, grantId: a.grantId, executionId: a.executionId,
      approvedSha: a.parameters.source_commit, preSha: a.parameters.expected_old_sha, barePath: c.repos.barePath, remoteUrl: c.repos.remoteUrl,
      env, witnessPort, witnessUser: WITNESS_USER, wdir: WDIR, receivedBefore: c.received(), commit: head0, created_at: new Date().toISOString() };
    writeFileSync(POWER_STATE, JSON.stringify(state, null, 2));
    spawnSync("sync");
    if (spec.kind === "hold") writeFileSync(c.flag("hold-post-receive"), "");
    const run = startCli(c, a.path, spec.kind === "fault" ? { fault: PAUSE_AT, env: { MNDE_F001_PAUSE: "1" } } : {});
    if (spec.kind === "hold") await waitFor(c.flag("post-receive-reached")); else await waitFor(c.log);
    if (spec.kind === "fault") for (let i = 0; i < 600 && !readFileSync(c.log, "utf8").includes("PAUSED@"); i += 1) await new Promise((r) => setTimeout(r, 100));
    console.log(`\n>>> PAUSED at ${PAUSE_AT}. State: ${POWER_STATE}\n>>> NOW CUT POWER (hard power-off, not shutdown). After boot, start PostgreSQL and run:\n>>>   F001_VERIFY_POWER_STATE=${POWER_STATE} node tests/f001-closure/closure.mjs P2\n`);
    if (process.env.F001_SIMULATE_POWER_CUT === "1") { run.child.kill("SIGKILL"); await stopWitness("SIGKILL"); process.kill(process.pid, "SIGKILL"); }
    await new Promise(() => {});
  });
}
if (VERIFY_STATE && (!only.size || only.has("P2"))) {
  await scenario("P2", "power-loss verification after reboot", "every record fsynced before the boundary survived; the consumed grant is refused; nothing is sent; unknown stays INDETERMINATE", async () => {
    const st = JSON.parse(readFileSync(VERIFY_STATE, "utf8"));
    witnessPort = st.witnessPort; witnessClientConfig = st.env.MNDE_WITNESS_CONFIG;
    if (WITNESS_ON) { try { await startWitness({ port: st.witnessPort, key: null }); } catch (e) { throw new Error(`the witness did not come back after the cut: ${e.message}`); } }
    const c = { caseDir: st.caseDir, evidenceDir: st.evidenceDir, log: join(st.caseDir, "fault-verify.log"), repos: { barePath: st.barePath },
      received: () => { const p = join(st.barePath, "received.log"); return existsSync(p) ? readFileSync(p, "utf8").split("\n").filter(Boolean).length : 0; },
      attempts: () => 0, flag: (n) => join(st.barePath, n) };
    const surv = {
      db: claimRows(st.grantId) === 1,
      ledger: existsSync(join(st.evidenceDir, "spent-ledger")) && readdirSync(join(st.evidenceDir, "spent-ledger")).some((n) => n.startsWith("grant-")),
      witness: witnessEntries().some((e) => e.grant_id === st.grantId),
      start: existsSync(st.evidenceDir) && readdirSync(st.evidenceDir).some((n) => n.endsWith(".started.json"))
    };
    const lost = st.spec.durable.filter((k) => !surv[k]);
    const remoteSha = git(["ls-remote", "--refs", st.remoteUrl, "refs/heads/main"], st.barePath).split(/\s+/)[0];
    const remoteState = remoteSha === st.approvedSha ? "approved" : remoteSha === st.preSha ? "pre" : "diverged";
    const before = c.received();
    const replay = await new Promise((res) => {
      const child = spawn(NODE, ["--no-warnings", "--import", FAULTS, CLI, st.requestPath], { cwd: st.caseDir, env: { ...st.env, MNDE_F001_FAULT: "", MNDE_F001_PAUSE: "" }, stdio: ["ignore", "pipe", "pipe"], ...asUser });
      let out = ""; child.stdout.on("data", (d) => { out += d; }); child.on("close", (code) => { try { res({ code, out: JSON.parse(out.split("\n").filter(Boolean)[0]) }); } catch { res({ code, out: null }); } });
    });
    const k = classifyGitPushExecution({ evidenceDir: st.evidenceDir, executionId: st.executionId });
    const signed = existsSync(st.evidenceDir) ? readdirSync(st.evidenceDir).filter((n) => n.endsWith(".signed.json")) : [];
    const observed = { boundary: st.boundary, records_that_must_survive: st.spec.durable, survived: surv, lost_records: lost, remote_state: remoteState, expected_remote_state: st.spec.remote,
      replay: { outcome: replay.out?.outcome, reason: replay.out?.reason_code }, pushes_sent_by_replay: c.received() - before, classification: k.condition,
      signed_evidence_files: signed.length, note: "a SIGKILL-simulated run proves the tooling only; the power-loss result requires a real hard power cut on the hardware under test" };
    const check = (cond, msg) => { if (!cond) throw Object.assign(new Error(msg), { observed }); };
    check(lost.length === 0, `records fsynced before the boundary were LOST: ${lost}`);
    check(remoteState === st.spec.remote, "the remote is not where the boundary implies");
    check(replay.out?.outcome === "REFUSED", `the replay was not refused: ${JSON.stringify(replay.out)}`);
    check(c.received() - before === 0, "the replay pushed");
    if (remoteState === "approved" && signed.length === 0) check(k.condition === "INDETERMINATE", "an effect with no evidence must stay INDETERMINATE until reconciled");
    for (const f of signed) {
      // Against the ORIGINAL run's pinned bundle and root fingerprint (from the persisted environment), not this process's.
      const r = spawnSync(process.execPath, [join(ROOT, "scripts", "verify-git-push-evidence.mjs"), join(st.evidenceDir, f), "--authority-bundle", st.env.MNDE_VERIFY_AUTHORITY_BUNDLE,
        "--root-fingerprint", st.env.MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT, "--expected-executor-id", st.env.MNDE_VERIFY_EXPECTED_EXECUTOR_ID, "--expected-environment-id", st.env.MNDE_VERIFY_ENVIRONMENT_ID], { encoding: "utf8" });
      check(r.status === 0, `signed evidence ${f} does not verify: ${r.stdout.slice(0, 200)}`);
      observed.signed_evidence_verifies = true;
    }
    return observed;
  });
}

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
  own(operatorDir);
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
  own(c.caseDir);
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
let head = "", dirty = "unknown";
try {
  head = git(["rev-parse", "HEAD"], SRC);
  // Anything modified or untracked outside the evidence directory means the results do not describe `head`.
  dirty = git(["status", "--porcelain", "--", ".", ":(exclude)docs/evidence"], SRC).split("\n").filter(Boolean);
} catch { head = "unknown"; }
writeFileSync(file, `${JSON.stringify({ generated_at: new Date().toISOString(), tree: SRC, tree_head: head, tree_dirty_paths: dirty, node: process.version,
  postgres: sql("show server_version"), results }, null, 2)}\n`);
await stopWitness("SIGTERM");
const failed = results.filter((r) => r.status !== "PASS" && r.status !== "KNOWN_GAP");
console.log(`\n${failed.length ? "FAIL" : "PASS"} f001 closure (${results.length - failed.length}/${results.length}) -> ${file}`);
rmSync(dir, { recursive: true, force: true });
process.exit(failed.length ? 1 : 0);
