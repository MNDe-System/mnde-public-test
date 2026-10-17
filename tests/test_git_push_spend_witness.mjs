// git.push with the external spend witness (F-001 whole-system rollback, scenario W0).
//
//   npm run test:git-push-spend-witness
//
// The witness here is the production server logic and client joined in-process; the claim store is the
// in-memory double. "Restore" is modelled the way the closure harness does it for real: a new executor,
// a new EMPTY claim store, and a deleted evidence directory (so the executor-local spent ledger is gone
// too) — while the witness keeps its own data directory, which the restore does not touch. The same
// scenario against a real PostgreSQL snapshot restore is tests/f001-closure/closure.mjs, case W0.

import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createGitPushExecutor, ERR_AUTHORITY_ALREADY_SPENT, ERR_WITNESS_ALREADY_CONSUMED, ERR_WITNESS_NOT_CONFIGURED,
  ERR_WITNESS_OUTCOME_UNKNOWN, ERR_WITNESS_UNAVAILABLE, OUTCOME
} from "../src/effects/git-push/index.mjs";
import { ERR_LEDGER_QUARANTINED } from "../src/freshness/local_spent_ledger.mjs";
import { signResponse } from "../src/freshness/spend_witness.mjs";
import { installClaimBackend } from "./support/claim_backend_double.mjs";
import { installWitnessClient } from "./support/witness_double.mjs";
import { newWitnessKey, startInProcessWitness } from "./support/witness_fixtures.mjs";
import {
  ENVIRONMENT_ID, EXECUTOR_ID, gitPushAuthorization, inMemoryClaimBackend, makeRepositories, productionTrust, pushParameters
} from "./support/git_push_fixtures.mjs";

const NAMESPACE = "mnde-git-push-witness-namespace";
let passed = 0, failed = 0;
const pending = [];
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  [PASS] ${name}`); }
  catch (error) { failed += 1; console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.stack : String(error)}`); }
  finally {
    installWitnessClient(undefined);
    while (pending.length) { try { rmSync(pending.pop(), { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* best effort */ } }
  }
}

const dir = mkdtempSync(join(tmpdir(), "mnde-git-push-witness-"));
process.env.MNDE_PROFILE = "production";
const trust = await productionTrust(dir);
const IDENTITY = { executor_id: EXECUTOR_ID, namespace: NAMESPACE };

let caseIndex = 0;
function world({ wrap } = {}) {
  caseIndex += 1;
  const caseDir = join(dir, `case-${caseIndex}`);
  pending.push(caseDir);
  const repos = makeRepositories(caseDir);
  process.env.MNDE_GIT_CREDENTIAL_CONFIG = repos.credentialConfigPath;
  const witness = startInProcessWitness({ identities: [IDENTITY], dataDir: join(caseDir, "witness-data") });
  pending.push(witness.dataDir);
  // An executor "machine": its own claim store and evidence directory. The witness is shared.
  const machine = (name, { backend = inMemoryClaimBackend({ namespace: NAMESPACE }), client = witness.client(IDENTITY, { wrap }), real = false, env = process.env } = {}) => {
    const evidenceDir = join(caseDir, `evidence-${name}`);
    installClaimBackend(backend);
    installWitnessClient(real ? undefined : client); // real: behave as production and read MNDE_WITNESS_CONFIG
    const executor = createGitPushExecutor({
      repoPath: repos.localPath, namespace: NAMESPACE, authorityBundle: trust.bundle, authorityBundlePath: trust.bundlePath,
      trustedRootFingerprint: trust.fingerprint, environmentId: ENVIRONMENT_ID, expectedExecutorId: EXECUTOR_ID,
      allowedSchemes: ["file"], evidenceDir, executorIdentity: trust.executor.identity, executorSigner: trust.executor.signer, env
    });
    return { executor, backend, evidenceDir };
  };
  const request = async (opts = {}) => {
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters, opts);
    return { parameters, body: { repository: parameters.repository, remote: parameters.remote, remoteUrl: parameters.remote_url,
      sourceCommit: parameters.source_commit, targetRef: parameters.target_ref, expectedOldSha: parameters.expected_old_sha, authorization } };
  };
  return { repos, witness, machine, request, caseDir };
}

console.log("── a witnessed push ──");

await test("a witnessed push executes once and records the witness entry in the start record and the evidence", async () => {
  const w = world(); const m = w.machine("a"); const a = await w.request();
  const r = await m.executor.executeGitPush(a.body);
  assert.equal(r.outcome, OUTCOME.EXECUTED, `${r.reason_code}: ${r.detail}`);
  assert.equal(w.witness.log.head().n, 1);
  const started = readdirSync(m.evidenceDir).find((n) => n.endsWith(".started.json"));
  const start = JSON.parse(readFileSync(join(m.evidenceDir, started), "utf8"));
  assert.equal(start.witness.n, 1);
  assert.match(start.witness.entry_digest, /^[0-9a-f]{64}$/);
  assert.equal(r.evidence.claim.witness.entry_digest, start.witness.entry_digest);
});

console.log("\n── W0: whole-system rollback ──");

await test("W0: database AND ledger restored — the witness still refuses the consumed grant, nothing is sent, the executor quarantines", async () => {
  const w = world(); const a = await w.request();
  const first = w.machine("a");
  assert.equal((await first.executor.executeGitPush(a.body)).outcome, OUTCOME.EXECUTED);
  w.repos.setRemoteTo(w.repos.commits[0]);                                  // pre-state would pass: only authority state can stop a replay
  rmSync(first.evidenceDir, { recursive: true, force: true });              // the ledger and start records are rolled back
  const restored = w.machine("a", { backend: inMemoryClaimBackend({ namespace: NAMESPACE }) }); // the claim store is rolled back
  const replay = await restored.executor.executeGitPush(a.body);
  assert.equal(replay.outcome, OUTCOME.REFUSED);
  assert.equal(replay.reason_code, ERR_WITNESS_ALREADY_CONSUMED, `${replay.reason_code}: ${replay.detail}`);
  assert.equal(w.repos.remoteSha(), w.repos.commits[0], "the rolled-back authorization pushed again");
  assert.ok(existsSync(join(restored.evidenceDir, "spent-ledger", "QUARANTINE.json")));
  const fresh = await w.request();
  assert.equal((await restored.executor.executeGitPush(fresh.body)).reason_code, ERR_LEDGER_QUARANTINED);
});

await test("W0 control: without a witness the same restore revives the grant (the documented gap)", async () => {
  const w = world(); const a = await w.request();
  const first = w.machine("a", { client: null });
  assert.equal((await first.executor.executeGitPush(a.body)).outcome, OUTCOME.EXECUTED);
  w.repos.setRemoteTo(w.repos.commits[0]);
  rmSync(first.evidenceDir, { recursive: true, force: true });
  const restored = w.machine("a", { backend: inMemoryClaimBackend({ namespace: NAMESPACE }), client: null });
  assert.equal((await restored.executor.executeGitPush(a.body)).outcome, OUTCOME.EXECUTED, "this control must reproduce W0, or the test above proves nothing");
});

await test("two executors with SEPARATE claim stores and ledgers racing one authorization: exactly one push", async () => {
  const w = world(); const a = await w.request();
  const x = w.machine("x"); const y = w.machine("y");
  const [rx, ry] = await Promise.all([x.executor.executeGitPush(a.body), y.executor.executeGitPush(a.body)]);
  const outcomes = [rx, ry].map((r) => r.outcome).sort();
  assert.deepEqual(outcomes, [OUTCOME.EXECUTED, OUTCOME.REFUSED].sort());
  assert.equal([rx, ry].find((r) => r.outcome === OUTCOME.REFUSED).reason_code === ERR_WITNESS_ALREADY_CONSUMED
    || [rx, ry].find((r) => r.outcome === OUTCOME.REFUSED).reason_code === "ERR_GIT_PUSH_REMOTE_MOVED", true);
  assert.equal(w.repos.remoteSha(), w.repos.commits[1]);
  assert.equal(w.witness.log.head().n, 1);
});

console.log("\n── the witness fails closed ──");

await test("witness unreachable BEFORE the claim: refused, nothing spent, and the same authorization works once it returns", async () => {
  const down = { on: true };
  const w = world({ wrap: (direct) => async (req) => (down.on ? { error: new Error("ECONNREFUSED") } : direct(req)) });
  const m = w.machine("a"); const a = await w.request();
  const r = await m.executor.executeGitPush(a.body);
  assert.equal(r.reason_code, ERR_WITNESS_UNAVAILABLE);
  assert.equal(m.backend.claimed().length, 0, "an unreachable witness must refuse BEFORE the claim");
  assert.equal(w.repos.remoteSha(), w.repos.commits[0]);
  down.on = false;
  assert.equal((await m.executor.executeGitPush(a.body)).outcome, OUTCOME.EXECUTED);
});

await test("consume reply lost after the witness recorded it: authority spent, nothing sent, never retried, reconcilable", async () => {
  const w = world({ wrap: (direct) => async (req) => { const out = await direct(req); return req.method === "POST" ? { error: new Error("reset after commit") } : out; } });
  const m = w.machine("a"); const a = await w.request();
  const r = await m.executor.executeGitPush(a.body);
  assert.equal(r.reason_code, ERR_WITNESS_OUTCOME_UNKNOWN);
  assert.equal(m.backend.claimed().length, 1);
  assert.equal(w.witness.log.head().n, 1, "the witness did record it");
  assert.equal(w.repos.remoteSha(), w.repos.commits[0]);
  assert.equal((await m.executor.executeGitPush(a.body)).reason_code, ERR_AUTHORITY_ALREADY_SPENT);
  const looked = await w.witness.client(IDENTITY).lookup({ namespace: NAMESPACE, grant_id: m.backend.claimed()[0].grant_id, execution_id: m.backend.claimed()[0].execution_id });
  assert.equal(looked.decision, "FOUND");
});

await test("a forged witness answer (wrong signing key) is never accepted as CONSUMED", async () => {
  const rogue = newWitnessKey("witness-key-1");
  const forge = (direct) => async (req) => {
    const out = await direct(req);
    if (req.method !== "POST") return out;
    const { signature: _s, ...body } = JSON.parse(out.text);
    return { status: out.status, text: JSON.stringify(await signResponse(body, rogue.private_pem)) };
  };
  const w = world({ wrap: forge });
  const m = w.machine("a"); const a = await w.request();
  const r = await m.executor.executeGitPush(a.body);
  assert.equal(r.reason_code, ERR_WITNESS_OUTCOME_UNKNOWN);
  assert.equal(w.repos.remoteSha(), w.repos.commits[0]);
});

await test("a witness required but not configured, or configured but broken, refuses every push", async () => {
  const w = world(); const a = await w.request();
  const required = w.machine("a", { real: true, env: { ...process.env, MNDE_WITNESS_REQUIRED: "true", MNDE_WITNESS_CONFIG: "" } });
  assert.equal((await required.executor.executeGitPush(a.body)).reason_code, ERR_WITNESS_NOT_CONFIGURED);
  const broken = w.machine("b", { real: true, env: { ...process.env, MNDE_WITNESS_CONFIG: join(dir, "no-such-config.json") } });
  assert.equal((await broken.executor.executeGitPush(a.body)).reason_code, ERR_WITNESS_UNAVAILABLE);
  assert.equal(w.repos.remoteSha(), w.repos.commits[0]);
});

await test("readiness reflects the witness: not ready while it is unreachable", async () => {
  const down = { on: false };
  const w = world({ wrap: (direct) => async (req) => (down.on ? { error: new Error("down") } : direct(req)) });
  const m = w.machine("a");
  assert.equal((await m.executor.readiness()).ready, true);
  down.on = true;
  assert.equal((await m.executor.readiness()).ready, false);
});

rmSync(dir, { recursive: true, force: true });
console.log(`\n${failed === 0 ? "PASS" : "FAIL"} git.push spend witness (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
