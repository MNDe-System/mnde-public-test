// git.push — the executor-local spent ledger (F-001 rollback resistance).
//
//   npm run test:git-push-spent-ledger
//
// The claim-store double here is in memory, so "the database was restored" is
// modelled by a restarted executor that opens an EMPTY store beside the same
// evidence directory. That models the property under test (a store that forgot a
// spend cannot revive it) and nothing about PostgreSQL itself; the real-database
// run is tests/f001-closure/closure.mjs, case R1.

import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createGitPushExecutor, ERR_AUTHORITY_ALREADY_SPENT, OUTCOME } from "../src/effects/git-push/index.mjs";
import {
  ERR_LEDGER_QUARANTINED, ERR_LEDGER_ROLLBACK_DETECTED, ERR_LEDGER_UNAVAILABLE, openLocalSpentLedger
} from "../src/freshness/local_spent_ledger.mjs";
import { installClaimBackend } from "./support/claim_backend_double.mjs";
import {
  ENVIRONMENT_ID, EXECUTOR_ID, gitPushAuthorization, inMemoryClaimBackend, makeRepositories, productionTrust, pushParameters
} from "./support/git_push_fixtures.mjs";

const NAMESPACE = "mnde-git-push-ledger-namespace";
let passed = 0;
let failed = 0;
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  [PASS] ${name}`); }
  catch (error) { failed += 1; console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.stack : String(error)}`); }
}

const dir = mkdtempSync(join(tmpdir(), "mnde-git-push-ledger-"));
process.env.MNDE_PROFILE = "production";
const trust = await productionTrust(dir);
const record = (n, over = {}) => ({ namespace: NAMESPACE, execution_id: `exec-${n}`, grant_id: `grant-${n}`, subject: "s", executor_id: "e", receipt_hash: "r".repeat(64), aplus_digest: "a".repeat(64), ...over });

console.log("── the ledger module ──");

await test("a pristine directory initializes; an entry blocks the grant and the execution id independently", () => {
  const opened = openLocalSpentLedger(join(dir, "l1"));
  assert.equal(opened.ok, true);
  const ledger = opened.ledger;
  assert.deepEqual(ledger.isSpent(record(1)), { ok: true, spent: false });
  assert.equal(ledger.commit(record(1)).ok, true);
  assert.equal(ledger.isSpent(record(1)).spent, true);
  assert.equal(ledger.isSpent(record(2, { grant_id: "grant-1" })).spent, true, "a new execution id must not unlock a spent grant");
  assert.equal(ledger.isSpent(record(1, { grant_id: "grant-other" })).spent, true, "a new grant must not unlock a spent execution id");
  assert.equal(ledger.isSpent(record(3)).spent, false);
  assert.equal(ledger.isSpent(record(1, { namespace: "another-namespace" })).spent, false, "entries are namespaced");
});

await test("committing twice reports a conflict and never overwrites", () => {
  const ledger = openLocalSpentLedger(join(dir, "l2")).ledger;
  assert.equal(ledger.commit(record(1)).ok, true);
  const again = ledger.commit(record(1));
  assert.equal(again.ok, false);
  assert.equal(again.conflict, true);
  assert.equal(again.reason, ERR_LEDGER_ROLLBACK_DETECTED);
  assert.equal(ledger.commit(record(2, { grant_id: "grant-1" })).conflict, true);
});

await test("a ledger reopened later still remembers; a missing marker next to state is refused, not re-initialized", () => {
  const path = join(dir, "l3");
  const first = openLocalSpentLedger(path).ledger;
  first.commit(record(1));
  assert.equal(openLocalSpentLedger(path).ledger.isSpent(record(1)).spent, true);
  rmSync(join(path, "LEDGER.json"));
  const lost = openLocalSpentLedger(path);
  assert.equal(lost.ok, false);
  assert.equal(lost.reason, ERR_LEDGER_UNAVAILABLE);
  // An empty directory beside prior execution history is also a lost ledger.
  const wiped = openLocalSpentLedger(join(dir, "l3b"), { hasHistory: true });
  assert.equal(wiped.ok, false);
  assert.equal(wiped.reason, ERR_LEDGER_UNAVAILABLE);
});

await test("a malformed marker and an unwritable location are unavailable, never 'unspent'", () => {
  const path = join(dir, "l4");
  mkdirSync(path);
  writeFileSync(join(path, "LEDGER.json"), "{not json");
  assert.equal(openLocalSpentLedger(path).reason, ERR_LEDGER_UNAVAILABLE);
  const blocker = join(dir, "l4-file");
  writeFileSync(blocker, "x");
  assert.equal(openLocalSpentLedger(join(blocker, "inside")).reason, ERR_LEDGER_UNAVAILABLE);
});

await test("quarantine persists across reopen until an operator removes the file", () => {
  const path = join(dir, "l5");
  const ledger = openLocalSpentLedger(path).ledger;
  ledger.quarantine("test");
  assert.equal(openLocalSpentLedger(path).reason, ERR_LEDGER_QUARANTINED);
  rmSync(join(path, "QUARANTINE.json"));
  assert.equal(openLocalSpentLedger(path).ok, true);
});

console.log("\n── the executor with a rolled-back claim store ──");

let caseIndex = 0;
function world() {
  caseIndex += 1;
  const caseDir = join(dir, `case-${caseIndex}`);
  const repos = makeRepositories(caseDir);
  process.env.MNDE_GIT_CREDENTIAL_CONFIG = repos.credentialConfigPath;
  const evidenceDir = join(caseDir, "evidence");
  const store = { backend: null };
  // A "restart": a new executor, a new (possibly empty) claim store, the same evidence directory.
  const boot = (backend = inMemoryClaimBackend({ namespace: NAMESPACE })) => {
    installClaimBackend(backend);
    store.backend = backend;
    return createGitPushExecutor({
      repoPath: repos.localPath, namespace: NAMESPACE, authorityBundle: trust.bundle, authorityBundlePath: trust.bundlePath,
      trustedRootFingerprint: trust.fingerprint, environmentId: ENVIRONMENT_ID, expectedExecutorId: EXECUTOR_ID,
      allowedSchemes: ["file"], evidenceDir, executorIdentity: trust.executor.identity, executorSigner: trust.executor.signer
    });
  };
  const request = async (opts = {}) => {
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters, opts);
    return { parameters, authorization, body: { repository: parameters.repository, remote: parameters.remote, remoteUrl: parameters.remote_url,
      sourceCommit: parameters.source_commit, targetRef: parameters.target_ref, expectedOldSha: parameters.expected_old_sha, authorization } };
  };
  return { repos, evidenceDir, boot, request, store };
}

await test("a restored (empty) claim store cannot revive a spent authorization: refused, rollback detected, nothing sent", async () => {
  const w = world();
  const a = await w.request();
  const first = await w.boot().executeGitPush(a.body);
  assert.equal(first.outcome, OUTCOME.EXECUTED);
  w.repos.setRemoteTo(w.repos.commits[0]); // pre-state would pass: only the authority record can stop the replay
  const restoredStore = inMemoryClaimBackend({ namespace: NAMESPACE });
  const replay = await w.boot(restoredStore).executeGitPush(a.body);
  assert.equal(replay.outcome, OUTCOME.REFUSED);
  assert.equal(replay.reason_code, ERR_LEDGER_ROLLBACK_DETECTED);
  assert.equal(w.repos.remoteSha(), w.repos.commits[0], "the rolled-back authorization pushed again");
  assert.equal(restoredStore.claimed().length, 0, "a rolled-back replay must not even reach the claim");
  assert.ok(existsSync(join(w.evidenceDir, "spent-ledger", "QUARANTINE.json")));
});

await test("after a detected rollback every authorization is refused until an operator clears the quarantine", async () => {
  const w = world();
  const a = await w.request();
  assert.equal((await w.boot().executeGitPush(a.body)).outcome, OUTCOME.EXECUTED);
  w.repos.setRemoteTo(w.repos.commits[0]);
  const executor = w.boot(inMemoryClaimBackend({ namespace: NAMESPACE }));
  assert.equal((await executor.executeGitPush(a.body)).reason_code, ERR_LEDGER_ROLLBACK_DETECTED);
  const fresh = await w.request();
  const refused = await executor.executeGitPush(fresh.body);
  assert.equal(refused.reason_code, ERR_LEDGER_QUARANTINED);
  assert.equal(w.repos.remoteSha(), w.repos.commits[0]);
  rmSync(join(w.evidenceDir, "spent-ledger", "QUARANTINE.json"));
  assert.equal((await w.boot().executeGitPush(fresh.body)).outcome, OUTCOME.EXECUTED);
});

await test("the F-001 case: a re-issued authorization (new execution id, same spent grant) after a restore is refused", async () => {
  const w = world();
  const a = await w.request({ grantId: "grant-reissue", executionId: "exec-original" });
  assert.equal((await w.boot().executeGitPush(a.body)).outcome, OUTCOME.EXECUTED);
  w.repos.setRemoteTo(w.repos.commits[0]);
  const reissued = await w.request({ grantId: "grant-reissue", executionId: "exec-reissued" });
  const replay = await w.boot(inMemoryClaimBackend({ namespace: NAMESPACE })).executeGitPush(reissued.body);
  assert.equal(replay.reason_code, ERR_LEDGER_ROLLBACK_DETECTED);
  assert.equal(w.repos.remoteSha(), w.repos.commits[0]);
});

await test("with an intact claim store a replay is the ordinary already-spent refusal and does not quarantine", async () => {
  const w = world();
  const a = await w.request();
  const executor = w.boot();
  assert.equal((await executor.executeGitPush(a.body)).outcome, OUTCOME.EXECUTED);
  w.repos.setRemoteTo(w.repos.commits[0]);
  const replay = await executor.executeGitPush(a.body);
  assert.equal(replay.reason_code, ERR_AUTHORITY_ALREADY_SPENT);
  assert.equal(existsSync(join(w.evidenceDir, "spent-ledger", "QUARANTINE.json")), false);
  assert.equal(w.repos.remoteSha(), w.repos.commits[0]);
});

await test("an executed push leaves the ledger marker plus one grant entry and one execution entry", async () => {
  const w = world();
  const a = await w.request();
  assert.equal((await w.boot().executeGitPush(a.body)).outcome, OUTCOME.EXECUTED);
  const names = readdirSync(join(w.evidenceDir, "spent-ledger"));
  assert.equal(names.filter((n) => n.startsWith("grant-")).length, 1);
  assert.equal(names.filter((n) => n.startsWith("exec-")).length, 1);
  assert.ok(names.includes("LEDGER.json"));
});

await test("a lost ledger (evidence history present, ledger gone) refuses before the claim store is touched", async () => {
  const w = world();
  const a = await w.request();
  assert.equal((await w.boot().executeGitPush(a.body)).outcome, OUTCOME.EXECUTED);
  rmSync(join(w.evidenceDir, "spent-ledger"), { recursive: true, force: true });
  const untouched = inMemoryClaimBackend({ namespace: NAMESPACE });
  const next = await w.request();
  const refused = await w.boot(untouched).executeGitPush(next.body);
  assert.equal(refused.reason_code, ERR_LEDGER_UNAVAILABLE);
  assert.equal(untouched.claimed().length, 0);
  assert.equal(w.repos.remoteSha(), w.repos.commits[1]);
});

rmSync(dir, { recursive: true, force: true });
console.log(`\n${failed === 0 ? "PASS" : "FAIL"} git.push spent ledger (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
