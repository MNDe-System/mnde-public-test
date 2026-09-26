// git.push — one route to the effect, and it goes through a durable claim.
//
//   npm run test:git-push-single-route
//
// F-001 asks for a protected effect to happen only through the executor, after
// authorization and an atomic durable single-use claim. The other git.push suites
// test the executor. This one attacks the ways AROUND it that exist in the code:
//
//   1. the push primitive is exported from transport.mjs, so import it and call it
//      with a well-formed argv — no ticket, a forged ticket, a ticket from a stub
//      claim backend, a ticket minted for a different push, a spent ticket;
//   2. the executor used to accept a caller-supplied claim backend, so try to hand
//      it one;
//   3. replay the same authority concurrently, across two executors sharing one
//      store, and under a fresh execution id on a spent grant;
//   4. make the claim store lie or disappear mid-claim (lost ack, partition,
//      inconsistent ack);
//   5. in a process WITHOUT the test claim double, with the real adapter and no
//      MNDE_CLAIM_CONFIG, nothing is sent and a stub backend mints no ticket.
//
// Everything runs against real git repositories; a case that moved the remote
// when it should not have fails on the remote's own ref, not on a return value.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  createGitPushExecutor,
  ERR_AUTHORITY_ALREADY_SPENT,
  ERR_BACKEND_SUBSTITUTION,
  ERR_CLAIM_NOT_ESTABLISHED,
  ERR_REMOTE_MOVED,
  OUTCOME
} from "../src/effects/git-push/index.mjs";
import { buildPushArgv, performPush, pushEffectDigest, buildTransportEnv } from "../src/effects/git-push/transport.mjs";
import { claimAuthority, DISPATCH, ERR_CLAIM_TICKET } from "../src/freshness/claim.mjs";
import { openExecutorClaimBackend } from "../src/freshness/postgres_claim.mjs";
import {
  ENVIRONMENT_ID,
  EXECUTOR_ID,
  gitPushAuthorization,
  inMemoryClaimBackend,
  makeRepositories,
  productionTrust,
  pushParameters
} from "./support/git_push_fixtures.mjs";
import { installClaimBackend } from "./support/claim_backend_double.mjs";

const NAMESPACE = "mnde-git-push-single-route-namespace";
const HERE = dirname(fileURLToPath(import.meta.url));

let passed = 0;
let failed = 0;
const pendingCleanup = [];
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  [PASS] ${name}`); }
  catch (error) { failed += 1; console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.stack : String(error)}`); }
  finally {
    while (pendingCleanup.length) {
      try { rmSync(pendingCleanup.pop(), { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* best effort */ }
    }
  }
}

process.env.MNDE_PROFILE = "production";

const dir = mkdtempSync(join(tmpdir(), "mnde-git-push-single-route-"));
const trust = await productionTrust(dir);
let caseIndex = 0;

function repositories() {
  caseIndex += 1;
  const caseDir = join(dir, `case-${caseIndex}`);
  pendingCleanup.push(caseDir);
  return { caseDir, repos: makeRepositories(caseDir) };
}

function executorFor(repos, caseDir, backend) {
  installClaimBackend(backend);
  return createGitPushExecutor({
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

// The push the attacker wants: commits[0] -> commits[1] on the real remote, run
// straight from the repository that holds the objects, with a clean environment.
function directPush(repos) {
  const argv = buildPushArgv({
    remoteUrl: repos.remoteUrl,
    sourceCommit: repos.commits[1],
    targetRef: "refs/heads/main",
    expectedOldSha: repos.commits[0]
  });
  const env = buildTransportEnv({});
  const context = { repoPath: repos.localPath, cwd: repos.localPath, env: env.env, timeoutMs: 30_000 };
  return { argv, context };
}

let seq = 0;
function claimRecord() {
  seq += 1;
  return {
    namespace: NAMESPACE, execution_id: `exec-direct-${seq}`, grant_id: `grant-direct-${seq}`,
    subject: "s", executor_id: EXECUTOR_ID, receipt_hash: "r".repeat(64), aplus_digest: "a".repeat(64)
  };
}

console.log("── 1. the exported push primitive reaches no effect on its own ──");

await test("a well-formed argv with no ticket is refused and the remote does not move", async () => {
  const { repos } = repositories();
  const { argv, context } = directPush(repos);
  const r = await performPush(argv, context);
  assert.equal(r.ok, false);
  assert.equal(r.reason, ERR_CLAIM_TICKET);
  assert.equal(repos.remoteSha(), repos.commits[0]);
});

await test("forged tickets (plain objects, frozen null-prototype objects, strings) are refused", async () => {
  const { repos } = repositories();
  const { argv, context } = directPush(repos);
  for (const forged of [{}, Object.freeze(Object.create(null)), "ticket", { ok: true, decision: "CLAIMED" }, null]) {
    const r = await performPush(argv, context, forged);
    assert.equal(r.reason, ERR_CLAIM_TICKET, `forged ${JSON.stringify(forged)} was accepted`);
  }
  assert.equal(repos.remoteSha(), repos.commits[0]);
});

await test("a CLAIMED decision from a stub backend the executor did not open mints no ticket", async () => {
  const { repos } = repositories();
  const { argv, context } = directPush(repos);
  // Right method names, right answers, but built by the caller.
  const stub = inMemoryClaimBackend({ namespace: NAMESPACE });
  const claim = await claimAuthority(stub, claimRecord(), { effectDigest: pushEffectDigest(argv) });
  assert.equal(claim.decision, DISPATCH.CLAIMED);
  assert.equal(claim.ticket, null);
  const r = await performPush(argv, context, claim.ticket);
  assert.equal(r.reason, ERR_CLAIM_TICKET);
  assert.equal(repos.remoteSha(), repos.commits[0]);
});

await test("a genuine ticket for one push cannot start a different push, and is burnt by trying", async () => {
  const { repos } = repositories();
  const { argv, context } = directPush(repos);
  installClaimBackend(inMemoryClaimBackend({ namespace: NAMESPACE }));
  const store = await openExecutorClaimBackend();
  const claim = await claimAuthority(store, claimRecord(), { effectDigest: pushEffectDigest(argv) });
  assert.ok(claim.ticket, "a claim through an executor-opened store should mint a ticket");

  const other = buildPushArgv({ remoteUrl: repos.remoteUrl, sourceCommit: repos.commits[2], targetRef: "refs/heads/main", expectedOldSha: repos.commits[0] });
  const wrong = await performPush(other, context, claim.ticket);
  assert.equal(wrong.reason, ERR_CLAIM_TICKET);
  // The mismatched attempt spent it: the ticket is not a key that can be retried.
  const after = await performPush(argv, context, claim.ticket);
  assert.equal(after.reason, ERR_CLAIM_TICKET);
  assert.equal(repos.remoteSha(), repos.commits[0]);
});

await test("a genuine ticket runs exactly one push; presenting it again runs nothing", async () => {
  const { repos } = repositories();
  const { argv, context } = directPush(repos);
  installClaimBackend(inMemoryClaimBackend({ namespace: NAMESPACE }));
  const store = await openExecutorClaimBackend();
  const claim = await claimAuthority(store, claimRecord(), { effectDigest: pushEffectDigest(argv) });
  const first = await performPush(argv, context, claim.ticket);
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.equal(repos.remoteSha(), repos.commits[1]);

  repos.setRemoteTo(repos.commits[0]);
  const again = await performPush(argv, context, claim.ticket);
  assert.equal(again.reason, ERR_CLAIM_TICKET);
  assert.equal(repos.remoteSha(), repos.commits[0]);
});

await test("a ticket requested without an effect digest is never minted", async () => {
  installClaimBackend(inMemoryClaimBackend({ namespace: NAMESPACE }));
  const store = await openExecutorClaimBackend();
  const claim = await claimAuthority(store, claimRecord());
  assert.equal(claim.decision, DISPATCH.CLAIMED);
  assert.equal(claim.ticket, null);
});

console.log("\n── 2. nobody hands the executor its claim store ──");

await test("createGitPushExecutor refuses a claimBackend, whatever its value", async () => {
  const { repos, caseDir } = repositories();
  for (const value of [inMemoryClaimBackend({ namespace: NAMESPACE }), null, undefined]) {
    assert.throws(() => createGitPushExecutor({
      repoPath: repos.localPath, namespace: NAMESPACE, evidenceDir: join(caseDir, "evidence"),
      executorIdentity: trust.executor.identity, executorSigner: trust.executor.signer,
      claimBackend: value
    }), (error) => error.code === ERR_BACKEND_SUBSTITUTION);
  }
});

console.log("\n── 3. one authority, one push — under concurrency and re-labelling ──");

await test("eight concurrent presentations of one authority: exactly one push", async () => {
  const { repos, caseDir } = repositories();
  const store = inMemoryClaimBackend({ namespace: NAMESPACE });
  const executor = executorFor(repos, caseDir, store);
  const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
  const authorization = await gitPushAuthorization(trust, parameters);
  const results = await Promise.all(Array.from({ length: 8 }, () => executor.executeGitPush(requestFor(parameters, authorization))));
  const executed = results.filter((r) => r.outcome === OUTCOME.EXECUTED);
  assert.equal(executed.length, 1, results.map((r) => `${r.outcome}:${r.reason_code}`).join(", "));
  // A loser either lost the claim race or arrived after the winner had already
  // moved the remote; both are refusals before anything is sent.
  for (const r of results.filter((x) => x !== executed[0])) {
    assert.ok([ERR_AUTHORITY_ALREADY_SPENT, ERR_REMOTE_MOVED].includes(r.reason_code), r.reason_code);
    assert.equal(r.evidence.effect_attempted, false);
  }
  assert.equal(store.claimed().length, 1, "the store recorded more than one claim");
  assert.equal(repos.remoteSha(), repos.commits[1]);
});

await test("two executors sharing one claim store: the authority spent by one is refused by the other", async () => {
  const { repos, caseDir } = repositories();
  const shared = inMemoryClaimBackend({ namespace: NAMESPACE });
  const a = executorFor(repos, join(caseDir, "a"), shared);
  const b = executorFor(repos, join(caseDir, "b"), shared);
  const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
  const authorization = await gitPushAuthorization(trust, parameters);
  assert.equal((await a.executeGitPush(requestFor(parameters, authorization))).outcome, OUTCOME.EXECUTED);
  repos.setRemoteTo(repos.commits[0]);
  const second = await b.executeGitPush(requestFor(parameters, authorization));
  assert.equal(second.reason_code, ERR_AUTHORITY_ALREADY_SPENT);
  assert.equal(repos.remoteSha(), repos.commits[0]);
});

await test("a fresh execution id on a spent grant is refused (the case F-001 names)", async () => {
  const { repos, caseDir } = repositories();
  const executor = executorFor(repos, caseDir, inMemoryClaimBackend({ namespace: NAMESPACE }));
  const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
  const first = await gitPushAuthorization(trust, parameters, { grantId: "grant-shared", executionId: "exec-one" });
  assert.equal((await executor.executeGitPush(requestFor(parameters, first))).outcome, OUTCOME.EXECUTED);
  repos.setRemoteTo(repos.commits[0]);
  const relabelled = await gitPushAuthorization(trust, parameters, { grantId: "grant-shared", executionId: "exec-two" });
  const second = await executor.executeGitPush(requestFor(parameters, relabelled));
  assert.equal(second.reason_code, ERR_AUTHORITY_ALREADY_SPENT);
  assert.equal(repos.remoteSha(), repos.commits[0]);
});

await test("a spent execution id under a new grant is refused", async () => {
  const { repos, caseDir } = repositories();
  const executor = executorFor(repos, caseDir, inMemoryClaimBackend({ namespace: NAMESPACE }));
  const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
  const first = await gitPushAuthorization(trust, parameters, { grantId: "grant-a", executionId: "exec-shared" });
  assert.equal((await executor.executeGitPush(requestFor(parameters, first))).outcome, OUTCOME.EXECUTED);
  repos.setRemoteTo(repos.commits[0]);
  const second = await executor.executeGitPush(requestFor(parameters,
    await gitPushAuthorization(trust, parameters, { grantId: "grant-b", executionId: "exec-shared" })));
  assert.equal(second.reason_code, ERR_AUTHORITY_ALREADY_SPENT);
  assert.equal(repos.remoteSha(), repos.commits[0]);
});

console.log("\n── 4. a claim store that lies, loses the ack, or is unreachable ──");

async function attemptWith(backend) {
  const { repos, caseDir } = repositories();
  const executor = executorFor(repos, caseDir, backend);
  const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
  const result = await executor.executeGitPush(requestFor(parameters, await gitPushAuthorization(trust, parameters)));
  return { result, remote: repos.remoteSha(), repos };
}

await test("claim recorded but acknowledgement lost: the lookup finds it SPENT and nothing is sent", async () => {
  const inner = inMemoryClaimBackend({ namespace: NAMESPACE });
  const lostAck = { ...inner, async claim(record) { await inner.claim(record); throw new Error("connection reset after commit"); } };
  const { result, remote, repos } = await attemptWith(lostAck);
  assert.equal(result.reason_code, ERR_AUTHORITY_ALREADY_SPENT);
  assert.equal(result.evidence.claim.note, "claim-ack-lost-but-durably-present");
  assert.equal(remote, repos.commits[0]);
});

await test("claim and lookup both partitioned: UNKNOWN, nothing sent, no retry", async () => {
  const inner = inMemoryClaimBackend({ namespace: NAMESPACE });
  let claims = 0;
  const partitioned = {
    ...inner,
    async claim() { claims += 1; throw new Error("ETIMEDOUT"); },
    async lookup() { throw new Error("ETIMEDOUT"); }
  };
  const { result, remote, repos } = await attemptWith(partitioned);
  assert.equal(result.reason_code, ERR_CLAIM_NOT_ESTABLISHED);
  assert.equal(result.evidence.claim.decision, DISPATCH.UNKNOWN);
  assert.equal(claims, 1, "an uncertain claim must never be retried");
  assert.equal(remote, repos.commits[0]);
});

await test("a store that says CLAIMED for a different record is not believed", async () => {
  const inner = inMemoryClaimBackend({ namespace: NAMESPACE });
  const liar = { ...inner, async claim(record) { return { status: "CLAIMED", record: { ...record, grant_id: "someone-else" } }; } };
  const { result, remote, repos } = await attemptWith(liar);
  assert.equal(result.reason_code, ERR_CLAIM_NOT_ESTABLISHED);
  assert.equal(result.evidence.claim.note, "inconsistent-ack");
  assert.equal(remote, repos.commits[0]);
});

console.log("\n── 5. the real adapter, with no test double loaded ──");

await test("real adapter, no MNDE_CLAIM_CONFIG: the executor sends nothing, and a stub mints no ticket", async () => {
  const caseDir = join(dir, "real-store");
  pendingCleanup.push(caseDir);
  const env = { ...process.env, MNDE_PROFILE: "production" };
  delete env.MNDE_CLAIM_CONFIG;
  // Deliberately NOT started with --import claim_backend_hooks.mjs.
  const child = spawnSync(process.execPath, ["--no-warnings", join(HERE, "support", "git_push_real_store_runner.mjs"), caseDir],
    { env, encoding: "utf8", timeout: 120_000 });
  assert.equal(child.status, 0, `runner failed: ${child.stderr}`);
  const out = JSON.parse(readFileSync(join(caseDir, "result.json"), "utf8"));
  assert.equal(out.double_loaded, false, "the runner must be using the real adapter");
  assert.equal(out.stub_ticket, null);
  assert.equal(out.direct_push_reason, ERR_CLAIM_TICKET);
  assert.equal(out.outcome, OUTCOME.REFUSED);
  assert.equal(out.reason_code, ERR_CLAIM_NOT_ESTABLISHED);
  assert.equal(out.claim_decision, DISPATCH.NO_BACKEND);
  assert.match(out.claim_note, /ERR_CLAIM_CONFIG/);
  assert.equal(out.remote_after, out.remote_before, "the remote moved without a durable claim");
});

rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
console.log(`\n${failed === 0 ? "PASS" : "FAIL"} git.push single route (${passed}/${passed + failed})`);
if (failed) process.exit(1);
