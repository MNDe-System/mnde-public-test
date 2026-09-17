// EXP-001 Stage 2 — fail-closed freshness (F-001 / F-002).
//
// Safety goal: one verified execution authority => AT MOST ONE protected dispatch
// attempt, across restart or restoration of executor-local files. At-most-once
// ATTEMPT, not exactly-once effect. Every refusal makes ZERO transport calls.
//
// The claim backend here is the FILE MODEL backend; when its dir is a separate
// location it MODELS the out-of-rollback-domain property. Deployment closure of
// F-002 needs a genuinely independent durable backend (see FRESHNESS-DESIGN.md).

import { rmSync, cpSync, mkdirSync } from "node:fs";
import { test, atest, done, assert } from "./_t.mjs";
import { createOfflineAdapter as createAdapter, ATTEMPT } from "../../../tests/support/offline_freshness_adapter.mjs";
import { deriveClaimRecord } from "../src/freshness.mjs";
import {
  createFileClaimBackend, createUnavailableBackend, createTimeoutBackend,
  createContradictoryBackend, createLostAckButPresentBackend
} from "../src/claim_store.mjs";
import { tmpDir } from "./_tmp.mjs";
import { makeRealVerifiedDeclaration } from "./_real_receipt.mjs";

const NS = "mnde:exp001s2:test";
const CONFIG = { owner: "mnde-labs", repo: "exp-001", target_ref: "main", namespace: NS };

const spyTransport = (resp = { status: 200, body: { merged: true } }) => {
  const calls = []; const fn = async (r) => { calls.push(r); return resp; }; fn.calls = calls; return fn;
};
const mkDecl = (over) => makeRealVerifiedDeclaration(over);
const backendAt = (dir) => createFileClaimBackend({ dir });

// ── F-001: no durable backend => fail closed (not permissive) ────────────────
await atest("F-001: unconfigured backend refuses dispatch (fail closed), zero transport", async () => {
  const transport = spyTransport();
  const adapter = createAdapter({ config: CONFIG, transport /* NO claimBackend */ });
  const decl = await mkDecl({ executionId: "F001-A" });
  const first = await adapter.attemptMerge(decl);
  assert.equal(first.outcome, ATTEMPT.REFUSED_BEFORE_DISPATCH);
  assert.equal(first.error, "ERR_NO_CLAIM_BACKEND");
  // "restart" (new adapter, still no backend) + reuse: still refused, never permissive.
  const afterRestart = await createAdapter({ config: CONFIG, transport }).attemptMerge(decl);
  assert.equal(afterRestart.outcome, ATTEMPT.REFUSED_BEFORE_DISPATCH);
  assert.equal(transport.calls.length, 0, "zero transport calls, ever");
});

// ── Positive: fresh authority + healthy backend => exactly one request ────────
await atest("positive: fresh authority + healthy backend performs exactly one request", async () => {
  const transport = spyTransport({ status: 200, body: { merged: true }, headers: { "x-github-request-id": "gh-1" } });
  const adapter = createAdapter({ config: CONFIG, transport, claimBackend: backendAt(tmpDir("f-pos")) });
  const rec = await adapter.attemptMerge(await mkDecl({ executionId: "POS-1" }));
  assert.equal(rec.outcome, ATTEMPT.RESPONDED);
  assert.equal(rec.dispatched, true);
  assert.equal(rec.claim.decision, "CLAIMED");
  assert.equal(transport.calls.length, 1);
  // authorization / claim / attempt / provider response are separate fields.
  assert.ok(rec.request && rec.claim && rec.httpStatus === 200);
});

// ── F-001 (configured) / restart durability: replay across restart is spent ──
await atest("configured backend: replay across restart is SPENT, zero extra transport", async () => {
  const dir = tmpDir("f-restart");
  const decl = await mkDecl({ executionId: "RESTART-1" });
  const t1 = spyTransport();
  const first = await createAdapter({ config: CONFIG, transport: t1, claimBackend: backendAt(dir) }).attemptMerge(decl);
  assert.equal(first.outcome, ATTEMPT.RESPONDED);
  // restart: brand-new adapter AND new backend instance on the SAME durable dir.
  const t2 = spyTransport();
  const again = await createAdapter({ config: CONFIG, transport: t2, claimBackend: backendAt(dir) }).attemptMerge(decl);
  assert.equal(again.outcome, ATTEMPT.REFUSED_BEFORE_DISPATCH);
  assert.equal(again.error, "ERR_AUTHORITY_SPENT");
  assert.equal(t2.calls.length, 0, "no transport on the replay");
});

// ── F-002: restore executor-local files; independent backend still refuses ───
await atest("F-002: executor-local restore leaves the independent backend intact => SPENT", async () => {
  const backendDir = tmpDir("f002-backend");      // INDEPENDENT store (out of local domain)
  const localDir = tmpDir("f002-local");          // executor-local files (rollback domain)
  mkdirSync(`${localDir}/state`, { recursive: true });
  const snapshot = tmpDir("f002-snap");
  cpSync(localDir, snapshot, { recursive: true }); // byte-for-byte earlier snapshot of LOCAL only

  const decl = await mkDecl({ executionId: "F002-1", grant_id: "F002-GRANT" });
  const t1 = spyTransport();
  const first = await createAdapter({ config: CONFIG, transport: t1, claimBackend: backendAt(backendDir) }).attemptMerge(decl);
  assert.equal(first.outcome, ATTEMPT.RESPONDED);

  // Restore ONLY the executor-local files from the earlier snapshot. The
  // independent backend dir is untouched.
  rmSync(localDir, { recursive: true, force: true });
  cpSync(snapshot, localDir, { recursive: true });

  const t2 = spyTransport();
  const again = await createAdapter({ config: CONFIG, transport: t2, claimBackend: backendAt(backendDir) }).attemptMerge(decl);
  assert.equal(again.outcome, ATTEMPT.REFUSED_BEFORE_DISPATCH);
  assert.equal(again.error, "ERR_AUTHORITY_SPENT");
  assert.equal(t2.calls.length, 0);
});

// ── Why separation matters: an in-domain backend, when restored, FAILS to protect
await atest("negative control: a backend INSIDE the restored domain does NOT protect (why F-002 needs separation)", async () => {
  const domain = tmpDir("f002-indomain");
  const backendDir = `${domain}/claims`;          // backend lives INSIDE the rollback domain
  const snapshot = tmpDir("f002-indomain-snap");
  mkdirSync(backendDir, { recursive: true });
  cpSync(domain, snapshot, { recursive: true });  // snapshot BEFORE the claim (empty claims)

  const decl = await mkDecl({ executionId: "INDOMAIN-1" });
  const t1 = spyTransport();
  await createAdapter({ config: CONFIG, transport: t1, claimBackend: backendAt(backendDir) }).attemptMerge(decl);

  // Roll the WHOLE domain (backend included) back to before the claim.
  rmSync(domain, { recursive: true, force: true });
  cpSync(snapshot, domain, { recursive: true });

  const t2 = spyTransport();
  const again = await createAdapter({ config: CONFIG, transport: t2, claimBackend: backendAt(backendDir) }).attemptMerge(decl);
  // The claim was rolled back with the domain => the old authority re-dispatches.
  assert.equal(again.outcome, ATTEMPT.RESPONDED, "an in-domain backend that is rolled back does NOT close F-002");
  assert.equal(t2.calls.length, 1);
});

// ── Independent uniqueness ───────────────────────────────────────────────────
await atest("same execution id + different grant is SPENT (exec uniqueness)", async () => {
  const dir = tmpDir("u-exec");
  const t1 = spyTransport(), t2 = spyTransport();
  await createAdapter({ config: CONFIG, transport: t1, claimBackend: backendAt(dir) }).attemptMerge(await mkDecl({ executionId: "U-EXEC", grant_id: "G1" }));
  const dup = await createAdapter({ config: CONFIG, transport: t2, claimBackend: backendAt(dir) }).attemptMerge(await mkDecl({ executionId: "U-EXEC", grant_id: "G2" }));
  assert.equal(dup.error, "ERR_AUTHORITY_SPENT");
  assert.equal(t2.calls.length, 0);
});
await atest("same grant + different execution id is SPENT (grant uniqueness)", async () => {
  const dir = tmpDir("u-grant");
  const t1 = spyTransport(), t2 = spyTransport();
  await createAdapter({ config: CONFIG, transport: t1, claimBackend: backendAt(dir) }).attemptMerge(await mkDecl({ executionId: "UG-1", grant_id: "SHARED-G" }));
  const dup = await createAdapter({ config: CONFIG, transport: t2, claimBackend: backendAt(dir) }).attemptMerge(await mkDecl({ executionId: "UG-2", grant_id: "SHARED-G" }));
  assert.equal(dup.error, "ERR_AUTHORITY_SPENT");
  assert.equal(t2.calls.length, 0);
});
await atest("same identifiers + changed action digest is SPENT (duplicate is spent regardless of digest)", async () => {
  const dir = tmpDir("u-digest");
  const t1 = spyTransport(), t2 = spyTransport();
  await createAdapter({ config: CONFIG, transport: t1, claimBackend: backendAt(dir) }).attemptMerge(await mkDecl({ executionId: "UD-1", grant_id: "UD-G" }));
  const changed = await mkDecl({ executionId: "UD-1", grant_id: "UD-G", parameters: {
    repository: { owner: "mnde-labs", repo: "exp-001" }, pull_request: 18,
    expected_source_sha: "a".repeat(40), target_ref: "main", expected_target_sha: "b".repeat(40), merge_method: "merge" } });
  const dup = await createAdapter({ config: CONFIG, transport: t2, claimBackend: backendAt(dir) }).attemptMerge(changed);
  assert.equal(dup.error, "ERR_AUTHORITY_SPENT");
  assert.equal(t2.calls.length, 0);
});

// ── Foreign namespace / wrong executor => refused before claim (backend untouched)
await atest("foreign authority is refused before claim (backend claim never called)", async () => {
  const spy = { claimed: 0, health() { return { ok: true }; }, claim() { this.claimed += 1; return { status: "CLAIMED" }; }, lookup() { return { found: false }; } };
  const { makeRealExecutorBoundReceipt } = await import("./_real_receipt.mjs");
  const { verifyDeclaration } = await import("../src/declaration.mjs");
  // A foreign-authority receipt verified against the GOOD authority's anchors fails.
  const goodPair = await makeRealExecutorBoundReceipt({ executionId: "FN-good" });
  const foreignPair = await makeRealExecutorBoundReceipt({ executionId: "FN-foreign", authorityId: "mnde-foreign" });
  const declForeign = await verifyDeclaration(foreignPair.receipt, goodPair.trustedConfig);
  assert.equal(declForeign.ok, false);
  const t = spyTransport();
  const rec = await createAdapter({ config: CONFIG, transport: t, claimBackend: spy }).attemptMerge(declForeign);
  assert.equal(rec.outcome, ATTEMPT.REFUSED_BEFORE_DISPATCH);
  assert.equal(rec.error, "ERR_NOT_PRODUCTION_VERIFIED");
  assert.equal(spy.claimed, 0, "backend claim must not be called for an unverified authority");
  assert.equal(t.calls.length, 0);
});
await atest("wrong executor identity is refused before claim", async () => {
  const spy = { claimed: 0, health() { return { ok: true }; }, claim() { this.claimed += 1; return { status: "CLAIMED" }; }, lookup() { return { found: false }; } };
  const { makeRealExecutorBoundReceipt } = await import("./_real_receipt.mjs");
  const { verifyDeclaration } = await import("../src/declaration.mjs");
  const pair = await makeRealExecutorBoundReceipt({ executionId: "WE-1", verifyExpectedExecutorId: "mnde:local:prod:executor:WRONG:99" });
  const decl = await verifyDeclaration(pair.receipt, pair.trustedConfig);
  assert.equal(decl.ok, false);
  const t = spyTransport();
  const rec = await createAdapter({ config: CONFIG, transport: t, claimBackend: spy }).attemptMerge(decl);
  assert.equal(rec.outcome, ATTEMPT.REFUSED_BEFORE_DISPATCH);
  assert.equal(spy.claimed, 0);
  assert.equal(t.calls.length, 0);
});

// ── Concurrency: two executor instances share the backend => one dispatch ────
await atest("concurrent instances sharing the backend: at most one claim + one request", async () => {
  const dir = tmpDir("conc");
  const backend = backendAt(dir);
  const decl = await mkDecl({ executionId: "CONC-1", grant_id: "CONC-G" });
  const tA = spyTransport(), tB = spyTransport();
  const a = createAdapter({ config: CONFIG, transport: tA, claimBackend: backend });
  const b = createAdapter({ config: CONFIG, transport: tB, claimBackend: backend });
  const [ra, rb] = await Promise.all([a.attemptMerge(decl), b.attemptMerge(decl)]);
  const dispatches = tA.calls.length + tB.calls.length;
  assert.equal(dispatches, 1, "exactly one provider request across instances");
  const outcomes = [ra.outcome, rb.outcome].sort();
  assert.deepEqual(outcomes, [ATTEMPT.REFUSED_BEFORE_DISPATCH, ATTEMPT.RESPONDED]);
});

// ── Crash ordering ───────────────────────────────────────────────────────────
await atest("crash BEFORE claim: nothing claimed, a later attempt claims exactly once", async () => {
  const dir = tmpDir("crash-before");
  const decl = await mkDecl({ executionId: "CB-1" });
  // (crash before claim => no claim written; simulate by simply not having claimed)
  const t = spyTransport();
  const rec = await createAdapter({ config: CONFIG, transport: t, claimBackend: backendAt(dir) }).attemptMerge(decl);
  assert.equal(rec.outcome, ATTEMPT.RESPONDED); // one attempt, no double
  assert.equal(t.calls.length, 1);
});
await atest("crash AFTER durable claim, BEFORE transport: recovery refuses, zero transport", async () => {
  const dir = tmpDir("crash-after-claim");
  const backend = backendAt(dir);
  const decl = await mkDecl({ executionId: "CAC-1", grant_id: "CAC-G" });
  // durable claim happened, then crash before dispatch:
  const claimed = await backend.claim(deriveClaimRecord(decl, { namespace: NS }).record);
  assert.equal(claimed.status, "CLAIMED");
  // recovery: same authority re-presented => spent, no transport.
  const t = spyTransport();
  const rec = await createAdapter({ config: CONFIG, transport: t, claimBackend: backendAt(dir) }).attemptMerge(decl);
  assert.equal(rec.error, "ERR_AUTHORITY_SPENT");
  assert.equal(t.calls.length, 0);
});
await atest("crash AFTER transport start, response lost: UNKNOWN, and recovery never re-dispatches", async () => {
  const dir = tmpDir("crash-after-send");
  const decl = await mkDecl({ executionId: "CAS-1", grant_id: "CAS-G" });
  const tLost = async () => { throw new Error("connection reset after send"); };
  const first = await createAdapter({ config: CONFIG, transport: tLost, claimBackend: backendAt(dir) }).attemptMerge(decl);
  assert.equal(first.outcome, ATTEMPT.UNKNOWN);        // provider response lost
  assert.equal(first.dispatched, true);
  assert.equal(first.claim.decision, "CLAIMED");
  // recovery must NOT re-dispatch (authority already spent).
  const t2 = spyTransport();
  const again = await createAdapter({ config: CONFIG, transport: t2, claimBackend: backendAt(dir) }).attemptMerge(decl);
  assert.equal(again.error, "ERR_AUTHORITY_SPENT");
  assert.equal(t2.calls.length, 0);
});

// ── Backend faults => fail closed, no provider request ───────────────────────
await atest("backend unavailable => refuse, no transport", async () => {
  const t = spyTransport();
  const rec = await createAdapter({ config: CONFIG, transport: t, claimBackend: createUnavailableBackend() }).attemptMerge(await mkDecl({ executionId: "BF-U" }));
  assert.equal(rec.error, "ERR_CLAIM_BACKEND_UNAVAILABLE");
  assert.equal(t.calls.length, 0);
});
await atest("claim timeout (also uncertain lookup) => UNKNOWN, no transport, no retry", async () => {
  const t = spyTransport();
  const rec = await createAdapter({ config: CONFIG, transport: t, claimBackend: createTimeoutBackend() }).attemptMerge(await mkDecl({ executionId: "BF-T" }));
  assert.equal(rec.outcome, ATTEMPT.UNKNOWN);
  assert.equal(rec.dispatched, false);
  assert.equal(t.calls.length, 0);
});
await atest("lost ack but durably present => SPENT (never re-send), no transport", async () => {
  const dir = tmpDir("bf-lostack");
  const backend = createLostAckButPresentBackend(backendAt(dir));
  const t = spyTransport();
  const rec = await createAdapter({ config: CONFIG, transport: t, claimBackend: backend }).attemptMerge(await mkDecl({ executionId: "BF-LA", grant_id: "BF-LA-G" }));
  assert.equal(rec.error, "ERR_AUTHORITY_SPENT");
  assert.equal(t.calls.length, 0);
});
await atest("contradictory backend => UNKNOWN, no transport", async () => {
  const t = spyTransport();
  const rec = await createAdapter({ config: CONFIG, transport: t, claimBackend: createContradictoryBackend() }).attemptMerge(await mkDecl({ executionId: "BF-C" }));
  assert.equal(rec.outcome, ATTEMPT.UNKNOWN);
  assert.equal(t.calls.length, 0);
});

// ── Non-authorities cannot dispatch (with a healthy backend present) ─────────
await atest("policy-only / copied marker / {verified:true} cannot dispatch", async () => {
  const { makeRealSignedReceipt } = await import("./_real_receipt.mjs");
  const { verifyDeclaration } = await import("../src/declaration.mjs");
  const dir = tmpDir("nonauth");
  const t = spyTransport();
  const adapter = createAdapter({ config: CONFIG, transport: t, claimBackend: backendAt(dir) });
  // policy-only
  const p = await makeRealSignedReceipt({ executionId: "NA-P" });
  const declP = await verifyDeclaration(p.receipt, p.trustedConfig);
  assert.equal((await adapter.attemptMerge(declP)).outcome, ATTEMPT.REFUSED_BEFORE_DISPATCH);
  // copied marker (shallow clone of a real production decl is NOT branded)
  const real = await mkDecl({ executionId: "NA-COPY" });
  const copied = { ...real };
  assert.equal((await adapter.attemptMerge(copied)).error, "ERR_NOT_PRODUCTION_VERIFIED");
  // {verified:true}
  assert.equal((await adapter.attemptMerge({ ok: true, verified: true })).error, "ERR_NOT_PRODUCTION_VERIFIED");
  assert.equal(t.calls.length, 0);
});

done("freshness-F001-F002");
