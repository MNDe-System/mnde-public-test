// Unit 3 — adapter skeleton. Drives the adapter with GENUINELY verified
// declarations (real receipt + real verifier via _real_receipt.mjs), and proves
// the production dispatch gate rejects a merely-branded test-only declaration.
import { test, atest, done, assert } from "./_t.mjs";
import { createOfflineAdapter as createAdapter, ATTEMPT } from "../../../tests/support/offline_freshness_adapter.mjs";
import { testOnlyVerifiedDeclaration, makeAPlus } from "../src/declaration.mjs";
import { createFileClaimBackend } from "../src/claim_store.mjs";
import { tmpDir } from "./_tmp.mjs";
import { makeRealVerifiedDeclaration } from "./_real_receipt.mjs";

const CONFIG = { owner: "mnde-labs", repo: "exp-001", target_ref: "main", namespace: "mnde:exp001s2:test" };
const freshBackend = () => createFileClaimBackend({ dir: tmpDir("adapter-claims") });

function recordingTransport(response) {
  const calls = [];
  const fn = async (req) => { calls.push(req); return response; };
  fn.calls = calls;
  return fn;
}

await atest("exactly one merge call for an eligible (production-verified) attempt", async () => {
  const transport = recordingTransport({ status: 200, body: { merged: true }, headers: { "x-github-request-id": "abc" } });
  const adapter = createAdapter({ config: CONFIG, transport, claimBackend: freshBackend() });
  const rec = await adapter.attemptMerge(await makeRealVerifiedDeclaration());
  assert.equal(transport.calls.length, 1, "transport called exactly once");
  assert.equal(adapter.dispatchCount, 1);
  assert.equal(rec.outcome, ATTEMPT.RESPONDED);
  assert.equal(rec.request.path, "/repos/mnde-labs/exp-001/pulls/17/merge");
  assert.equal(rec.request.body.sha, "a".repeat(40));
});

await atest("a lost response is UNKNOWN and never auto-retries", async () => {
  let calls = 0;
  const transport = async () => { calls += 1; throw new Error("socket hang up"); };
  const adapter = createAdapter({ config: CONFIG, transport, claimBackend: freshBackend() });
  const rec = await adapter.attemptMerge(await makeRealVerifiedDeclaration());
  assert.equal(rec.outcome, ATTEMPT.UNKNOWN);
  assert.equal(calls, 1, "must not retry after a lost response");
  assert.equal(adapter.dispatchCount, 1);
});

test("a config carrying a token is refused", () => {
  assert.throws(() => createAdapter({ config: { ...CONFIG, token: "REDACTED-CREDENTIAL" }, transport: async () => ({}) }),
    (e) => /ERR_TOKEN_IN_CONFIG/.test(e.message));
});

await atest("the test-only pause hook cannot change the dispatched request", async () => {
  const transport = recordingTransport({ status: 409, body: { message: "Head branch was modified" } });
  const modelled = { head: "a".repeat(40) };
  const adapter = createAdapter({
    config: CONFIG, transport, claimBackend: freshBackend(),
    beforeDispatch: async () => { modelled.head = "c".repeat(40); } // move the world; request already frozen
  });
  const rec = await adapter.attemptMerge(await makeRealVerifiedDeclaration());
  assert.equal(rec.request.body.sha, "a".repeat(40), "frozen request must be unaffected by the hook");
  assert.equal(modelled.head, "c".repeat(40), "hook did run (modelled head moved)");
});

await atest("an invalid (target-mismatched) declaration is refused BEFORE dispatch", async () => {
  const transport = recordingTransport({ status: 200, body: {} });
  const adapter = createAdapter({ config: CONFIG, transport, claimBackend: freshBackend() });
  const wrongTarget = await makeRealVerifiedDeclaration({ parameters: {
    repository: { owner: "mnde-labs", repo: "exp-001" }, pull_request: 17,
    expected_source_sha: "a".repeat(40), target_ref: "release", expected_target_sha: "b".repeat(40), merge_method: "merge"
  } });
  const rec = await adapter.attemptMerge(wrongTarget);
  assert.equal(rec.outcome, ATTEMPT.REFUSED_BEFORE_DISPATCH);
  assert.equal(rec.dispatched, false);
  assert.equal(transport.calls.length, 0, "transport must not be called on a refused build");
});

await atest("SECURITY: a test-only (unverified) declaration cannot dispatch through the adapter", async () => {
  const transport = recordingTransport({ status: 200, body: { merged: true } });
  const adapter = createAdapter({ config: CONFIG, transport, claimBackend: freshBackend() });
  const testOnly = testOnlyVerifiedDeclaration(makeAPlus()); // branded, but NOT production-verified
  const rec = await adapter.attemptMerge(testOnly);
  assert.equal(rec.outcome, ATTEMPT.REFUSED_BEFORE_DISPATCH);
  assert.equal(rec.error, "ERR_NOT_PRODUCTION_VERIFIED");
  assert.equal(transport.calls.length, 0, "an unverified declaration must never reach the transport");
});

await atest("SECURITY: a plain {verified:true} object cannot dispatch through the adapter", async () => {
  const transport = recordingTransport({ status: 200, body: {} });
  const adapter = createAdapter({ config: CONFIG, transport, claimBackend: freshBackend() });
  const rec = await adapter.attemptMerge({ ok: true, verified: true, declaration: makeAPlus() });
  assert.equal(rec.outcome, ATTEMPT.REFUSED_BEFORE_DISPATCH);
  assert.equal(rec.error, "ERR_NOT_PRODUCTION_VERIFIED");
  assert.equal(transport.calls.length, 0);
});

test("an accidental real fetch fails immediately (network guard)", () => {
  assert.throws(() => fetch("http://127.0.0.1/merge"), (e) => /E_NETWORK_BLOCKED/.test(e.message));
});

done("Unit3-adapter");
