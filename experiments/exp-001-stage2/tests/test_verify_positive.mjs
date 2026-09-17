// verifyDeclaration — EXACT-ACTION execution authority (production path).
//
// Positive: a genuinely issued + verified EXECUTOR-BOUND mnde.signed-receipt.v2
// envelope reaches the fixed request builder with every signed field unchanged.
// Negative: a policy-only receipt, a foreign signer, a changed trusted key, a
// tampered signature, and any changed subject/execID/action/param/source-sha/
// target/expected-target-sha are each refused BEFORE any transport call. Uses
// generated in-memory keys and an independently configured trusted public key.
import { test, atest, done, assert } from "./_t.mjs";
import { verifyDeclaration, isProductionVerified } from "../src/declaration.mjs";
import { buildMergeRequest } from "../src/build_request.mjs";
import { createAdapter, ATTEMPT } from "../src/adapter.mjs";
import { makeRealExecutorBoundReceipt, makeRealSignedReceipt } from "./_real_receipt.mjs";

const CONFIG = { owner: "mnde-labs", repo: "exp-001", target_ref: "main" };
const rt = (resp = { status: 200, body: { merged: true } }) => { const calls = []; const fn = async (r) => { calls.push(r); return resp; }; fn.calls = calls; return fn; };

// Every refusal path: verification fails → not production-verified → the adapter
// refuses BEFORE dispatch with zero transport calls.
async function refusedBeforeTransport(label, receipt, trustedConfig) {
  const decl = await verifyDeclaration(receipt, trustedConfig);
  assert.equal(decl.ok, false, `${label}: verification must fail`);
  assert.equal(isProductionVerified(decl), false, `${label}: must not be production-verified`);
  const transport = rt();
  const adapter = createAdapter({ config: CONFIG, transport });
  const rec = await adapter.attemptMerge(decl);
  assert.equal(rec.outcome, ATTEMPT.REFUSED_BEFORE_DISPATCH, `${label}: adapter must refuse before dispatch`);
  assert.equal(transport.calls.length, 0, `${label}: zero transport calls`);
}

// ── POSITIVE ────────────────────────────────────────────────────────────────
await atest("an executor-bound v2 receipt verifies and is production-branded", async () => {
  const { receipt, trustedConfig } = await makeRealExecutorBoundReceipt();
  const decl = await verifyDeclaration(receipt, trustedConfig);
  assert.equal(decl.ok, true, decl.reason ?? "");
  assert.equal(isProductionVerified(decl), true);
  assert.equal(receipt.schema_version, "mnde.signed-receipt.v2");
  assert.ok(decl.trust.executor_id, "executor identity must surface");
});

await atest("the signed A⁺ reaches the fixed request builder unchanged", async () => {
  const { receipt, trustedConfig } = await makeRealExecutorBoundReceipt();
  const decl = await verifyDeclaration(receipt, trustedConfig);
  const req = buildMergeRequest(decl, CONFIG);
  assert.equal(req.method, "PUT");
  assert.equal(req.path, "/repos/mnde-labs/exp-001/pulls/17/merge");
  assert.equal(req.body.sha, decl.declaration.expected_source_sha);
  assert.equal(req.body.sha, "a".repeat(40));
  assert.equal(req.body.merge_method, "merge");
  assert.equal(decl.declaration.expected_target_sha, "b".repeat(40));
  assert.ok(!("expected_target_sha" in req.body), "expected_target_sha is carried but never sent");
});

await atest("verification does NOT establish durable single-use (consumption limit)", async () => {
  const { receipt, trustedConfig } = await makeRealExecutorBoundReceipt();
  const decl = await verifyDeclaration(receipt, trustedConfig);
  assert.equal(decl.freshness.durably_consumed, false);
  assert.equal(decl.freshness.basis, "NOT_ESTABLISHED_BY_VERIFICATION");
  // The production marker means authentic + executor-bound, NOT replay-protected.
});

// ── NEGATIVE: policy-only is authentic but NOT execution authority ────────────
await atest("a valid policy-only receipt cannot dispatch (not executor-bound)", async () => {
  const { receipt, trustedConfig } = await makeRealSignedReceipt();
  const decl = await verifyDeclaration(receipt, trustedConfig);
  assert.equal(decl.ok, false);
  assert.equal(decl.reason, "ERR_NOT_EXECUTOR_BOUND");
  await refusedBeforeTransport("policy-only", receipt, trustedConfig);
});

// ── NEGATIVE: trust failures ─────────────────────────────────────────────────
await atest("a foreign signer (different authority) is refused before transport", async () => {
  const good = await makeRealExecutorBoundReceipt({ authorityId: "mnde-good" });
  const foreign = await makeRealExecutorBoundReceipt({ authorityId: "mnde-foreign" });
  // Verify the foreign receipt against the GOOD authority's trust anchors.
  await refusedBeforeTransport("foreign-signer", foreign.receipt, good.trustedConfig);
});

await atest("a changed trusted root fingerprint is refused before transport", async () => {
  const { receipt, trustedConfig } = await makeRealExecutorBoundReceipt();
  const wrong = { ...trustedConfig, trustedRootFingerprint: "0".repeat(64) };
  await refusedBeforeTransport("wrong-trusted-key", receipt, wrong);
});

await atest("a tampered attestation signature is refused before transport", async () => {
  const { receipt, trustedConfig } = await makeRealExecutorBoundReceipt();
  const tampered = structuredClone(receipt);
  const v = tampered.custody_attestation.signature.value;
  // Deterministically change the first hex digit (0<->1) so the signature bytes
  // always differ — a value derived from a different index could coincide.
  tampered.custody_attestation.signature.value = (v[0] === "0" ? "1" : "0") + v.slice(1);
  await refusedBeforeTransport("tampered-signature", tampered, trustedConfig);
});

// ── NEGATIVE: any changed signed field breaks verification ───────────────────
async function tamperField(label, find, replace) {
  const { receipt, trustedConfig } = await makeRealExecutorBoundReceipt();
  const tampered = structuredClone(receipt);
  const before = tampered.receipt.canonical_request;
  tampered.receipt.canonical_request = before.replace(find, replace);
  assert.notEqual(tampered.receipt.canonical_request, before, `${label}: tamper must change the signed request`);
  await refusedBeforeTransport(label, tampered, trustedConfig);
}
await atest("changed subject is refused", () => tamperField("subject", "EXP001S2-SUBJECT", "EXP001S2-ATTACKER"));
await atest("changed execution id is refused", () => tamperField("execution-id", "EXP001S2-EXEC-1", "EXP001S2-EXEC-2"));
await atest("changed action is refused", () => tamperField("action", "github.pull_request.merge", "github.pull_request.close"));
await atest("changed parameter (pull_request) is refused", () => tamperField("pull_request", '"pull_request":17', '"pull_request":18'));
await atest("changed source sha is refused", () => tamperField("source-sha", "a".repeat(40), "f".repeat(40)));
await atest("changed target branch is refused", () => tamperField("target-branch", '"target_ref":"main"', '"target_ref":"release"'));
await atest("changed expected target sha is refused", () => tamperField("expected-target-sha", "b".repeat(40), "e".repeat(40)));

done("verifyDeclaration-exact-action");
