// verifyDeclaration — the PRODUCTION-FACING path runs the REAL MNDe verifier and
// fails closed. (Offline we can drive the fail-closed direction with real crypto;
// a fully-passing receipt requires the sidecar's signed inner receipt, so the
// positive wiring path uses the labelled test-only fixture instead.)
import { test, atest, done, assert } from "./_t.mjs";
import { verifyDeclaration, isVerifiedDeclaration } from "../src/declaration.mjs";
import { buildMergeRequest } from "../src/build_request.mjs";
import { loadSigningConfig, signReceiptForDelivery } from "../../../src/authority-signing/index.mjs";

const CONFIG = { owner: "mnde-labs", repo: "exp-001", target_ref: "main" };

function innerWithAPlus(execId = "E-real") {
  const canonical = JSON.stringify({
    execution_request: {
      request_id: execId,
      actor: { user_id: "SUBJ" },
      release_request: { execution_id: execId },
      tool_calls: [{ priority: 1, tool: "github.pull_request.merge", parameters: {
        repository: { owner: "mnde-labs", repo: "exp-001" }, pull_request: 17,
        expected_source_sha: "a".repeat(40), target_ref: "main", expected_target_sha: "b".repeat(40), merge_method: "merge"
      } }]
    }
  });
  return { schema_version: "ecs.receipt.v2", canonical_request: canonical, request_hash: "rh",
    decision_output: { decision: "ALLOW", execution_id: execId, policy_hash: "ph", policy_version: "v1" } };
}

await atest("a plain {verified:true} object does not verify and is not branded", async () => {
  const out = await verifyDeclaration({ verified: true, declaration: { foo: 1 } }, {});
  assert.equal(out.ok, false);
  assert.equal(isVerifiedDeclaration(out), false);
});

await atest("buildMergeRequest refuses a plain {verified:true} object", async () => {
  assert.throws(() => buildMergeRequest({ verified: true, declaration: {} }, CONFIG), (e) => e.code === "ERR_UNVERIFIED_DECLARATION");
});

await atest("a custody envelope with NO authority bundle fails closed (attestation unverifiable)", async () => {
  const cfg = await loadSigningConfig({ MNDE_RECEIPT_SIGNING_MODE: "custody" });
  const signed = await signReceiptForDelivery(innerWithAPlus(), cfg);
  const out = await verifyDeclaration(signed.receipt, {}); // no bundle/fingerprint
  assert.equal(out.ok, false, "must not verify without the trusted authority bundle");
});

await atest("a foreign-authority envelope is rejected against a different bundle", async () => {
  const cfgA = await loadSigningConfig({ MNDE_RECEIPT_SIGNING_MODE: "custody" });
  const cfgB = await loadSigningConfig({ MNDE_RECEIPT_SIGNING_MODE: "custody" });
  const forged = await signReceiptForDelivery(innerWithAPlus("E-forged"), cfgB);
  const out = await verifyDeclaration(forged.receipt, { authorityBundle: cfgA.provider.getPublicBundle(), trustedRootFingerprint: cfgA.fingerprint });
  assert.equal(out.ok, false, "foreign authority must not verify against A's bundle");
  assert.equal(isVerifiedDeclaration(out), false);
});

done("verifyDeclaration-failclosed");
