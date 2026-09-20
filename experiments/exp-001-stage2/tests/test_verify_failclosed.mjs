// verifyDeclaration — fail-closed basics for the production path.
// (Trust-anchor / foreign-signer / tamper coverage lives in test_verify_positive.)
import { atest, done, assert } from "./_t.mjs";
import { verifyDeclaration, isProductionVerified } from "../src/declaration.mjs";
import { buildMergeRequest } from "../src/build_request.mjs";
import { makeRealExecutorBoundReceipt } from "./_real_receipt.mjs";

const CONFIG = { owner: "mnde-labs", repo: "exp-001", target_ref: "main" };

await atest("a plain {verified:true} object does not verify and is not branded", async () => {
  const out = await verifyDeclaration({ verified: true, declaration: { foo: 1 } }, {});
  assert.equal(out.ok, false);
  assert.equal(isProductionVerified(out), false);
});

await atest("buildMergeRequest refuses a plain {verified:true} object", async () => {
  assert.throws(() => buildMergeRequest({ verified: true, declaration: {} }, CONFIG), (e) => e.code === "ERR_UNVERIFIED_DECLARATION");
});

await atest("an executor-bound v2 envelope with NO trust anchors fails closed", async () => {
  const { receipt } = await makeRealExecutorBoundReceipt();
  const out = await verifyDeclaration(receipt, {}); // no authorityBundle / fingerprint / env / executor id
  assert.equal(out.ok, false, "must not verify without out-of-band trust anchors");
  assert.equal(isProductionVerified(out), false);
});

done("verifyDeclaration-failclosed");
