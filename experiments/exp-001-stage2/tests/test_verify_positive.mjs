// verifyDeclaration — PRODUCTION positive path.
//
// Generates a REAL MNDe policy-engine receipt signed by an in-memory, ephemeral
// authority (keys never touch disk), verifies it with the ACTUAL trusted verifier
// (tools/verify.mjs via verifyDeclaration), and shows the signed A⁺ reaches the
// fixed request builder unchanged. Also shows tampering breaks verification, so
// the positive result depends on real signatures, not on the fixture.
import { test, atest, done, assert } from "./_t.mjs";
import { verifyDeclaration, isProductionVerified, isVerifiedDeclaration } from "../src/declaration.mjs";
import { buildMergeRequest } from "../src/build_request.mjs";
import { makeRealSignedReceipt } from "./_real_receipt.mjs";

const CONFIG = { owner: "mnde-labs", repo: "exp-001", target_ref: "main" };

await atest("a real signed receipt verifies through the production verifier and is production-branded", async () => {
  const { receipt, trustedConfig } = await makeRealSignedReceipt();
  const decl = await verifyDeclaration(receipt, trustedConfig);
  assert.equal(decl.ok, true, decl.reason ?? "");
  assert.equal(decl.provenance, "VERIFIED");
  assert.equal(isProductionVerified(decl), true, "real verification must set the production brand");
  assert.equal(isVerifiedDeclaration(decl), true);
});

await atest("the signed A⁺ reaches the fixed request builder unchanged", async () => {
  const { receipt, trustedConfig } = await makeRealSignedReceipt();
  const decl = await verifyDeclaration(receipt, trustedConfig);
  const req = buildMergeRequest(decl, CONFIG);
  // The dispatched sha and path derive solely from the authenticated declaration.
  assert.equal(req.method, "PUT");
  assert.equal(req.path, "/repos/mnde-labs/exp-001/pulls/17/merge");
  assert.equal(req.body.sha, decl.declaration.expected_source_sha);
  assert.equal(req.body.sha, "a".repeat(40));
  assert.equal(req.body.merge_method, "merge");
  // expected_target_sha is carried in the declaration but never sent.
  assert.equal(decl.declaration.expected_target_sha, "b".repeat(40));
  assert.ok(!("expected_target_sha" in req.body));
});

await atest("tampering the verified receipt's decision breaks verification (real signature)", async () => {
  const { receipt, trustedConfig } = await makeRealSignedReceipt();
  receipt.decision_output.decision = "REFUSE"; // forge after signing
  const decl = await verifyDeclaration(receipt, trustedConfig);
  assert.equal(decl.ok, false, "a tampered receipt must not verify");
  assert.equal(isProductionVerified(decl), false);
});

await atest("tampering a parameter (source sha) in the signed request breaks verification", async () => {
  const { receipt, trustedConfig } = await makeRealSignedReceipt();
  receipt.canonical_request = receipt.canonical_request.replace("a".repeat(40), "f".repeat(40));
  const decl = await verifyDeclaration(receipt, trustedConfig);
  assert.equal(decl.ok, false, "a tampered request must not verify");
});

done("verifyDeclaration-positive");
