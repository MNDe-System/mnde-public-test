// Unit 1 — fixed request construction.
import { test, done, assert } from "./_t.mjs";
import { buildMergeRequest, BuildError } from "../src/build_request.mjs";
import { testOnlyVerifiedDeclaration, makeAPlus } from "../src/declaration.mjs";

const CONFIG = { owner: "mnde-labs", repo: "exp-001", target_ref: "main" };
const verified = (over) => testOnlyVerifiedDeclaration(makeAPlus(over));

test("sha and path come solely from the verified declaration", () => {
  const req = buildMergeRequest(verified(), CONFIG);
  assert.equal(req.method, "PUT");
  assert.equal(req.path, "/repos/mnde-labs/exp-001/pulls/17/merge");
  assert.deepEqual(req.body, { sha: "a".repeat(40), merge_method: "merge" });
});

test("expected_target_sha is NOT placed in the request body", () => {
  const req = buildMergeRequest(verified(), CONFIG);
  assert.ok(!("expected_target_sha" in req.body), "target sha must not be sent to the merge endpoint");
});

test("mutating the caller's A⁺ after verification cannot change the request", () => {
  const src = makeAPlus();
  const decl = testOnlyVerifiedDeclaration(src);
  src.expected_source_sha = "f".repeat(40);         // caller mutates original
  src.repository.repo = "evil";
  const req = buildMergeRequest(decl, CONFIG);
  assert.equal(req.body.sha, "a".repeat(40), "snapshot must be independent of caller mutation");
  assert.equal(req.path, "/repos/mnde-labs/exp-001/pulls/17/merge");
});

test("a plain {verified:true} object is refused (not branded)", () => {
  const plain = { ok: true, verified: true, declaration: makeAPlus() };
  assert.throws(() => buildMergeRequest(plain, CONFIG), (e) => e instanceof BuildError && e.code === "ERR_UNVERIFIED_DECLARATION");
});

function refuses(label, over, code, config = CONFIG) {
  test(`refuses ${label} before any transport call`, () => {
    assert.throws(() => buildMergeRequest(verified(over), config), (e) => e instanceof BuildError && e.code === code);
  });
}
refuses("wrong repository (config mismatch)", { repository: { owner: "other", repo: "x" } }, "ERR_REPO_IDENTITY_MISMATCH");
refuses("wrong PR (non-integer)", { pull_request: "17" }, "ERR_BAD_PR");
refuses("wrong target branch", { target_ref: "release" }, "ERR_TARGET_IDENTITY_MISMATCH");
refuses("malformed head SHA", { expected_source_sha: "nothex" }, "ERR_BAD_SOURCE_SHA");
refuses("missing head SHA", { expected_source_sha: null }, "ERR_BAD_SOURCE_SHA");
refuses("unsupported merge method", { merge_method: "squash" }, "ERR_UNSUPPORTED_MERGE_METHOD");
refuses("unexpected action", { action: "github.pull_request.close" }, "ERR_UNEXPECTED_ACTION");
refuses("extra/unknown parameter key", { parameterKeys: ["repository", "pull_request", "expected_source_sha", "target_ref", "expected_target_sha", "merge_method", "commit_title"] }, "ERR_UNEXPECTED_PARAM");

test("absent config is refused", () => {
  assert.throws(() => buildMergeRequest(verified(), undefined), (e) => e.code === "ERR_NO_CONFIG");
});

done("Unit1-build_request");
