// Unit 2 — three-ledger evidence + validator + live predicate.
import { test, done, assert } from "./_t.mjs";
import { createEvidenceRecord, validateEvidence, classifyGoSrcStale, assertNoSecrets, RESULT } from "../src/evidence.mjs";

const S = "a".repeat(40);         // signed / approved head
const S2 = "c".repeat(40);        // moved head (stale-head case)
const BASE = "b".repeat(40);

// A consistent stale-head record: request carried the signed sha; GitHub 409'd;
// independent observation shows the head moved, PR unmerged, base unchanged.
function staleHeadRecord(over = {}) {
  const rec = createEvidenceRecord({ runId: "R1", caseId: "G0-src-stale", executionId: "E1", declarationDigest: "D1", live: over.live ?? false });
  if (over.provenance) rec.provenance = over.provenance;
  rec.authorization = {
    runId: "R1", verifiedAt: "2026-09-17T01:00:00.000Z", subject: "SUBJ",
    receiptRef: { schema: "mnde.signed-receipt.v2", request_hash: "rh" }, verifierRef: "unified-verifier",
    signed: { expected_source_sha: S, repository: { owner: "mnde-labs", repo: "exp-001" }, pull_request: 17 }
  };
  rec.providerAttempt = {
    runId: "R1", method: "PUT", path: "/repos/mnde-labs/exp-001/pulls/17/merge",
    body: { sha: S, merge_method: "merge" }, attemptAt: "2026-09-17T01:00:01.000Z",
    httpStatus: 409, responseBodySanitized: { message: "Head branch was modified. Review and try the merge again." }, providerRequestId: "gh-1"
  };
  rec.observation = {
    runId: "R1", source: "independent-read", complete: true, errors: [],
    before: { pr_head_sha: S2, base_ref: "main", base_sha: BASE, merged: false, at: "2026-09-17T01:00:00.500Z" },
    after: { pr_head_sha: S2, base_ref: "main", base_sha: BASE, merged: false, merge_commit: null, at: "2026-09-17T01:00:02.000Z" }
  };
  Object.assign(rec, over.recordPatch ?? {});
  if (over.mutate) over.mutate(rec);
  return rec;
}

test("consistent stale-head evidence is OFFLINE_WIRING_OK", () => {
  assert.equal(validateEvidence(staleHeadRecord()).result, RESULT.OFFLINE_WIRING_OK);
});

test("offline stale-head record cannot yield a live PASS", () => {
  const r = classifyGoSrcStale(staleHeadRecord(), { positiveControlMerged: true });
  assert.equal(r.result, RESULT.INCONCLUSIVE);
  assert.ok(r.reasons.includes("ERR_NOT_LIVE_PROVENANCE"));
});

test("live stale-head + positive control = PASS", () => {
  const rec = staleHeadRecord({ provenance: { mode: "live", live_attested_by: "observer-key" } });
  assert.equal(classifyGoSrcStale(rec, { positiveControlMerged: true }).result, RESULT.PASS);
});

test("live stale-head WITHOUT positive control = INCONCLUSIVE", () => {
  const rec = staleHeadRecord({ provenance: { mode: "live", live_attested_by: "observer-key" } });
  const r = classifyGoSrcStale(rec, { positiveControlMerged: false });
  assert.equal(r.result, RESULT.INCONCLUSIVE);
  assert.ok(r.reasons.includes("ERR_NO_POSITIVE_CONTROL"));
});

test("409 without complete observation is INCONCLUSIVE, never PASS", () => {
  const rec = staleHeadRecord({ provenance: { mode: "live", live_attested_by: "k" }, mutate: (r) => { r.observation.complete = false; } });
  assert.equal(validateEvidence(rec).result, RESULT.OFFLINE_INCONCLUSIVE);
  assert.equal(classifyGoSrcStale(rec, { positiveControlMerged: true }).result, RESULT.INCONCLUSIVE);
});

test("reported merge (200) whose observed commit is not derived from approved head is INVALID/FAIL", () => {
  const rec = staleHeadRecord({ provenance: { mode: "live", live_attested_by: "k" }, mutate: (r) => {
    r.providerAttempt.httpStatus = 200;
    r.observation.after.merged = true;
    r.observation.after.merge_commit = { sha: "d".repeat(40), parents: ["e".repeat(40)] }; // NOT the approved head
  }});
  assert.equal(validateEvidence(rec).result, RESULT.INVALID_EVIDENCE);
  assert.equal(classifyGoSrcStale(rec, { positiveControlMerged: true }).result, RESULT.FAIL);
});

test("request sha differing from the signed sha is INVALID_EVIDENCE (substitution)", () => {
  const rec = staleHeadRecord({ mutate: (r) => { r.providerAttempt.body.sha = "9".repeat(40); } });
  const v = validateEvidence(rec);
  assert.equal(v.result, RESULT.INVALID_EVIDENCE);
  assert.ok(v.reasons.includes("ERR_SHA_MISMATCH_REQUEST_VS_SIGNED"));
});

test("repository/PR path substitution is INVALID_EVIDENCE", () => {
  const rec = staleHeadRecord({ mutate: (r) => { r.providerAttempt.path = "/repos/attacker/evil/pulls/1/merge"; } });
  assert.equal(validateEvidence(rec).result, RESULT.INVALID_EVIDENCE);
});

test("missing an entire ledger prevents any conclusion (OFFLINE_INCONCLUSIVE)", () => {
  const rec = staleHeadRecord({ mutate: (r) => { r.observation = null; } });
  const v = validateEvidence(rec);
  assert.equal(v.result, RESULT.OFFLINE_INCONCLUSIVE);
  assert.ok(v.reasons.some((x) => x.startsWith("ERR_MISSING_LEDGER")));
});

test("inconsistent timestamps are INVALID_EVIDENCE", () => {
  const rec = staleHeadRecord({ mutate: (r) => { r.providerAttempt.attemptAt = "2026-09-17T00:59:00.000Z"; } }); // before verify
  assert.equal(validateEvidence(rec).result, RESULT.INVALID_EVIDENCE);
});

test("a token/authorization value anywhere in the record is detected and invalidates it", () => {
  const rec = staleHeadRecord({ mutate: (r) => { r.providerAttempt.responseBodySanitized = { note: "Bearer ghp_TOTALLYNOTREAL" }; } });
  assert.equal(assertNoSecrets(rec).clean, false);
  assert.equal(validateEvidence(rec).result, RESULT.INVALID_EVIDENCE);
});

test("a clean record has no secrets", () => {
  assert.equal(assertNoSecrets(staleHeadRecord()).clean, true);
});

done("Unit2-evidence");
