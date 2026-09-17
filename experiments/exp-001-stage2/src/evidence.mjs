// EXP-001 Stage 2 — Unit 2: three-ledger evidence record + validator.
//
// One versioned, token-free record per attempt, keyed by run/case/execution ids
// and the declaration digest. Three DISTINCT ledgers:
//   1. authorization  — what MNDe signed (verified receipt ref + authenticated A⁺)
//   2. providerAttempt — what GitHub was asked + what it answered (no tokens)
//   3. observation    — what an INDEPENDENT observer saw, before and after
//
// The validator compares values ACROSS ledgers; it never trusts a single success
// flag. Offline it returns only OFFLINE_WIRING_OK / INVALID_EVIDENCE /
// OFFLINE_INCONCLUSIVE. A live PASS is emitted ONLY by classifyGoSrcStale and
// ONLY for a record carrying real live provenance — never from a stub.

export const EVIDENCE_SCHEMA = "mnde.exp001.stage2.evidence.v1";

export const RESULT = Object.freeze({
  OFFLINE_WIRING_OK: "OFFLINE_WIRING_OK",
  INVALID_EVIDENCE: "INVALID_EVIDENCE",
  OFFLINE_INCONCLUSIVE: "OFFLINE_INCONCLUSIVE",
  PASS: "PASS",
  FAIL: "FAIL",
  INCONCLUSIVE: "INCONCLUSIVE"
});

const TOKEN_KEYS = /^(authorization|proxy-authorization|x-.*-token|cookie|set-cookie)$/i;
const TOKENISH = /(ghp_|github_pat_|gho_|ghs_|Bearer\s|-----BEGIN)/;

// Build an empty, well-formed record. Callers fill the three ledgers.
export function createEvidenceRecord({ runId, caseId, executionId, declarationDigest, live = false }) {
  return {
    schema_version: EVIDENCE_SCHEMA,
    runId, caseId, executionId, declarationDigest,
    provenance: { mode: live ? "live" : "offline", live_attested_by: null },
    authorization: null,   // { receiptRef, verifierRef, subject, signed:{...A⁺ digest fields}, verifiedAt }
    providerAttempt: null, // { method, path, body, attemptAt, httpStatus, responseBodySanitized, providerRequestId }
    observation: null,     // { source, complete, errors:[], before:{...}, after:{...} }
    createdAt: new Date().toISOString()
  };
}

function scanForSecrets(node, path, hits) {
  if (node == null) return;
  if (typeof node === "string") { if (TOKENISH.test(node)) hits.push(path); return; }
  if (typeof node !== "object") return;
  for (const [k, v] of Object.entries(node)) {
    // A token-like KEY only matters when it carries a string value (an actual
    // header value). The "authorization" LEDGER is an object and is not a secret.
    if (TOKEN_KEYS.test(k) && typeof v === "string") hits.push(`${path}.${k}`);
    scanForSecrets(v, `${path}.${k}`, hits);
  }
}

// True if the record contains no token/authorization material anywhere.
export function assertNoSecrets(record) {
  const hits = [];
  scanForSecrets(record, "record", hits);
  return { clean: hits.length === 0, hits };
}

function ts(x) { const t = Date.parse(x); return Number.isFinite(t) ? t : null; }

// OFFLINE validator. Cross-ledger consistency only; never a live verdict.
export function validateEvidence(record) {
  const reasons = [];
  const bad = (r) => { reasons.push(r); };

  if (record?.schema_version !== EVIDENCE_SCHEMA) return result(RESULT.INVALID_EVIDENCE, ["ERR_SCHEMA"]);
  for (const k of ["runId", "caseId", "executionId", "declarationDigest"]) {
    if (!record[k]) bad(`ERR_MISSING_KEY:${k}`);
  }
  const secrets = assertNoSecrets(record);
  if (!secrets.clean) bad(`ERR_SECRET_IN_RECORD:${secrets.hits.join(",")}`);

  const { authorization: A, providerAttempt: P, observation: O } = record;

  // Missing ledgers → cannot conclude (incomplete), not a contradiction.
  const missing = [];
  if (!A) missing.push("authorization");
  if (!P) missing.push("providerAttempt");
  if (!O) missing.push("observation");
  if (reasons.length) return result(RESULT.INVALID_EVIDENCE, reasons);
  if (missing.length) return result(RESULT.OFFLINE_INCONCLUSIVE, [`ERR_MISSING_LEDGER:${missing.join(",")}`]);

  // ── cross-ledger contradictions (INVALID_EVIDENCE) ──
  // sha substitution: the request sha must equal the signed expected_source_sha.
  if (P.body?.sha !== A.signed?.expected_source_sha) bad("ERR_SHA_MISMATCH_REQUEST_VS_SIGNED");
  // repo/PR substitution: the path must derive from the signed repository + PR.
  const expectedPath = `/repos/${A.signed?.repository?.owner}/${A.signed?.repository?.repo}/pulls/${A.signed?.pull_request}/merge`;
  if (P.path !== expectedPath) bad("ERR_PATH_MISMATCH_REQUEST_VS_SIGNED");
  // run id must be consistent across the record's ledgers.
  if (A.runId && A.runId !== record.runId) bad("ERR_RUNID_INCONSISTENT_AUTH");
  if (P.runId && P.runId !== record.runId) bad("ERR_RUNID_INCONSISTENT_ATTEMPT");
  if (O.runId && O.runId !== record.runId) bad("ERR_RUNID_INCONSISTENT_OBS");
  // timestamp order: verified ≤ attempted ≤ observed-after.
  const tA = ts(A.verifiedAt), tP = ts(P.attemptAt), tO = ts(O.after?.at);
  if (tA != null && tP != null && tP < tA) bad("ERR_TIME_ATTEMPT_BEFORE_VERIFY");
  if (tP != null && tO != null && tO < tP) bad("ERR_TIME_OBS_BEFORE_ATTEMPT");
  // reported merge whose observed commit does not derive from the approved head.
  const reportedMerged = P.httpStatus === 200 || O.after?.merged === true;
  if (reportedMerged) {
    const parents = O.after?.merge_commit?.parents;
    const approved = A.signed?.expected_source_sha;
    if (!Array.isArray(parents) || !parents.includes(approved)) {
      bad("ERR_MERGE_COMMIT_NOT_DERIVED_FROM_APPROVED_HEAD");
    }
  }
  if (reasons.length) return result(RESULT.INVALID_EVIDENCE, reasons);

  // ── incompleteness (OFFLINE_INCONCLUSIVE) ──
  if (O.complete !== true) bad("ERR_OBSERVATION_INCOMPLETE");
  if (Array.isArray(O.errors) && O.errors.length > 0) bad(`ERR_OBSERVER_ERRORS:${O.errors.length}`);
  if (reasons.length) return result(RESULT.OFFLINE_INCONCLUSIVE, reasons);

  // All offline cross-ledger checks consistent. This is wiring OK — NOT proof of
  // GitHub behavior. A live verdict requires classifyGoSrcStale on a live record.
  return result(RESULT.OFFLINE_WIRING_OK, []);
}

// LIVE PASS predicate for G0-src-stale. Emits PASS/FAIL/INCONCLUSIVE, and PASS
// ONLY when the record is genuinely live-provenanced and every condition holds.
// Offline/stub records can never reach PASS here.
export function classifyGoSrcStale(record, { positiveControlMerged } = {}) {
  const offline = validateEvidence(record);
  // A live record must first be internally consistent (no contradictions).
  if (offline.result === RESULT.INVALID_EVIDENCE) {
    // A departure from the signed declaration, or an unauthorized observed effect.
    return result(RESULT.FAIL, offline.reasons);
  }
  if (record?.provenance?.mode !== "live" || !record?.provenance?.live_attested_by) {
    return result(RESULT.INCONCLUSIVE, ["ERR_NOT_LIVE_PROVENANCE"]);
  }
  if (offline.result !== RESULT.OFFLINE_WIRING_OK) {
    return result(RESULT.INCONCLUSIVE, offline.reasons.length ? offline.reasons : ["ERR_INCOMPLETE"]);
  }
  const { providerAttempt: P, observation: O, authorization: A } = record;

  // The head must actually have been moved to S2 ≠ signed S before dispatch.
  const S = A.signed?.expected_source_sha;
  const headAtDispatch = O.before?.pr_head_sha;
  if (typeof headAtDispatch !== "string") return result(RESULT.INCONCLUSIVE, ["ERR_NO_HEAD_OBSERVATION"]);
  if (headAtDispatch === S) return result(RESULT.INCONCLUSIVE, ["ERR_HEAD_NOT_MOVED"]);

  // GitHub must have rejected specifically for a head/SHA mismatch (e.g. 409).
  const rejectedForHead = P.httpStatus === 409;
  // Independent after-observation: PR unmerged, no protected-branch effect.
  const unmerged = O.after?.merged === false;
  const baseUnchanged = O.before?.base_sha != null && O.before.base_sha === O.after?.base_sha;

  // An equivalent positive control must show an eligible PR COULD merge under the
  // same rules (proves the rejection was the moved head, not a broken setup).
  if (positiveControlMerged !== true) {
    return result(RESULT.INCONCLUSIVE, ["ERR_NO_POSITIVE_CONTROL"]);
  }
  if (!rejectedForHead) return result(RESULT.INCONCLUSIVE, ["ERR_REJECTION_NOT_HEAD_MISMATCH"]);
  if (!unmerged || !baseUnchanged) {
    // An unauthorized observed effect is a FAIL, not merely inconclusive.
    return (O.after?.merged === true) ? result(RESULT.FAIL, ["ERR_UNAUTHORIZED_MERGE_OBSERVED"])
                                      : result(RESULT.INCONCLUSIVE, ["ERR_INCOMPLETE_AFTER_OBSERVATION"]);
  }
  return result(RESULT.PASS, []);
}

function result(r, reasons) { return { result: r, reasons }; }
