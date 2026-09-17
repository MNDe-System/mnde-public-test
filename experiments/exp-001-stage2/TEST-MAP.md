# EXP-001 Stage 2 offline units — test → property map

**Date:** 2026-09-17
**Scope:** offline wiring + evidence validation. No network, no token, no live
GitHub. Baseline `experiments/exp-001/` not rerun, not modified.
**Count:** 41 passing (Unit 1: 13, Unit 2: 12, Unit 3: 8, verify fail-closed: 4,
verify positive: 4). Reported separately from EXP-001's 30 baseline tests.

## Unit 1 — fixed request construction (`test_build_request.mjs`)

| Test | Property checked |
|---|---|
| sha and path come solely from the verified declaration | request values originate only from A⁺, not the caller |
| expected_target_sha is NOT in the request body | target/base binding is not asserted via the merge endpoint |
| mutating the caller's A⁺ after verification cannot change the request | verified values are snapshotted/frozen at verification time |
| plain {verified:true} is refused / buildMergeRequest refuses it | authorization requires the non-forgeable brand, not a self-declared flag |
| refuses wrong repository / PR / target / head / method / action / extra param | any deviation from the signed declaration or trusted config fails closed pre-dispatch |
| absent config is refused | no request without a pinned repo+target |

## Unit 2 — three-ledger evidence + validator (`test_evidence.mjs`)

| Test | Property checked |
|---|---|
| consistent stale-head evidence is OFFLINE_WIRING_OK | cross-ledger consistency passes offline (not a live claim) |
| offline stale-head cannot yield a live PASS | a stub/offline record never produces PASS |
| live stale-head + positive control = PASS | the live PASS predicate is complete only with live provenance AND a positive control |
| live stale-head WITHOUT positive control = INCONCLUSIVE | a 409 alone is insufficient for PASS |
| 409 without complete observation = INCONCLUSIVE | missing observation blocks PASS |
| 200 with observed commit not derived from approved head = INVALID/FAIL | a reported merge inconsistent with the approved head is a conflict/FAIL |
| request sha ≠ signed sha = INVALID_EVIDENCE | detects SHA substitution across ledgers |
| repository/PR path substitution = INVALID_EVIDENCE | detects repo/PR substitution across ledgers |
| missing a ledger = OFFLINE_INCONCLUSIVE | missing authorization/attempt/observation prevents a conclusion |
| inconsistent timestamps = INVALID_EVIDENCE | verified ≤ attempted ≤ observed ordering enforced |
| token/authorization value anywhere = detected + invalid | no secret material may live in a record |
| a clean record has no secrets | the scanner does not false-positive on the ledger name |

## Unit 3 — adapter skeleton (`test_adapter.mjs`)

| Test | Property checked |
|---|---|
| exactly one merge call for an eligible attempt | single dispatch, single call site |
| lost response is UNKNOWN and never auto-retries | uncertainty never triggers a second merge |
| config carrying a token is refused | the token boundary is visible; agent/config cannot inject a credential |
| test-only pause hook cannot change the dispatched request | the request is frozen before dispatch |
| invalid (target-mismatched) declaration refused before dispatch (transport untouched) | fail-closed happens before egress |
| SECURITY: test-only (unverified) declaration cannot dispatch | the adapter requires REAL verification, not a wiring brand |
| SECURITY: plain {verified:true} cannot dispatch | a self-declared flag never authorizes a dispatch |
| accidental real fetch fails immediately | the network guard is active |

## verifyDeclaration fail-closed (`test_verify_failclosed.mjs`)

| Test | Property checked |
|---|---|
| plain {verified:true} does not verify and is not branded | production path runs the real verifier; a self-declared flag is not proof |
| buildMergeRequest refuses a plain {verified:true} | brand gate holds end-to-end |
| custody envelope with NO authority bundle fails closed | verification without the trusted bundle → not authorized |
| foreign-authority envelope rejected against a different bundle | an untrusted signer does not verify |

## verifyDeclaration positive — real receipt + real verifier (`test_verify_positive.mjs`)

| Test | Property checked |
|---|---|
| a real signed receipt verifies through the production verifier and is production-branded | the production path accepts a genuinely valid receipt and marks it production-verified |
| the signed A⁺ reaches the fixed request builder unchanged | authenticated head SHA + repo/PR flow through to the request untouched |
| tampering the decision breaks verification | the positive result depends on real signatures, not the fixture |
| tampering a request parameter (source sha) breaks verification | request tampering fails closed under the real verifier |

Keys for the positive path are generated in memory (PEM strings) and never
written to disk — nothing enters the repository, nothing to clean up.

## Bottom line

Offline wiring checked; **GitHub source enforcement not yet measured**;
target/base binding unresolved; **F-001 and F-002 unchanged**.
