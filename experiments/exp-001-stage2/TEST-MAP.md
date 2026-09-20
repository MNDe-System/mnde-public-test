> Current safety posture (2026-09-17): live dispatch is disabled; injectable dispatch is isolated in tests/support. SQLite is same-machine model evidence, never deployment proof. The 82 tests now exercise that isolated model. See [the follow-up audit](../../docs/FRESHNESS-BOUNDARY-AUDIT.md). Earlier production-backend and closure wording below is superseded.

# EXP-001 Stage 2 offline units — test → property map

**Date:** 2026-09-17
**Scope:** offline wiring + evidence validation. No network, no token, no live
GitHub. Baseline `experiments/exp-001/` not rerun, not modified.
**Count:** 82 passing (Unit 1: 13, Unit 2: 12, Unit 3: 8, verify fail-closed: 3,
verify exact-action: 14, freshness F-001/F-002: 19, freshness atomicity: 5,
freshness integration/SQLite: 8). Reported separately from EXP-001's 30 baseline
tests. Freshness test→finding mapping is in `FRESHNESS-DESIGN.md`.

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
| buildMergeRequest refuses a plain {verified:true} | wiring brand gate holds |
| executor-bound v2 envelope with NO trust anchors fails closed | verification without out-of-band bundle/fingerprint/env/executor → not authorized |

## verifyDeclaration exact-action authority (`test_verify_positive.mjs`)

Uses generated in-memory keys and an independently configured trusted public key.
Every refusal is confirmed to make **zero transport calls** via the adapter.

| Test | Property checked |
|---|---|
| an executor-bound v2 receipt verifies and is production-branded | the production path accepts the exact-action authority the design requires |
| the signed A⁺ reaches the fixed request builder unchanged | authenticated head SHA + repo/PR flow through untouched; expected_target_sha carried, never sent |
| verification does NOT establish durable single-use | consumption is a separate, unproven property (F-001/F-002); a signature is not replay protection |
| a valid policy-only receipt cannot dispatch | an authentic policy decision is not execution authority (ERR_NOT_EXECUTOR_BOUND) |
| a foreign signer is refused before transport | a different authority does not verify against the trusted bundle |
| a changed trusted root fingerprint is refused | the trusted key is out-of-band; a wrong anchor rejects |
| a tampered attestation signature is refused | executor/authority signature integrity |
| changed subject / execID / action / parameter / source-sha / target / expected-target-sha refused | every signed A⁺ field is bound; any change breaks verification, zero transport calls |

Keys for the positive/executor-bound path: root/receipt/executor generated in
memory; the receipt private key + bundle are written to an OS temp dir OUTSIDE
the repo only for signing and removed immediately after — nothing enters the
repository.

## Bottom line

Offline wiring checked; **GitHub source enforcement not yet measured**;
target/base binding unresolved. Claim atomicity fixed (single transactional
insert / crash-safe file model). **F-001 closed for the Stage 2 adapter path only
(Stage 1 sidecar unchanged); F-002 mechanism demonstrated against a production
backend in separate storage, deployment proof pending** (same-machine storage,
not genuinely independent infrastructure). See `FRESHNESS-DESIGN.md`.
