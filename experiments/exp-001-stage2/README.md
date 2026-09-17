# EXP-001 Stage 2 — G0 offline units

Wiring + evidence-validation only. **No network, no GitHub token, no live GitHub
calls.** Does not touch or rerun the frozen `experiments/exp-001/` baseline
(`27 PASS / 2 FAIL / 1 INCONCLUSIVE`, tag `exp-001-stage1-baseline`).

## What this establishes — and what it does not

- **Establishes (offline):** that the signed head SHA reaches the merge request
  unchanged; that the request is a single fixed operation with no caller-supplied
  URL/body/option; that evidence is checked *across* three ledgers rather than
  trusting one success flag; that fail-closed and no-retry behaviors hold.
- **Does NOT establish:** GitHub's actual behavior. GitHub documents a `sha`
  request field and a `409` for a mismatched supplied SHA, but that is measured
  only in the later live step. **GitHub source enforcement is not yet measured.**
- **UNRESOLVED:** target/base-state binding. The merge endpoint has no expected
  target/base SHA field. `expected_target_sha` is carried in the declaration and
  evidence but is never sent to the merge endpoint and is not enforced here.
- **F-002 note:** a successful merge is *not* an external freshness anchor (the
  merge does not move the PR head). F-001 and F-002 remain separate freshness
  failures, unchanged by this step.

## Units

| Unit | File | Role |
|---|---|---|
| 1 — fixed request | `src/build_request.mjs` | Pure `buildMergeRequest(verifiedDecl, config)` → one fixed `PUT .../merge` with `{sha, merge_method:"merge"}`; fails closed on any malformed/mismatched/unverified input. |
| 2 — evidence | `src/evidence.mjs` | Versioned, token-free three-ledger record + `validateEvidence` (offline classes) + `classifyGoSrcStale` (live PASS predicate). |
| 3 — adapter | `src/adapter.mjs` | One stubbed merge call site via an injected transport; returns an attempt record; UNKNOWN + no retry on lost reply; token boundary visible. |
| — declaration | `src/declaration.mjs` | `verifyDeclaration` (real verifier, fail-closed) + labelled `testOnlyVerifiedDeclaration`; A⁺ extraction (legacy + policy-engine shapes); two brands — a wiring brand and a **production-verified** brand only the real verifier can mint. |

## Authorization boundary

A JavaScript brand or a `{verified:true}` field alone does **not** authorize a
dispatch. The adapter's production entry (`attemptMerge`) requires a declaration
that passed the **real** receipt verifier (`isProductionVerified`, an
unexported WeakSet only `verifyDeclaration` populates). The labelled test-only
fixture carries the *wiring* brand for Unit 1/2 construction tests but can never
enter the production brand, and is refused at the adapter
(`ERR_NOT_PRODUCTION_VERIFIED`) before any transport call. The positive path is
proven with a genuine policy-engine receipt signed by an in-memory, ephemeral
authority (keys never written to disk) and verified by the actual trusted
verifier (`tests/_real_receipt.mjs`, `tests/test_verify_positive.mjs`).

## Run

```bash
node experiments/exp-001-stage2/run-tests.mjs
```

Each test runs in its own process with the network guard pre-imported
(`--import tests/_guard.mjs`), so any accidental real `fetch`/socket fails
immediately. Node ≥ 24.

Optional — the relevant existing verifier tests (unchanged MNDe code):

```bash
npm run test:layered-receipt-verification
npm run test:custody
```

## Result classes (offline)

`OFFLINE_WIRING_OK` · `INVALID_EVIDENCE` · `OFFLINE_INCONCLUSIVE`. A live `PASS`
is emitted only by `classifyGoSrcStale` on a record with genuine live provenance
plus a passing positive control — never from a stub or simulated observation.

## Test count (reported separately from EXP-001)

**41 Stage 2 offline tests, all passing** — Unit 1: 13, Unit 2: 12, Unit 3: 8
(incl. 2 dispatch-authorization security tests), verifyDeclaration fail-closed:
4, verifyDeclaration positive (real receipt + real verifier): 4. This is
independent of the EXP-001 baseline's 30 tests, which were not rerun.

## Status

Offline wiring checked. **GitHub source enforcement not yet measured.**
Target/base binding unresolved. **F-001 and F-002 unchanged.** See
`OUTCOME-BINDING-GAP.md` for the one design gap recorded during this build, and
`TEST-MAP.md` for the test→property mapping.
