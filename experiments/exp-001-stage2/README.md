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

The production path accepts **only a verified executor-bound
`mnde.signed-receipt.v2` envelope** — the exact-action execution authority the
Stage 2 design requires. `verifyDeclaration` mints the private
`PRODUCTION_VERIFIED` brand only when the real verifier returns
`verified:true` / `kind:custody-signed` / `state:executor_and_authority_verified`
for a v2 envelope; the adapter's `attemptMerge` requires that brand before it
builds or dispatches anything. A JavaScript brand, a `{verified:true}` field, the
labelled test-only fixture, **and a policy-only receipt** all fail this and are
refused (`ERR_NOT_PRODUCTION_VERIFIED` / `ERR_NOT_EXECUTOR_BOUND`) with zero
transport calls. The positive path is proven with a genuine v2 executor-bound
envelope produced offline from the repository's own primitives (`_real_receipt.mjs`)
and verified by the actual trusted verifier; private keys are written to an OS
temp dir outside the repo and removed immediately after signing. See
`RECEIPT-CONTRACT-AUDIT.md` for the full trace, including the separate,
**unproven** durable-consumption claim (a signature is not replay protection).

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

**82 Stage 2 offline tests, all passing** — Unit 1: 13, Unit 2: 12, Unit 3: 8,
verifyDeclaration fail-closed: 3, verifyDeclaration exact-action: 14, freshness
(F-001/F-002): 19, freshness atomicity: 5, freshness integration (SQLite): 8.
Independent of the EXP-001 baseline's 30 tests, which were not rerun.

## Freshness (F-001 / F-002)

The protected dispatch path atomically **claims** the verified authority in a
durable, out-of-rollback-domain backend **before any transport**, so one authority
causes at most one dispatch attempt across restart or executor-local file
restoration. No configured backend → refuse (F-001 fail-closed). The production
backend (`node:sqlite`) claims both identities in a single transactional insert
with two unique constraints; `requireProductionBackend` refuses any non-production
backend. See `FRESHNESS-DESIGN.md` for the claim identity, crash ordering, the
audited atomicity fix, the backend trust boundary, and the per-test result table.

**Status (scoped):** F-001 closed **for the Stage 2 adapter path only** — the
Stage 1 sidecar still uses the optional `MNDE_EXEC_ID_CACHE`. Claim atomicity
fixed (single transactional insert / crash-safe commit+reconcile). **F-002
mechanism implemented and demonstrated against the production backend in separate
storage, but deployment proof pending** — that backend is same-machine storage,
not genuinely independent infrastructure. Live dispatch remains disabled.

## Status

Offline wiring checked. **GitHub source enforcement not yet measured.**
Target/base binding unresolved. **F-001 and F-002 unchanged.** See
`OUTCOME-BINDING-GAP.md` for the one design gap recorded during this build, and
`TEST-MAP.md` for the test→property mapping.
