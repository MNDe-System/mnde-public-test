> Current safety posture (2026-09-17): live dispatch is disabled; injectable dispatch is isolated in tests/support. SQLite is same-machine model evidence, never deployment proof. The 82 tests now exercise that isolated model. See [the follow-up audit](../../docs/FRESHNESS-BOUNDARY-AUDIT.md). Earlier production-backend and closure wording below is superseded.

# Fail-closed freshness (F-001 / F-002) — design note

**Date:** 2026-09-17. Offline; no network, no token, no live dispatch.

## Safety goal

One verified execution authority causes **at most one protected dispatch
attempt**, even after process restart or restoration of the executor's local
files. This is **at-most-once attempt**, not exactly-once effect: a claim made
just before a crash may consume authority without an effect — an acceptable
fail-closed outcome.

## Audit (before the change)

- **F-001 mechanism.** Stage 1's durable dedup (`sidecar/execution_id_store.mjs`)
  is gated on `MNDE_EXEC_ID_CACHE`; unset (the default) → in-process only → replay
  succeeds across restart. That store is also **executor-local** (in the rollback
  domain).
- **v2 verifier.** `verifyDeclaration` proves an authentic, executor-bound
  authority (`RECEIPT-CONTRACT-AUDIT.md`) but **never** touches a nonce store —
  it establishes authenticity, not consumption.
- **Signed vs config.** Signed (from the receipt): subject, action, params,
  execution id, `expected_source_sha`, `target_ref`, `expected_target_sha`,
  grant/nonce (when present), receipt hash. Trusted config (never an agent
  field): the claim **namespace**, the trust root, expected executor id,
  environment. The private JS production brand is **not** consumption evidence.

## Audit addendum (review of commit `2aef7e68`)

Two boundaries were audited before extending:

1. **Atomicity across both keys — was a real defect, now fixed.** The original
   file backend claimed `(namespace,exec_id)` and `(namespace,grant_id)` in **two
   separate `O_EXCL` writes**. A crash between them left one identity unclaimed and
   **reusable** (regression: `test_freshness_atomicity.mjs` shows the unsafe
   backend reusing a grant after a partial claim). Fixes:
   - **Production backend** (`createSqliteClaimBackend`): a **single transactional
     `INSERT`** guarded by two unique indexes — `(namespace,exec_id)` and a partial
     `(namespace,grant_id)` — so both identities are claimed atomically, or neither.
   - **Crash-safe file model** (`createFileClaimBackend`): one atomic commit record
     + reconciled index entries, serialized per instance; a crash after the commit
     is healed by `reconcile()`. (The unsafe variant is retained only to
     demonstrate the flaw.)
2. **F-001 scope — narrow, stated explicitly.** The original optional
   `MNDE_EXEC_ID_CACHE` behavior still governs the **Stage 1 sidecar** decision
   path (`mnde-local-sidecar.mjs:1123` calls `reserveExecutionId`, off by default,
   executor-local). The new claim gate lives **only in the Stage 2 adapter** and
   does not touch `MNDE_EXEC_ID_CACHE`. **F-001 is therefore closed only for the
   new Stage 2 adapter dispatch path — not for MNDe as a whole.** No broader claim
   is made.

## Claim identity

The adapter derives the claim itself (never a caller "claimed" flag), from the
verified declaration + trusted namespace:

```
record = { namespace,          ← trusted config (derives the trust namespace)
           execution_id,        ← signed A⁺
           grant_id,            ← signed grant/nonce where present, else null
           subject,             ← authenticated
           executor_id,         ← verified executor identity
           receipt_hash,        ← signed inner-receipt hash
           aplus_digest }       ← digest of the signed canonical request
```

**Two independent uniqueness keys** are claimed atomically:
`(namespace, exec, execution_id)` and, when a grant is present,
`(namespace, grant, grant_id)`. Independence means changing only the execution id
still collides on the grant, and changing only the grant still collides on the
execution id. A duplicate on either key is **spent** — including when identifiers
and digest match. A returned prior record is for inspection, not permission. There
is no auto-expiry into reusable authority.

## Dispatch contract (order matters)

1. Require the exact-action production brand (verified executor-bound v2). Else
   refuse — no claim, no transport.
2. Build + freeze the request from the signed A⁺.
3. Require a configured, healthy durable claim backend. **Unset / unavailable →
   refuse** (`ERR_NO_CLAIM_BACKEND` / `ERR_CLAIM_BACKEND_UNAVAILABLE`). No
   fallback to memory or a local dedup dir.
4. **Atomically claim** in the backend *before any transport*. CLAIMED → proceed;
   ALREADY_SPENT → refuse (`ERR_AUTHORITY_SPENT`); UNKNOWN (submit failed and a
   consistent lookup is uncertain) → send nothing, no retry.
5. Send the fixed request exactly once, only after a durable CLAIMED ack.
6. A lost provider response → UNKNOWN; **never** auto-retry and **never** re-claim
   (the authority is already spent). Observation + operator reconciliation.

## Crash ordering

- **Before claim.** Nothing consumed; a later attempt claims once (one attempt).
- **After a durable claim, before transport.** Re-presenting the authority is
  SPENT → refuse, zero transport. Authority consumed without effect — acceptable.
- **After transport starts, response lost.** First attempt is UNKNOWN
  (`dispatched:true`); recovery re-presents the authority → SPENT → **no
  re-dispatch**. At most one provider request ever.

## Backend trust assumption

The claim backend must provide an **atomic conditional first-claim (unique
constraint)**, a **durable acknowledgement**, and **consistent reads across
executor processes**, and it must live **outside the executor's local rollback
domain** — separately controlled storage, credentials, and backups. Restoring the
executor's local files must not un-spend a claim. **Putting a second database
file in the same restored directory does not meet this condition** (the negative-
control test demonstrates it fails).

**Backends:**
- **Production:** `createSqliteClaimBackend` (`node:sqlite`) — one transactional
  `INSERT` + two unique indexes (atomic across both identities), WAL +
  `synchronous=FULL` (durable ack), `busy_timeout` for competing writers
  (consistent cross-process claims). `production:true`. The Stage 2 adapter's
  `requireProductionBackend` config refuses any non-production backend, so a
  production deployment never falls back to the file model or memory.
- **Model:** `createFileClaimBackend` — crash-safe (atomic commit record +
  reconcile), single-process. Fine for offline model tests; not for production
  cross-process concurrency.

**Trust boundary actually used in tests:** a SQLite database **file** in a
directory **separate** from the modeled executor-local files. That is genuinely
separate *storage*, but on the **same machine** — **not** genuinely independent
infrastructure (no separate credentials or backups). It **models** the
out-of-rollback-domain property and demonstrates the mechanism; it is **not** a
deployment proof. Live dispatch stays disabled (injected transport only).

## Result table

| Test | Finding | What it shows |
|---|---|---|
| unconfigured backend refuses dispatch, zero transport | **F-001** | no durable backend → fail closed (not permissive), across restart |
| configured backend: replay across restart is SPENT | **F-001** | durable claim survives restart; replay refused |
| executor-local restore, independent backend intact → SPENT | **F-002** | restoring local files does not un-spend a claim in a separated backend |
| in-domain backend rolled back does NOT protect (negative control) | **F-002** | proves the separation requirement is load-bearing |
| same exec + different grant → SPENT | contract | exec-id uniqueness |
| same grant + different exec → SPENT | contract | grant uniqueness |
| same identifiers + changed digest → SPENT | contract | duplicate spent regardless of digest |
| foreign authority refused before claim | contract | unverified authority never reaches the backend |
| wrong executor identity refused before claim | contract | executor binding enforced pre-claim |
| concurrent instances sharing backend → one claim, one request | contract | atomic unique constraint under concurrency |
| crash before claim → one later attempt | crash | no double attempt |
| crash after claim, before transport → SPENT, zero transport | crash | authority consumed once, no second attempt |
| crash after send, response lost → UNKNOWN, recovery refuses | crash | at-most-once attempt across lost responses |
| backend unavailable / timeout / lost-ack-present / contradictory | contract | fail closed, no provider request |
| positive: fresh authority + healthy backend → one request | contract | not merely "deny everything" |
| policy-only / copied marker / {verified:true} cannot dispatch | contract | only exact-action authority dispatches |
| non-atomic backend reuses a grant after a partial claim | atomicity | documents the original defect |
| crash-safe backend refuses grant/exec reuse after a post-commit crash | atomicity | commit+reconcile fixes it |
| SQLite single-insert enforces both unique identities | atomicity | production atomic two-identity claim |
| SQLite restore/restart → SPENT, zero transport | **F-002** | production backend in separate storage |
| SQLite two separate processes racing → exactly one claim | contract | cross-process atomic first-claim |
| SQLite crash-after-ack → recovery SPENT | crash | durable claim survives restart |
| SQLite lost-ack-present → SPENT; unavailable → refuse | contract | fail closed |
| requireProductionBackend refuses a file-model backend | **F-001** | no fallback to model/memory |
| records authorization / claim / attempt / observation separately | contract | four distinct artifacts |

## Status (honest, scoped to what the tests prove)

- **F-001 — closed for the Stage 2 adapter dispatch path only.** That path fails
  closed with no durable backend (`ERR_NO_CLAIM_BACKEND`), refuses a non-production
  backend under `requireProductionBackend`, and refuses replay across restart with
  a durable backend. **The broader MNDe sidecar/executor paths still use the
  optional `MNDE_EXEC_ID_CACHE` and are NOT changed here.**
- **Claim atomicity — fixed.** The production backend claims both identities in a
  single transactional insert; the file model is crash-safe via commit+reconcile.
  The partial-claim reuse regression is demonstrated (unsafe) and refused (fixed).
- **F-002 — mechanism implemented and demonstrated against the production backend
  in separate storage; DEPLOYMENT PROOF PENDING.** The restore/restart integration
  test refuses the old authority with zero transport, separate processes racing
  yield exactly one claim, and crash-after-ack and backend-loss all fail closed —
  but the backend is same-machine storage, **not** genuinely independent
  infrastructure. **F-002 is not described as fixed.** Deployment closure needs the
  same integration test against a backend with separately controlled storage,
  credentials, and backups. That infrastructure is unavailable here.
- **Live dispatch remains disabled** (injected transport). Remaining F-002 blocker:
  genuinely independent durable infrastructure. G0 source enforcement, target/base
  binding, and the observed-outcome receipt remain separate work; a merge is not a
  freshness anchor.
