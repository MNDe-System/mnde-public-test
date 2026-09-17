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

**Backend used here:** `createFileClaimBackend` — a file-per-key O_EXCL **model**
backend. O_EXCL gives atomic cross-process first-claim (the same primitive MNDe's
own `execution_id_store` relies on). In the F-002 test it is placed in a directory
**separate** from the modeled executor-local files, which **models** the
out-of-domain property. It is **not** a production backend and does **not** by
itself satisfy the independent-infrastructure requirement.

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

## Status (honest)

- **F-001 — implemented and demonstrated.** The protected path fails closed with
  no durable backend and refuses replay across restart with one. Its restart
  acceptance tests pass.
- **F-002 — mechanism implemented; deployment proof pending.** The rollback
  acceptance test passes **against a separated model backend**, and the negative
  control shows an in-domain backend does not close it. Because the model backend
  is not genuinely independent infrastructure, **F-002 is not yet closed in a
  deployment.** Closing it requires an integration test against a real independent
  durable backend: restore only the executor-local state and show the backend
  still refuses the old authority. That infrastructure is unavailable here →
  **F-002 implementation prepared, deployment proof pending.**
- **Live dispatch remains disabled** (injected transport only). The remaining
  blocker for F-002 closure is a production out-of-rollback-domain backend; the
  G0 source probe, target/base binding, and observed-outcome receipt remain
  separate work.
