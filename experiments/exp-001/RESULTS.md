# MNDe EXP-001 — Stage 1 Results

**Experiment:** MNDE-EXP-001, Stage 1 (MNDe as-is; no GitHub adapter).
**MNDe commit tested:** `9295635b6d92cc448b9fefa8524d1a21e8f0e4d6`
**Branch:** `feat/sidecar-graceful-shutdown` (working tree clean except this experiment's own files)
**Node:** v24.14.1 · **Platform:** win32 · **Run:** 2026-09-15
**Signing posture:** legacy HMAC (harness default) for A/C/D; **custody Ed25519** for the crypto self-checks.

## Threat assumptions (Stage 1)

- We test what MNDe *is*: an authorization sidecar + a client-side execution gate
  that binds a **declared** action to a verified, request-bound receipt and gates
  a local `run()` call.
- We do **not** test any real external side effect. There is no GitHub, no
  network mutation, no repository state. Those belong to Stage 2 (MNDe + a
  concrete executor adapter).
- MNDe source is unmodified. Every check drives the real executor, sidecar,
  canonicalizer, custody signer, and verifier.

## Scope tested

| Conjunct | Question | Verdict |
|---|---|---|
| **A Encoding** | Can two security-distinct requests collapse to one identity? | **PASS** (no collision found) |
| **C Structural binding** | Can a receipt for action A authorize a different declared action B? | **PASS** (all substitutions refused) |
| **D Freshness** | Is `Consumed→Unused` prevented across replay / restart / rollback? | **MIXED — 2 findings** |
| **Crypto self-checks (custody)** | Do signature/trust checks reject tamper & untrusted signers? | **PASS** |
| **B Completeness** | Does MNDe bind external execution state? | **Capability boundary (not a test failure)** — see FINDINGS F-003 |
| **E Atomic exec / G0, credential boundary** | — | **Out of scope for Stage 1** (no external effect exists to bind) |

## Totals

`30 tests — 27 PASS · 2 FAIL · 1 INCONCLUSIVE`

| Conjunct | Pass | Fail | Inconclusive | Total |
|---|---|---|---|---|
| A-encoding | 11 | 0 | 0 | 11 |
| C-binding | 8 | 0 | 1 | 9 |
| D-freshness | 3 | **2** | 0 | 5 |
| crypto-custody | 5 | 0 | 0 | 5 |

## A — Encoding & canonicalization (11/11 PASS)

MNDe's strict parser + canonicalizer (`shared/json.ts`) resisted every collision
and ambiguity probe: key-order is canonicalized (A1, A10); duplicate keys (A2),
floats/exponents (A8), and unsafe integers (A9) are rejected; and `"17"`≠`17`
(A3), `main`≠`refs/heads/main` (A4), `main`≠`Main` (A5), NFC≠NFD (A6), and
trailing-space refs (A7) are all distinct identities. **No `enc(X)=enc(Y)` with
`X≠Y` was found.**

- **Characteristic (not a defect):** MNDe applies **no Unicode normalization**.
  This is *safe against collision* (distinct byte forms → distinct identities),
  but a Stage-2 executor adapter that normalizes a ref before acting on it could
  re-introduce ambiguity. Carried to Stage 2 as an adapter requirement (see A6
  note in `evidence/A_encoding.json`).

## C — Structural binding (8/9 PASS, 1 INCONCLUSIVE)

One genuine ALLOW receipt (C001) was captured from the real sidecar, then
**replayed verbatim** against mutated requests via a stand-in decision endpoint
(the real sidecar stopped). The executor's strict gate refused every structural
substitution and never called `run()`:

| Test | Mutation | Result | Reason code |
|---|---|---|---|
| T005 | action merge→force_push | REFUSE | `ERR_RECEIPT_ACTION_MISMATCH` |
| T001 | target_ref main→production | REFUSE | `ERR_RECEIPT_ACTION_MISMATCH` |
| T002 | source_commit abc123→def456 | REFUSE | `ERR_RECEIPT_ACTION_MISMATCH` |
| T003 | pull_request 17→18 | REFUSE | `ERR_RECEIPT_ACTION_MISMATCH` |
| T004 | repository change | REFUSE | `ERR_RECEIPT_ACTION_MISMATCH` |
| Tid | receipt reused for a new execution id | REFUSE | `ERR_RECEIPT_REQUEST_MISMATCH` |
| T007 | subject mismatch (expect B, receipt A) | REFUSE | `ERR_SUBJECT_MISMATCH` |

- **T009-exec (INCONCLUSIVE, characterization):** re-presenting the **identical**
  receipt with the identical execution id re-authorizes (`ALLOW`, `run()` runs
  again). This is expected and correct for the *executor*, which is a per-call
  **binding** check, not a consumption ledger. Single-use is the **sidecar's**
  job — measured in conjunct D. Recorded as INCONCLUSIVE (of C), not promoted to
  PASS, and cross-referenced to D.

## D — Freshness / replay / restart / rollback (3/5 PASS, 2 FAIL)

Driven against the real sidecar's own execution-id dedup store.

| Test | Scenario | Verdict | Observed |
|---|---|---|---|
| D1 | durable store ON, same process, replay | **PASS** | 2nd `REFUSE ERR_EXECUTION_ID_DUPLICATE` |
| D2 | durable store ON, replay after restart | **PASS** | still `REFUSE` (survives restart) |
| D5 | default (no store), same-process replay | **PASS** | 2nd `REFUSE ERR_EXECUTION_ID_REPLAYED` (in-proc) |
| **D3** | **rollback of the store, then replay** | **FAIL** | consumed id `ALLOW`s again → `Consumed→Unused` |
| **D4** | **default posture, replay after restart** | **FAIL** | replay `ALLOW`ed (no durable store by default) |

The two FAILs are **findings inside MNDe's own authority state** → F-001, F-002.
Per the experiment protocol they are **preserved, not remediated.**

## Crypto self-checks under custody (5/5 PASS)

Real Ed25519 custody signing + offline verification: a valid receipt verifies
(CS1); inner-receipt tamper (CS2, `receipt hash mismatch`), signature tamper
(CS3, `SIGNATURE_INVALID`), a foreign/untrusted signer (CS4, `authority
fingerprint mismatch`), and a wrong pinned root (CS5, `UNTRUSTED_ROOT`) are all
rejected. These establish the crypto substrate only — **not** temporal exact
binding.

## Bounded conclusion

> Under the tested MNDe commit (`9295635b`), stated Stage-1 assumptions, and no
> external executor adapter, MNDe **did not** permit any tested structural
> substitution of a declared authorized action into a different declared action
> (conjunct C), and no encoding collision was found (conjunct A). Its
> signature/trust verification correctly rejected tamper and untrusted signers.
>
> MNDe's single-use guarantee is **conditional**: it holds with a durable
> execution-id store configured and intact (D1, D2, D5), and **fails** in the
> default posture across restart (D4) and when the durable store is rolled back
> (D3).
>
> MNDe has **no representation of external execution state** (e.g.
> `expected_target_sha`); exact external-state binding is therefore **not
> provided by the current abstraction** (F-003) and is the subject of Stage 2.

## Reproduction

```bash
# From the repo root, on the pinned commit, Node ≥ 24:
node experiments/exp-001/run-all.mjs
# Per-conjunct, standalone:
node experiments/exp-001/attacks/a_encoding.mjs
node experiments/exp-001/attacks/c_binding.mjs
node experiments/exp-001/attacks/d_freshness.mjs
node experiments/exp-001/attacks/e_crypto_custody.mjs
```

Evidence is written to `experiments/exp-001/evidence/*.json` and the aggregate to
`experiments/exp-001/results.json`. No GitHub account, token, or network is
required. The crypto self-checks generate their own ephemeral custody keys per
run. See `PRECONDITIONS.md` for environment details and known limitations.
