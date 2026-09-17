# MNDe EXP-001 Stage 2 — G0 Probe Plan (source-binding)

**Status:** Design only. No harness built, no live GitHub calls, no repo/token
setup in this step. No MNDe source changes. Baseline (`exp-001-stage1-baseline`,
`3368126`) untouched.

## Objective (scope (a))

Measure ONE thing: **does GitHub's merge `sha` parameter enforce source/head
binding** — i.e., can an authorization bound to `expected_source_sha` be used to
merge a *different* head after the PR moved?

- **In scope to measure (later, live):** G0-source.
- **Recorded UNRESOLVED, not measured:** G0-base / target-state binding. GitHub's
  update-a-reference API offers only a fast-forward check, no expected-old-SHA
  compare-and-swap; the `POST /merges` + ref-update route is an untested
  hypothesis. Base binding is explicitly out of scope for this probe.

This is a **research scope, not a claim**. A G0-source PASS says only "the merge
head-SHA check behaved as documented in our test"; it does **not** assert that
Stage 2 v1 guarantees the exact approved effect (target state remains unbound).

## The three ledgers (kept strictly separate)

Every probe case records three independent columns. They are never merged into a
single "it worked" line; a verdict is a *relationship between the three*.

| Ledger | Source of truth | Example fields |
|---|---|---|
| **1. What MNDe signed** | the verified, request-bound receipt (authenticated `canonical_request`) | `repository`, `pull_request`, `operation`, `expected_source_sha`, `target_ref`; `request_hash`; receipt schema (`mnde.signed-receipt.v2`, provisionally reused) |
| **2. What GitHub enforced** | the exact request the adapter sent + GitHub's own response | endpoint (`PUT .../pulls/{n}/merge`), `sha` sent, HTTP status, GitHub error/`merged` body |
| **3. What the observer saw** | an independent read, before and after, not via the adapter | PR head SHA (before/after), PR `merged` state, base ref SHA (before/after), resulting merge commit SHA |

A verdict is only meaningful when all three agree in the intended direction. A
merge that "succeeded" in ledger 2 but whose ledger-3 resulting commit does not
correspond to ledger-1's `expected_source_sha` is a **FAIL**, not a pass.

## Probe cases (semantics predetermined)

| Case | Setup | Adapter sends | PASS | FAIL |
|---|---|---|---|---|
| **G0-src-control** | PR head == `expected_source_sha` (unchanged since approval) | merge with `sha = expected_source_sha` | ledger 2 = merged; ledger 3 resulting commit derives from the approved head; ledgers 1/2/3 agree | any disagreement |
| **G0-src-stale** | after approval, advance PR head to a NEW commit `S1 ≠ expected_source_sha` | merge with `sha = expected_source_sha` (now stale) | ledger 2 = GitHub REJECTS (head moved); ledger 3 shows no merge of `S1` under this authorization | GitHub merges `S1` (or anything) under the stale-SHA authorization → source binding does NOT hold |
| **G0-src-omitted** (control on the control) | head unchanged | merge with **no** `sha` | records provider behavior when the binding parameter is absent — establishes that the PASS in G0-src-stale is attributable to `sha`, not to unrelated state | — (characterization) |

`G0-src-stale` is the falsifier. If a stale-SHA authorization can still drive a
merge of the moved head, MNDe's source binding is not enforced by the provider
and Stage 2's source claim fails at G0.

## Result states

Per case: **PASS / FAIL / INCONCLUSIVE**, never promoted. Overall G0-source is:

- **PASS** only if `G0-src-control` succeeds *and* `G0-src-stale` is rejected,
  each with all three ledgers consistent, reproducibly.
- **INCONCLUSIVE** if the live environment cannot establish the head-moved
  rejection (e.g. the probe could not actually move the head between approval and
  merge) — "could not reproduce the race" is never a PASS.
- **FAIL** if a stale authorization mutates.

G0-base is fixed at **UNRESOLVED** in this probe by construction.

## What is buildable now (offline, non-authoritative)

Because live repo/token are out of this step, only these parts are designed/built
now, and each is explicitly labelled **non-authoritative** (does not establish
provider enforcement):

1. **Request-construction unit** — from a verified Stage-1-style receipt carrying
   `A⁺`, deterministically build the exact merge request (endpoint + `sha`), and
   assert the `sha` sent equals ledger-1 `expected_source_sha`. This is a pure
   binding check (MNDe signed → adapter request), testable with no network.
2. **Three-ledger evidence schema + recorder** — the JSON record shape above,
   with a validator that refuses to emit a PASS unless all three ledgers are
   present and consistent. Testable against *recorded/mock* GitHub responses,
   clearly marked as fixtures, never as enforcement evidence.
3. **Adapter skeleton** — reads the verified receipt, extracts authenticated
   `A⁺`, and has exactly one call site for the GitHub merge (mirroring the
   Stage-1 executor's single-call-site discipline). The token read is stubbed;
   no real credential is present.

The live measurement (actually issuing merges against a throwaway repo, moving
the head between approval and merge, capturing independent before/after reads)
is a **separate later step**, gated on you provisioning the repo and a scoped
token held only in the adapter process, plus the credential-boundary freeze
(DESIGN §6).

## Preconditions deferred to the live step (not this one)

- A throwaway GitHub repository with a PR.
- A scoped write token present **only** in the adapter process env.
- Credential-boundary freeze proving the agent has no independent mutation path.
- Independent-observer read path (separate token/read or unauthenticated read),
  distinct from the adapter, for ledger 3.

## Corrections carried in from review (so implementation starts clean)

1. A successful merge does **not** move the PR head; it is **not** a freshness
   anchor. F-002 keeps its own durable, fail-closed solution (DESIGN §8).
2. `POST /merges` + ref update is **not** an atomic old-target-SHA check; ref
   update has only a fast-forward flag. Base binding stays UNRESOLVED (DESIGN §5).
3. Signed-receipt binding for the adapter's outcome receipt is **provisionally**
   the existing `mnde.signed-receipt.v2` executor binding — provisional, to be
   confirmed when the live step is designed.

## Decision needed before the live step (not before building the offline units)

- Confirm you will provision the throwaway repo + adapter-only token when we move
  to live measurement. Until then, only the three offline, non-authoritative
  units above are in scope.
