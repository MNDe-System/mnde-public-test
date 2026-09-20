# MNDe EXP-001 — Preflight Report

**Phase:** Preflight (inspection only). No code modified. No remediation. Awaiting approval.
**Do not read this as a result.** Nothing here is a PASS. This records what MNDe
currently *is*, so the experiment can measure it without first changing it.

---

## Headline finding (read this first)

EXP-001 is written as if MNDe performs the GitHub merge and must bind the merge
to repository state. **MNDe does not perform GitHub operations.** MNDe is an
authorization sidecar plus a client-side execution gate:

- The **sidecar** (`mnde-local-sidecar.mjs`, `POST /v1/decisions`) evaluates a
  canonical request against a policy and returns a decision + a receipt.
- The **executor** (`executor/index.mjs`) wraps an arbitrary developer function
  `run()`. It calls `run()` **once**, and only after a receipt is present,
  offline-verified, carries its own signed `ALLOW`, and is bound to the exact
  `(action, parameters, executionId)` the caller submitted
  ([executor/index.mjs:236-266](executor/index.mjs), [315-394](executor/index.mjs)).

There is **no GitHub API call, no `git` primitive, no `sha`-conditional merge,
and no repository-state field anywhere in MNDe** (grep for
`api.github.com|octokit|pulls|/merge|expected_target_sha|source_sha|head_sha`
across `executor/ src/ sidecar/ mnde-local-sidecar.mjs` returns nothing but
comments and tests).

**Consequence for the experiment:** MNDe binds the *declared parameters of an
action* to a signed, single-use, request-bound receipt that gates a *local
function call*. It never observes or enforces *real GitHub repository state*.
Therefore the conjuncts split cleanly:

| Conjunct | Testable about MNDe? | Why |
|---|---|---|
| A Encoding | **Yes** | `canonicalizeJson` / `parseStrictJson` are MNDe code |
| B Completeness | **Yes, and preliminary answer is "incomplete by design"** | MNDe binds declared params, not world state; no expected_target_sha exists |
| C Structural binding | **Yes** | executor param/action binding + sidecar request hash |
| D Freshness | **Yes** | exec-id store + nonce store are MNDe code |
| E Atomic execution / G0 | **No — INCONCLUSIVE by construction** | MNDe performs no mutation; there is no primitive to make conditional |
| Credential boundary | **No — must be built in the harness** | MNDe holds no GitHub credentials |

The race/state tests (§7 source race, §8 target race, §9 TOCTOU, G0) cannot
produce a PASS or FAIL *about MNDe*, because the property they test lives
entirely in the developer's `run()` closure and the GitHub primitive it chooses.
They become tests of **the EXP-001 harness's** execution boundary, not of MNDe.
This must be resolved before building the harness (see "Decision required").

---

## A. Exact MNDe commit under test

```
commit:  9295635b6d92cc448b9fefa8524d1a21e8f0e4d6
branch:  feat/sidecar-graceful-shutdown
subject: feat(sidecar): graceful shutdown with single-deadline drain sequence
tree:    clean except untracked experiments/ (this experiment's own files)
```

The experiment must pin this SHA in every record. Note the tested commit is a
feature branch, not `main`; confirm whether EXP-001 should test this branch or a
`main` commit.

## B. Current execution path (agent request → "mutation")

```
caller → executor.execute({action, input, run})            executor/index.mjs:315
       → askMnde(): POST {sidecarUrl}/v1/decisions           :280-313
           request built by reviewerRequest()                scripts/reviewer-request.mjs
       → sidecar evaluates policy, signs receipt, returns decision+receipt
       → executor persists receipt BEFORE running            :337-343
       → offlineVerify(receiptPath)                          :215-231
       → authorizeExecution(): strict gate                   :236-266
           requires verified ALLOW receipt bound to this exact
           executionId + action + canonical params (+ policy/subject if declared)
       → run()  ← THE ONLY call site of the wrapped function :377-379
```

`run()` is developer code. In EXP-001 it would be "call the GitHub merge API."
MNDe's guarantee ends at "we called `run()` with these authorized parameters."
It does **not** extend to what `run()` does with GitHub or to repo state at that
instant.

## C. Location of authority signing

- Signing adapter is selected at sidecar startup
  ([mnde-local-sidecar.mjs:499-518](mnde-local-sidecar.mjs)).
- **Default (`MNDE_PROFILE=local`, `SIGNING_MODE=legacy`): signing is a no-op
  passthrough** — `signReceiptAdapter = async (receipt) => ({ ok: true, receipt })`
  ([:501](mnde-local-sidecar.mjs)). Receipts are self-asserted, not
  cryptographically signed by an authority key.
- Custody signing (`MNDE_RECEIPT_SIGNING_MODE=custody|external-signer`) loads
  `src/authority-signing/index.mjs` (`signLiveReceipt`) and requires
  `MNDE_KEY_CUSTODY=file-backed-production` under `MNDE_PROFILE=production`
  ([src/authority-signing/preflight.mjs:106-109](src/authority-signing/preflight.mjs)).
- A committed **dev private key** exists at `authority/root_authority_private.pem`
  (must never anchor a real result; clean reproduction must generate its own).

**EXP-001 must declare the exact profile/signing mode it runs under**, because
T008/T011 (tamper / untrusted signer) mean very different things under legacy
no-op signing versus custody signing.

## D. GitHub write credentials — location and loading

**None in MNDe.** MNDe never authenticates to GitHub. Any GitHub token used by
EXP-001 lives in the harness's `run()` closure and is entirely the harness's
responsibility to hold and isolate. This is the central gap the credential-
boundary phase must address, and it cannot be answered by inspecting MNDe.

## E. Current canonical request fields

Built by `reviewerRequest()` (scripts/reviewer-request.mjs) — a reviewer-kit /
GPU-execution shape, **not** a VCS shape:

```
execution_request:
  request_id            ← the executionId (anti-replay handle)
  actor.user_id         ← subject/tester identity
  tool_calls[0].tool    ← the action name
  tool_calls[0].parameters  ← opaque action parameters (where a repo/PR/SHA
                              would have to live, as ordinary strings)
  release_request.execution_id / hold_state / already_consumed
  orbit_intent, resources, execution, runtime_observation, pricing_data
```

A GitHub merge would be modeled as `tool = "github.merge"` with
`{repository, pull_request, source_commit, target_ref, ...}` inside
`parameters`. MNDe binds those **strings** exactly; it assigns them no VCS
meaning and never compares them to GitHub.

## F. Receipt fields relevant to execution identity

`request_hash` (SHA-256 of canonical request), `canonical_request`,
`decision_output.decision` / `decision_hash` / `execution_id`, policy hash/version,
and (custody) a signed envelope `mnde.signed-receipt.v1/v2`. The executor derives
its binding from the verified inner receipt
([executor/index.mjs:98-161](executor/index.mjs)). No repository-state fields
exist in the receipt.

## G. Is source SHA bound?

Only as an **opaque declared parameter string**, if the caller puts it in
`parameters`. MNDe binds the string exactly but never verifies it against the
PR's real head. There is no `source_sha` / `head_sha` concept in MNDe.

## H. Is target ref bound?

Same as G — opaque string only, no ref semantics, no comparison to GitHub.

## I. Is expected target SHA bound?

**No. The field does not exist anywhere in MNDe.** MNDe cannot bind approval to a
target repository state it has no representation of.

## J. Current replay / freshness mechanism

Two layers:

1. **Executor per-call binding** ([executor/index.mjs:251](executor/index.mjs)):
   the receipt's every execution-id-like field must equal the freshly generated
   `executionId`. A captured receipt cannot be replayed through a *new*
   `execute()` call, because that call mints a new id the old receipt won't match.
2. **Sidecar durable dedup** (`sidecar/execution_id_store.mjs`): one file per
   execution id via `openSync(path,"wx")` (O_EXCL, atomic). **Gated on
   `MNDE_EXEC_ID_CACHE` being set — when unset (the default), file-based dedup is
   OFF and only an in-process `Set` dedups, which resets on restart**
   ([execution_id_store.mjs:44-50](sidecar/execution_id_store.mjs)). A separate
   nonce store lives under `nonceDirPath()`
   ([sidecar/auth_authority.mjs:179](sidecar/auth_authority.mjs), dir
   `auth-nonce-cache.d`).

**Preliminary freshness read:** monotonic `Unused→Consumed` holds only when a
durable store is configured *and* not rolled back. With defaults, restart alone
can reopen a consumed id. This is a real thing to test (T009), not a foregone
pass.

## K. Current persistence / rollback domain

All freshness/consumption state is **local filesystem**: the exec-id dir
(`MNDE_EXEC_ID_CACHE`), the nonce dir (`auth-nonce-cache.d` / `grant-nonce-store.d`),
and the append-only receipt ledger. There is **no external/out-of-domain store**.
Restoring or clearing that directory tree reverts `Consumed(n) → Unused(n)`. The
§12 rollback attack therefore has a concrete, plausible target; treat it as a
likely FAIL/INCONCLUSIVE candidate and **preserve evidence before any fix.**

## L. Exact GitHub execution primitive currently used

**None.** MNDe issues no GitHub request. The "execution mechanism" is a
JavaScript function call (`run()`), which has no notion of conditional execution
against remote state.

## M. Preliminary G0 assessment

**INCONCLUSIVE (by construction), trending FAIL for the atomicity claim.** MNDe
provides no primitive that makes a mutation conditional on authorized repository
state, because MNDe performs no mutation. The window between `authorizeExecution`
returning ok ([:355](executor/index.mjs)) and `run()` ([:379](executor/index.mjs))
is an unconstrained TOCTOU gap that MNDe has no mechanism to close. Whether the
*real* merge is safe depends entirely on the harness's chosen GitHub primitive
(e.g. the merge API `sha` parameter). Any PASS obtained there is a statement
about GitHub, not about MNDe — and EXP-001 must label it that way.

## N. Obvious alternate credential path around MNDe

Because MNDe holds no GitHub credentials and does not gate the network, **the
entire question of bypass resistance is a property of the harness, not of MNDe.**
If the harness's agent process can read the GitHub token that `run()` uses (env
var, file, git credential helper, inherited process env), it merges without ever
calling MNDe and the binding is irrelevant. Additionally, the committed
`authority/root_authority_private.pem` means anyone with the repo can mint
"authority" signatures under legacy/dev posture. Both must be designed out in the
harness (separate processes, token held only by the executor process, custody
signing), and the design itself is what the credential-boundary phase tests.

## O. Proposed harness files (nothing created yet)

```
experiments/exp-001/
  README.md            purpose, scope, how to run
  SPEC.md              formal model + five conjuncts (draft already written: FORMAL-MODEL.md)
  THREAT-MODEL.md      roles, trust assumptions, what is in/out of MNDe's boundary
  PRECONDITIONS.md     profile/signing mode, env, credential placement, G0 decision
  environment/         pinned commit, node version, env manifest, key generation script
  fixtures/            canonical requests, sample policy, test PR/repo descriptors
  harness/             agent / authority(sidecar) / executor process wiring,
                       and the GitHub `run()` closure + its conditional-merge primitive
  attacks/             one script per test (C001, T001-T011, races, rollback, injection)
  evidence/            independent GitHub state snapshots, sidecar logs, receipts
  receipts/            captured receipts per test
  verifier/            offline receipt verifier invocation + independent checks
  results.json         machine record, per-test
  RESULTS.md           per-conjunct human report
  FINDINGS.md          one entry per discovered issue
```

## P. Parts of the spec that cannot currently be tested as written, and why

1. **G0 / source race (§7) / target race (§8) / TOCTOU (§9):** MNDe has no
   GitHub primitive and no repo-state binding (items H, I, L, M). These cannot
   PASS/FAIL about MNDe. Options in "Decision required" below.
2. **Completeness re: `expected_target_sha` (§B):** the field does not exist
   (item I); the honest result is a documented *completeness gap*, not a mutation
   test. This is arguably the most important true finding available and should be
   reported as such rather than forced into an INCONCLUSIVE bucket.
3. **Credential boundary / bypass (§10):** not a property of MNDe (items D, N);
   testable only against a harness we have not yet designed.
4. **T008 / T011 signature tests:** meaningful only under a declared signing
   posture; under the default legacy no-op signer (item C) they test almost
   nothing. Requires choosing custody mode for a meaningful run.
5. **Independent GitHub evidence (§ evidence rules):** requires a real throwaway
   GitHub repo + token provisioned by the operator; cannot be done from
   inspection and needs explicit authorization and credentials outside this repo.

---

## Decision required before building the harness

The experiment's most important tests assume MNDe binds and enforces GitHub
repository state. It does not. Choose the framing before any code is written:

1. **Test MNDe's actual claim only.** Scope EXP-001 to what MNDe guarantees:
   exact binding of declared action+params to a verified, request-bound,
   single-use receipt gating a local call (conjuncts A, C, D testable; B reported
   as a documented completeness gap; E and credential boundary reported as
   out-of-scope-for-MNDe with rationale). Cleanest, most honest, no GitHub needed.
2. **Build the missing execution boundary in the harness and test the whole
   chain.** Have the executor's `run()` use the GitHub merge `sha`-conditional
   primitive, hold the token in the executor process only, and run the full
   race/rollback/bypass matrix — clearly labeling which results are about MNDe
   versus about the harness/GitHub. More work; needs a real test repo + token;
   risks attributing GitHub's behavior to MNDe if not carefully labeled.
3. **Both, staged:** run (1) now as the baseline evidence package, then (2) as a
   follow-on that explicitly tests the harness-supplied boundary.

I recommend **(3): run (1) first.** It measures what MNDe actually claims,
surfaces the real findings (the completeness gap at I, the default-off dedup at
J, the local-only rollback domain at K, the legacy no-op signer at C), and does
not require live GitHub credentials or risk misattributing GitHub semantics to
MNDe. Then decide on (2).

**No code will be written and no test run until this framing is approved.**
