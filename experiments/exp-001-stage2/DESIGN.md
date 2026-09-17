# MNDe EXP-001 Stage 2 — Design

**Status:** Design only. No harness, no MNDe source changes, no remediation yet.
**Baseline invariant:** `experiments/exp-001/` and the tag `exp-001-stage1-baseline`
(`3368126`) stay byte-for-byte unchanged. Stage 2 lives in this sibling
directory. F-001 / F-002 are handled as *separate* freshness work (see §8), never
by editing the baseline.

Stage 1 established what MNDe proves today: **approved declaration ⇒ gated
`run()` on the exact declared parameters.** It does not prove the external effect
matched the declaration (finding F-003). Stage 2 designs the layer that closes
that gap.

---

## 1. The narrow claim

> **An approval for a specific effect, against observed external state, cannot
> authorize a different effect.**

"Effect" and "observed external state" are the two words Stage 1 could not test,
because MNDe performs no external mutation and has no representation of external
state. Stage 2 introduces both — as a **GitHub execution adapter** downstream of
the existing executor gate — and tries to falsify the claim against a real
throwaway repository.

## 2. Formalization (extending the Stage-1 model)

Stage 1 bound a declared action vector `A = [r, p, s, t, o, e]`. Stage 2 requires
the declaration to also carry the **expected external preconditions** so the
authorization identity includes the state it was granted against:

```
A⁺ = [ r, p, s, t, o, e,  expected_source_sha, expected_target_sha ]
```

The five-conjunct property from `FORMAL-MODEL.md` maps onto Stage 2 like this:

| Conjunct | Stage 1 status | Stage 2 obligation |
|---|---|---|
| A encoding | PASS | unchanged; new coords are opaque hex strings under exact equality |
| B completeness | boundary (F-003) | **close it**: `expected_source_sha`, `expected_target_sha` become bound coordinates of `A⁺` |
| C structural binding | PASS | unchanged executor gate; extends to the new coords for free (hash-bound) |
| D freshness | 2 findings | F-001/F-002 fixed separately (durable, fail-closed); NOT anchored by the merge effect — see §8 correction |
| E atomic execution / **G0** | deferred | **the core of Stage 2**: adapter performs `enc⁻¹(A⁺)` conditionally on observed state, atomically |

The claim holds iff: the declaration binds `A⁺` (B+C, already true for declared
strings), **and** the adapter refuses to mutate unless observed external state
still equals the bound `expected_*` (E/G0), **and** the resulting receipt is tied
to the *observed* outcome, not merely the declared intent.

## 3. Architecture

```
 Agent ──▶ MNDe authority (sidecar) ──▶ MNDe executor gate ──▶ GitHub adapter ──▶ GitHub
  │            issues receipt bound        Stage-1 strict         NEW: conditional      real
  holds        to A⁺ (incl. expected_*)    gate (unchanged)       mutation + outcome    repo
  NO creds                                                        receipt
```

- **Reuse unchanged:** the sidecar decision path, receipt signing/verification,
  and the executor's strict request-binding gate. Stage 2 adds exactly one new
  trusted component — the **adapter** — as the `run()` implementation.
- **The adapter is the only holder of GitHub write credentials.** It receives a
  verified, request-bound receipt, reads the *authenticated* `A⁺` from the
  receipt's `canonical_request`, and performs a mutation that is **conditional on
  the bound expected state**.
- **Provider-agnostic MNDe, provider-specific enforcement.** MNDe binds the
  *declaration* of expected state (it is part of the signed authorization
  identity). The adapter *enforces* it at mutation time using GitHub's own
  state-conditional primitives. This is the answer to the open design question
  from Stage 1: declaration-of-state lives in MNDe; enforcement-of-state lives in
  the adapter. MNDe stays clean; G0 becomes an adapter+provider property.

## 4. Binding chain (how a declaration becomes a bound effect)

```
approved declaration A⁺
  │  (already bound: request_hash over canonical A⁺, verified receipt — Stage 1)
  ▼
cryptographically bound execution request
  │  adapter reads authenticated expected_source_sha / expected_target_sha
  ▼
conditional external mutation
  │  GitHub merge issued ONLY if live head == expected_source_sha
  │  (and, to the degree the provider allows, live base == expected_target_sha)
  ▼
verifiable receipt tied to observed outcome
     adapter records the OBSERVED result (merge commit sha, new base sha, HTTP
     status) and signs an execution-outcome receipt binding A⁺-hash ⇄ observed
     state. Verification compares declared-vs-observed, not declared-vs-declared.
```

The last step is what upgrades Stage 1's *"we called run() with these params"*
to *"the external effect that occurred matched the authorized declaration, and
here is the evidence."*

## 5. G0 — does GitHub enforce expected state at mutation? (run FIRST)

G0 is the feasibility gate: if the provider cannot make the mutation conditional
on `A⁺`'s expected state, the race tests are INCONCLUSIVE by construction (Stage 1
preflight, item M). Establish empirically, per state dimension:

- **Source / PR head binding — expected strong.** `PUT /repos/{owner}/{repo}/pulls/{n}/merge`
  accepts an optional `sha` (the PR head the caller expects); GitHub rejects the
  merge if the head has moved. Predicted **G0-source = PASS**, to be *confirmed*
  empirically — never inferred. This directly defeats the §7 source race: bind
  `sha = expected_source_sha`.
- **Target / base state binding — the hard case, treated as UNRESOLVED.** The
  merge API has no "expected base sha" parameter, and GitHub's REST update-a-
  reference API offers only a **fast-forward check**, *no expected-old-SHA
  compare-and-swap*. The `POST .../merges` (merge-a-branch) + subsequent ref
  update route does **not** give an atomic check of the old target SHA either;
  it is a **hypothesis to test, not a mechanism already established**. So
  base/target-state binding is recorded as **UNRESOLVED** and is out of scope for
  the first probe (§10.1 decision = (a): measure source, leave base unresolved).
  Docs: merge-a-PR, merge-a-branch, update-a-reference.
- **Lean on prior empirical work, do not re-derive.** The retarget-race live
  result (2026-09-15, positive provider-control; bare update rule, admins not
  auto-exempt, unauthenticated CDN cache) is the substrate for base-state
  behavior and provider-side race semantics. G0 cites it rather than repeating it.

G0 result states remain PASS / FAIL / INCONCLUSIVE per dimension; a partial G0
(source-yes, base-inconclusive) is reported as such and scopes which race tests
can conclude.

## 6. Credential boundary (must be frozen before the matrix)

The whole claim is vacuous if the agent can mutate GitHub without the adapter.
Design:

- **Three OS processes**, not one: agent, sidecar (authority), adapter+executor.
- The **GitHub token exists only in the adapter process's environment**, never in
  the agent's env, files, git credential helper, or inherited process env.
- The agent's only path to a mutation is: submit a declaration to the sidecar →
  receive nothing actionable itself → the adapter (holding the token) acts on a
  verified receipt. The bypass matrix (direct REST, GraphQL, `git push`, `gh`
  CLI, credential reuse, calling adapter internals) must all fail for the agent.
- This is an *infrastructure* property; it is proven by process/credential
  isolation evidence, not by application-level asserts. Freeze and document it as
  a precondition (Stage-1 preflight, item N).

## 7. Stage 2 test matrix (what falsification looks like)

Predetermined semantics, three-state results, per conjunct — never a single
score. Run order fails cheap (G0 → credential boundary → control → races →
outcome-receipt):

| Test | Attack | PASS = |
|---|---|---|
| G0-source | merge with stale `sha` | GitHub rejects (head moved) |
| G0-base | advance base under a stale expected base | provider rejects, or documented INCONCLUSIVE |
| C2-control | authorized merge, state unchanged | merges; outcome receipt matches A⁺ |
| §7 source race | move PR head after approval, execute old auth | REFUSE / provider-reject; no merge of the new head |
| §8 target race | move base after approval, execute old auth | reject, or INCONCLUSIVE per G0-base |
| §9 TOCTOU | force state change between gate and mutation | conditional primitive prevents the invalid transition (evidence, not "couldn't reproduce") |
| bypass ×6 | agent mutates without a receipt | every path fails |
| outcome-receipt | tamper the observed-state binding | verification detects declared≠observed |

Independent GitHub evidence (API state, refs, PR head/base, merge commit) is
captured before and after every attempt — MNDe's own logs are never the sole
proof (Stage-1 preflight, evidence rules).

## 8. F-001 and F-002 — separate freshness work (NOT baseline edits)

Per instruction, these are addressed as their own freshness failures, on their
own branches, each **preserving the Stage-1 failing test as a regression test**;
the `27/2/1` baseline stays as-is.

- **F-001 (durable dedup off by default).** Fix: under a production profile,
  require a durable execution-id store and **fail closed at startup** if
  unconfigured. Regression: the D4 scenario must flip `ALLOW → REFUSE` under the
  production profile while the Stage-1 test still records the *default-posture*
  failure it captured.
- **F-002 (rollback reverts Consumed→Unused).** Fix: anchor freshness outside
  MNDe's rollback domain with its **own durable, fail-closed** solution
  (append-only external log or a monotonic counter service whose state is not in
  MNDe's rollback domain). **Correction (retraction of an earlier claim):** a
  successful GitHub merge does **not** provide this anchor. The merge `sha`
  parameter checks the PR head *at merge time*; the docs do not say a successful
  merge changes that head, so a completed merge cannot be relied on to make a
  replay fail. Stage 2's conditional execution binds the *effect*, but it does
  **not** harden D — F-002 remains an independent freshness problem and must be
  solved on its own terms, not as a side effect of the adapter.

## 9. Scope guards (what Stage 2 still will NOT prove)

Host compromise, GitHub infrastructure compromise, authority-key theft, adapter-
host compromise, production readiness, or universal security. A Stage 2 PASS is
bounded to: *under the tested GitHub primitives and threat assumptions, an
authorization bound to effect X against observed state S₀ did not authorize a
different effect Y or an execution against a different state S₁, for the
conjuncts marked PASS.*

## 10. Open decisions for you

1. **Target-state binding ambition.** If G0-base comes back INCONCLUSIVE (likely,
   given the REST CAS gap), do we (a) accept source-only binding + documented
   base-race INCONCLUSIVE for v1, or (b) invest in the `POST .../merges` +
   conditional-ref-advance mechanism to try for base binding too? (Recommend (a)
   first — ship the honest source-bound result, then attempt (b).)
2. **Where the outcome receipt is anchored.** Adapter-signed under the existing
   custody chain, or a distinct executor-credential (Stage-1 already supports
   `mnde.signed-receipt.v2` executor binding)? (Recommend reusing v2 executor
   binding — it already exists and isolates the adapter's authority.)
3. **Live-repo logistics.** Stage 2 needs a throwaway GitHub repo + a scoped token
   held only by the adapter process. That requires you to provision both;
   Claude will not hold or place the token.

**Nothing is built until you pick a direction on §10.1 and confirm §10.3.**
