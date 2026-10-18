# 10 · Top ten Git push improvements, decisions, and a 30-day plan

Evidence tags are defined in [00-README.md](00-README.md). Effort figures are my estimates
for one engineer familiar with the codebase, **excluding waiting on people and
infrastructure**, and are not commitments. Every change carries the tests it would need.
Dates assume work starts Monday 2026-10-19.

## 1. Top ten improvements to MNDe's Git push path

Ordered by expected long-term return. "Core" means it strengthens a signed claim or closes
a bypass; the others improve operation or adoption.

| # | Improvement | Impact | Difficulty | Risk | Depends on | Effort | Core? | Tests it needs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | **Run the operated F-001 proof**: agent/credential separation, independent claim database, approver on separate hardware (R2–R4 in `NEXT-MILESTONES.md`). Not code | Highest: it is the difference between "designed" and "demonstrated" | Medium (logistics) | Medium: the final push is permanent | An independent DB operator; a non-admin agent identity; a GitHub App installation | 3–5 days of work spread over ≥1–2 calendar weeks | Core | Existing protocol; collector exits 0; offline verification; GitHub activity record matches |
| 2 | **Fix repository-identity canonicalization and make the validator never throw** (N1–N3): include the port, reject percent-escapes of `/` and control bytes, return a refusal for malformed escapes | Medium | Low | Low, but it changes what identity strings approvals bind: needs a versioned identity or an additive rule so historical receipts still replay | Decision on compatibility (ledger/replay) | 1–2 days | Core | `lab/identity-probe.mjs` cases as regression tests; a fuzz corpus; a test that an old receipt with an old-style identity still verifies |
| 3 | **`doctor`: one command that answers "can the agent push without MNDe, and is the ruleset exclusive?"** by merging `check-agent-environment` and `check-repository-controls` into a supported, documented tool | High: tests the premise and is the five-minute demo | Low (scripts exist) | Low | None | 2–3 days | Core (verifies exclusivity) | Exit 1 on admin token in env; exit 0 with App-only; ruleset with a human bypass actor → exit 1; no secret values in output |
| 4 | **Unaccounted-push detector**, read-only: list host push events for protected refs and join them to executed authorizations; alert on any push MNDe did not perform | High: the only continuous check of the central claim | Medium | Low (read-only), medium for API drift | #3's host-API plumbing | 4–6 days | Core | A planted out-of-band push on a throwaway branch is flagged; an MNDe push is matched by `(ref, old, new)`; clock-skew tolerance; pagination |
| 5 | **Action-bound approval preview**: render, from the signed SHAs and the local object store, the commit list, file list, and flags for workflow/lockfile/hook/submodule/binary/size changes; sign a digest of the rendering so the approver's view is part of the receipt | High: makes the human half of "exact action" real | Medium | Low: additive optional field | None; benefits from #2 | 5–8 days | Core (preview), convenience (flags) | Byte-reproducible render across machines; workflow change always flagged; digest mismatch refuses; golden files |
| 6 | **Make recovery state trustworthy**: sign (or MAC with the executor key) the start record and verify it in `classifyGitPushExecution` (N5) | Medium | Low–medium | Low | Executor identity (exists) | 2–3 days | Core | Tampered start record is `UNTRUSTED`, never `NOT_STARTED`; legacy unsigned records handled explicitly |
| 7 | **Spend authority only after write-ability is proven**, and size-aware timeouts (N6, N7): probe write access through the receive-pack advertisement (a `--dry-run`-style contact), and scale the 30 s timeout with pack size | Medium (operational) | Medium | Medium: touches the claim ordering, which "must never be reordered" per the code comment; the probe must be before the claim and add no effect | A measurement from X07 first | 2–3 days after X07 | Convenience, protects against burned approvals | Permission change between approval and push does not spend the grant; probe failure sends nothing; ordering test unchanged |
| 8 | **Name the credential in signed evidence** (kind, repository scope, expiry, App id) (C6/O9) | Medium | Low | Medium: evidence schema change | Schema versioning decision | 2 days | Core | Evidence verifies offline; old evidence still verifies; credential secret never present |
| 9 | **Close the Git LFS gap** (N8): immediately, document it in `KNOWN-ISSUES.md`; then refuse pushes whose range changes LFS-tracked paths; later, upload LFS objects inside the executor | Medium for LFS repos | Low (document/refuse), high (upload) | Low | `[L31]` result | 0.5 d doc, 1 d refuse, 4–5 d upload | Core correctness | A repo with LFS-tracked changes is refused with a named code; non-LFS unaffected |
| 10 | **Reconciler for `INDETERMINATE`**: read-only join of claim row, signed start record, remote ref; one verdict with next steps; optionally emits a signed reconciliation record | Medium | Medium | Low | #1's real cases; #6 | 3–5 days | Core (recovery) | Each of the four outcomes + both crash windows; never suggests a retry of a spent authority |

### Not on the list on purpose

Branch-create and PR-open effects (more coverage, but "doubles the surface that was never
operated"); the claim-store witness (decide after #1 quantifies Q6); server-side
`pre-receive` verifier and CI-status-check gate (spikes, not builds); AI risk scoring,
secret scanning, hook frameworks (see [09](09-prioritized-findings.md)).

## 2. Decisions with competing options

### Decision 1: where should "only approved pushes land" be enforced?

| Option | Benefits | Downsides | Long-term consequences | Recommendation |
| --- | --- | --- | --- | --- |
| **A. Credential custody** (executor alone holds the push credential; today's design) | Strongest *if* exclusive; works with any host; matches the sandbox-broker pattern `[S]` | Exclusivity is a host property MNDe cannot see; the assessed environment's agent held an admin token; admin can edit rulesets | Needs continuous verification (#3, #4) to stay honest | **Keep, but never claim exclusivity without #3/#4 output** |
| **B. Merge-time gate**: MNDe posts a required status check only when a valid receipt exists for the PR head SHA | No custody change; the host enforces; low adoption friction | Moves the control from push to merge; pushing a branch is no longer gated; semantics unverified here `[H]` | Fits agent PR flows (agents already work on branches); competes less with the host | **Spike before deciding** (week 4) |
| **C. Server-side `pre-receive` verifier** on self-hosted forges | The host itself enforces; hardest to bypass | Unavailable on GitHub.com; heavy to operate | Niche but strong | **Park**; revisit with a self-hosted design partner |
| **D. Client-side hooks / harness rules only** | Free, fast | Bypassable `[L18]`; reported to fail open `[S: C06 C14]` | Cannot support an audit claim | **Reject as enforcement**; fine as advisory |

### Decision 2: single-use claim strictness for `git.push`

| Option | Benefits | Downsides | Long-term | Recommendation |
| --- | --- | --- | --- | --- |
| **Claim-before-effect, never retry** (today) | Safe against replay when the remote returns to the approved old state or is restored | Burns authority on transient failures; every retry costs a human approval | Teaches users to approve loosely | **Keep as the default** (the repository's stated trade) |
| Claim-on-success only | Fewer burned approvals | Re-opens the ambiguous-outcome replay F-001 names | Weakens the thesis | **Reject** |
| Rely on the lease alone | No database to run | Git's lease makes replay of a *fast-forward* harmless unless the remote is restored to the old SHA `[L25][L27]`; fails exactly where F-001 says it matters | Loses the "single-use" claim | **Reject for the claim; note honestly that for `git.push` specifically the lease already blocks most replays, so the claim store's marginal value is restore/reset scenarios and the template for non-idempotent effects** |

A point worth stating plainly: **`git push` is close to the least favorable showcase for a
durable single-use store**, because Git already offers an atomic compare-and-swap that makes
a replayed fast-forward fail on its own. The store earns its keep on effects that lack such
a primitive. If `git.push` remains the only effect for long, the operational cost of an
independently administered PostgreSQL (the repository's own words: "the honest price of the
single-use guarantee") may exceed the benefit for push alone. That is a business-premise
concern, not a flaw in the engineering.

## 3. Thirty-day plan (2026-10-19 → 2026-11-17)

Each week ends with something verifiable by someone who did not write it.

### Week 1 (Oct 19–25): make the foundation honest and cheap to verify

* Run the entire suite on **Node 24** (the repo's declared runtime) and record the result;
  this research ran on Node 22 without `npm ci`, so case N of the CLI suite is unverified here.
* Land improvement **#2** (identity canonicalization, validator never throws) with the
  probe cases as tests and a short fuzz corpus; confirm historical receipts still verify.
* Add the LFS caveat (**#9, docs part**) to `KNOWN-ISSUES.md`; run **X11** to settle the
  downstream effect.
* Start the logistics for **#1** (name an independent DB operator; create the non-admin agent
  identity). This is the long pole.

*Exit check:* suite green on Node 24; every `lab/identity-probe.mjs` case returns a stable
identity or a refusal; no historical-replay regression.

### Week 2 (Oct 26–Nov 1): the five-minute demo

* Ship **#3** (`doctor`). Run it in the F-001 environment, record the failing exit with
  the admin token, remove the token, record the passing exit.
* Run **X02** (many-writer soak) and **X12** (fuzz) locally.
* Draft the schema notes for **#6** and **#8** (additive, versioned).

*Exit check:* a stranger can run one command in a repo and see, in under five minutes, whether
an agent there can push without MNDe. Demo script committed.

### Week 3 (Nov 2–8): independent checks and the human view

* Build **#4** read-only against the proof repository. Validate with two pushes on a
  throwaway branch under the F-001 protocol: one through the executor, one deliberately
  out-of-band by an authorized human. The detector must flag only the second.
* Prototype **#5** (preview) with golden-file tests; run it on three real diffs including a
  workflow change.
* Implement **#6** (signed/verified start record).

*Exit check:* the detector's flag appears with the correct actor and SHAs; preview output is
byte-identical on two machines.

### Week 4 (Nov 9–15): operate it, and test the premise with people

* Run the **operated F-001 proof (#1)** if the independent operator is ready; otherwise
  record exactly what is blocking, and do not claim progress.
* Spike **Decision 1, option B** (merge-time gate) on the proof repository.
* Run **X07** to measure how often permission/protection refusals burn authority; decide **#7**.
* **Talk to at least five teams** that run coding agents with push access. Ask what they do today,
  what incident (if any) they had, whether they would put an approval step with a separate
  device in front of agent pushes, and who pays. The single biggest hole in this research is
  that it contains no demand evidence.

*Exit check:* the operated run's collector output and offline verification exist, or the
blocker is named; the interview notes exist.

### Validation and kill criteria (proposals, not evidence)

| Signal | Continue if | Reconsider if |
| --- | --- | --- |
| `doctor` finds a push-capable credential in a real agent environment | It does in ≥ half of the environments tried | It finds none anywhere: the problem may be solved by existing practice |
| Detector flags real unaccounted pushes | It flags at least one real out-of-band push in a design-partner repo | Zero in all tried repos and no partner can name an incident |
| Interviews | Most teams would route agent pushes through an approval step, and one names a budget | Teams prefer rulesets + App tokens and see no need for per-push approval |
| Operated proof | Collector verifies; direct push from the agent identity is denied | Exclusivity cannot be demonstrated in a realistic topology |

If the interviews and the operated proof both come back weak, the defensible fallback is the
**evidence and monitoring layer** (receipts, read-back, `doctor`, detector) on top of the host's
own rules, rather than a custody-and-approval gateway.

## 4. Three explicit answers

**1. What are developers most frustrated by when pushing code?**
In this sample, two things, with low-to-moderate confidence (the sample is small, second-hand
and query-biased): **opaque rejections and errors** (`fetch first`, "remote end hung up
unexpectedly", `GH006`/`GH013`, large-file and LFS failures, hook declines that do not name a
rule), and, newest and sharpest, **agents that push or force-push against written
instructions**. I could not measure frequency. Human complaints are about diagnosis; agent
complaints are about control.

**2. What problems remain unsolved or poorly solved by current tools?**
(a) Knowing the true outcome of an interrupted push, and whether *your* attempt caused it:
the server finishes after the client dies `[L12]`, the client reports nothing, and a retry
prints `Everything up-to-date`. (b) Approval bound to an exact `{repo, ref, old, new}` state
and verifiable by a third party; existing controls authorize command patterns or branch names.
(c) Continuous proof that no other push path exists. (d) Enforcement an agent cannot defeat
when the control shares its process (hook and permission bypasses were reported). (e) Quiet
footguns that remain the default or opt-in only: bare `--force-with-lease` defeated by
auto-fetch `[L3]`, `--no-verify` silently skipping LFS upload `[L31]`.

**3. What unique and defensible Git push safety capability should MNDe own?**
**Verifiable push accountability**: an independent, offline-checkable chain from a *separate
human's approval of one exact state transition* to a *signed read-back of the remote result*,
plus a continuous monitor that shows there were no pushes outside that chain. Not "blocking
agents" (a ruleset and a scoped token already do that more cheaply), not secret scanning, not
a generic approval gateway. The honest caveat: this is defensible only if (i) the operated,
independent proof succeeds, (ii) the receipt format is neutral enough that third parties
verify it without trusting MNDe, and (iii) real buyers value being able to *prove* what was
approved and what happened. None of the three is established today, and a host could
ship signed push outcomes itself. Today it is a well-engineered design whose moat is untested.
