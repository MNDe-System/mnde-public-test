# The approval gate

What a human actually approves when MNDe maintains itself, and what the code
enforces on its own.

This describes the repository as it is at `main` (fc46936), not as the README or
the roadmap describes it. Every claim below names the file that backs it. Where
the code does not enforce what a reader would expect, it says so under
[What the code does not enforce](#what-the-code-does-not-enforce).

Claims about repository settings — branch protection, required checks,
environments — cannot be read from the repository. Those were read from the
GitHub API on 2026-09-21 and are dated where they appear, because unlike
everything else here they can change without a commit.

---

## The short version

There are exactly two places a human says yes:

1. **Merging a pull request into `main`.** This is where a change to MNDe enters
   the product.
2. **Approving the `release` environment.** This is where a change leaves the
   repository and reaches the outside world as a tagged, published release.

Everything else — branches, draft pull requests, CI runs, test output, receipts,
this document — happens without a human and changes nothing outside the
repository.

**MNDe's own authorization gate is not what guards MNDe.** The executor, the
signed receipts and the freshness claim protect *callers of MNDe*. Nothing in
this repository produces a receipt for "merge this pull request". The
self-maintenance loop is gated by GitHub settings, not by MNDe. That is a
deliberate description of the present state, not a criticism of it, but it
matters for any claim that MNDe approves its own changes.

---

## What MNDe proposes

A branch and a draft pull request. That is the whole proposal surface.

What the code allows it to be:

- Work lands on a branch (`claude/*` by convention). `main` carries a ruleset
  that requires a passing `Guardrails` check and one approving review before a
  merge — read from the API on 2026-09-21, and outside the repository, so see
  [item 5](#5-the-merge-gate-lives-outside-the-repository) for what that does
  and does not settle.
- `.github/workflows/ci.yml` declares `permissions: contents: read`. No CI job
  in this repository can push a commit, move a tag, or publish anything.
- The only job anywhere with write access is the `publish` job in
  `.github/workflows/release.yml`, and it is behind the approval gate described
  below.

So the worst outcome of an unreviewed proposal is a branch nobody merged.

---

## What evidence the human sees

Per pull request, CI runs two jobs on `windows-latest`
(`.github/workflows/ci.yml`):

| Job | Required to merge? | What it proves |
| --- | --- | --- |
| **Guardrails** | Yes | `npm test` runs *every* `test:*` script; the reviewer kit runs its ALLOW and REFUSE demos; whitespace, replay verification and the conformance freeze all pass |
| **Release contract** | No | version drift, a real release build with checksums, then pack / install into a clean project / run outside the repository / prove fail-closed / uninstall |

The distinction is worth stating plainly, because the two ticks look identical
in the pull request UI. As of 2026-09-21 the `main` ruleset names exactly one
required check, `Guardrails`. **`Release contract` runs, reports, and does not
block a merge.** A reviewer who merges on "CI is green" without looking at which
job is red can merge a change that broke packaging, installation, or the
fail-closed behaviour the release path depends on.

Two things make that evidence harder to fake than a passing tick usually is:

- `scripts/run-all-tests.mjs` cross-checks `package.json` against
  `tests/expected-test-scripts.json` and fails if they differ. A suite cannot be
  quietly deleted to make the build green — removing it makes the run fail.
- `tests/test_ci_contract.mjs` asserts the workflows themselves: the pinned
  action SHAs, the read-only permissions, the `release` environment on the
  publish job, and the digest re-check. A pull request that weakens the gate
  fails the suite that describes the gate.

Beyond CI, the reviewer sees the diff. That is it. There is no generated summary,
no risk score, and no signed artifact describing the change.

---

## What a yes authorizes

### Yes to a merge

The commits become `main`. Nothing else happens. In particular, merging cannot:

- publish, tag or release anything — that needs a separate, separately approved
  workflow dispatch;
- enable execution. `src/execution-availability/index.mjs` holds
  `const DISPATCH_ENABLED = false` as a hard-coded constant, not a feature flag.
  There is no environment variable and no caller option that flips it. Turning
  execution on is a reviewed code change that also has to satisfy the freshness
  suite.

### Yes to a release

The `publish` job (`.github/workflows/release.yml`) starts. Only then does it
hold `contents: write`, `id-token: write` and `attestations: write`. Before it
touches anything outward-facing it:

- checks out the exact commit that was built, not the branch head, which may
  have moved while the run waited for the approval;
- re-derives the artifact digests and compares them against the ones recorded
  before approval, so the thing published is the thing approved;
- attests build provenance, tags at the built commit, and publishes.

The build job refuses to build at all unless the `release` environment really
has a required-reviewer rule. `build/release-publication.mjs`
(`verify-approval-gate`) reads the environment over the API and fails on 404 or
on any non-OK response, because naming an environment in a workflow is not a gate
by itself — with no reviewer configured, the job would simply run.

---

## What a no does

Nothing. That is the point.

No is the default state of every proposal, and it is reached by inaction:

- An unmerged pull request stays unmerged. There is no timeout that merges it,
  no retry, and no escalation path.
- An unapproved release run stops at the `publish` job. The build job that ran
  before it was read-only and produced an artifact that goes nowhere.
- There is no scheduled job, cron trigger or routine that drives MNDe's
  maintenance. Every change in this loop starts with a person asking for one.

---

## What MNDe is never allowed to do without a yes

These are enforced in code, not by convention:

**Turn an ALLOW into a real effect.** `executor/index.mjs` is the enforcement
point. `execute()` calls the sidecar, persists the receipt, verifies it offline,
and runs the strict gate — the receipt must verify, its *own signed* decision
must be ALLOW, and it must be bound to the exact execution id, action and
parameters submitted. Then, having passed all of that, it returns REFUSE with
`ERR_FRESHNESS_DEPLOYMENT_DISABLED` and never calls the supplied function. The
reason is F-001: a verified receipt is a signature, and a signature can be
presented twice. `wrapTool()` routes through the same `execute()`, so there is no
second path.

**Publish or tag.** Only the approval-gated `publish` job has `contents: write`.

**Re-enable itself.** See the hard-coded constant above. The comment in
`executor/index.mjs` is explicit that deleting the final `return` does not
produce an executor — it produces an undefined result and a failing freshness
suite.

---

## What the code does not enforce

Ordered by how much it matters.

### 1. A policy can require approval and be silently ignored

`src/policy-engine/index.mjs` gates a rule's `approval_required` on approval
trust anchors being configured:

```js
const approvalEnforced = Boolean(approvalTrustAnchors);
```

Anchors arrive from one place — `MNDE_PE_APPROVAL_TRUST_ANCHORS`
(`src/policy-engine/sidecar-adapter.mjs`). **If that variable is unset, every
`approval_required` in the policy has no effect and the request is allowed.** The
receipt carries no `approval_enforced` field, so the omission is visible to
someone who knows to look for it, but the decision itself is an unqualified
ALLOW.

This is documented in the source as deliberately inert. It is still a
configuration-dependent fail-open on the one field whose entire purpose is to
stop an action until a human signs off. A policy author who writes
`approval_required: 1` will not expect a missing environment variable to delete
it.

*Suggested fix:* refuse to load a policy that declares `approval_required` when
no approval trust anchors are configured. Fail closed at startup, where an
operator sees it, rather than per-decision, where nobody does.

### 2. An approval is not necessarily single-use, or bound to one request

In `src/policy-engine/authenticated-approvals.mjs`, an approval's scope is
checked like this:

- `scope.request_id` is **optional**. If it is absent, the approval is not bound
  to any particular request.
- `scope.tool_name` of `"*"` matches every tool.
- Nothing marks an approval as spent.

So a signed approval scoped to `{ tool_name: "deploy_update" }` authorizes every
matching request until `expires_at` — and one scoped to `{ tool_name: "*" }`
authorizes everything. That is the same replay shape as F-001, one layer up from
the executor, and the freshness claim does not cover it because the claim is
derived from the execution authority, not from the approval.

*Suggested fix:* require `scope.request_id` when the deployment is in production
posture, and record approval ids in the same durable claim store the executor
will use.

### 3. The single-use claim is experiment code and has never run against a database

The claim is the thing that would make an approval safe to act on once. Today:

- The claim logic — `deriveClaimRecord()` and `claimAuthority()` — lives in
  `experiments/exp-001-stage2/src/freshness.mjs`. It is imported only by tests
  and by `tests/support/offline_freshness_adapter.mjs`, which is test-only.
- `src/freshness/` contains exactly one file, the unwired PostgreSQL backend.
  Nothing outside tests imports it.
- `deployment/freshness/postgres.sql` has not been applied anywhere.
- `docs/FRESHNESS-BOUNDARY-AUDIT.md` marks the deployment race/rollback/failure
  test **NOT RUN**.

"The executor cannot spend the same authority twice" is therefore a design with
unit tests behind it, not a demonstrated property of a deployment.

### 4. The release approval gate has never been exercised

The verification code is sound and fails closed. But the `release` GitHub
Environment has not been created, so the release workflow has never completed a
run, and the `verify-approval-gate` call has never been answered by a real
environment. Until that environment exists with the owner as required reviewer,
the release half of this document describes code, not a working gate.

There is also a structural limit worth naming: `verify-approval-gate` runs inside
the same workflow it is checking, using that workflow's token. What keeps it
honest is `tests/test_ci_contract.mjs`, which is a test in the same repository. A
pull request that changed both would have to get past the human reviewer — which
is the gate this document is about, and is the gate that has no code behind it.

### 5. The merge gate lives outside the repository

The rules themselves are now known. Read from the GitHub API on 2026-09-21, the
`main protection` ruleset requires:

- a passing check run named exactly **`Guardrails`**, from integration 15368;
- **strict** status checks, so the branch must be up to date with `main` before
  it merges;
- **one approving review**;
- **stale-review dismissal on push**, so a new commit drops the approval it was
  not given for;
- **all review threads resolved**.

It lists **no bypass actors**. `Release contract` runs but is not a required
check.

That is stronger than this document originally claimed, and it settles the
question this item used to ask: a pull request cannot be merged here with
`Guardrails` red, and an approval alone does not override it. Two of those rules
were observed working rather than merely read — a stale failed `Guardrails` run
on a green commit held a pull request at `blocked` until it was re-run, and a
push to an approved branch dismissed its approval.

**What remains is not that the rules are unknown. It is where they live.**

- None of this is in the repository. It is account configuration, and no commit,
  test or receipt in this tree attests to it. `tests/test_ci_contract.mjs` can
  assert that the workflow still produces a check named `Guardrails`; it cannot
  assert that `main` still requires one.
- A reader verifying this document offline — the posture the rest of MNDe is
  built for — cannot check any of it. They have to trust this paragraph, or hold
  an account with access and read it themselves.
- "No bypass actors" is a statement about the ruleset as it was read on
  2026-09-21, not a claim that nobody can change it. Whoever administers the
  repository can edit or delete the ruleset, and that edit leaves no trace in
  the repository. The control is real; it is simply not the kind of control the
  rest of MNDe is about.

This is the same point the short version makes, now with the rules filled in:
the loop that maintains MNDe is gated by GitHub settings, not by MNDe.

### 6. Green CI is not fully trustworthy yet

The evidence a human approves on is a tick. Three separate things have made that
tick mean less than it looks. One is fixed; two are not.

**Fixed.** `createSqliteClaimBackend`
(`experiments/exp-001-stage2/src/claim_store.mjs`) installed
`PRAGMA busy_timeout` *after* `PRAGMA journal_mode=WAL`. Changing the journal
mode takes a brief exclusive lock, so when the freshness suite's deliberate
two-executor race had both processes open the same file at once, the loser met
that lock with the timeout still at SQLite's default of zero and failed
instantly with `SQLITE_BUSY` instead of waiting. That is how a documentation-only
commit produced a red `Guardrails` run. Merged 2026-09-21 with regression tests
that drive the real factory from a second process against a held lock and assert
the wait, the refusal when contention outlives the timeout, and that a failing
cleanup never masks the original error.

**Open — fixed sidecar ports.** Several suites start a real sidecar bound to
`127.0.0.1:8787` (`executor/sidecar-harness.mjs`). Two suites that overlap on
that port fail each other. The proposed fix — ephemeral ports plus a bind retry
in the harness — has not been authorized.

**Open, and worse than a flake — a vacuous assertion.** In
`tests/test_sign_policy_bundle_cli.mjs`, the test that proves a tampered
signature is rejected tampers by rewriting the signature's first character:
`value[0] === "A" ? "B" : "A"`. Signatures are lowercase hex, so that expression
always writes `"A"`; when a signature already begins with lowercase `a`, the
rewrite changes `a` to `A`, hex decoding is case-insensitive, and the verifier
receives **the untampered signature**. Roughly one run in sixteen (measured:
6.29% over 16,000 random signatures; 2 failures in 40 consecutive suite runs)
the assertion either fails for no reason or — the half that matters — the test
passes while proving nothing. It has behaved that way for as long as the line
has existed. A one-line fix (flip a bit of the first byte instead of rewriting a
character) has been proposed and not authorized.

The first two produce red runs a reviewer might wave through as noise. The third
produces *green* runs that assert nothing, which is the failure mode this
document cares about most: a human approving on evidence that was never
collected.

### 7. The sample policies advertise an approval field nothing reads

`sample-policies/strict-production.json` and `sample-policies/balanced-ops.json`
list tools under `requires_approval`. No `.mjs` file in the repository reads that
key. Only `policy-editor/mnde-policy-editor.html` understands it, converting it
into engine rules on import. A file called "Strict Production" that names
`deploy_update` and `modify_config` as requiring approval, which no engine will
ever enforce, reads as a shipped guarantee and is not one.

*Suggested fix:* either move these under a directory named for what they are
(policy-editor inputs) or ship their compiled engine-schema equivalents.

---

## Summary

| Claim | Enforced by | Status |
| --- | --- | --- |
| MNDe cannot merge its own changes | `main` ruleset: required `Guardrails`, one approving review | Enforced as of 2026-09-21; account setting, not in-repo |
| A red required check blocks a merge | same ruleset, strict status checks | Enforced; `Release contract` is *not* a required check |
| MNDe cannot publish without approval | `release` environment reviewer | Code ready, environment not created |
| CI cannot write to the repository | `permissions: contents: read` | Enforced and contract-tested |
| A test suite cannot be silently dropped | `tests/expected-test-scripts.json` | Enforced |
| An ALLOW never causes an effect | `executor/index.mjs` | Enforced, unconditionally |
| Execution cannot be enabled by config | hard-coded `DISPATCH_ENABLED` | Enforced |
| A policy's `approval_required` is honored | approval trust anchors | Fail-open when unconfigured |
| An approval is single-use | nothing | Not enforced |
| An authority is spent exactly once | claim store | Experiment code, never deployed |
