# What MNDe needs next

First written 2026-10-16 (after PR #58); revised the same day after the guarded-issuance
review and the F-001 acceptance assessment. Tags: **Fact** (read or run, and I can point at
it), **Judgment** (my conclusion), **Speculation** (market or future, no evidence here).
Claims live in `README.md`, `SECURITY_CLAIMS.md` and `docs/F001-REASSESSMENT.md`; where this
document disagrees with them, they win and this one has a bug.

## 1. Where MNDe is

**Fact.** MNDe decides, signs and records; protected execution is held off everywhere except
one typed effect, `git.push`, which has a production CLI and a Hub prototype. The claim that
matters ("an agent cannot push except through the boundary") has **never been demonstrated on
independent infrastructure**, and in the environment this assessment ran in, the agent itself
holds an admin GitHub token (`docs/F001-ACCEPTANCE-MATRIX.md`, C2). On Node 24.22.0 the full
suite passes; exact commands and results are in `docs/evidence/f001/2026-10-16/README.md`.

**Judgment.** The engineering discipline (claims written beside the evidence that does and does
not support them) is the product's best asset and the cheapest thing to lose. The weakest point
is not a missing feature. It is that the strongest claim is unproven and one environment
contradicts its premise.

## 2. What the 2026-10-16 passes changed

1. **UC-002** (an `approval_required` gate silently skipped without anchors): fixed in PR #58
   for two callers, then fixed at the issuance chokepoint with one validation routine
   (`docs/UC-002-SECURITY-REVIEW.md`). Replay of historical receipts is preserved and proven with a
   fixture issued by pre-guard code. A mutation checker shows 11 removals of the fix are caught.
2. **A way to find old exposure:** `npm run audit:unenforced-approvals`.
3. **Three new findings, recorded and unclassified** (`KNOWN-ISSUES.md`): UC-003 (unverified
   authority grants without anchors), UC-004 (no `exports` map), UC-005 (approvals bound to a tool
   name, not the action; confirmed by running it).
4. **A read-only F-001 toolkit** (`scripts/f001/`) and an operator protocol, with the pending action
   prepared and **not** executed.
5. **One flaky test fixed** (`TF-001`) and **one guard respected, not weakened** (the
   git-push reachability test: the new tools are kept out of the package, as the repo does for its
   other operator tools).

## 3. Ranked work

**Required security work.** Ordered by dependency, then impact. Effort excludes waiting on people
and infrastructure and is an estimate.

| # | Work | Security impact | Depends on | Independently verifiable? | Operational risk | Effort | First-customer value |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R1 | Review and merge PR #58, then the stacked guarded-issuance PR (authorized reviewers only) | High: closes UC-002 end to end | human review | yes: tests + mutation checker | Low; startup refusals are intended | review time | High: an approval gate that cannot silently vanish |
| R2 | **Separate the agent from push credentials** and re-run `check-agent-environment.mjs` as the agent | Highest: without it F-001's premise is false | operator decision on topology | yes: the checker exits 0 or it does not | Low | 0.5-1 day | Highest |
| R3 | **Independent claim database** (an operator who is not the executor operator) and run the 22-case harness against it | Highest: Q1, Q4 (partly), C9, database criteria | an independent DB operator | yes: harness output + operator's observation | Medium: rows are permanent | 1-2 days | Highest |
| R4 | **Operate the end-to-end protocol once** (`F001-PROOF-PROTOCOL.md`) | Highest: moves Q8, C3-C6 | R2, R3, an Approver on separate hardware, an App installation | yes: collector, offline verification, GitHub's activity record | Medium: the protected-ref push is **permanent** | 1-2 days | Highest |
| R5 | Decide and state the two limits: Q4 (accept `-m immediate` or test power loss) and Q6 (owner can restore; or design a witness) | High for honesty of the claim | R3 for Q4 evidence | partly | Low | 0.5 day to decide | High |
| R6 | Publish a stable authority bundle and root fingerprint (`AUTHORITY-BUNDLE-PUBLICATION-PLAN.md`) | High: makes third-party verification real | key ceremony; owner decisions | yes, by design | Medium: a published root is a long commitment | 3-5 days | High |
| R7 | Decide UC-005: action-bound approvals (additive, optional scope field, required for new issuance) | High on the sidecar path | a contract decision | yes | Low if additive | 3-4 days | Medium-high |
| R8 | Decide UC-003 (apply the UC-002 treatment to `authority_required`) | Medium | a contract decision | yes | Breaks non-production demos | 1-2 days | Medium |
| R9 | Name the credential in signed evidence (or accept GitHub's record as corroboration) | Medium: closes C6's gap | schema decision | yes | Schema change | 2 days | Medium |
| R10 | Add a package `exports` map (UC-004) | Medium | decide supported entry points | yes | Breaking for deep importers | 1 day | Low now |

**Optional product work** (do not start until R2-R4 are done):

| # | Work | Why it waits |
| --- | --- | --- |
| P1 | A second typed effect | Doubles the surface that was never operated |
| P2 | Hosted/central service | Concentrates the trust the receipt design avoids |
| P3 | Dashboard / policy editor / installer polish | Optimizes the demo, not the trust |
| P4 | Sidecar harness reports runtime-health transitions (KI-005) | Reduces CI cost only; marked unauthorised |
| P5 | `license` field (KI-003), release workflow (KI-004) | Maintainer decisions; KI-004 is release hygiene that undercuts the "approval-gated" story if left |

### Why the alternatives lose

- **More effects before R4.** Breadth does not make an unoperated design more trusted; one operated
  effect does.
- **A local container as the "independent" database.** It would produce a green result the written
  criteria say not to count. It is useful only as a rehearsal, and only if labelled one.
- **Fixing UC-002 in the evaluator.** That breaks replay of every historical receipt. The fix belongs
  at issuance.
- **Raising the CI watchdog threshold for KI-005.** The threshold is the control.

## 4. The strategy questions

**Does this strengthen the execution-firewall category?** R2-R4 do, more than anything else:
they are the difference between "a policy engine that signs receipts" and "a boundary the agent
cannot cross". Judgment.

**Network effects.** Almost none today; receipts are per deployment. The nearest candidate is the
receipt format plus a published trust root plus conformance vectors others can verify against
(R6). Speculation on whether anyone adopts a format from a pilot.

**Trust.** R1-R6 and R9 move it. Each doc/code mismatch costs more than a feature earns; this pass
found one: PR #58 described itself as closing UC-002, but its check did not cover direct callers of
`buildPolicyReceipt*` and accepted unusable anchors.

**Switching costs.** Weak, and arguably correct for a pilot. Signed history accrues only if a
deployment runs long enough to have history, which points again at R3-R4.

**Operational complexity.** R3 requires an independently administered database. That is the honest
price of the single-use guarantee; state it in adoption docs rather than let a buyer discover it.

## 5. What I did not do, and why

- Did not run the F-001 demonstration: it needs an Approver's key, an App installation, an executor
  OS identity and an independent database, and the final push to the protected ref is permanent.
- Did not attempt a direct push to test denial, in a session whose token has admin rights.
- Did not generate, rotate or publish any key or bundle.
- Attempted to rehearse the claim-store harness against the sandbox's local PostgreSQL; the permission
  classifier denied the `npm install` of the `pg` driver it needed. I did not work around it and
  restored every sandbox change. A rehearsal would not have counted for independence anyway.
- Did not merge, approve or mark ready any PR.

## 6. Unknowns and risks

- **Unknown:** whether anyone outside this repository runs `approval_required` without anchors
  (the new startup refusal would affect them), and how many historical receipts the audit tool will flag.
- **Unknown:** the MNDe-side artifacts of the 2026-10-01/02 `mnde-execution-gate[bot]` pushes; if the
  operator supplies them, `collect-evidence.mjs` can bind them to GitHub's record.
- **Risk:** the physical-hub rulesets (created 2026-10-04) are editable by a repository admin, and this
  session's token is one.
- **Risk:** Windows CI flake (KI-005) and Windows directory-flush durability are unexercised here.

## 7. Next three actions

1. **R2 + R3 in parallel** (they are independent): remove admin/push tokens from agent sessions, and
   stand up the claim database under an operator who is not the executor operator.
2. **R4:** run the protocol once, with the Approver on separate hardware, and collect with
   `collect-evidence.mjs`.
3. **R1** whenever reviewers are available; it does not block the others.
