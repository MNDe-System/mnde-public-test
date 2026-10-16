# What MNDe needs next — assessment of 2026-10-16

This is an engineering and strategy assessment, not a specification. Every
statement is tagged by how it is known:

- **Fact** — read in this repository or observed by running it on 2026-10-16.
- **Judgment** — my conclusion from the facts. Argued, not proven.
- **Speculation** — about the market or the future. No evidence in this repo.

Nothing here changes what MNDe claims. Claims are in `README.md`,
`SECURITY_CLAIMS.md` and `docs/F001-REASSESSMENT.md`; where this document
disagrees with those, they win and this document has a bug.

## 1. Where MNDe actually is

**Fact.** At `178342b` MNDe decides and records; it does not execute. The README
opens with the execution hold: protected execution is disabled in the generic
executor and the MCP proxy. One typed effect, `git.push`, has a production path
(`bin/mnde-git-push.mjs`, `src/effects/git-push/`) with an executor-owned push
credential, a durable claim before the effect, and signed evidence afterwards.
`docs/F001-REASSESSMENT.md` scores it six of nine questions established and says
plainly: *"no deployment has ever run this"*, so F-001 is not closed.

**Fact.** With dependencies installed (`npm ci`), the full suite passes: 109 of
109 test scripts. Run on Node 22.22.0, although `package.json` requires Node 24
or later; nothing in the suite failed for that reason, but it was not run on 24
here, and the Windows CI flake in KI-005 cannot be reproduced on this machine.
Without `npm ci`, five suites fail with `Cannot find package 'typescript'`
because the packaging tests build `dist/`. That is an environment gap, not a
defect, but it is also a first-run trap (see item 8 below).

**Judgment.** The engineering discipline is unusually strong for the stage:
claims are written next to the evidence that does and does not support them,
known issues carry a "why is this safe to defer" argument, and fixed findings
stay on record. That discipline is itself a trust asset, and the cheapest way to
lose it is to let a doc say something the code does not do. Protect it.

**Judgment.** The product's real position is narrower than the category name
"execution firewall" suggests, and the repo is honest about it. Enforcement is
cooperative for everything except effects where MNDe's executor holds the
credential, which today means `git.push` only. The distinction that matters to a
buyer is not "MNDe can refuse" (any policy engine can) but "the agent never
holds the credential, so it cannot do the thing without MNDe". That property
exists in one place. Everything below is ranked by how fast it turns that one
place into something operated, verifiable by outsiders, and then repeatable.

## 2. What was done in this session

**Fixed UC-002** (`docs/KNOWN-ISSUES.md`, Resolved): a policy declaring
`approval_required` silently allowed with no approval whenever
`MNDE_PE_APPROVAL_TRUST_ANCHORS` was unset. It now refuses at configuration load
(`ERR_PE_APPROVAL_REQUIRED_WITHOUT_TRUST_ANCHORS`) in the sidecar and in
`mnde decide`.

Why this one, ahead of anything else I could have built:

- It was the only open finding that is a *fail-open on the control whose entire
  purpose is to hold an action for a human*. Everything else open is either
  infrastructure, a human decision, or CI cost.
- It could be fixed completely and tested in this sandbox, so the result is
  verified, not described.
- **The repository's own example demonstrated the bug.** The shipped
  `sample-policy.json` declares `approval_required`, and eight test suites plus
  `reviewer-kit:pe` booted it with no anchors, so none of them was enforcing the
  approval they appeared to define. Fixing the loader surfaced that immediately.

Two decisions inside the fix that are worth a reviewer's attention:

1. **The check is at configuration load, not in the evaluator.** The receipt
   verifier replays the evaluator; making it refuse without anchors would turn
   every previously issued receipt into "decision drift" on replay. Breaking
   verification of historical evidence is a worse failure for this product than
   the gap being fixed. The evaluator's old behaviour is frozen and a test pins it.
2. **It is a behaviour change.** Anyone running a policy with `approval_required`
   and no anchors now gets a startup refusal naming the cause. I believe that is
   correct (it is the fix the finding itself proposed) but it is a decision, and
   the doc says so.

Also: added `examples/policy-engine/sample-policy-no-approval.json`, pointed the
eight suites, `reviewer-kit:pe` and three spec snippets at it, and added tests
(`test:approvals` 20/20, `test:sidecar-pe` 9/9 including a real-process refusal).

## 3. Ranked work

Ranked by expected long-term return to the goal of MNDe becoming trusted
infrastructure. "Effort" is engineering time, excluding waiting on people or
infrastructure, and is an estimate.

| # | Work | Impact | Difficulty | Risk | Depends on | Effort |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Operate `git.push` once, end to end, against a real independent PostgreSQL claim primary (F-001 blocker 1) | Highest. The only item that changes what MNDe may claim. | Medium | Will find real bugs; that is the point | An independent infrastructure operator and a restricted claim login; `docs/FIRST-PRODUCTION-GIT-PUSH.md` is the runbook | 2–5 days plus provisioning wait |
| 2 | Publish a stable MNDe authority bundle with a documented rotation story | High. Without it, third-party verification is repo-local, which the README states as the pilot's main gap. This is where "verify without trusting the operator" becomes true for outsiders. | Low–medium in code; the key ceremony is the hard part | A published root is a long-lived commitment | A decision on root custody and who holds it | 3–5 days |
| 3 | Write down the F-001 limits you will ship with (question 6 restore, power loss) | High for credibility, tiny to build | Low | None | Item 1 for the power-loss evidence | 0.5 day |
| 4 | Cut one release through the approval-gated workflow (KI-004) | Medium. Releases are currently hand-tagged, the opposite of what the repo argues for. | Low | None | A GitHub Environment with a required reviewer, a version bump | 0.5 day |
| 5 | Authenticated approver binding for the legacy path (`hold_state`) and verification of `orbit_intent.signatures` | Medium. Closes two README "Limitations" bullets. UC-002's fix covers the policy-engine path only. | Medium | Touches the legacy engine; backwards compatibility matters | Decide whether the legacy engine is being retired instead | 3–4 days |
| 6 | Make the sidecar test harness report runtime-health transitions (KI-005) | Low–medium. A red Windows run says "runner stalled" in one line instead of a log read. Does not touch the watchdog threshold, which is the control. | Low | Low | KI-005 says it is unauthorised; needs a yes | 1 day |
| 7 | A second typed effect | Potentially high, but only after item 1 | Medium each | Doubles the surface that was never operated | Item 1 done and stable | 1–2 weeks each |

### Why the alternatives lose

- **More effects before item 1 (item 7 first).** This feels like progress and
  adds the most risk. A second effect on top of a claim path nobody has operated
  doubles the unproven surface. Breadth does not make an unoperated design more
  trusted; one operated effect does.
- **A hosted/central MNDe service now.** The Hub prototype exists
  (`docs/MNDE-HUB.md`), but a hosted service concentrates trust in the operator,
  which is the thing the receipt design exists to avoid. Judgment: it should
  follow, not precede, an outsider being able to verify without it.
- **A dashboard / policy editor / installer.** `installer/README.md` and the
  README say there is no installer. Polishing the surface around a decision engine
  that cannot yet execute optimises the demo, not the trust. Skip for now.
- **Raising the CI watchdog threshold to quiet KI-005.** KI-005 is explicit that
  the threshold is the control. This would trade a real property for green builds.

## 4. The strategic questions, answered

**Does the work above strengthen the execution firewall category?** Item 1 does,
more than anything else, because it is the difference between "a policy engine
that signs receipts" and "a boundary the agent cannot cross". Judgment.

**Network effects.** Honestly, almost none exist today. Receipts are per
deployment. The nearest candidate is the conformance material
(`conformance/`, `tests/vectors/`): if third-party verifiers and other tools
produce or consume MNDe receipts against those vectors, the *format* becomes
the shared asset, not the product. That is a plausible moat and it depends on
item 2 (a stable anchor others can trust). Speculation on whether anyone will
adopt a format from a pilot.

**Trust.** Items 1, 2, 3 and the UC-002 fix all move it. A trusted-infrastructure
buyer reads the claims-versus-evidence discipline first; every doc/code mismatch
costs more than any feature earns.

**Switching costs.** Weak today, and arguably correct for a pilot. The durable
form is signed history: a ledger of receipts, policies and anchors that an
auditor needs the matching verifier to read. That accrues only if deployments run
long enough to have history, which again points at item 1.

**Simplifies adoption?** Mixed. `npm run sidecar` on a fresh clone is a good
story. The first-run trap in item 8 and the new approval-anchor refusal both cost
a newcomer a minute; the refusal at least names its cause.

**Reduces operational complexity?** No, and it should not claim to. Item 1
requires an independently administered database. That is a real operating burden
and the honest price of the single-use guarantee. Better to state the cost in the
adoption docs than discover a buyer resents it.

## 5. What I did not do, and why

- **Did not provision or test against PostgreSQL (item 1).** There is no
  independent infrastructure available from this sandbox, and the freshness audit
  is explicit that a same-machine database proves nothing about administrative
  independence. Doing it against a local container would have produced a
  green-looking result that the repo's own rules say not to count.
- **Did not touch `package.json` `license` (KI-003).** The entry records it as a
  legal-facing string that is the maintainer's call. I agree.
- **Did not change the evaluator, receipt format, or any signed fixture.** See
  section 2 for why.
- **Did not touch the CI watchdog or KI-005.** Its remediation is marked
  unauthorised.
- **Did not enable execution or edit the execution hold.**

## 6. Unknowns and risks to watch

- **Unknown:** whether any deployment outside this repository runs a policy with
  `approval_required` and no anchors. If one does, the UC-002 fix is a startup
  failure for them. I cannot see that from here. Confidence it affects anyone:
  low, since the project is a pilot with a source-checkout-only install, but I
  have no data.
- **Unknown:** Node 24 behaviour and the Windows flake; neither exercised here.
- **Risk:** `approval_required` is still inert for any code that calls the
  evaluator directly without anchors. Four in-repo callers were checked (listed
  in `KNOWN-ISSUES.md` UC-002); a future fifth is where this regresses. A cheap
  guard is a test that fails when a new caller of `buildPolicyReceipt*` appears
  without being on an allowlist. Not built; noted.
- **Risk:** the documentation-truth tests (`test:release-documentation-truth`)
  guard some claims, not all. Prose like this file is not machine-checked.

## 7. Suggested next milestone

**Milestone: "F-001 operated once."** Provision the claim primary under an
independent operator, run `docs/FIRST-PRODUCTION-GIT-PUSH.md` start to finish
once, record the real result (including failures) as an addendum to
`F001-REASSESSMENT.md`, and write down the question-6 and power-loss limits
(item 3). Everything else on the list is either blocked by it or smaller than it.

## 8. Small things noticed

- **First-run trap.** A fresh clone running `npm test` without `npm install`
  fails five packaging suites with a missing-`typescript` error that reads like a
  defect. A preflight message ("run `npm ci` first; the packaging tests build
  `dist/`") would cost a few lines. Not done; low priority.
