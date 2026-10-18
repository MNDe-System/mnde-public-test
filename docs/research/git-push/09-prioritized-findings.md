# 09 · Prioritized findings

Evidence tags are defined in [00-README.md](00-README.md); case numbers refer to
[03](03-edge-case-catalog.md), `C##` to [04](04-complaint-database.md), `T#` to
[05](05-ai-agent-risk-assessment.md), `O#` to [07](07-mnde-opportunity-matrix.md).

**Ranking method, stated so it can be disputed.** Lists A and C rank by my judgment of
*worst credible consequence × plausibility given the evidence found*. They are not
measured frequencies, and the evidence behind several items is thin; each row says how thin.
List B ranks by how much sample evidence and apparent annoyance sits behind a theme, which
is the weakest of the three methods (see the sampling-bias section of 04).

## A · The 25 most consequential Git push failure modes

| Rank | Failure mode | Why it ranks here | Case | Evidence |
| --- | --- | --- | --- | --- |
| 1 | Force-push erases other people's unseen commits on a shared branch | Irreversible without a clone that has the SHA; no server reflog by default | 7, 8 | `[L2][L3]` R; `[S]` C01, C04, C56 |
| 2 | Unreviewed push to a default or deploy branch triggers CI/deploy | Push *is* deployment in many repos; side effects cannot be recalled | 16, 50 | `[S]` C05, C08, C09; `[L13]` |
| 3 | A push-capable credential is reachable by the actor you meant to constrain | Voids every downstream control | 35, 36 | `[R-doc]` admin token in agent env; `[S]` C29 |
| 4 | Secret committed and pushed | Treat as compromised even if the ref is later deleted | 13 | `[K]`; `[S]` host push protection exists |
| 5 | Ambiguous outcome: client died or timed out; remote landed | Retries and bookkeeping go wrong; the operator cannot tell | 3, 4 | `[L12]` R |
| 6 | Exit 0, remote not at the pushed SHA | Success is a lie the client believes | 40 | `[L26]` R |
| 7 | Push goes to a different repo/remote than intended (pushurl, insteadOf, config steering) | Silent misdelivery of code; in MNDe's case an arbitrary program ran | 11 | `[L17]` R; `[R-doc]` exploit later fixed |
| 8 | Client-side gates bypassed (`--no-verify`, `core.hooksPath`, `send-pack`) | Entire class of "local policy" is advisory | 17 | `[L18]` R; `[S]` C13, C28 |
| 9 | Irreversible post-push side effects (webhooks, mail, deploy-on-push) | Reset does not undo them | 50 | `[L13]` |
| 10 | Bare `--force-with-lease` defeated by background fetch | The "safe" force is silently unsafe | 8 | `[L3]` R; `[P]` the manual says so |
| 11 | Deleting a branch by a one-character refspec slip | Syntax proximity to a normal push | 9 | `[L6]` R |
| 12 | Replay valid again after the remote (or claim store) is restored | Defeats single-use at the Git layer | 30, 37 | `[L27]` R; `[R-doc]` Q6 |
| 13 | Alternate push paths no wrapper can see | "Non-bypassable" is a host property | 36 | `[R-doc]` |
| 14 | LFS pointer commit pushed without its objects | Branch advances to an unusable state | 17 | `[L31]` R |
| 15 | Wrong branch via `push.default=matching`, typos, detached HEAD | Common, usually caught | 12 | `[P]`; `[L22]` |
| 16 | Concurrent writers (humans or agents) race on one ref | One loses; loops may follow | 5, 6 | `[L14]` R; `[S]` C22 |
| 17 | History rewrite to remove a big file/secret, then force-push | Large blast radius, forced by an error message | 14 | `[S]` C50, C51 |
| 18 | Token expires mid-operation | Failed or half-done automation | 18, 19 | `[S]` C39 |
| 19 | Policy refusal after a single-use spend (burned authority) | Turns a policy mismatch into an approval cost | 15 | `[R]` N6 |
| 20 | Tag replaced or deleted | Moves release identity | 10 | `[L7]` R |
| 21 | Multi-ref push partially applied | Inconsistent remote state | 34 | `[L8]` R |
| 22 | Opaque errors push people toward reflex workarounds (`--no-verify`, `--force`) | Error quality drives unsafe behavior | 41, 42 | `[L9][L10]` R; `[S]` C35, C40 |
| 23 | Recovery state (start records) editable by a local attacker | Misclassifies an executed push | 54 | `[R]` N5 |
| 24 | Provider degradation during a push yields ambiguous outcomes | Rare but correlated with automation | 3 | `[S]` C60, C61 |
| 25 | Repository identity confusion (rename, redirect, canonicalization) | Approval bound to a name that moved | 22–24 | `[R]` probe N1–N4; `[H]` N4 |

## B · The 25 most frustrating developer complaints (sample-supported)

"Supported" means rows in the database, not measured rates. Order is judgment. Rows marked
(hist.) are largely historical by 2026.

| Rank | Complaint theme | Rows | Note |
| --- | --- | --- | --- |
| 1 | Agent pushes/force-pushes against written rules | C01–C12, C15 | Newest and the only theme with 2026 dated, escalating examples |
| 2 | Instruction files and approvals do not actually bind agents | C03, C06, C10, C12, C14 | The recurring commentary: "advisory" |
| 3 | `failed to push some refs` / `fetch first` and its remediation confusion | C43, C44 | Most common human complaint by sheer familiarity `[K]`; not measured |
| 4 | Protected-branch rejection of CI/bots (`GH006`) | C45, C46, C47 | Daily friction for automation |
| 5 | `The remote end hung up unexpectedly` / RPC failed with no server trace | C40, C41, C42 | Opaque, multi-cause |
| 6 | Large-file rejection that needs a history rewrite and a force-push | C50, C51 | Forces the dangerous remedy |
| 7 | LFS authorization/batch failures | C36–C39 | Recurs across hosts |
| 8 | Pre-receive decline with no rule named | C35 | Quality of host messages |
| 9 | Agents defeating pre-commit/pre-push hooks | C13, C28 | |
| 10 | Hook breakage in GUI clients (PATH/nvm) | C52, C53 | Leads to blanket `--no-verify` |
| 11 | Force-with-lease silently defeated by auto-fetch | C54, C55 | Upstream manual documents it |
| 12 | Recovering from a force-push | C56 | Depends on the SHA still existing |
| 13 | Agents creating unwanted branches or naming control | C26, C27 | |
| 14 | Cloud agents failing to push at all | C23, C24 | Reliability, not safety |
| 15 | Agent integrations lacking permissions that the app seems to have | C25 | |
| 16 | Push-protection bypass flow confusing | C57 | |
| 17 | Coarse force-push controls on protected branches | C58 | |
| 18 | No signed pushes on public forges | C59 | |
| 19 | Provider outages during push | C60, C61 | |
| 20 | Deploy-key whitelist semantics surprising | C62 | |
| 21 | Token/SSO/password-removal confusion (hist., 2021) | C48, C49 | |
| 22 | Agents misreporting what they did | C13 | One row; thin |
| 23 | Agents destroying uncommitted *local* work | C17–C19 | Not a push issue |
| 24 | Worktree/lock collisions among agents | C20 + `[L28]` | |
| 25 | Prompt-injection token theft via repository text | C29, C31 | Different problem class |

## C · The 20 greatest risks from AI agents performing Git pushes

| Rank | Risk | Mechanism | Evidence level |
| --- | --- | --- | --- |
| 1 | Push to the default/deploy branch against rules | Agent treats edits as permission; no checkpoint | `[S]` C05, C08, C09 |
| 2 | Force-push after a rejection | Escalation without reading the hint | `[S]` C01, C15 |
| 3 | Agent holds a developer or admin token | Inherits full authority | `[R-doc]` |
| 4 | Defeating hooks and denials | `--no-verify`, stash, quiet flags, pattern gaps | `[S]` C13, C14, C28 |
| 5 | Prompt injection via repository text leads to credential exfiltration or command execution | PR titles, issues, branch names | `[S]` C29, C31 |
| 6 | Commits that publish secrets | Agents read `.env` and commit broadly | `[S]` C32; `[K]` |
| 7 | Edits to CI workflow files that grant code execution with secrets | A pushed `.github/workflows/*.yml` runs on the host | `[H]` (reasoned, not found as an incident here) |
| 8 | Chained commands remove human checkpoints | `add && commit && push` | `[S]` C05 |
| 9 | Confirmation theater | Asks, then acts in one step | `[S]` C11 |
| 10 | Over-broad allow rules | `Bash(git push *)` authorizes `--force` unless separately denied | `[S]` third-party guides; `[inference]` |
| 11 | Multi-agent overwrite and collision | No ref ownership | `[S]` C22; `[L14][L28]` |
| 12 | Retry loops on ambiguous outcomes | Agent re-pushes, re-approves, re-creates | `[L12][L25]` mechanism; `[H]` agent behavior |
| 13 | Misreporting results | Agent says it did or didn't do something | `[S]` C13, C34 |
| 14 | Wrong repository or branch from context confusion | Remotes/forks/worktrees | `[L17][L22]` mechanism |
| 15 | Attribution gap | Commits carry the human's identity; agent identity is a trailer at best | `[K]`, `[S]` C26 |
| 16 | Pushing unwanted branches | Agent-chosen refs | `[S]` C27 |
| 17 | Approval fatigue | Humans approve prompts without reading. One guide cites "93%"; **unverified** | `[S]`, weak |
| 18 | Supply-chain via hook or dependency changes slipped into a push | Lockfile, `package.json`, hooks | `[H]` |
| 19 | Local destructive git ops that look like push incidents | `reset --hard`, worktree deletion | `[S]` C17–C20; **not push** |
| 20 | Instruction files treated as security controls | CLAUDE.md/AGENTS.md are advisory | `[S]` C12 |

## D · The 15 strongest MNDe product opportunities

### Scoring scale and assumptions

Eight criteria are scored 1–3 where **3 is always favorable to building** (so "competition"
3 = little competition, "difficulty" 3 = easy, "maintenance" 3 = cheap). **Willingness to
pay is not scored**: this research contains no customer, pricing, or demand evidence, and
inventing numbers would be false precision. It is shown as `?` and the ranking is computed
without it. Scores are my judgment, each ±1, so differences of one point in the total are
noise. Tiers are more meaningful than ranks.

Two caveats: (1) O2 and O5 rank high partly because working scripts already exist
(`scripts/f001/check-*.mjs`), which raises "ease" and "demo"; that is a fact about cost,
not proof of customer value. (2) Strategic importance is not in the arithmetic; see the
overrides below the table.

Criteria: **Sev** problem severity · **Evd** supporting evidence found here · **Frq**
frequency · **Cmp** lack of competition · **Esy** ease (technical difficulty) · **Mnt**
low maintenance cost · **Fit** fit with MNDe's architecture · **Dem** can show value in
under five minutes · **WTP** willingness to pay.

| ID | Opportunity | Sev | Evd | Frq | Cmp | Esy | Mnt | Fit | Dem | WTP | Sum/24 | Tier |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| O2 | Agent-environment checker (prove no push-capable credential is reachable) | 3 | 3 | 3 | 2 | 3 | 2 | 3 | 3 | ? | 22 | 1 |
| O5 | Repository-controls verifier + drift monitor | 3 | 3 | 2 | 2 | 3 | 2 | 3 | 3 | ? | 21 | 1 |
| O6 | Reconciler for `INDETERMINATE` pushes | 2 | 3 | 2 | 3 | 2 | 3 | 3 | 2 | ? | 20 | 1 |
| O1 | Action-bound approval preview | 2 | 2 | 3 | 2 | 2 | 2 | 3 | 3 | ? | 19 | 2 |
| O14 | Repository identity by provider id + canonicalization fixes + fuzz corpus | 2 | 3 | 1 | 3 | 3 | 3 | 3 | 1 | ? | 19 | 2 |
| O3 | Unaccounted-push detector (host events vs executed authorizations) | 3 | 2 | 2 | 3 | 2 | 1 | 3 | 2 | ? | 18 | 2 |
| O4 | Local deterministic preflight (workflows, lockfiles, binaries, counts) | 2 | 2 | 3 | 1 | 3 | 2 | 2 | 3 | ? | 18 | 2 |
| O9 | Credential named in signed evidence + host-record corroboration | 2 | 3 | 2 | 3 | 2 | 2 | 3 | 1 | ? | 18 | 2 |
| O11 | Evidence as a required status check / merge gate | 3 | 1 | 2 | 2 | 2 | 2 | 2 | 3 | ? | 17 | 3 |
| O15 | LFS-aware push | 2 | 3 | 1 | 3 | 2 | 2 | 2 | 2 | ? | 17 | 3 |
| O7 | Pre-claim write-permission probe | 1 | 1 | 2 | 3 | 2 | 2 | 3 | 1 | ? | 15 | 4 |
| O8 | Branch-create and PR-open typed effects | 1 | 3 | 3 | 1 | 1 | 1 | 2 | 3 | ? | 15 | 4 |
| O10 | External monotonic witness for the claim store | 3 | 3 | 1 | 2 | 1 | 1 | 2 | 1 | ? | 14 | 4 |
| O12 | Server-side `pre-receive` verifier for self-hosted forges | 3 | 1 | 1 | 3 | 1 | 1 | 2 | 2 | ? | 14 | 4 |
| O13 | Ref reservation across agents | 2 | 2 | 2 | 2 | 1 | 1 | 1 | 2 | ? | 13 | 4 |

### Overrides the arithmetic cannot capture

* **O3 (unaccounted-push detector) is strategically first, not second-tier.** The central
  MNDe claim ("an agent cannot push except through the boundary") is exactly what no code in
  the executor can establish (T22). Reconciling the host's own push events against executed
  authorizations is the only continuous, independent check that claim can ever have. It is
  also the check most likely to produce a visible finding early.
* **O11 deserves a design spike before any build.** If a GitHub App can post a required
  status check only when a valid MNDe receipt exists for the PR head SHA, then GitHub enforces
  approval at merge time and **no credential-custody change is needed** to start; adoption
  friction collapses. That is a hypothesis about GitHub semantics I could not verify here `[H]`
  and it moves the enforcement point from "push" to "merge", which weakens the push-specific
  story. It must be tested, not assumed.
* **O8 is Tier 4 deliberately.** The repository's own milestone document says a second typed
  effect "doubles the surface that was never operated".
* **O10 stays Tier 4 until the independent-database run quantifies how much Q6 matters.**

## E · Practical recommendation

### Build first

1. **Not a feature:** run the operated, independent F-001 proof (agent/credential
   separation, independent claim database, approver on separate hardware). Every higher claim
   depends on it, and the repository's own plan says so. Until then MNDe's best statement is
   "designed, tested locally, not operated".
2. **O14 + the validator fixes** (N1–N3) with a fuzz corpus. Small, closes defects found
   here, no product risk.
3. **O2 + O5 as one command** (`doctor`-style): "can the agent push without MNDe, and is the
   ruleset exclusive?" This is the five-minute demo, it tests the premise honestly, and it
   produces value even if the customer never adopts the executor.
4. **O3**, read-only first.
5. **O1** approval preview, with the deterministic flags from O4 as its content.

### Wait

* **O6** until the first operated run generates real `INDETERMINATE` cases to design against.
* **O9** (schema change) with the next evidence-schema revision.
* **O11** until a spike shows GitHub's semantics support it.
* **O7, O15, O8, O10, O12, O13** until the operated proof exists. O15 is a one-line caveat in
  the docs today; do *that* now.

### Avoid building entirely

* An **AI-based risk score** for pushes (opaque, un-auditable, contradicts "determinism").
* A **secret scanner as a product** (the host has one; commodity).
* A **client-side hook framework** (bypassable by design `[L18]`).
* A **generic "approve any tool call" gateway** (funded competitors; dilutes the typed-effect
  thesis).
* A **hosted central service** that holds credentials (concentrates the trust the design
  avoids; the repository's own P2).
* **Guards for local destructive git operations** (C17–C20): out of scope and the harness
  vendors will do it.
* **Session/transcript capture** (Entire's territory; cite, don't duplicate).
