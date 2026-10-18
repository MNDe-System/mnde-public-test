# 06 · Existing products, prior art, and the remaining gap

Evidence tags are defined in [00-README.md](00-README.md). Competitor facts here are `[S]`
(search summaries of vendor pages I could not open), `[P]` (Git's own docs, read), or
`[K]` (prior knowledge, **not re-checked and possibly stale; the date is October 2026**).

**Not researched in this pass** (listed so absence is not read as a finding): OPA/Rego and
Conftest specifics, Cerbos, Kyverno, GitGuardian/Gitleaks/TruffleHog product details,
Teleport/StrongDM/Aembit-style access brokers, GitHub deployment-protection rules, Bitbucket
Forge, SonarQube/Snyk-class scanners, Harness/Spinnaker approvals, Slack-based approval bots.
Statements about these are `[K]` only.

## 1. Capability comparison

| Capability | Existing solutions | Evidence | Remaining gap |
| --- | --- | --- | --- |
| **Exact-action authorization** (this SHA → this ref, from this prior state, once) | **Git push certificates**: the pusher signs `old new ref` plus a server-issued nonce; the server verifies and exposes `GIT_PUSH_CERT*` to hooks `[P: git-receive-pack, config/receive certNonceSeed]`. Agent harnesses authorize a **command pattern** (`Bash(git push *)`, `prefix_rule(["git","push"])`) `[S]`. Rulesets authorize by **branch name** `[S]`. GitHub Environments' required reviewers approve a *job* tied to a commit `[K]` | Push certs are real but **the pusher signs, not an approver**, and most public forges do not enable them `[S: kernel.org post; gitlab#283916]` | A *separate human approver* signing the exact `{repo, ref, old, new}` before execution, verifiable by a third party. **No product doing this for pushes was found in this pass** (a narrow search; absence is weak evidence) |
| **Non-bypassable enforcement** | Server-side: rulesets, protected branches, push rules, pre-receive hooks, `receive.deny*` `[S][P][L19]`. Copilot coding agent: `copilot/` prefix only `[S]` | Strong where the host enforces and the actor is not an admin/bypass actor | Admins, bypass actors, other credentials. Exempt "silent" bypass type exists `[S: github.blog 2025-09-10]`. MNDe's own F-001 notes say rulesets are editable by repo admins |
| **Credential isolation** | GitHub Apps and one-hour installation tokens `[S]`; fine-grained PATs (capped at 50 per account, tied to a user) `[S]`; sandboxes that keep the token on the host (BoxLite) or inject it with network policy (OpenShell) `[S]`; secret managers `[K]` | Mature | The *agent's own environment* often still holds a developer token; the F-001 assessment found an admin token in the agent environment `[R-doc]` |
| **One-use authorization** | Environment approvals are per run `[K]`; push-cert nonces are server-issued and HMAC'd, bounding replay `[P]`; OAuth/device flows are not single-use `[K]` | Partial | A durable *claim before effect* in a store the executor cannot roll back. MNDe has the design; it is not proven on independent infrastructure |
| **Remote-state confirmation** | `git ls-remote`, host APIs, required status checks `[K]`; plain Git prints `Everything up-to-date` on a benign re-push `[L25]` | Trivial to do; rarely done by wrappers | Reading back *and* binding the result to the approval. MNDe does this |
| **Signed execution receipts** | Sigstore/gitsign sign *commits* with ephemeral Fulcio certs and log to Rekor `[S]`; SLSA/attestations sign *build* provenance `[K]`; push certs sign *intent* | Mature for artifacts and commits | A signed statement of *what the pusher observed on the remote after the push*. Not found |
| **Independent offline verification** | `git verify-commit`, `gitsign verify` `[S]`; Sigstore bundles `[K]` | Mature for the above | For push outcomes: no standard format. MNDe defines its own (conformance vectors exist in the repo `[R]`) |
| **Crash recovery** | Server: quarantine + atomic ref update; interrupted pushes leave nothing `[P][L30]` | Strong on the server | The **client-side ambiguity** (case 3, 4, 40) has no tooling. MNDe classifies but has no reconciler |
| **Multi-agent coordination** | Worktrees per agent `[S]`; merge queues `[K]`; Entire links sessions to commits and warns when two sessions share a commit `[S]`; CooperBench documents coordination failure `[S]` | Advice, not enforcement | Ref-level reservation or leasing across agents |
| **Safe retry after uncertainty** | Explicit-SHA leases `[L4]`; idempotent re-push `[L25]` | Git already does the safe thing at the ref level | Knowing whether *your* attempt caused the state. Needs a correlation signal (the ref update carries none) |
| **Developer-friendly diagnostics** | Git hints `[L1]`, host error codes `GH001/GH006/GH013` `[S]` | Good for common cases | Opaque for capability mismatches (exit 128, "hung up unexpectedly") `[L9][L10][L20]` and for hook rejections `[S: gitlab#287684]` |

### Where existing infrastructure already matches or beats the claim

* **Atomic compare-and-swap on a ref** is built into Git's wire protocol (the update
  command carries the old value) and surfaced as `--force-with-lease=<ref>:<sha>`
  `[P][L4][L14]`. MNDe uses it; it did not invent it. MNDe's own code comment says so.
* **Credential minimization** (per-repo, one-hour App tokens) is GitHub's feature
  `[S]`. MNDe adds per-push minting and post-push revocation, a refinement not an invention.
* **Refusing force-pushes and deletions server-side** is a one-line server setting
  upstream (`receive.denyNonFastForwards`, `receive.denyDeletes`) `[L19]` and a ruleset
  checkbox on GitHub/GitLab `[S]`. For the stated worry "an agent might force-push", **a
  ruleset is cheaper and stronger than any wrapper** provided the agent is not an admin.
* **Signed intent for a push** exists as push certificates `[P]`. MNDe's contribution is who
  signs (an independent approver) and the executor-side enforcement, not the idea.
* **A durable single-use token** is an old pattern (database unique constraint). MNDe's
  `UNIQUE(namespace, grant_id)` is correct engineering, not novelty.
* **Ed25519 receipts, Merkle ledgers, witness checkpoints** are standard techniques
  (Sigstore/Rekor/Certificate Transparency lineage `[K]`).

## 2. Per-category assessment

### GitHub (rulesets, push protection, Apps, Copilot agent)

* *What it does.* Server-side policy at push time (rulesets incl. path/extension/size
  push rules `[S]`; secret-scanning push protection with logged bypass `[S]`); scoped
  identities (Apps, fine-grained PATs); first-party agent identity with a hard
  `copilot/` branch restriction and an option to make the agent a ruleset bypass actor
  `[S: github.blog 2025-11-13]`; user-level bypass actors added 2026-05-07 `[S]`.
* *Why customers buy.* It is already where the code lives; policy ships in the same bill.
* *Strengths.* Enforcement sits on the host, which is where non-bypassability has to live.
* *Weaknesses.* Policy is by name/path/size/identity, never by "this exact approved
  commit". Bypass and admin exist. Push outcomes are not signed for third parties. Error
  codes are decent, messages vary.
* *Learn.* Push protection's "bypass with reason, logged, notify" is a good UX for rare
  exceptions. The agent-as-first-class-identity direction (Copilot bypass actor) is where the
  market is moving.
* *Ignore.* Trying to out-feature rulesets on branch or file rules.
* *Roadmap impact.* **Yes: MNDe should treat GitHub rulesets as the enforcement layer and
  position itself as the approval-and-evidence layer on top of them,** rather than imply
  it replaces them. See [10](10-recommendations-and-roadmap.md).

### GitLab, Bitbucket, Gitea/Forgejo

* *GitLab:* protected branches with per-rule force-push toggles; most-permissive rule wins
  when several match; push rules for server-side checks; push options (`ci.skip`, merge
  request options); signed-push is an open request `[S]`.
* *Bitbucket:* branch restrictions for push/force/delete/merge; some merge checks absent on
  Cloud versus Server (e.g. "require approval from all reviewers", BCLOUD-14510) and
  restrictions do not migrate Server→Cloud `[S: Atlassian]`.
* *Gitea/Forgejo:* push allowlists, a separate force-push allowlist, deploy-key allowlisting
  introduced as a breaking change (2019) `[S]`.
* *Strengths.* Self-hosting means the customer can own the server, which is the only way
  to control the remote.
* *Weaknesses.* Same by-name model; semantics differ subtly per product (the GitLab
  "most permissive wins" rule and the Gitea deploy-key change are both surprise sources).
* *Learn.* For self-hosted customers, MNDe could ship server-side `pre-receive`
  hooks that verify an MNDe authorization, which would make the *host* enforce the
  approval. That is stronger than credential custody and unique to hosts that allow hooks
  (not GitHub.com) `[H]`.
* *Roadmap impact.* A GHES/GitLab-self-managed `pre-receive` verifier is a candidate
  differentiator. Unvalidated demand.

### Client-side hook frameworks (husky, pre-commit, lefthook, LFS)

* *What they do.* Run checks on the developer machine before the push.
* *Why bought.* Free, fast feedback.
* *Weakness that matters.* Bypassable by `--no-verify`, `core.hooksPath` and plumbing
  `[L18]`; documented failures in GUI clients `[S: C52 C53]`; agents have been reported to
  defeat them `[S: C13 C28]`.
* *Learn.* Developers value fast local feedback; a deterministic preflight must be local and
  quick (see O4).
* *Ignore.* Do not build a hook framework. Do not rely on client hooks for enforcement.
* *Roadmap impact.* None, except: **MNDe itself skips client hooks, which silently breaks
  Git LFS uploads `[L31]`.**

### Agent harness controls (Claude Code, Codex)

* *What they do.* Deny/ask/allow permission rules, hooks, managed policy, auto-mode
  classifiers (Claude Code); sandbox + approval modes + `execpolicy` rules (Codex) `[S]`.
* *Why bought.* They ship with the agent and reduce prompts.
* *Strengths.* Enforced by the harness, not the model `[S]`; fast; improving.
* *Weaknesses.* Command-pattern granularity; share a process with the agent; reported to fail
  open (C06, C14); a determined agent can route around a pattern (the reported `--no-verify`
  routes).
* *Learn.* Auto-mode's idea of trusting "the working directory and the repo's configured
  remotes" by default is a sensible deterministic baseline `[S]`.
* *Ignore.* Competing on prompt-time permission UX. The harness vendors will win that.
* *Roadmap impact.* **Integrate, don't compete.** A harness `PreToolUse` hook that routes
  `git push` to the MNDe Hub (instead of denying it) is the lowest-friction adoption path.
  Unvalidated.

### Credential brokers and sandboxes (BoxLite, NVIDIA OpenShell, secret managers)

* *What they do.* Keep the token outside the agent's sandbox or inject it under network
  policy `[S]`.
* *Strength.* Eliminates a whole class (agent holds the token).
* *Weakness.* Authorizes *access*, not *each action*; no approval-per-push, no evidence.
* *Learn.* This is the credible alternative to MNDe's custody model; compare honestly.
* *Roadmap impact.* MNDe's executor-held credential is the same architecture plus
  per-action approval and a receipt. The delta MNDe sells is approval + evidence, not custody.

### CI/CD policy engines and OPA-class policy-as-code

* `[K]` only. They evaluate policy over structured input and are good at "may this identity
  do this class of thing". They don't hold credentials or execute, so they don't address
  exact-action single-use authorization or read-back. MNDe's policy engine is its own
  (`src/policy-engine`); I did not assess whether adopting OPA instead would reduce
  maintenance.

### Secret scanning and supply-chain vendors

* GitHub push protection `[S]` and third-party scanners `[K]` block known secret patterns at
  push time or in CI. Reported leakage statistics (GitGuardian's State of Secrets Sprawl
  2026: ≈29 million hardcoded secrets on public GitHub in 2025) are **secondary-source
  numbers I could not verify** `[S]`.
* Sigstore/gitsign/SLSA give provenance for commits and artifacts `[S][K]`. GitHub reportedly
  did not show Sigstore-signed commits as Verified (2022 post) `[S]`; I did not check the
  current state.
* *Learn.* Server-side scanning is mature and free; **MNDe should not build its own secret
  scanner as a product**. A thin local pattern check inside the approval preview (O4) is
  fine; a competitor to GitHub push protection is not.

### AI-agent governance gateways and approval platforms

* *What they do.* Gateways between agents and tools (NeuralTrust, Noma, TrueFoundry,
  ServiceNow AI Gateway), per-agent identity with allow/review/block states, mobile or
  chat approvals, SDKs such as HumanLayer that wrap tool calls with approval gates `[S]`.
  The phrases "MCP firewall" and "execution firewall" are already used descriptively in
  vendor content `[S]`.
* *Why bought.* Compliance and audit for agent fleets.
* *Strengths.* Broad: any tool, not only git.
* *Weaknesses.* Typically authorize a **tool call**, not a state transition; typically do not
  hold the effect's credential or read the effect back; many are announcements, not
  evidence of enforcement (one review noted a vendor with no shipped runtime
  enforcement) `[S]`.
* *Learn.* The category is forming and crowded at the gateway layer. "Execution firewall"
  is **not yet a category with a standard** in anything I found; it is a phrase.
* *Ignore.* A generic "approve any tool call" product. The gateway vendors have that.
* *Roadmap impact.* **This is the main strategic caution.** MNDe's defensible territory is
  *typed, state-bound effects with read-back and offline-verifiable receipts*, of which
  `git.push` is one. Breadth will be contested by funded gateways; depth on a few
  irreversible effects is where MNDe differs. One effect is too thin a base, which is
  a business-premise concern recorded in [01](01-executive-summary.md).

### Entire (session-to-commit linkage)

* `[S]`: open-source CLI linking agent sessions (prompts, transcripts, tool use) to
  commits through an `Entire-Checkpoint` trailer, stored on a separate branch; reported
  seed funding from several sources with inconsistent figures.
* *Relevance.* Complementary evidence ("why did the agent do this") versus MNDe's
  ("what exactly was allowed and what happened"). A signed MNDe receipt could cite an
  Entire checkpoint id. *Do not* build session capture.

## 3. Net assessment

1. Almost every **individual** safeguard MNDe's git path provides can be had more cheaply from
   the host (rulesets + App token) or the harness (deny/ask rules) *for the threat of an
   agent pushing where it shouldn't*.
2. What is **not** available elsewhere, as far as this limited search can tell: (a) approval
   bound to `{repo, ref, old SHA, new SHA}` and signed by a party other than the actor;
   (b) durable single-use spend before the effect; (c) read-back bound to the approval and
   signed; (d) offline verification of (a) and (c). They matter to buyers who must *prove
   to someone else* what was approved and what happened, which is an audit/compliance
   motive. Whether that population pays is untested here.
3. Because exclusivity ultimately depends on the host's configuration, **the product's
   honesty depends on continuously checking that configuration**, which MNDe already has the
   beginnings of (`scripts/f001/check-repository-controls.mjs`,
   `check-agent-environment.mjs`) and which no competitor in this sample offers for pushes.
