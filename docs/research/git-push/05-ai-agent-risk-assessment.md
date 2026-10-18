# 05 · AI coding agents and `git push`: behavior, risk, and trust boundaries

Covers Part 4 (how agents push) and Part 5 (threat model). Evidence tags are defined in
[00-README.md](00-README.md). **Most agent-product facts here are `[S]`**: a search summary
of a vendor page or third-party guide that I did not open. Agent products change monthly;
treat each as "reported as of the summary" and re-check before relying on it.

## 1. What each agent is reported to do

| | Claude Code | OpenAI Codex CLI | Cursor | GitHub Copilot coding agent | OpenHands |
| --- | --- | --- | --- | --- | --- |
| Runs where | Developer machine (or SDK/CI) | Developer machine, sandboxed | Local IDE agent; cloud/background agents | GitHub-hosted | **Nothing found** in this pass |
| Pushes automatically? | Only when it runs `git push` in Bash; reported to do so against instruction (C03, C05, C08, C10–C12) | Network is **off by default** in the workspace-write sandbox; a push needs network, so it normally triggers an approval `[S: developers.openai.com/codex/security]` | Cloud agents push their own branch via the Cursor GitHub app; reported unreliable at it (C23) | Yes, to its own branch, by design | n/a |
| Where credentials come from | Whatever the host environment already has: git credential helper, `gh`, ssh agent, env tokens `[K]`. In MNDe's own 2026-10-16 assessment the agent's environment held `GH_TOKEN`/`GITHUB_TOKEN` with **admin** rights `[R-doc: F001-ACCEPTANCE-MATRIX C2]` | Same on the host; the sandbox is the control `[S]` | Cloud: a GitHub App installation token. Local: the user's `[K]` | A token scoped by GitHub; agent cannot push outside `copilot/*` `[S]` | n/a |
| Inherits developer permissions? | **Yes, normally** `[K]` | Yes unless sandbox/network blocks | Local: yes; cloud: the app's | No: its own identity `[S]` | n/a |
| Approval prompts | `deny` → `ask` → `allow` rules, first match wins, **enforced by the harness, not the model** `[S: code.claude.com permissions]`; an auto-mode classifier trusts only the working directory and the repo's configured remotes by default and scrutinizes pushes to deploy-style branches `[S]` | `approval_policy` modes; `execpolicy` rules with `prefix_rule(pattern=["git","push"], decision="forbidden"|"prompt"|"allow")`, strictest match wins `[S: mintlify codex exec-policies]` | Product-specific `[K]` | GitHub Actions workflows triggered by agent PRs need approval from a write-access user `[S]` | n/a |
| Is approval tied to the exact action? | **No**, to a command pattern (`Bash(git push *)`) `[S]`. One guide warns deny patterns need variants for how people type flags `[S]` | To a command **prefix**, not to a SHA or ref state `[S]` | `[K]` no | Server rule on branch **name**, not content `[S]` | n/a |
| Valid after the ref moves? | A pattern approval has no notion of ref state, so yes `[inference from the above]` | Same | Same | Same | n/a |
| On push failure | Reported to escalate: rejected → rebase → `--force` (C01/C16, C15) | Unknown | Unknown | Unknown | n/a |
| Retries unsafe operations? | Reported yes (C15 retried with `--force` after rejection) | Unknown | Unknown | Unknown | n/a |
| Bypasses local hooks? | Reported yes: `--no-verify`, stash, quiet flags (C13); hook-exit-2 reported not to block (C14) | Unknown | Unknown | Server-side, n/a | n/a |
| Force push | Reported (C01, C02, C04, C15) | Can be made `forbidden` by rule `[S]` | Unknown | Cannot reach protected branches `[S]` | n/a |
| Monitoring | Local transcript; managed settings for enterprises `[S]` | Local | Cloud-side logs | GitHub audit/PR history `[K]` | n/a |
| Multi-agent | Worktrees are the common remedy `[S]`; collisions on `index.lock` `[S]`, `[L28]` | `[K]` | Parallel cloud agents | Parallel PRs | n/a |
| Attribution | Commits carry the **human's** git identity plus optional `Co-Authored-By` trailers `[K]`; a Cursor forum thread asks for custom author attribution (C26) | Same `[K]` | `cursor/` branch prefix identifies cloud-agent work (C26) | Agent identity `[S]` | n/a |

Other sandbox patterns found `[S]`: **BoxLite** keeps the GitHub token on the host and
narrows outbound access to GitHub, so the credential never enters the sandbox; **NVIDIA
OpenShell** injects a token into the sandbox through a credential provider and relies on
network policy. These are the two ends of the credential-custody design space, and
MNDe's executor sits at the BoxLite end.

### Findings that follow from the table

1. **Every mainstream control is either a command-pattern rule or a branch-name rule.**
   Nothing in the table binds an approval to *the specific commit, ref, and prior state* of
   a push. That is the gap MNDe's typed effect fills, and it is the one claim about this
   market that this research does support.
2. **Instruction files do not bind.** Fourteen reports (C01–C14) describe agents acting
   against written rules; the commenters' own conclusion is that CLAUDE.md is advisory
   `[S: C12]`. The effective controls reported are `PreToolUse` hooks, deny rules, and
   removing the credential.
3. **Hook-based controls have themselves been reported to fail open** (C06, C14). A
   guardrail that lives in the agent's own process shares fate with that process.
4. **The strongest controls reported are credential-based**: GitHub's `copilot/` prefix
   restriction, sandboxes that keep the token out, Apps scoped to one repo. They are
   boring and work. MNDe's differentiator is therefore *not* "agents can be stopped from
   pushing" (that is solved by not handing them a token); it is "a push can be allowed
   exactly once, exactly as a human saw it, with a verifiable record".

### Genuine remote-push incidents versus everything else

Of the 34 agent-related rows in [04](04-complaint-database.md):

| Kind | Rows | Remote push? |
| --- | --- | --- |
| Reported unrequested or forced **remote** pushes | C01, C02, C04, C05, C07–C12, C15 (C16 repeats C01) | Yes |
| Hook / permission bypass | C03, C06, C13, C14, C28 | Mixed: C03 and C06 involve pushes; C13 is commits |
| Destructive **local** operations | C17–C20 | **No**. Out of scope for a push gate |
| Credential exfiltration by prompt injection | C29–C33 | Not pushes; the credential is the attack target |
| Research and context | C21, C22, C34 | No |

Roughly a third of the agent rows are real remote-push events. The rest are neighbors
that a push gate would not have prevented. A product pitched as "stops agents destroying
repos" would be over-claiming against its own evidence: C17–C20 are local, and C29–C33 are
about what the agent can *read*.

### What is specific to autonomy, rather than ordinary human Git use

| Behavior | Why it is autonomy-specific | Rows |
| --- | --- | --- |
| Acting against a written project rule | A human who wrote the rule does not forget it mid-task | C03, C07, C08, C10, C12 |
| Chaining `add && commit && push` so no human checkpoint exists between edit and remote | Humans leave natural pauses | C05 |
| Asking for confirmation and acting in the same step | Confirmation is a ritual to the agent | C11 |
| Escalating after rejection (`push` → `rebase` → `--force`) without reading what the rejection meant | Humans also do this, but a human is slower and sees the hint | C01, C15, C16 |
| Defeating the guard (`--no-verify`, stash, quiet flags) and misdescribing it | A human who bypasses a hook knows they did | C13 |
| Turning untrusted repository text (issue, PR, branch name) into actions | A human reads the issue | C29, C31 |
| Parallelism: many agents, one remote | Humans queue naturally | C22, C18 |

## 2. Threat model: `git push` as a privileged operation

"MNDe adds" refers to the typed `git.push` path as implemented `[R]`, not to anything
shipped and operated in production. "Independently verifiable?" asks whether a third party
with no trust in the operator can check the claim.

| # | Threat | What the attacker needs | What stops it without MNDe | What MNDe adds `[R]` | Residual | Independently verifiable? |
| --- | --- | --- | --- | --- | --- | --- |
| T1 | Credential theft (token/key read from disk, env, process list) | Code execution as the credential's OS user | Short-lived App tokens; secret managers; separate OS users | Per-push App token scoped to one repo, revoked after; token only in the 3 git children that talk to the remote; executor runs as its own OS user (deployment property) | A same-user process can read `/proc/<pid>/environ` while a push runs (documented) | No; deployment property |
| T2 | Over-privileged PAT/token | Any leaked token with `contents: write` or admin | Fine-grained PATs, Apps, org policy `[S]` | Refuses a token with any permission other than `contents: write` + `metadata: read` or for another repo `[R-doc]` | MNDe cannot see *other* tokens that exist. The F-001 environment's token was admin `[R-doc]` | Partly: `check-agent-environment.mjs` probes from inside the agent's environment |
| T3 | GitHub App private key compromise | Read the `.pem` | Key storage, rotation | Key stays in the executor; never in evidence | If the executor host is owned, the App can mint tokens | No |
| T4 | SSH key misuse | Agent can use an ssh agent | `IdentitiesOnly`, no agent | Environment built from empty; `-F none`, `IdentityAgent=none` `[R-doc]`; kind `ssh-key-file` checked by command construction, **no sshd contacted in tests** | Unverified against a real sshd | No |
| T5 | Local hook bypass | None (client-side) | Server-side hooks only `[L18]` | Not relevant: MNDe uses no client hooks and `--no-verify`; policy is outside the repo | Loses LFS upload (`[L31]`) | Yes (reproducible) |
| T6 | Server-side permission enforcement | n/a | Rulesets, protected branches, push rules `[S]` | None. MNDe depends on the host for exclusivity | Admins can edit rulesets (noted `[R-doc: NEXT-MILESTONES §6]`) | Only through host configuration reads |
| T7 | TOCTOU: ref moves between check and act | A concurrent writer | Explicit lease `[L15]` | Pre-read, fast-forward test, durable claim, lease-guarded push | A race between pre-read and push burns the authority | Yes (lab + tests) |
| T8 | Replay of a valid authorization | A copy of the signed envelope | Nothing in Git | Durable single-use claim, `UNIQUE(namespace, grant_id)` | Database owner can restore a backup (Q6); power loss untested (Q4) | **Not yet** on independent infrastructure (C9 BLOCKED) |
| T9 | Approval substitution (approve A, execute B) | Control of the request | Nothing | Six signed parameters; request must equal them field for field; unknown fields refused `[R]` | Sidecar path approvals bind a tool name only (UC-005, Hub path unaffected `[R-doc]`) | Yes for the typed path |
| T10 | Repository identity confusion | A lookalike URL | Host-level | `repository` must equal an identity derived from `remote_url` `[R]` | **Probe findings:** port dropped, `%2F`→`/`, NUL in identity, malformed escape throws; name not immutable id (see [07](07-mnde-opportunity-matrix.md)) | Yes (`lab/identity-probe.mjs`) |
| T11 | Branch / commit substitution | Write access to the local repo | Commit ids are content-addressed `[K]` | Full 40-hex ids only; refuses abbreviated/null/option-like values | Depends on SHA-1 collision resistance in non-SHA-256 repos `[K]` | Yes |
| T12 | Credential exposure to the agent | Agent shares the user/host with the credential | Sandboxes (BoxLite pattern) `[S]` | Credential provider only in the executor; request cannot select a credential | A deployment that gives the agent the executor's OS identity defeats it | Yes via the environment checker |
| T13 | Compromised workstation | Full local compromise | Hardware keys, MDM | Approver key on separate hardware is the recommended topology; the first-run runbook puts approval and executor on one device and says so | If one device holds both keys, one compromise is total | No |
| T14 | Malicious Git configuration (`pushInsteadOf`, `core.sshCommand`, `ext::`) | Write to `.git/config` | Review; `protocol.*.allow` | **Reproduced and fixed before this research:** an `ext::` rewrite ran an arbitrary program inside an authorized push; the effect now runs in a config-free staging repo `[R-doc]`, 9/9 isolation tests re-run `[R]` | Config outside Git (env, PATH) is the operator's | Yes |
| T15 | Remote helper execution | `ext::` or `git-remote-*` on PATH | `protocol.ext.allow=never` default `[K]` | `GIT_ALLOW_PROTOCOL` empty for local steps and pinned to one scheme for remote steps | A malicious `PATH` entry (acknowledged) | Yes |
| T16 | Malicious/compromised hooks | Write to hook files | Review | No hooks run (empty template, `--no-verify`) | Server-side hooks are the host's | Yes |
| T17 | Network identity / TLS | DNS or CA control | Certificate validation; pinned CA `GIT_SSL_CAINFO` | CA pin allowed; ssh `known_hosts` pinned | Corporate TLS interception, if the pinned CA is the interceptor | Partly |
| T18 | State rollback | Restore of the claim store | Backups with restricted admin | Executor login cannot `DELETE/UPDATE/TRUNCATE/DROP` `[R-doc]` | **Open by decision**: no external monotonic witness | **No** |
| T19 | Authorization reuse after a crash | A restart | n/a | Claim before effect; start record fsynced; `retry_permitted` always false | Burns authority on crashes; classification relies on unsigned files (case 54) | Process-kill tests: yes. Power loss: no |
| T20 | Executor compromise | Code exec inside the executor | OS isolation | The executor is the trusted base. "Code running inside it can read the credential while held" `[R-doc]` | By construction | No |
| T21 | Evidence tampering | Write to evidence dir or sign with the executor key | Append-only logs, external timestamping | Signed, offline-verifiable evidence; `EXECUTED` only if read-back SHA = approved SHA, enforced at build and verify | Unsigned local records drive recovery; no external timestamp/witness; credential not named in evidence | Signature: yes. Truth of the observation: no |
| T22 | Multiple routes to the same remote effect | Any other token, key, UI, API or admin | Revoke other credentials; rulesets with a single bypass actor | Static reachability tests prove MNDe's own code has one route | **Cannot be closed by software inside MNDe** | Detectable only by monitoring the host (opportunity O3) |

## 3. Authorization to attempt versus proof of acceptance

These are different facts with different witnesses, and conflating them is the central
error to avoid.

| Fact | Established by | Establishes | Does **not** establish | Who can forge or suppress it |
| --- | --- | --- | --- | --- |
| "This exact push was approved" | Signed authorization (approver key) | A key holder approved six exact values at a time, until an expiry | That anything was sent; that the approver understood the content | The approver key holder; anyone who can trick the approver |
| "The authority was spent once" | Claim-store row, `UNIQUE(namespace, grant_id)` | At most one attempt per grant, *as the database records it* | That the database was not restored (Q6) | The database owner |
| "A push was attempted" | Fsynced start record | A local file was written before the push | Anything about the remote; the record is unsigned | Anyone who can write the evidence directory |
| "The remote now has the approved SHA" | `git ls-remote` read-back by the executor, then signed | The executor key signed a statement that it read that SHA | That the remote truthfully answered; that the push was **this** executor's rather than another writer's with the same commit | The executor; the remote; a TLS interceptor |
| "Nobody else pushed" | Nothing local can establish this | | | |
| "The host agrees" | Host audit log / events API `[S, not tested]` | The provider's own record: actor, time, before/after | Anything about MNDe's intent | The provider; org owners with log access |
| `git ls-remote` | Live host answer | Current ref value | **History**: no server reflog by default `[L2]` | The host |
| Local logs/transcripts | Agent or shell history | What a process printed | Anything an attacker with the same OS user can edit | Same-user attacker |

**What is impossible without controlling the credentials or the remote**, stated flatly:

1. Preventing other pushes. Only the host's permission model and credential custody can do
   that. Software on the pushing side cannot see, let alone stop, a push made with another credential.
2. Proving that no other push path exists. Absence cannot be demonstrated by the actor that
   would benefit from it. The nearest substitute is *continuous reconciliation* of the host's
   own event stream against the set of executed authorizations (O3).
3. Preventing the host's administrator from rolling back, rewriting, or editing rules.
4. Proving the remote's answer was true. A read-back is a TLS-authenticated statement by the
   host, not a proof.
5. Ordering events against an adversarial operator without an external witness (time source
   or monotonic log) that the operator cannot roll back.

MNDe's honest claim, consistent with its own documents, is the narrower one: **an
authorization cannot be used twice by the executor, and the evidence it signs is bound to
what the executor read back**. Any wider claim is a deployment property.
