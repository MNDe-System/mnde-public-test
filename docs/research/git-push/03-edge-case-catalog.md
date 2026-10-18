# 03 · Git push edge-case catalog

Sixty-one cases: the forty requested (numbered 1–40, matching the brief's order) plus
twenty-one found while researching (41–61). Rows are grouped by theme, not in numeric order. Evidence tags are defined in [00-README.md](00-README.md).
Lab cases are in [`lab/run-lab.sh`](lab/run-lab.sh) with verbatim output in
[`evidence/lab-output.md`](evidence/lab-output.md).

**How to read the columns.** *Trigger* is in the Case column. *Remote changes?* means the
remote ref state after the event. *Retry safe?* means "can the same `git push` be re-run
with no new harm", which is different from "should MNDe's authority be reused" (it must not).
*MNDe* is what the typed `git.push` path does today, from code and tests `[R]`.

**Deliberate deviation from the brief.** The brief asks for GitHub/GitLab/Bitbucket
differences "where relevant" for every case. I could not test any hosted server and could
not open vendor documentation. Host differences are therefore given only where a search
summary supplied one, tagged `[S]`; otherwise the cell says nothing rather than guessing.
A per-case "Sources" column is merged into the *Evidence* column.

Reproducibility key: **R** = reproduced locally this session; **D** = documented upstream
and read this session; **T** = reported or reasoned only.

## A · Interruption, uncertainty, retry

| # | Case (trigger) | Git behavior | Remote changes? | Observable? | Retry safe? | MNDe handling → remaining gap | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Network drops **before** anything is sent | Client errors (exit 128) | No | Yes (error) | Yes | Pre-claim read fails → refuse, nothing spent `[R]`. Gap: none | `[K]` T |
| 2 | Drops **during object transfer** | Server discards the quarantine directory; "will not leave any on-disk data" | No | Client: error. Server: none | Yes | Claim already spent by then → `RECONCILED_NOT_APPLIED` after read-back (authority burned by design) `[R]`. Gap: burn rate on flaky links | `[P]` `[L30]` R (one run; timing-dependent) |
| 3 | Drops **after the remote accepted**, before the client got confirmation | Server finishes the update regardless; client prints nothing and does not update its tracking ref | **Yes** | Only by asking the remote | Git: yes (`Everything up-to-date`, exit 0); but it cannot tell you whether *you* or *someone else* made the state | Read-back after push decides `EXECUTED` vs not; ambiguous → `INDETERMINATE`, never retried `[R]`. Gap: nothing proves *this* push caused the observed SHA if another writer pushed the identical commit | `[L12]` `[L25]` R |
| 4 | **Timeout with unknown outcome** (client killed at its own timeout) | Same as 3: killing the client does not stop the server | Unknown until read | Via `ls-remote` | Git: yes. MNDe: no, the claim is spent | `execFile` timeout (30 s default) marks the push `indeterminate`, then the remote is read `[R: transport.mjs]`. Gap: 30 s is short for large packs; a legitimately slow push is killed mid-flight and classified by read-back only `[H]` | `[L12]` R · `[R]` |
| 5 | **Two developers** push at once | One wins by server CAS; loser `cannot lock ref … is at X but expected Y` → `remote rejected (failed to update ref)`, exit 1 | One change | Loser: yes | Yes after fetch/rebase | n/a | `[L14]` R |
| 6 | **Two agents** push at once | As 5; nothing coordinates them above Git | One change | Loser only if it reads the error | Agents may loop `pull --rebase` and re-push | Hub admits one action at a time (`busy` flag) `[R]`; the loser's `expected_old_sha` mismatch refuses **before** the claim when the remote already moved `[R]`. Gap: the narrow window between pre-read and push burns the loser's authority | `[L14]` R · `[R]` |
| 7 | **Force push overwrites** another's work | Old tip becomes an unreachable object; **no reflog on a bare repo** | **Yes (destructive)** | Only by comparing before/after | n/a | MNDe never forces: `--force-with-lease=<ref>:<sha>` plus a separate fast-forward test; `--force` is a forbidden argv member `[R]`. Gap: other credentials can still force | `[L2]` R |
| 8 | **Force-with-lease races** | Bare lease is defeated if anything fetched in the background; explicit `<ref>:<sha>` is not; `--force-if-includes` closes the bare case | Bare: yes (overwrites). Explicit: no | Explicit: `stale info` | n/a | MNDe uses the explicit form with the SHA the approver saw `[R]`. Gap: none for this effect | `[L3]` `[L4]` `[L5]` `[P]` R |
| 25 | **Ref moves between validation and execution** | Explicit lease turns validate-then-act into a refusal | No | `stale info` | Yes after re-read | Pre-read → FF check → claim → push-with-lease. Race between pre-read and push burns the authority `[R]`. Gap: window is small but real | `[L15]` R |
| 29 | **Retrying after an uncertain outcome** | Re-push of an applied update: `Everything up-to-date`, exit 0 | No | Yes | Git: yes | `retry_permitted` is always `false`; a human reconciles `[R]`. Gap: **no reconciliation tool exists**; each uncertain case needs manual inspection of PostgreSQL + start record + remote | `[L25]` R · `[R]` |
| 31 | **OS kills the process** (SIGKILL / OOM / reboot) | Client dies; server proceeds `[L12]` | Possibly | Not from the client | Not blindly | Start record is fsynced before the push, so the crash window is classifiable: after claim, before push → `NOT_STARTED`; start recorded, no outcome → `INDETERMINATE` `[R: test:git-push-isolation 9/9 re-run]`. Gap: classification reads **unsigned local files** (see 54) | `[L12]` R · `[R]` |

## B · Concurrency, ownership, ordering

| # | Case | Git behavior | Remote changes? | Observable? | Retry safe? | MNDe → gap | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 32 | **Multiple worktrees / concurrent git processes** | Shared object store and refs; one `index.lock` per worktree; second process fails `Unable to create '…index.lock'` (exit 128) | No | Yes | After the other process ends | Each execution builds its own staging repository from an empty template `[R]`. Gap: concurrent *executions* share the local repo's objects via alternates | `[L28]` R · `[R]` |
| 45 | Stale `index.lock` after a crash | Blocks every later git command in that tree until deleted by hand | No | Yes | After manual removal | Not MNDe's tree. Agent harnesses hit it `[S]` | `[L28]` R · `[S: augmentcode, termdock]` |
| 61 | Agents sharing one branch name | A branch can be checked out in only one worktree `[K]`; pushes still race on the remote ref | One change | | | No ref ownership or leasing across agents. Gap | `[K]` T |
| 52 | **Clock skew** between approver and executor | Authorization expiry is judged on the executor's clock | No | Refusal at executor | Needs fresh authorization | Executor uses its own clock; skew shortens or lengthens the window `[H]` | `[H]` T |

## C · Destructive or misdirected updates

| # | Case | Git behavior | Remote changes? | Observable? | Retry safe? | MNDe → gap | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 9 | **Branch deletion** | `git push origin --delete b` or `:b`: one character from `main:b` | **Yes** | Printed `- [deleted]` | n/a | Null SHA refused: "creating or deleting a ref is not in this effect's scope" `[R: validate.mjs]`. Gap: cannot delete even on request | `[L6]` R |
| 10 | **Tag replacement / deletion** | Tag update rejected unless forced (`already exists`) | With force: yes | Yes | n/a | Only `refs/heads/*` accepted `[R]` | `[L7]` `[P]` R |
| 11 | **Wrong repository** | `pushurl` and `pushInsteadOf` make "origin" mean different things for fetch and push | **Yes, elsewhere** | Not from `git remote get-url origin` (shows fetch URL) | | MNDe pushes to the signed `remote_url` literally (never the remote *name*) from a config-free staging repo; checks the local remote's URL equals the signed one `[R]`. Gap: identity is a name, not a provider repo id (24) | `[L17]` R · `[R]` |
| 12 | **Wrong branch** | `push.default=matching` pushes all same-named; typos like `origin/main` (new advice in 2.56); detached HEAD refuses | Possibly several | Printed refs | | `target_ref` is signed and exact `[R]` | `[P: RelNotes/2.56.0, config/push]` `[L22]` R |
| 39 | **Create vs update** | New ref has old = 0…0; an empty lease expectation means "must not exist" | Create: yes | | | **Creation is unsupported by design.** Most agent work starts with "create branch + push", so the typed effect covers only the second push onward. Coverage gap | `[L16]` R · `[R]` |
| 38 | **Commit changes after review** | A commit id fixes its content; an amended commit is a new id | No | | | `source_commit` is a full 40-hex id bound by signature, so the approved bytes cannot change `[R]`. **Strongest property of the design.** Gap: approver must see content, not just hex (opportunity O1) | `[K]` + `[R]` |
| 40 | **Exit 0 but remote ≠ pushed SHA** | A server-side hook or bot moved the ref after accepting it; client still prints success and its tracking ref says it landed | Ref differs | **Only** by reading the remote | No | Evidence says `EXECUTED` only if the read-back SHA equals the approved SHA; a third SHA is `INDETERMINATE`; enforced at build **and** at verify `[R: test:git-push-execution-evidence 49/49 re-run]`. Gap: none for this case | `[L26]` R · `[R]` |
| 50 | **Post-push side effects** (CI, deploy, webhooks, mail) | Run after the ref is updated and after the client already has its answer or not | Side effects irreversible | Host logs | n/a | MNDe can approve a push; it cannot recall the CI it triggers. A push to a deploy branch *is* a deployment | `[L13]` R |
| 59 | Merge queue / auto-merge bot moves the ref after a push | Same shape as 40 | Ref differs | Read-back | | `INDETERMINATE` `[R]`; operator reconciles | `[L26]` R (simulated) |

## C2 · Policy rejection, mixed outcomes, remote CI

| # | Case | Git / host behavior | Remote changes? | Observable? | Retry safe? | MNDe → gap | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 15 | **Remote rejected by branch protection** | Server-side refusal (`GH006` "protected branch hook declined", `GH013` rule violations on GitHub `[S]`); upstream equivalents `receive.deny*` and hooks refuse even `--force` `[L19]`. The rejection text may bury the rule name `[S: gitlab#287684]` | No | Yes, but message quality varies | Only after the cause is fixed | Claim is spent before the server decides, so a policy refusal **burns the authority**: the refusal is `RECONCILED_NOT_APPLIED`. A pre-claim probe of protection state would avoid it `[H]` | `[L19]` R · `[S]` |
| 16 | **CI passes locally, fails remotely** | Not a push failure: the push succeeds and CI (triggered by the host) fails afterwards | Yes | CI status | n/a | Approval binds a SHA, not "the SHA that passed CI". If approval is meant to mean "safe to land", the signed fields do not carry check status `[R]`. Gap, and an easy deterministic addition (O4) | `[K]` `[R]` |
| 34 | **Multi-ref push with mixed outcomes** | Without `--atomic`, rejected refs fail and the rest land; exit 1 hides which succeeded. With `--atomic` all fail together `[L8]`. Servers that do not advertise atomic hard-fail `[L9]` | Partial | Per-ref lines | Partial retry is safe per ref | One ref per execution; refspecs are not accepted `[R]`. Gap: none | `[L8]` `[L9]` R |

## D · Data hazards

| # | Case | Git behavior | Remote changes? | Observable? | Retry safe? | MNDe → gap | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 13 | **Accidental secret exposure** | Once pushed, treat the secret as compromised; deleting the ref does not recall clones, forks or caches `[K]`. Host push protection can block known patterns and logs overrides `[S]` | Yes | Host alerts `[S]` | No | **No secret detection in MNDe.** The approver sees six fields | `[S: docs.github.com enterprise-server push protection]` `[K]` |
| 14 | **Large files / LFS failures** | Over 100 MB is rejected by GitHub's pre-receive (`GH001`), warning at 50 MB `[S]`; LFS batch auth errors recur across hosts `[S]` | No (rejected) | Yes | After fixing history | No size check. See 17 for LFS | `[S]` |
| 17 | **`--no-verify` skips pre-push** | Hook never runs; also bypassed by `core.hooksPath` and `git send-pack` | Yes | No | | MNDe *itself* pushes with `--no-verify` and from an empty-template repository, deliberately `[R: transport.mjs]`. **Consequence `[L31]`: LFS-tracked files' objects are not uploaded**, so an approved push of a repo using LFS moves the branch to a commit whose large files are missing. Not in `KNOWN-ISSUES.md` | `[L18]` `[L31]` R |
| 26 | **Missing objects / shallow history** | Server connectivity check rejects pushes that reference absent objects; shallow clones can push normally in simple cases | No on reject | Yes | | MNDe requires both SHAs to resolve locally as commits; the ancestry test in a shallow clone may error → refuse (fail closed) `[H]` | `[L21]` R · `[P: receive-pack]` |
| 57 | Submodule pointer to a commit the submodule remote lacks | Superproject push succeeds; checkouts later fail | Yes | Not by push | | Not checked `[H]` | `[K]` T |
| 58 | SHA-1 collision | Content binding by commit id depends on the hash; Git uses collision-detecting SHA-1; SHA-256 repositories exist | n/a | | | Theoretical. Id-binding is only as strong as the object format | `[K]` T |

## E · Authority, identity, credentials

| # | Case | Behavior | Remote changes? | MNDe → gap | Evidence |
| --- | --- | --- | --- | --- | --- |
| 18 | **Credential expires during execution** | HTTPS: later request gets 401; stateless POST means no partial update `[H]`. Long LFS uploads retry on 401 `[S]` | No | Credential is acquired late and released right after the post-read; token lifetime > 2 h refused `[R]`. Gap: expiry between claim and push burns the authority | `[S: gitlab#218818]` `[R]` |
| 19 | **GitHub App installation token expires** | One-hour lifetime; new token format rollout dated 2026-04-27 `[S]` | No | MNDe mints one per execution and revokes after (tested against a **stub** of the GitHub API only) `[R-doc]`. Gap: never run against GitHub | `[S: docs.github.com]` |
| 20 | **Permissions change between authorization and execution** | Server judges permission at push time | No (refused) | Pre-state read uses the credential for *upload-pack*, which proves read, not write. The first proof of write permission is the push itself, after the claim is spent. **Opportunity:** a pre-claim write probe via the receive-pack advertisement (`git push --dry-run` form) `[H]` | `[R]` `[H]` |
| 33 | **Protected branches, required checks, policy changes** | Server refuses with `GH006`/`GH013` `[S]` | No | Claim already spent. No drift detection between approval and execution | `[S]` |
| 35 | **Compromised credentials / unexpected remote access** | Anything with a valid token pushes | Yes | MNDe cannot see pushes it did not perform. Nothing detects "unaccounted pushes" (O3) | `[R]` |
| 36 | **Alternate push paths** | Web editor, contents API, other tokens, deploy keys, Actions `GITHUB_TOKEN`, repo admins, `git send-pack`, a second remote | Yes | `test:git-push-reachability` 14/14 proves **MNDe's own code** has one path; it cannot prove the agent lacks others. In the 2026-10-16 assessment the agent held an **admin** token (criterion C2 NOT ESTABLISHED) `[R-doc: F001-ACCEPTANCE-MATRIX]` | `[R]` |
| 37 | **Rollback of spent-authority state** | At the Git layer an identical push becomes valid again if the remote is restored: after a restore, re-running the same push applied it a second time and nothing at the Git layer remembered it was spent | Yes | Claim store prevents replay unless the database owner restores a backup (Q6, open by decision) | `[L27]` R · `[R-doc]` |
| 30 | **Replay of valid authorization** | Git has no authorization concept; replay safety is only the lease | | Single-use claim keyed `UNIQUE(namespace, grant_id)`; 16/16 single-route suite re-run with a **test double**; PostgreSQL 22/22 is `[R-doc]` | `[R]` `[R-doc]` |
| 24 | **Local and remote identity disagree** (rename, transfer, fork, case) | GitHub redirects renamed/transferred repos `[K]`; owner/repo case-insensitive `[K]` | Possibly another repo | MNDe binds a *name-derived* identity (`https:github.com/org/repo`), not the provider's immutable repository id `[R]`. Case differences fail closed `[R: probe]`. Gap `[H]` | `[R]` |
| 21 | **DNS changes / endpoint substitution** | TLS hostname validation protects https; ssh needs `known_hosts` | Possibly | `GIT_SSL_CAINFO` pin; ssh credential kind pins `known_hosts`; environment built from empty `[R]` | `[R]` |
| 22 | **Redirects** | `http.followRedirects` governs; token header could follow a redirect | Possibly | Credential header is attached for one URL and "redirects refused" `[R-doc: PRODUCTION-TRUST-BOUNDARY]`. Repo renames still redirect server-side `[K]` | `[K]` `[R-doc]` |
| 23 | **Malformed URL escaping, Unicode** | See below | | **Observed by probe** `[R]`: port is dropped from identity (`github.com:8443` ≡ `github.com`); `%2F` decodes to `/`; `%00` yields an identity containing NUL; a malformed escape (`%E0%A4%A`) makes the validator **throw** `URIError` instead of refusing; IDN hosts become punycode (distinct, good) | `lab/identity-probe.mjs` R |
| 60 | Credential-helper injection (CRLF / escape sequences) | Fixed upstream in 2.43.6 / 2.48.1 and siblings | | MNDe does not use credential helpers (token via `GIT_CONFIG_*` header). The local Git reports 2.43.0; distributions often backport security fixes without changing that string, and I did not check | `[S: github.blog git-security-vulnerabilities-announced-5]` |

## F · Evidence and local failure

| # | Case | Behavior | MNDe → gap | Evidence |
| --- | --- | --- | --- | --- |
| 27 | **Disk failure while writing evidence** | n/a | Start record write failure → nothing sent. Signed evidence failure **after** a landed push → `EFFECT_EXECUTED_EVIDENCE_FAILURE`, "do not retry" `[R]`; fault-injected in CLI tests `[R-doc]` | `[R]` |
| 28 | **Power loss before / during / after acceptance** | n/a | **Never tested** (Q4). `-m immediate` restart is not power loss. Windows directory flush "not a demonstrated guarantee". Hub reports `powerLossProtection: "not_installed"` | `[R-doc]` |
| 54 | **Evidence tamper on the executor host** | n/a | Signed evidence is verifiable offline; but `classifyGitPushExecution` decides `NOT_STARTED` / `INDETERMINATE` from **unsigned** local files in the evidence directory. Anyone who can write that directory can turn "sent" into "not started" (a retry-permission lie) or the reverse `[R: reading index.mjs]`. Severity depends on directory permissions | `[R]` |
| 53 | Large push vs fixed 30 s timeout | n/a | See 4 | `[R]` |
| 55 | Fork pushes / bypass inherit from the root repo | Push rules apply to the fork network; bypass comes from the root repository `[S]` | Not applicable to MNDe today | `[S: docs.github.com about-rulesets]` |

## G · Operator-facing error quality

| # | Case | Observed | Evidence |
| --- | --- | --- | --- |
| 41 | Hook rejection text varies; the real reason may be above the final error line | `remote: locked branch` / `hook declined to update`; a GitLab issue complains the user gets no description of which rule failed | `[L8][L11]` R · `[S: gitlab#287684]` |
| 42 | Unsupported capability → **exit 128** and "the remote end hung up unexpectedly", the same sentence used for proxy/size failures | `--atomic`, `--signed`, `-o` | `[L9][L10][L20]` R · `[S: Atlassian KB]` |
| 43 | A push blocked by secret scanning because the git config pushes extra refs the user did not intend | host docs warn about it | `[S]` |
| 44 | Editors and shell plugins fetch in the background and silently weaken bare leases | Git's manual documents the cause and a workaround (second remote) | `[P]` `[L3]` R |
| 46 | Detached HEAD with no refspec | `fatal: You are not currently on a branch` (exit 128) with the exact fix printed | `[L22]` R |
| 47 | Branch names differing only by case on case-insensitive filesystems | Loose-ref files collide `[K]` | `[H]` |
| 48 | A name that is both branch and tag is ambiguous in a refspec | `[K]` | `[H]` |
| 49 | Unsupported server capability silently downgrades vs hard-fails | Hard-fails for atomic/signed/options `[L]` | `[L9][L10][L20]` R |
| 51 | Webhook and merge-queue interplay | not tested | `[H]` |
| 56 | Hidden refs (`receive.hideRefs`) and namespaces change what a push can see | `[P: config/receive]` | `[P]` |

## What this catalog says in one paragraph

Of the sixty cases, the ones that Git itself handles safely (rejects, CAS races, quarantine
cleanup) are mostly *safe by default and boring*. The cases that hurt are the **ambiguous
ones** (3, 4, 29, 31, 40), the **bypassable-client-check ones** (17, 36), and the
**destructive-by-syntax ones** (7, 8, 9). MNDe's typed effect removes the destructive-by-syntax
and bypass cases by construction and handles the ambiguous ones conservatively. What it does
not yet address: write-permission proof before spending authority (20), LFS (17), repository
identity by immutable id (24), canonicalization defects (23), unsigned recovery state (54),
and the large class of alternate paths that no code inside the executor can close (36).
