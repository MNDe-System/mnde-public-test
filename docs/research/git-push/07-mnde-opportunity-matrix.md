# 07 · MNDe's Git push model: what exists, what is proven, what to add

Evidence tags are defined in [00-README.md](00-README.md). Everything labelled `[R]` was
read in this checkout (merged `main` at `3f0e3a5`) or re-run this session. `[R-doc]` means a
repository document records it and I did not reproduce it. **Passing unit tests are never
treated here as production readiness**, as the brief requires, and the repository's own
documents take the same position.

## 1. The model under review

```
Agent proposes push → MNDe validates exact action → policy evaluates → approval if necessary
 → execution authority claimed → isolated executor performs push → remote outcome checked
 → signed evidence produced
```

As built `[R: src/effects/git-push/index.mjs, docs/GIT-PUSH-EFFECT.md]`, the operative order
inside the executor is: verify an executor-bound authorization (both signature layers rest
on the operator's authority, never the shipped demo one) → bind six signed fields to the
request exactly → check the local remote URL equals the signed one → build a config-free
staging repository → confirm both commits exist → acquire a per-push credential → read the
remote ref (must equal `expected_old_sha`) → require fast-forward ancestry → **durably claim
the grant** → fsync a start record → `git push --no-verify --force-with-lease=<ref>:<old> --
<url> <new>:<ref>` → read the remote back → release the credential → sign evidence.

## 2. Status of each capability (the five-way classification)

Key: **IMPL** implemented in code · **LOCAL** tested locally (CI-style, test doubles) ·
**INDEP** proven on independent infrastructure · **UNVER** unverified · **DEFECT** known
defect or documented open limit.

Re-run this session on **Node 22.22.0** (the repository requires Node ≥ 24, so these are
re-runs on the wrong runtime, with `npm ci` not run): `test:git-push-effect` 27/27,
`-isolation` 9/9, `-single-route` 16/16, `-reachability` 14/14, `-execution-evidence` 49/49,
`test:hub` 18 passed / 0 failed, `test:issuance-guard` 53/53. `test:git-push-cli` scored 34/35;
the one failure (case N) is the packaging step failing with
`Cannot find package 'typescript'` because dev dependencies were not installed; the
2026-10-16 assessment records the same suite at 35/35 on Node 24.22.0 `[R-doc]`. I did not
run it on Node 24. Raw tails: [`evidence/repo-test-run-2026-10-18.txt`](evidence/repo-test-run-2026-10-18.txt).

| Capability | IMPL | LOCAL | INDEP | UNVER | DEFECT / limit | Evidence and notes |
| --- | --- | --- | --- | --- | --- | --- |
| Typed `git.push` effect: fixed argv, no shell, no caller flags, forbidden-flag list | ✔ | ✔ | ✘ | | | `[R]` code read; suites above |
| **Exact ref + commit binding**: 6 signed fields, exact key set, request must equal signed values field for field; full 40-hex only; null/abbreviated/option-like refused | ✔ | ✔ | ✘ | | **New (this research):** canonicalization defects, §3 | `[R]` |
| Fast-forward only, existing refs only, `refs/heads/*` only | ✔ | ✔ | ✘ | | **By design, a coverage limit:** cannot create or delete branches or move tags | `[R: validate.mjs]` |
| Remote pre-state read and lease-guarded push (TOCTOU) | ✔ | ✔ | ✘ | | Window between pre-read and push burns authority | `[R]` `[L15]` |
| **One-use execution authority** (claim before effect, ticket bound to argv digest, ticket spent on first redemption) | ✔ | ✔ with a **test double** | ✘ | PostgreSQL behavior at this commit | | `[R]` single-route 16/16; PostgreSQL 22/22 at `714b8ff` is `[R-doc]` and was not re-run |
| **PostgreSQL claim durability** (fsync on, restricted `NOINHERIT` login, `UNIQUE(namespace, grant_id)`, 32-way concurrency) | ✔ | ✘ in CI (no PostgreSQL) | **✘** (C9 BLOCKED: no independent DB) | Power loss (Q4) | Operated 2026-09-26 on a self-hosted primary, "a rehearsal, not a deployment" `[R-doc]` | `docs/F001-CLAIM-STORE-PROOF.md`; `psql` client present here, no server |
| **Rollback attacks on the claim store** | ✘ (no witness) | | | | **KNOWN, open by decision (Q6):** "the executor cannot roll the claim store back" is the only supportable claim; the DB owner can restore a backup. `docs/PRODUCTION-TRUST-BOUNDARY.md`: "No such design exists" | `[R-doc]` |
| **GitHub App credential isolation** (per-push App JWT, token scoped to one repo, permission check, expiry cap, revoke after) | ✔ | ✔ against a **stub** of the GitHub API | ✘ | Behavior against real GitHub | Agent held an **admin** token in the assessed environment (C2 NOT ESTABLISHED) | `[R-doc]`; credential-custody suite 17/17 recorded `[R-doc]` |
| ssh-key credential kind | ✔ | command construction only | ✘ | "no sshd was contacted in tests" | | `[R-doc]` |
| **Physical Hub approval** | Hub service: ✔ (headless Node service, loopback, bearer auth). **Physical device/button/OLED: ✘ "future work"** | ✔ `test:hub` 18/18 re-run | ✘ | Raspberry Pi behavior, arm64, thermal, power loss, systemd | `powerLossProtection: "not_installed"`; "USB flash does not solve sudden power loss" | `[R]` `docs/MNDE-HUB.md`. The Hub accepts *existing signed approval artifacts*; it does not mint approvals |
| Approvals (Hub path): signed, scoped to the action record, distinct issuer keys, expiry | ✔ | ✔ | ✘ | | **UC-005 (unclassified):** the sidecar path's approvals bind a tool name, not the action; Hub path avoids it | `[R-doc]`, pinned by `test:issuance-guard` 53/53 `[R]` |
| `approval_required` must have anchors (UC-002) | ✔ fixed | ✔ + mutation checker (11/11 `[R-doc]`) | ✘ | | UC-003 (`authority_required`) unclassified | `[R]` |
| Config-free staging repo (blocks `.git/config` steering) | ✔ | ✔ isolation 9/9 | ✘ | | Fixed after a reproduced exploit (arbitrary program ran in an authorized push) | `[R]` |
| Static single-route guarantee for MNDe's own code | ✔ | ✔ 14/14 | n/a | | Cannot cover other credentials or in-process hostile code | `[R]` |
| **Crash consistency**: fsynced start record; `classifyGitPushExecution` | ✔ | ✔ real child process killed at two points | ✘ | **Power loss (Q4); Windows directory flush** | Classification reads **unsigned** local files (case 54) | `[R]` |
| **Signed evidence** (root → credential → evidence; `EXECUTED` only if read-back SHA = approved SHA, checked at build and verify) | ✔ | ✔ 49/49 | ✘ | | Evidence **does not name the credential** (C6); pre-verification refusals are unsigned | `[R]` `[R-doc]` |
| **Replay and freshness** (expiry, executor-bound, nonce store, policy serial floor) | ✔ | ✔ | ✘ | Clock-skew behavior | | `[R]` |
| **Recovery after an uncertain push** | classification ✔; **reconciler ✘** | ✔ | ✘ | | `retry_permitted` always false; a human reconciles three stores by hand | `[R]` |
| **Independent infrastructure verification** (F-001) | | | **✘ none** | | F-001 NOT closed; blockers: independent DB (C9), credential separation (C2), Q4, Q6, C6 | `docs/F001-ACCEPTANCE-MATRIX.md` `[R-doc]` |
| Offline verification of evidence | ✔ | ✔ | n/a | | Verifies a *signature and coherence*; not the truth of the observation | `[R]` |
| Alternate effect paths | ✔ closed inside MNDe code | ✔ | ✘ | Other credentials | `DISPATCH_ENABLED=false` for the generic executor `[R]`; UC-004 (no `exports` map → deep imports) unclassified | `[R-doc]` |
| Git LFS correctness of the pushed state | ✘ | | | | **New:** `--no-verify` + hook-free staging ⇒ LFS objects not uploaded `[L31]` | not in `KNOWN-ISSUES.md` |

**Statement of record.** Nothing above is `INDEP`. By the repository's own acceptance matrix,
the claim that matters ("an agent cannot push except through the boundary") "has never been
demonstrated on independent infrastructure", and in the assessed environment the agent held
an admin token. The code is better evidenced than most; the **claim** is not yet evidenced
at all.

## 3. New findings from reading and probing the code (not in `KNOWN-ISSUES.md`)

All reproducible with [`lab/identity-probe.mjs`](lab/identity-probe.mjs) (read-only) or the
lab. None changes any code. Severity is my judgment.

| # | Finding | Evidence | Severity | Why it matters |
| --- | --- | --- | --- | --- |
| N1 | `canonicalRepositoryIdentity` **drops the port**: `https://github.com:8443/org/repo.git` ≡ `https://github.com/org/repo.git` | `[R]` probe | Low–medium | The credential allowlist and the `repository` binding are keyed on this string. A self-hosted forge on a non-default port shares identity with its default-port twin. Exploitation needs a host the attacker controls on another port of an allowed host; not demonstrated |
| N2 | The identity **percent-decodes the path**: `org%2Frepo.git` ≡ `org/repo`, and `repo%00.git` yields an identity containing a NUL character | `[R]` probe | Low | Two different URLs, one identity. `hasUnsafeCharacters` runs on the raw URL, so `%00` and `%2F` pass |
| N3 | A malformed escape (`%E0%A4%A`) makes `validateGitPushParameters` **throw `URIError`** instead of returning a refusal | `[R]` probe; the CLI maps a throw to `INTERNAL_ERROR` ("may have come after the push began") and the Hub maps it to a 400 at its front door `[R]` | Low | Inconsistent fail-closed: nothing was sent, but the CLI tells the operator it may have been. Only reachable with a *signed* authorization for such a URL |
| N4 | **Repository identity is a name, not the provider's immutable id**; GitHub redirects renamed/transferred repos `[K]` | `[R]` + `[K]` | Medium `[H]` | After a rename, an approval for the old URL may still push (via redirect) to the new owner's repo, or fail closed, depending on redirect handling; untested |
| N5 | Recovery classification reads **unsigned** files (`git-push-<id>.started.json`, `*.json`) | `[R: index.mjs classifyGitPushExecution]` | Medium if the evidence directory is writable by an attacker | Rewriting these converts `INDETERMINATE` to `NOT_STARTED`, which the docs map to "needs a fresh authorization" |
| N6 | **Claim is spent before write permission is proven.** The pre-state read uses `ls-remote` (upload-pack: read), so a permission change, branch-protection refusal, or expired token discovered at push time burns the authority | `[R]` | Medium (operational) | Each such failure costs a new human approval. A write-permission probe before the claim is feasible `[H]` |
| N7 | Fixed **30 s** timeout; a legitimately slow push is killed and classified by read-back | `[R: DEFAULT_TIMEOUT_MS = 30_000]` | Low–medium | Large pushes become `INDETERMINATE` or `RECONCILED_NOT_APPLIED` despite landing a few seconds later |
| N8 | `--no-verify` and hook-free staging **skip LFS** | `[L31]` | Medium for LFS repos | An approved push can move a branch to a commit whose large files do not exist on the LFS server |
| N9 | Creating a branch is unsupported by design | `[R]` | Product-coverage | The most common agent flow is `create branch → push → open PR`; only step 2's *later* pushes fit |

## 4. What a deterministic, no-inference "push preflight" could check

The brief asks which checks belong in MNDe and which are convenience. **Criterion used:**
a feature is *core enforcement* if it strengthens a signed claim or closes a bypass;
*convenience* if it only helps a human decide; *avoid* if it duplicates the host or needs
inference.

| Check | What it computes locally (no model) | Core / convenience / avoid | Reasoning |
| --- | --- | --- | --- |
| Wrong-branch detection | Signed `target_ref` vs. current branch, upstream, and `push.default` result | Convenience (the signed ref already prevents the effect) | Useful in the approval preview |
| Protected-branch warning | Read host ruleset/protection for the ref (GitHub API) | Convenience now; **core** if used as the pre-claim probe (N6) | Avoids burning authority |
| Unexpected commit count | `git rev-list --count old..new` shown and optionally signed as a bound field | Convenience; **core if signed** | A signed upper bound limits "approve one commit, push forty" |
| Unexpected file modifications | `git diff --name-status old..new` with a signed digest of the file list | **Core for the approval preview** | Makes the approval human-meaningful; the SHA already fixes content, the preview makes it legible |
| Secret detection | Pattern/entropy scan of the diff | Convenience only | The host already scans (push protection `[S]`); do not become a scanner |
| Large binary detection | Blob size and binary detection over the diff | Convenience | Also host-enforced (100 MB) `[S]` |
| Dependency / workflow changes | Flag changes to lockfiles, `package.json`, `.github/workflows/**`, `.gitmodules`, hook paths | **Core for the preview** | A workflow edit is a code-execution grant inside CI; highest-value deterministic flag |
| Ref ancestry | Already implemented (`merge-base --is-ancestor`) | Core, exists | |
| Concurrent update detection | Already implemented (pre-read + lease) | Core, exists | |
| Policy drift | Re-read rulesets and compare to the last verified snapshot; alert on new bypass actors or admins | **Core** | Converts the unverifiable exclusivity claim into a monitored one (O3) |
| Push risk score | Explicit rule table → low/medium/high | Convenience | Only if rules are explicit and shown; **avoid** any opaque or learned score |
| Recovery and reconciliation | Read-only join of claim row + start record + remote ref → one verdict | **Core** | Closes the gap in case 29 |
| Action-bound approval preview | Render `{repo, ref, old→new, commit list, file list, flags}` from the signed values and the local object store, byte-reproducible | **Core** | It is the human half of "exact action". What-you-see-is-what-you-sign needs the render to be derivable from the signed SHA, which it can be |

## 5. Opportunities (O1–O15), summarized

Full scoring and ranking are in [09](09-prioritized-findings.md). The list:

| ID | Opportunity | One line |
| --- | --- | --- |
| O1 | Action-bound approval preview | Deterministic render of exactly what the signed SHA contains |
| O2 | Productized agent-environment checker | Prove, from inside the agent's session, that no push-capable credential is reachable |
| O3 | Unaccounted-push detector | Reconcile the host's push events against executed authorizations; alert on pushes MNDe did not perform |
| O4 | Local deterministic preflight | Workflow/lockfile/binary/commit-count flags shown at approval time |
| O5 | Repository-controls verifier + drift monitor | Productize `check-repository-controls`; watch for bypass-actor changes |
| O6 | Reconciler for `INDETERMINATE` | One command that joins claim row, start record and remote state |
| O7 | Pre-claim write-permission probe | Stop burning authority on permission/protection refusals |
| O8 | Branch-create and PR-open typed effects | Cover the actual agent flow |
| O9 | Credential named in signed evidence + host-record corroboration | Closes C6 |
| O10 | External monotonic witness for the claim store | Closes Q6 |
| O11 | Evidence as a required status check | Make the host demand a valid MNDe receipt for the head SHA |
| O12 | Server-side `pre-receive` verifier for self-hosted forges | Host enforces approval itself |
| O13 | Ref reservation across agents | Per-ref ownership leases |
| O14 | Identity by provider repository id; canonicalization fixes | Closes N1–N4 |
| O15 | LFS-aware push (upload in the executor) | Closes N8 |
