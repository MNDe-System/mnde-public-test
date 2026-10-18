# 08 · Git push failure laboratory: design, results, and what local simulation cannot prove

Evidence tags are defined in [00-README.md](00-README.md).

## 1. Design rules

* **Isolation.** Every remote is a bare repository under `mktemp -d`; every client is a
  clone of it. `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`,
  `GIT_TERMINAL_PROMPT=0`. No network socket is opened. The temp tree is removed on exit.
* **No production effect.** No GitHub operation, credential, token, or permission change.
  The only network use in this whole research was web search and one public `git clone` of
  `git/git`.
* **Honesty about scope.** The transport is Git's *file transport* (`git-receive-pack`
  spawned locally) on **Git 2.43.0** with git-lfs 3.4.1. It proves upstream-Git properties.
  It does not prove anything about HTTP, SSH, GitHub, GitLab or Bitbucket.
* **Asserts are written before looking at results, then corrected honestly.** Two of my
  initial assertions were wrong (L09/L10: I expected exit 1; Git exits 128 for an
  unsupported capability). The script keeps the corrected assertions and says why. 33
  assertions passed, 0 failed in the final run.
* **Race outcomes are printed, not asserted**, when timing decides them (L12, L13, L30).

Run: `bash lab/run-lab.sh > out.md` (≈ 40 s). Verbatim output of the run reported here:
[`evidence/lab-output.md`](evidence/lab-output.md).

## 2. Executed experiments (L01–L31)

"Initial state" is always: remote `R` (bare, one commit `base` on `main`), clones `A` and
`B` at `base`, unless stated. "Cleanup" is always: the whole temp tree is deleted on exit.

| ID | Experiment | Actions | Assertions | Observed (this session) |
| --- | --- | --- | --- | --- |
| L01 | Non-fast-forward | A pushes a commit; B (behind) pushes | exit ≠ 0; remote keeps A's commit | `! [rejected] main -> main (fetch first)`, exit 1 |
| L02 | Plain `--force` | A pushes; B force-pushes | remote at B | Overwritten. **No reflog on the bare remote.** A's commit remained as an object but reachable from 0 refs |
| L03 | Bare lease vs background fetch | A pushes; B fetches (auto-fetch stand-in); B `--force-with-lease` | (documenting) | **Push succeeded and removed A's unseen commit**, exit 0 |
| L04 | Explicit lease on reviewed SHA | Remote moves after "review"; B pushes with `--force-with-lease=main:<seen>` | refused; remote unchanged | `! [rejected] (stale info)`, exit 1 |
| L05 | `--force-if-includes` | As L03 plus `--force-if-includes` | refused; remote unchanged | `! [rejected] (remote ref updated since checkout)`, exit 1 |
| L06 | Branch deletion | `git push origin --delete feature` | ref gone | `- [deleted]`, exit 0 |
| L07 | Tag replacement | Move local tag; push; push `--force` | rejected, then replaced | `(already exists)`; with force, remote tag = local |
| L08 | Multi-ref, one rejected by an `update` hook | Push `ok` + `locked`; then `--atomic` | non-atomic: `ok` lands, `locked` not; atomic: neither | Exactly that; non-atomic exit 1 with **partial success** |
| L09 | `--atomic`, server not advertising | `receive.advertiseAtomic=false` | fails closed | **exit 128**: `the receiving end does not support --atomic push` / `remote end hung up unexpectedly` |
| L10 | `--signed`, no push-cert | `git push --signed=yes` | fails closed | **exit 128**, `does not support --signed push` |
| L11 | `pre-receive` rejection; quarantine | Hook prints `$GIT_QUARANTINE_PATH`, reads new object, exits 1 | ref unchanged | Object readable inside the hook via a `tmp_objdir-incoming-*` path; after rejection **absent from the permanent store** |
| L12 | Client SIGKILLed mid-push | `pre-receive` sleeps 3 s; kill client at 1 s | (documenting) | Client exit 137. **Remote ref advanced 3 s later.** Client's tracking ref stale. Naive retry: `Everything up-to-date`, exit 0 |
| L13 | When does the client hear back? | `post-receive` sleeps 3 s then exits 3 | ref updated | Client exit 0 after **3.0 s**; `remote: post-receive done` printed before the result. Failing `post-receive` did not change the exit status |
| L14 | Two clients, same ref, simultaneously | `pre-receive` sleeps 2 s; A and B push different fast-forwards at once | exactly one winner | A: `cannot lock ref 'refs/heads/main': is at … but expected …` → `remote rejected (failed to update ref)`, exit 1; B exit 0 |
| L15 | Remote moves between validation and execution | Read remote; another writer pushes; A pushes with `--force-with-lease=…:<read>` | refused; remote at B | `stale info`, exit 1 |
| L16 | Create vs update leases | Lease with an existing SHA on a non-existent ref; empty-expect lease; repeat | create only with the empty form | `stale info` for the first; second creates; third `Everything up-to-date` |
| L17 | `pushurl` / `pushInsteadOf` | Set `remote.origin.pushurl` to another repo; then `url.<x>.pushInsteadOf` | push goes to the push URL | Push landed in the other repo; `remote get-url origin` still showed the fetch URL; `--push` showed the real destination |
| L18 | Hook bypass | Blocking `pre-push`; try normal, `--no-verify`, `git send-pack`, `-c core.hooksPath=/nonexistent` | normal blocked; each of the three others lands | All three bypasses landed |
| L19 | Server-side deny settings | `receive.denyNonFastForwards`, `receive.denyDeletes` | `--force` and delete refused | Both refused; message `denying non-fast-forward` |
| L20 | Push options | `-o ci.skip` before and after `receive.advertisePushOptions` | fails then works | **exit 128** `does not support push options`; then hook saw `GIT_PUSH_OPTION_0=ci.skip` |
| L21 | Shallow clone | `--depth 1` clone; fast-forward push; push a new branch | (documenting) | Both succeeded |
| L22 | Detached HEAD | `git push origin`; then `HEAD:refs/heads/x` | explicit form creates | exit 128 `You are not currently on a branch` with fix text; explicit form worked |
| L23 | Unwritable remote | `chmod -R a-w` on remote | (documenting) | **Inconclusive**: lab ran as root, so mode bits did not apply (push succeeded) |
| L24 | Protocol version | `GIT_TRACE_PACKET`, `protocol.version=2` | (documenting) | Zero `version 2` lines; v0 advertisement with capabilities `report-status report-status-v2 delete-refs side-band-64k quiet atomic ofs-delta …` |
| L25 | Benign retry | Re-push an applied update | exit 0 | `Everything up-to-date` |
| L26 | Exit 0 but remote ≠ pushed SHA | `post-receive` moves the ref back one commit | remote differs from pushed SHA | Client printed success, exit 0; remote at a different SHA; client's tracking ref believed it landed |
| L27 | Remote restored from backup, identical push re-run | Copy `R` to backup; push; restore backup; push again | second push applies | It applied again. Nothing at the Git layer remembered it was spent |
| L28 | Stale `index.lock` | Create `.git/index.lock`; `git add` | (documenting) | exit 128 with the "Another git process seems to be running" text |
| L29 | Bare lease without a tracking ref | Bare lease creating a branch; bare lease on a ref with no tracking ref | (documenting) | Creating: exit 0. Ref with no tracking ref: `stale info`, exit 1 |
| L30 | Client SIGKILLed during a 120 MB pack transfer | Random 120 MB blob; kill at 0.4 s | (documenting) | Exit 137; ref unchanged; object absent; **no leftover quarantine dirs or `tmp_pack_*`**. Single run; timing-dependent |
| L31 | Git LFS and `--no-verify` | LFS-tracked `*.bin`; normal push, then push with `--no-verify` | (documenting) | Normal push: 1 LFS object on remote. After `--no-verify` push: pointer commit accepted, **LFS object count still 1** (second object not uploaded). Clone check inconclusive on file transport |

Also re-run from the repository (not part of the lab script): `test:git-push-isolation` 9/9
(including a real child process killed after the claim → `NOT_STARTED`, and killed while the
push was blocked inside a remote `pre-receive` → `INDETERMINATE`), `test:git-push-effect`
27/27, `-single-route` 16/16, `-reachability` 14/14, `-execution-evidence` 49/49,
`test:hub` 18/18 `[R]`.

## 3. Mapping to the brief's required experiment areas

| Area | Covered by | Gap |
| --- | --- | --- |
| Network interruption | L12, L30 (client kill on file transport) | Real HTTP/SSH connection resets, proxies that drop mid-stream, half-open TCP: **X01** |
| Concurrent updates | L14, L28 | Host-side behavior; many-writer soak; **X02** |
| Replay | L25, L27; repo single-route tests (test double) | Against a real PostgreSQL with restore: **X03** |
| Push-result ambiguity | L12, L13, L26 | MNDe-level run of the executor against a remote that moves the ref: **X04** |
| Remote mismatch | L17; repo isolation suite | Redirects and renamed repositories on a real host: **X05** |
| Force-with-lease behavior | L03, L04, L05, L15, L16, L29 | None for upstream Git |
| Branch deletion | L06, L19 | None for upstream Git |
| Ref creation | L16 | None |
| Multiple-ref updates | L08, L09 | Host atomic support: **X06** |
| Credential failures | none | Needs an HTTP server: **X07** |
| Hook bypass | L18, L31 | None for upstream Git |
| Evidence persistence | repo fault-injection tests (documented 35/35 on Node 24) | ENOSPC/EIO injection that is not mocked: **X08** |
| Simulated crashes / power failure | L12; repo child-process kill tests | Real power loss: **X09** |
| Claim-store rollback | none | Needs PostgreSQL snapshot/restore: **X03** |
| Alternate execution paths | L18 (`send-pack`); `test:git-push-reachability` | From a non-admin identity in the deployed topology: **X10** |

## 4. Experiments that need infrastructure this environment does not have

Each lists what is needed, the check, and what a pass or fail would mean. **None has been
run. No result is claimed.**

| ID | Needs | Initial state | Actions | Assertions | If it passes | If it fails |
| --- | --- | --- | --- | --- | --- | --- |
| X01 | A local HTTP server for `git http-backend` plus a fault-injecting TCP proxy (loopback only) | Bare repo behind http-backend | Reset the TCP connection at: before request, mid-POST body, after the POST body but before the response; repeat with a 120 MB pack | After each: ref value; leftover quarantine; client exit; tracking ref | Confirms the HTTP analogue of L12/L30 (update lands if the body was complete) | The HTTP stateless-RPC path differs from the file path, which would invalidate parts of case 3/4 |
| X02 | None beyond this machine | Bare repo; N=16 clients with unique fast-forward commits | Push all at once, repeat 200 times | Exactly one winner per round; no corrupt refs; every loser sees `cannot lock ref` or `fetch first` | Confirms L14 at scale | Ref-lock leak or corruption (unexpected) |
| X03 | A disposable PostgreSQL server and a snapshot facility; ideally an independently administered one (criterion C9) | Claim table with N spent grants | Stop; restore an older snapshot; re-present a spent grant | Executor login cannot delete/update; restored snapshot **does** revive the grant | Quantifies Q6 exactly; justifies the witness | If a spent grant stayed spent after restore, the store has an unexpected extra durability (not expected) |
| X04 | Existing test fixtures (`tests/support/git_push_fixtures.mjs`) | Remote with a `post-receive` that moves the ref | Run the executor on an approved push | Outcome `INDETERMINATE`, reason `ERR_GIT_PUSH_POSTSTATE_MISMATCH`, signed evidence verifies, `EXECUTED` never emitted | Confirms case 40 end-to-end at the MNDe layer (pure function `decidePushOutcome` is already unit-tested `[R-doc]`) | A reported `EXECUTED` would be a serious defect |
| X05 | A forge that supports rename/transfer (self-hosted Gitea/GitLab) | Repo renamed after approval | Execute the old-URL authorization | Refused vs. pushed through a redirect | Settles finding N4 | Pushing through a redirect = identity binding too weak |
| X06 | Each target forge | Branch protection rules | `git push --atomic a b` where `b` is blocked | Atomic honored? partial? exit codes | Per-host atomic semantics (L09 shows upstream behavior only) | |
| X07 | The HTTP server from X01, plus a stub returning 401/403/expired after N requests | `info/refs` ok, POST rejected | Run the real executor credential path with a token that expires between pre-read and push | Authority consumed? outcome `RECONCILED_NOT_APPLIED`? | Measures finding N6 | |
| X08 | A way to force `EFBIG`/`ENOSPC` on the evidence directory (`ulimit -f`, a small loop-mounted filesystem needing mount privileges, or an LD_PRELOAD shim) | Executor with an evidence dir | Fail at: start record write; signed-evidence write; directory fsync | Nothing sent when the start record fails; `EFFECT_EXECUTED_EVIDENCE_FAILURE` after a landed push | Confirms the documented behavior with a real I/O failure instead of an injected fault | |
| X09 | A disposable VM with power-cut capability (hypervisor hard-reset, or `dm-flakey` / `dm-log-writes`) and the target filesystem | PostgreSQL primary + executor | Cut power: after claim commit; between claim and start record; between start record and push; after push before evidence | Claim row present? start record present? which classification results? | Settles Q4 for the chosen stack | A lost claim row with a landed push is a **replay-enabling defect** |
| X10 | The deployed topology and a **non-admin** identity (the F-001 protocol, `docs/F001-PROOF-PROTOCOL.md`) | App-only ruleset; agent OS user without the App key | As the agent: attempt a direct push; attempt via `gh api`; attempt via the web API with its token | Every route refused; `check-agent-environment.mjs` exits 0 | The only experiment that tests the premise | Any success means exclusivity is false in that deployment |
| X11 | git-lfs with an LFS server (or the standalone file agent configured for clones) | LFS repo | Execute an approved push through the executor; clone elsewhere | Does the checkout resolve large files? | Confirms or retires finding N8's downstream effect | |
| X12 | Fuzzer (offline) | n/a | Fuzz `canonicalRepositoryIdentity` / `validateGitPushParameters` with URL variants (ports, escapes, userinfo, IDN, dot segments) | No throw; no two distinct *destinations* share an identity | Closes N1–N3 with a regression corpus | |

## 5. What local simulation can never prove

* That **a host's** server behaves like `git-receive-pack` after a client disconnects, applies
  quarantine semantics, or keeps unreachable objects.
* That an `fsync` in the executor reaches stable storage on a given disk and filesystem.
* That a database operator cannot roll back a snapshot: that is a property of people and
  procedures, so the minimum needed is the independent operator the repository's own matrix
  already asks for.
* That the agent has no other route to the remote. Only X10, run in the deployed topology by
  a party who does not control the agent's environment, bears on this.
