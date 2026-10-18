# 02 · How `git push` actually works

Evidence tags are defined in [00-README.md](00-README.md). Short version: `[P]` upstream
Git documentation read this session, `[L<n>]` lab case executed this session
(Git 2.43.0, **file transport only**), `[K]` prior knowledge not re-checked, `[H]`
hypothesis. Nothing here was verified against GitHub, GitLab or Bitbucket servers.

## 1. What is being moved

**Objects** `[K]`. Four kinds, addressed by hash of content: blob (file bytes), tree
(directory listing), commit (tree + parents + author/committer + message), annotated
tag (pointer + signature + message). Because a commit id covers its tree and its
parents, **a commit id fixes the entire content and history beneath it**. This is the
single most useful property for any authorization system: approving 40 hex characters
approves every byte they reach. The remote recomputes object ids from the bytes it
receives, so a sender cannot lie about which object it is sending `[P: git-receive-pack
quarantine, connectivity check; K]`.

**Refs** `[K]`. Names that point at objects. Namespaces that matter for push:

| Namespace | Meaning | Push relevance |
| --- | --- | --- |
| `refs/heads/*` | branches | The default push target. Fast-forward rule applies `[P: git-push PUSH RULES]` |
| `refs/tags/*` | tags | **All updates rejected without force**, regardless of direction `[P]`; observed `[L7]` |
| `refs/remotes/<r>/*` | *local* record of what a remote looked like at last contact | Never pushed. This is what `--force-with-lease` consults, which is its weakness `[P][L3]` |
| `refs/notes/*` | git notes | Not pushed unless named in a refspec `[K]` |
| host-specific (e.g. `refs/pull/*`) | maintained by the host | Often hidden from push by `receive.hideRefs` `[P: config/receive]` |

Three views of "the branch" therefore exist and they disagree routinely: the **local ref**
(`refs/heads/main`), the **remote-tracking ref** (`refs/remotes/origin/main`, a cache of the
last fetch or push), and the **remote ref** (the truth, held by the server). Most push
incidents are a decision made on the second while the effect lands on the third.

## 2. Transports and protocol versions

| Transport | How it works `[K][P]` | Where authentication happens |
| --- | --- | --- |
| HTTPS ("smart HTTP") | `GET <url>/info/refs?service=git-receive-pack`, then `POST <url>/git-receive-pack` (stateless RPC); chunked bodies once past `http.postBuffer` (1 MiB default) `[P: gitprotocol-http]` | HTTP auth on the first request. Typically a 401 first, then the credential helper supplies a token, then the request is retried |
| SSH | runs `git-receive-pack <path>` on the server over the ssh channel | At SSH connection setup (key / agent / certificate), before any Git bytes |
| `git://` | unauthenticated daemon; almost never write-enabled | None |
| file / local path | spawns `git-receive-pack` locally `[L]` | Filesystem permissions only |
| `ext::` and remote helpers | runs an arbitrary program as the transport | Whatever the program does. Disabled unless `protocol.ext.allow` permits `[K]` |

**Protocol versions.** Version 2 defines exactly four commands: `ls-refs`, `fetch`,
`object-info`, `bundle-uri` `[P: gitprotocol-v2, command list]`. **There is no push
command in v2.** Push still negotiates over the v0/v1 pack protocol: the server
advertises `<oid> <ref>\0<capabilities>` and the client replies with update commands.
Observed: with `protocol.version=2` set, the packet trace of a push shows `receive-pack>`
advertisement lines with capabilities and **zero** `version 2` lines `[L24]`. Practical
meaning: everything push relies on (capability list, report-status, atomic, push-options,
push-cert) lives in the v0 protocol; protocol-v2 improvements to fetch do not carry over.

Receive-pack capabilities the client can use `[P: gitprotocol-pack, gitprotocol-capabilities]`:
`report-status`, `report-status-v2`, `delete-refs`, `side-band-64k`, `quiet`, `atomic`,
`ofs-delta`, `push-options`, `push-cert=<nonce>`, `object-format`, `agent`, `session-id`.
Locally observed advertisement: `report-status report-status-v2 delete-refs side-band-64k
quiet atomic ofs-delta …` `[L24]`. A client that asks for a capability the server did not
advertise fails closed **with exit 128 and the misleading message "the remote end hung up
unexpectedly"**: `--atomic` `[L9]`, `--signed` `[L10]`, `-o` push options `[L20]`.

## 3. The execution sequence

Numbered steps for one `git push origin main`. Column 3 says what is irreversible after
the step; column 4 what evidence exists afterwards.

| # | Step | Irreversible? | Evidence afterwards |
| --- | --- | --- | --- |
| 1 | **Resolve.** Choose remote and refspec from args, `remote.<n>.push`, `push.default` (default `simple`), `branch.<n>.pushRemote`, `remote.pushDefault`. Rewrite the URL via `remote.<n>.pushurl` and `url.<base>.pushInsteadOf` | No | Only config. Fetch URL and push URL can differ and `origin` then "lies" `[L17]` |
| 2 | **Client `pre-push` hook** runs (skipped by `--no-verify`). Receives remote name + URL on argv, and `<local ref> <local sha> <remote ref> <remote sha>` lines on stdin `[P: githooks]`. A non-zero exit aborts. Hooks such as Git LFS do real work here (uploading LFS objects) | LFS uploads: yes | Hook's own output. Bypassed by `--no-verify`, by `core.hooksPath`, and by plumbing such as `git send-pack`, none of which needs any privilege `[L18]` |
| 3 | **Connect and authenticate.** **This is where the credential is first used.** HTTPS: the token goes on the first authenticated request. SSH: at connect | Credential exposure to the remote: yes | Provider-side access logs `[K]`. Nothing durable locally |
| 4 | **Read advertisement.** Server lists its refs and capabilities | No | Packet trace if `GIT_TRACE_PACKET` was on |
| 5 | **Client-side checks.** Fast-forward test for branches; lease check for `--force-with-lease`; shallow/`--atomic`/`--signed` capability checks | No | Rejections print `! [rejected] … (fetch first | non-fast-forward | stale info | already exists)` and exit 1 `[L1][L4][L7]` |
| 6 | **Send update commands** `<old-oid> <new-oid> <ref>` (+ capabilities, optional push options, optional signed push certificate), then a pack built by `pack-objects` | No | None |
| 7 | **Server receives the pack into a quarantine directory.** Objects are not in the main store yet. A failed push at or before this point "will not leave any on-disk data" `[P: git-receive-pack QUARANTINE]`; observed for a pre-receive rejection `[L11]` and for a client killed mid-transfer of a 120 MB pack `[L30]` | No | None server-side beyond logs |
| 8 | **Connectivity check** (new tips must reach only present objects), optional `receive.fsckObjects` | No | |
| 9 | **`pre-receive` hook** (once, all refs; non-zero aborts everything `[P]`). It sees the quarantined objects, and may read them but "MUST NOT update any refs" `[P][L11]` | No | Hook output is relayed to the client as `remote:` lines |
| 10 | **Quarantine migrated** into the main object store | Objects now persist (until the host garbage-collects unreachable ones) | |
| 11 | **Per-ref `update` hook**, then the **ref update**. The command carries the old value, so the server performs a compare-and-swap: a mismatch yields `cannot lock ref 'refs/heads/main': is at X but expected Y` and the ref is reported `failed to update ref` `[L14]`. With `--atomic` the whole set is one transaction `[L8]` | **Yes, per ref, at this instant.** A client that dies later cannot undo it | Ref value only. **No reflog on a bare repository by default** `[L2]`; the previous commit survives as an unreachable object `[L2]` |
| 12 | **Report.** `unpack ok` / `ng <ref> <reason>` per ref `[P: gitprotocol-pack report-status]` | | |
| 13 | **`post-receive`, then `post-update`** hooks. Their exit status does **not** change the push result `[L13]`. In the lab the client received its result only *after* a 3-second `post-receive` finished, so a slow server hook lengthens the window in which the client has no answer `[L13]` | Side effects (CI trigger, mail, webhook, deploy-on-push) are irreversible even if the ref is later reset | Whatever the hooks wrote |
| 14 | **Client prints status and updates `refs/remotes/<r>/<b>`** for refs that succeeded. Exit code: 0 all ok; 1 any ref rejected; 128 fatal transport/protocol error `[L1][L8][L9]` | | The tracking ref is the only client-side durable trace, and it is written only if the client survived to this step: after a SIGKILL during step 9 the remote advanced but the client's tracking ref did not `[L12]` |

Two timing consequences `[L12]`: (a) **killing the client does not stop the server.** The
update landed three seconds after the client was SIGKILLed, and the client never recorded
it. (b) A naive retry then reports `Everything up-to-date` and exits 0 `[L12][L25]`, which
is correct but tells the operator nothing about whether *their* attempt or *someone else's*
produced the state.

## 4. Update-safety options, and what each really guarantees

| Mechanism | Guarantee | Failure shown |
| --- | --- | --- |
| Default fast-forward rule | Branch moves only to a descendant of its current value `[P]` | Rejects on `fetch first` `[L1]`. Checked client-side from the advertisement, **and** re-checked by the server's CAS at update time `[L14]` |
| `--force` / `+refspec` | Disables fast-forward, tag, and lease checks `[P]` | Silently discards the previous tip; it stays only as an unreachable object `[L2]`. Server config can still refuse it `[L19]` |
| `--force-with-lease` (bare) | Remote must equal **the remote-tracking ref** | **Defeated by any background fetch.** Git's own manual says so: it "interacts very badly with anything that implicitly runs git fetch" `[P: git-push]`. Reproduced: push succeeded and removed a commit the pusher never saw `[L3]` |
| `--force-with-lease=<ref>:<sha>` | Remote must equal the SHA you name | Refused with `stale info` when the remote moved `[L4][L15]`. **This is the exact-state primitive.** The SHA must come from the review step, not from local refs |
| `--force-with-lease --force-if-includes` | Adds: tip of the remote-tracking ref must be reachable from a local reflog entry | Closes the background-fetch hole for the bare form `[L5][P]`. It is a no-op alongside an explicit `<ref>:<sha>` lease `[P]`. A 2.98 fix concerns an empty-reflog case `[P: RelNotes/2.98.0]` |
| `--atomic` | All refs update or none; requires `atomic` capability `[P]` | One bad ref blocks the rest `[L8]`; unsupported server → exit 128 `[L9]`. Not supported for remote-group pushes `[P]` |
| `--signed` | Sends a signed push certificate to be checked/logged by the server | Fails if the server does not advertise `push-cert` `[L10][P]`. A search summary reports most public forges do not enable it and that GitLab has an open request `[S: gitlab-org/gitlab#283916, people.kernel.org/monsieuricon/signed-git-pushes]` |
| Server `receive.denyNonFastForwards`, `receive.denyDeletes` | Refuse force or delete even when the client forces | Refused despite `--force` `[L19]`. This is the only layer a client cannot disable |

Creation vs update `[L16]`: a lease expecting an existing SHA on a ref that does not exist
is `stale info`; an *empty* expectation (`--force-with-lease=<ref>:`) means "must not exist"
and creates it; repeating it once the ref exists and is current prints `Everything
up-to-date` and exits 0. Deletion is `git push origin :ref` / `--delete`, one character
from a normal refspec `[L6]`.

## 5. Hooks and who can turn them off

| Hook | Side | Can stop a push? | Can be bypassed by the pusher? |
| --- | --- | --- | --- |
| `pre-push` | client | Yes | **Yes**, three independent ways: `--no-verify`, `-c core.hooksPath=…`, `git send-pack` `[L18]` |
| `pre-receive` | server | Yes, whole push | No. Runs as the receiving process |
| `update` | server | Yes, per ref; others may still land (non-atomic) `[L8]` | No |
| `proc-receive` | server | Rewrites/handles pseudo-refs `[P]` | No |
| `post-receive` / `post-update` | server | **No**; cannot fail a completed push `[L13]` | n/a |

Anything that a client-side hook is relied on to do (LFS upload, lint, secret scan) is
advisory. Only the server's own checks bind a client that wants to push anyway.

**Git LFS makes this concrete** `[L31]`: LFS installs a `pre-push` hook that uploads the
large objects. With `git push --no-verify` the pointer commit was accepted by the remote
(`main` advanced) but the LFS object store stayed at one object instead of two: **the
branch moved to a commit whose large file does not exist on the LFS server.** The clone
check in L31 was inconclusive on a file transport (even the correctly uploaded object
stayed a pointer), so the downstream failure mode is `[H]`; the missing upload is `[L31]`.

## 6. Configuration that changes where or whether a push lands

| Setting | Effect | Attack or incident relevance |
| --- | --- | --- |
| `remote.<n>.pushurl`, `url.<base>.pushInsteadOf` | Push URL differs from fetch URL | `git remote get-url origin` shows the fetch URL; the push went elsewhere `[L17]`. A repo whose `.git/config` an agent can write can redirect a push |
| `remote.<n>.push`, `push.default`, `remote.pushDefault`, `branch.<n>.pushRemote` | Which refs go where when no refspec is given | `push.default=matching` pushes every same-named branch `[P: config/push]`. Default `simple` since Git 2.0 `[P]` |
| `push.followTags`, `push.recurseSubmodules`, `push.autoSetupRemote`, `push.useForceIfIncludes`, `push.gpgSign`, `push.pushOption` | Extra refs, submodule behavior, tracking, safer force, signing, options | |
| `core.hooksPath`, `core.sshCommand`, `credential.helper`, `protocol.<name>.allow` | Which program runs for hooks / transport / credentials | MNDe's own tests show `protocol.ext.allow=always` + `url.ext::<prog>.pushInsteadOf` ran an arbitrary program inside an authorized push before MNDe moved the effect into a config-free staging repository `[R: docs/GIT-PUSH-EFFECT.md; test:git-push-isolation 9/9 re-run]` |
| Server: `receive.denyNonFastForwards`, `denyDeletes`, `denyCurrentBranch`, `fsckObjects`, `maxInputSize`, `hideRefs`, `advertiseAtomic`, `advertisePushOptions`, `certNonceSeed`, `shallowUpdate`, `procReceiveRefs` | Server-side policy and capability advertisement `[P: config/receive]` | Capability absence turns into exit 128 `[L9][L10][L20]` |
| `GIT_TRACE*`, `transfer.fsckObjects`, `http.postBuffer`, `http.followRedirects` | Diagnostics, integrity, size/redirect behavior | Redirect-following (`http.followRedirects`) can send a push to a different URL than the one named `[K]`; not tested |

## 7. Special cases

| Case | Behavior | Evidence |
| --- | --- | --- |
| Submodules | Pushing a superproject commit does not push submodule commits unless `--recurse-submodules=check|on-demand|only` / `push.recurseSubmodules`. A superproject can therefore reference a submodule commit the submodule's remote lacks | `[K]`, not tested |
| Annotated tags | Separate objects; `--follow-tags` pushes reachable annotated tags; any tag update needs force `[L7]` | `[L7][P]` |
| Git notes | Live in `refs/notes/*`, not pushed by default | `[K]` |
| Shallow clone | Fast-forward push and new-branch push from a depth-1 clone both succeeded on a file transport. Pushes that would require the server to accept shallow boundaries are governed by `receive.shallowUpdate` | `[L21]` for the two cases; the shallowUpdate path `[H]` |
| Partial clone / promisor objects | A push may need objects the local repo only has as promises; whether it lazily fetches or fails was not tested | `[H]` |
| Detached HEAD | `git push` with no refspec fails `fatal: You are not currently on a branch` (exit 128); `HEAD:refs/heads/<name>` works and creates the branch | `[L22]` |
| Multiple worktrees | Refs and objects are shared; each worktree has its own index. Two Git processes in one tree collide on `index.lock` (exit 128) | `[L28]` |
| Two writers, same ref | Exactly one wins; the loser gets `cannot lock ref … is at X but expected Y` and exit 1 | `[L14]` |
| New in recent Git | `git push` accepts a remote group name (2.55), advice for `git push origin/main` typos (2.56) | `[P: RelNotes/2.55.0, 2.56.0]` |

## 8. What the hosted layer adds (mostly unverified here)

Hosts wrap `receive-pack` with their own policy engine, and their error text is not Git's.
From search summaries `[S]`, not opened:

* GitHub: `GH013` "Repository rule violations found", `GH006` "Protected branch update
  failed / protected branch hook declined", `GH001` "Large files detected" (100 MB hard
  limit, 50 MB warning), push protection for secrets with a logged bypass.
* GitHub installation tokens expire after one hour `[S: docs.github.com enterprise-server
  mirrors]`.
* The Copilot coding agent can push only to `copilot/` branches `[S: docs.github.com,
  learn.microsoft.com]`.

None of this was reproduced. The honest statement about hosts is: **the lab proves
properties of upstream `git-receive-pack`; a hosted service can be stricter, looser, or
simply different, and I did not measure it.** Where a conclusion in later documents depends
on host behavior it is marked `[S]`, `[K]` or `[H]` accordingly.

## 9. Things this document could not settle

1. Whether GitHub/GitLab/Bitbucket send the client its result before or after their own
   post-receive-equivalent work. Locally the client waited `[L13]`.
2. Whether a hosted server completes a ref update after the client disconnects, on HTTPS.
   Locally (file transport) it did `[L12]`; stateless HTTP processes the request body
   server-side and likely behaves alike, but that is `[H]`.
3. Retention of unreachable objects and any server-side ref history on each host
   (recovery of force-pushed commits is reported to work "only while the object still exists
   on the server" `[S: github community 147441]`).
4. Whether any host honors `--signed`. A summary says most public forges do not `[S]`.
