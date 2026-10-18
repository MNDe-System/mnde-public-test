# Git push lab results

- git: git version 2.43.0
- host: Linux 6.18.44-fc-v139
- transport: file:// style local paths only. HTTP/SSH, GitHub, GitLab, Bitbucket NOT exercised.
- date of run: 2026-10-18T18:17:59Z

### L01 non-fast-forward is rejected; exit code and message

- observed: exit=1
    To /tmp/tmp.7Iyg3Scixh/L01/remote.git
     ! [rejected]        main -> main (fetch first)
    error: failed to push some refs to '/tmp/tmp.7Iyg3Scixh/L01/remote.git'
    hint: Updates were rejected because the remote contains work that you do not
    hint: have locally. This is usually caused by another repository pushing to
    hint: the same ref. If you want to integrate the remote changes, use
    hint: 'git pull' before pushing again.
    hint: See the 'Note about fast-forwards' in 'git push --help' for details.
- ASSERT ok   : rejected push exits non-zero
- ASSERT ok   : remote kept A's commit

### L02 plain --force destroys another writer's commit (no server reflog)

- ASSERT ok   : remote now at B's commit
- observed: bare remote reflog for main present? no (core.logAllRefUpdates default for bare repos)
- observed: lost commit object still in remote object store: commit
- observed: lost commit reachable from any ref: 0 refs

### L03 bare --force-with-lease is defeated by a background fetch

- observed: bare lease after background fetch: exit=0
    To /tmp/tmp.7Iyg3Scixh/L03/remote.git
     + c28bb02...9eb464b main -> main (forced update)
- ASSERT ok   : bare lease let the overwrite through
- observed: A's commit c28bb0242d6948472b85dbfd90b7a7085f5e995b is no longer on main: 0 refs contain it

### L04 explicit lease on the reviewed SHA refuses the same overwrite

- observed: explicit lease on stale SHA: exit=1
    To /tmp/tmp.7Iyg3Scixh/L04/remote.git
     ! [rejected]        main -> main (stale info)
    error: failed to push some refs to '/tmp/tmp.7Iyg3Scixh/L04/remote.git'
- ASSERT ok   : explicit lease refused
- ASSERT ok   : remote unchanged

### L05 --force-if-includes closes the background-fetch hole for bare leases

- observed: lease + force-if-includes after fetch (A's commit not integrated): exit=1
    To /tmp/tmp.7Iyg3Scixh/L05/remote.git
     ! [rejected]        main -> main (remote ref updated since checkout)
    error: failed to push some refs to '/tmp/tmp.7Iyg3Scixh/L05/remote.git'
    hint: Updates were rejected because the tip of the remote-tracking branch has
    hint: been updated since the last checkout. If you want to integrate the
    hint: remote changes, use 'git pull' before pushing again.
    hint: See the 'Note about fast-forwards' in 'git push --help' for details.
- ASSERT ok   : overwrite refused
- ASSERT ok   : remote still A's

### L06 ref deletion and what a lease says about it

- observed: delete exit=0: To /tmp/tmp.7Iyg3Scixh/L06/remote.git
 - [deleted]         feature
- ASSERT ok   : ref gone on remote
- observed: the same delete is a plain refspec ':feature' — one character from 'main:feature'

### L07 tag replacement

- observed: moved tag without force: exit=1
    To /tmp/tmp.7Iyg3Scixh/L07/remote.git
     ! [rejected]        v1 -> v1 (already exists)
    error: failed to push some refs to '/tmp/tmp.7Iyg3Scixh/L07/remote.git'
    hint: Updates were rejected because the tag already exists in the remote.
- observed: moved tag with --force: exit=0
- ASSERT ok   : remote tag now equals local

### L08 multi-ref push, one ref rejected by a server hook: partial success

- observed: exit=1
    remote: locked branch        
    remote: error: hook declined to update refs/heads/locked        
    To /tmp/tmp.7Iyg3Scixh/L08/remote.git
     * [new branch]      ok -> ok
     ! [remote rejected] locked -> locked (hook declined)
    error: failed to push some refs to '/tmp/tmp.7Iyg3Scixh/L08/remote.git'
- ASSERT ok   : non-atomic: 'ok' was created
- ASSERT ok   : non-atomic: 'locked' was not
- observed: --atomic: exit=1
    remote: locked branch        
    remote: error: hook declined to update refs/heads/locked        
    To /tmp/tmp.7Iyg3Scixh/L08/remote.git
     ! [remote rejected] ok2 -> ok2 (atomic push failure)
     ! [remote rejected] locked -> locked (hook declined)
    error: failed to push some refs to '/tmp/tmp.7Iyg3Scixh/L08/remote.git'
- ASSERT ok   : atomic: 'ok2' NOT created because 'locked' failed

### L09 --atomic against a server that does not advertise atomic

- observed: exit=128
    fatal: the receiving end does not support --atomic push
    fatal: the remote end hung up unexpectedly
- ASSERT ok   : push fails closed when atomic unsupported (git exits 128, not 1)

### L10 --signed against a server without push-cert

- observed: exit=128
    fatal: the receiving end does not support --signed push
    fatal: the remote end hung up unexpectedly
- ASSERT ok   : signed push fails when server lacks push-cert (git exits 128, not 1)

### L11 server hooks: pre-receive sees quarantined objects; rejection leaves no trace

- observed: exit=1
    remote: QUARANTINE=/tmp/tmp.7Iyg3Scixh/L11/remote.git/./objects/tmp_objdir-incoming-qQKzxG        
    remote: commit        
    remote: rejecting by policy        
    To /tmp/tmp.7Iyg3Scixh/L11/remote.git
     ! [remote rejected] main -> main (pre-receive hook declined)
    error: failed to push some refs to '/tmp/tmp.7Iyg3Scixh/L11/remote.git'
- ASSERT ok   : ref unchanged after pre-receive rejection
- observed: rejected commit's object in permanent remote store: fatal: git cat-file: could not get object info

### L12 client killed (SIGKILL) while the server is still processing

- observed: client exit status after SIGKILL: 137
- observed: remote ref 1s after kill: b222074b2a82 (base was b222074b2a82, new is 508fdb15bad3)
- observed: remote ref 4s later:       508fdb15bad3
- observed: RESULT: the update LANDED although the client died and never saw a result
- observed: local remote-tracking ref in A: b222074b2a82 (client never recorded the new state)
- observed: naive retry afterwards: exit=0  output: Everything up-to-date

### L13 when does the client learn the result — before or after post-receive?

- observed: exit=0 after 3.0s (post-receive sleeps 3s then exits 3)
    remote: post-receive done        
    To /tmp/tmp.7Iyg3Scixh/L13/remote.git
       b222074..a81c958  main -> main
- ASSERT ok   : ref updated
- observed: a failing post-receive hook does not change the push exit status (exit=0)

### L14 two clients push different fast-forwards at once

- observed: A exit=0 B exit=1
- observed: A output: To /tmp/tmp.7Iyg3Scixh/L14/remote.git|   b222074..7e53fd1  main -> main|
- observed: B output: remote: error: cannot lock ref 'refs/heads/main': is at 7e53fd1f1f104c29452c89c00062ad16b5024045 but expected b222074b2a82dfd49e9d9fed353274e2a62733b1        |To /tmp/tmp.7Iyg3Scixh/L14/remote.git| ! [remote rejected] main -> main (failed to update ref)|error: failed to push some refs to '/tmp/tmp.7Iyg3Scixh/L14/remote.git'|
- ASSERT ok   : exactly one writer won
- observed: sum of exit codes (1 = one winner and one loser reported): 1

### L15 remote moves between validation and execution (TOCTOU)

- observed: exit=1
    To /tmp/tmp.7Iyg3Scixh/L15/remote.git
     ! [rejected]        HEAD -> main (stale info)
    error: failed to push some refs to '/tmp/tmp.7Iyg3Scixh/L15/remote.git'
- ASSERT ok   : lease turned the validate-then-act race into a refusal
- ASSERT ok   : remote still B's commit

### L16 creating a ref vs updating one: leases mean different things

- observed: lease expecting an existing SHA on a ref that does not exist: exit=1
    To /tmp/tmp.7Iyg3Scixh/L16/remote.git
     ! [rejected]        newb -> newb (stale info)
    error: failed to push some refs to '/tmp/tmp.7Iyg3Scixh/L16/remote.git'
- observed: lease expecting 'must not exist' (empty expect): exit=0
- ASSERT ok   : created with empty-expect lease
- observed: same command again, ref now exists and is up to date: exit=0  output: Everything up-to-date

### L17 wrong destination: pushurl/insteadOf make 'origin' lie

- observed: fetch URL : /tmp/tmp.7Iyg3Scixh/L17/remote.git
- observed: push  URL : /tmp/tmp.7Iyg3Scixh/L17/other.git
- ASSERT ok   : push went to the pushurl, not the fetch URL
- ASSERT ok   : the remote named origin was NOT updated
- observed: with url.<x>.pushInsteadOf, 'remote get-url origin' (fetch) = /tmp/tmp.7Iyg3Scixh/L17/remote.git
- observed: with url.<x>.pushInsteadOf, 'remote get-url --push origin' = /tmp/tmp.7Iyg3Scixh/L17/other.git

### L18 hook bypass: --no-verify, and push paths that never run pre-push

- observed: normal push with blocking pre-push: exit=1
- ASSERT ok   : hook blocked it
- observed: --no-verify: exit=0
- ASSERT ok   : --no-verify bypassed the hook
- observed: git send-pack (plumbing): exit=0
- ASSERT ok   : send-pack bypassed pre-push without any flag
- ASSERT ok   : core.hooksPath override disabled the hook

### L19 server-side policy is the only non-bypassable layer (and who can edit it)

- observed: force push vs receive.denyNonFastForwards: exit=1
    remote: error: denying non-fast-forward refs/heads/main (you should pull first)        
    To /tmp/tmp.7Iyg3Scixh/L19/remote.git
     ! [remote rejected] main -> main (non-fast-forward)
    error: failed to push some refs to '/tmp/tmp.7Iyg3Scixh/L19/remote.git'
- ASSERT ok   : server refused force even with --force
- observed: delete vs receive.denyDeletes: exit=1
- ASSERT ok   : server refused delete

### L20 push options reach server hooks only if advertised

- observed: server not advertising push-options: exit=128
    fatal: the receiving end does not support push options
    fatal: the remote end hung up unexpectedly
- observed: server advertising push-options: exit=0
    remote: push-option-count=1 opt0=ci.skip        
    To /tmp/tmp.7Iyg3Scixh/L20/remote.git
       b222074..14f2f17  main -> main

### L21 shallow clone push

- observed: push from a depth-1 clone (fast-forward): exit=0
    To file:///tmp/tmp.7Iyg3Scixh/L21/remote.git
       b222074..2e25e95  main -> main
- observed: pushing to a NEW branch from a shallow clone:
- observed: exit=0
    To file:///tmp/tmp.7Iyg3Scixh/L21/remote.git
     * [new branch]      nb -> nb

### L22 detached HEAD

- observed: 'git push origin' on detached HEAD: exit=128
    fatal: You are not currently on a branch.
    To push the history leading to the current (detached HEAD)
    state now, use
    
        git push origin HEAD:<name-of-remote-branch>
- observed: explicit HEAD:refs/heads/from-detached: exit=0
- ASSERT ok   : explicit refspec creates the branch

### L23 unreadable / unwritable remote: error surface

- observed: exit=0 (running as uid 0; root ignores file modes so this may succeed)
    To /tmp/tmp.7Iyg3Scixh/L23/remote.git
       b222074..b18f7c3  main -> main

### L24 protocol version used by push

- observed: packet trace mentions 'version 2': 0
- observed: packet trace mentions receive-pack advertisement lines (capabilities): 4
- observed: first capability line: 18:18:12.935485 pkt-line.c:85           packet: receive-pack> b222074b2a82dfd49e9d9fed353274e2a62733b1 refs/heads/main\0report-status report-status-v2 delete-refs side-band-64k quiet atomic ofs-delta 

### L25 retry after an uncertain outcome is idempotent only when the ref already matches

- observed: re-push of an already-applied update: exit=0 output: Everything up-to-date
- ASSERT ok   : benign retry returns success

### L26 exit 0 while the remote does NOT end up at the pushed SHA

- observed: client exit=0, client printed: To /tmp/tmp.7Iyg3Scixh/L26/remote.git|   b222074..5417680  main -> main
- observed: pushed 5417680ffacbe558f13eafa95a7dc79e2b926c8b ; remote now 30f72a5e9c967b331cdaf0176d6c05efb84f542e
- ASSERT ok   : exit 0 but remote differs from pushed SHA
- observed: client's own remote-tracking ref says: 5417680ffacbe558f13eafa95a7dc79e2b926c8b (it believes the push landed)

### L27 remote rollback (restore from backup) makes an identical push valid again

- observed: remote after restore: b222074b2a82 ; local believes origin/main = 64f8f8091a1c
- observed: re-running the identical push: exit=0
- ASSERT ok   : the same push applied twice, nothing at the git layer remembered it was spent

### L28 concurrent git processes in one working tree: stale index.lock

- observed: git add with index.lock present: exit=128
    fatal: Unable to create '/tmp/tmp.7Iyg3Scixh/L28/a/.git/index.lock': File exists.
    
    Another git process seems to be running in this repository, e.g.
    an editor opened by 'git commit'. Please make sure all processes
    are terminated then try again. If it still fails, a git process
    may have crashed in this repository earlier:
    remove the file manually to continue.

### L29 bare --force-with-lease with no remote-tracking ref

- observed: bare lease creating a branch with no tracking ref: exit=0
    To /tmp/tmp.7Iyg3Scixh/L29/remote.git
     * [new branch]      solo -> solo
- observed: bare lease on a ref we hold no tracking ref for: exit=1
    To /tmp/tmp.7Iyg3Scixh/L29/remote.git
     ! [rejected]        main -> other (stale info)
    error: failed to push some refs to '/tmp/tmp.7Iyg3Scixh/L29/remote.git'

### L30 client killed during object transfer (large pack)

- observed: client exit after SIGKILL at 0.4s: 137 (137 = killed; 0 would mean it had already finished)
- observed: remote main: b222074b2a82 ; base b222074b2a82 ; new 62b1b858e8c1
- observed: new commit present in remote object store: fatal: git cat-file: could not get object info
- observed: leftover quarantine dirs in remote: 0
- observed: leftover incoming pack files in remote: 0

### L31 Git LFS: does a push that skips the pre-push hook upload LFS objects?

- observed: normal push (hook runs): exit=0
- observed: pointer commit on remote: yes
- observed: LFS objects stored on remote after normal push: 1
- observed: push --no-verify: exit=0
    To /tmp/tmp.7Iyg3Scixh/L31/remote.git
       f6b8e98..68d2fde  main -> main
- observed: pointer commit on remote: yes
- observed: LFS objects stored on remote after --no-verify push: 1 (one more than before would mean it uploaded)
- observed: fresh clone of the pushed state: exit=0
- observed: one.bin in the clone starts with: version https://git-lfs.
- observed: two.bin (pushed with --no-verify) in the clone starts with: version https://git-lfs.
- observed: two.bin size in clone: 131 bytes (200000 = real content; ~130 = unresolved LFS pointer)

## Summary

- assertions passed: 33
- assertions failed: 0
