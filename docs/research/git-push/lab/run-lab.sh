#!/usr/bin/env bash
# Git push failure laboratory — local only.
#
# Every remote is a disposable bare repository on the local filesystem reached
# over the file transport. Nothing here touches a network, a credential, or a
# real repository. Results describe `git` as installed locally (printed below)
# over the FILE transport only: they say nothing about GitHub/GitLab/Bitbucket
# server behaviour, HTTP, or SSH.
#
# Usage: run-lab.sh [workdir]   (default: a fresh mktemp -d, removed on exit)

set -u
export LC_ALL=C LANG=C
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME=lab GIT_AUTHOR_EMAIL=lab@example.invalid
export GIT_COMMITTER_NAME=lab GIT_COMMITTER_EMAIL=lab@example.invalid
export GIT_AUTHOR_DATE="2026-01-01T00:00:00Z" GIT_COMMITTER_DATE="2026-01-01T00:00:00Z"

ROOT="${1:-$(mktemp -d)}"
CLEAN=0; [ $# -eq 0 ] && CLEAN=1
cleanup() { [ "$CLEAN" = 1 ] && rm -rf "$ROOT"; }
trap cleanup EXIT
mkdir -p "$ROOT"

PASS=0; FAIL=0
say()  { printf '%s\n' "$*"; }
hdr()  { printf '\n### %s\n\n' "$*"; }
obs()  { printf -- '- observed: %s\n' "$*"; }
# assert <description> <expected> <actual>
assert() {
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf -- '- ASSERT ok   : %s\n' "$1";
  else FAIL=$((FAIL+1)); printf -- '- ASSERT FAIL: %s (expected [%s] got [%s])\n' "$1" "$2" "$3"; fi
}
sha() { git -C "$1" rev-parse "$2" 2>/dev/null || echo NONE; }
rsha() { git --git-dir="$1" rev-parse --verify -q "$2" 2>/dev/null || echo NONE; }   # bare remote

# fresh world: bare remote R, two clones A and B, one commit on main
world() {
  local n="$1"; W="$ROOT/$n"; rm -rf "$W"; mkdir -p "$W"
  R="$W/remote.git"; A="$W/a"; B="$W/b"
  git init -q --bare -b main "$R"
  git clone -q "$R" "$A" 2>/dev/null
  git -C "$A" checkout -q -b main 2>/dev/null
  echo base > "$A/f"; git -C "$A" add f; git -C "$A" commit -q -m base
  git -C "$A" push -q origin main
  git clone -q "$R" "$B" 2>/dev/null
}
commit() { # commit <clone> <file> <text> <msg>
  echo "$3" >> "$1/$2"; git -C "$1" add "$2"
  GIT_COMMITTER_DATE="2026-01-0$((RANDOM%9+1))T0$((RANDOM%9)):00:00Z" git -C "$1" commit -q -m "$4"
}

say "# Git push lab results"
say ""
say "- git: $(git --version)"
say "- host: $(uname -sr)"
say "- transport: file:// style local paths only. HTTP/SSH, GitHub, GitLab, Bitbucket NOT exercised."
say "- date of run: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
hdr "L01 non-fast-forward is rejected; exit code and message"
world L01
commit "$A" f a1 "a1"; commit "$B" f b1 "b1"
git -C "$A" push -q origin main
out=$(git -C "$B" push origin main 2>&1); rc=$?
obs "exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
assert "rejected push exits non-zero" 1 "$rc"
assert "remote kept A's commit" "$(sha "$A" HEAD)" "$(rsha "$R" main)"

# ---------------------------------------------------------------------------
hdr "L02 plain --force destroys another writer's commit (no server reflog)"
world L02
commit "$A" f a1 "a1"; git -C "$A" push -q origin main; LOST=$(sha "$A" HEAD)
commit "$B" f b1 "b1"
git -C "$B" push -q --force origin main
assert "remote now at B's commit" "$(sha "$B" HEAD)" "$(rsha "$R" main)"
obs "bare remote reflog for main present? $( [ -e "$R/logs/refs/heads/main" ] && echo yes || echo no) (core.logAllRefUpdates default for bare repos)"
obs "lost commit object still in remote object store: $(git --git-dir="$R" cat-file -t "$LOST" 2>&1)"
obs "lost commit reachable from any ref: $(git --git-dir="$R" branch --contains "$LOST" 2>&1 | wc -l) refs"

# ---------------------------------------------------------------------------
hdr "L03 bare --force-with-lease is defeated by a background fetch"
world L03
commit "$A" f a1 "a1"; git -C "$A" push -q origin main; LOST=$(sha "$A" HEAD)
commit "$B" f b1 "b1"           # B has NOT seen A's commit
git -C "$B" fetch -q origin     # an editor/IDE auto-fetch
out=$(git -C "$B" push --force-with-lease origin main 2>&1); rc=$?
obs "bare lease after background fetch: exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
assert "bare lease let the overwrite through" "$(sha "$B" HEAD)" "$(rsha "$R" main)"
obs "A's commit $LOST is no longer on main: $(git --git-dir="$R" branch --contains "$LOST" 2>&1 | wc -l) refs contain it"

hdr "L04 explicit lease on the reviewed SHA refuses the same overwrite"
world L04
commit "$A" f a1 "a1"; git -C "$A" push -q origin main
SEEN=$(rsha "$R" main)
commit "$A" f a2 "a2"; git -C "$A" push -q origin main     # remote moves after 'review'
commit "$B" f b1 "b1"; git -C "$B" fetch -q origin
out=$(git -C "$B" push --force-with-lease=main:"$SEEN" origin main 2>&1); rc=$?
obs "explicit lease on stale SHA: exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
assert "explicit lease refused" 1 "$rc"
assert "remote unchanged" "$(sha "$A" HEAD)" "$(rsha "$R" main)"

hdr "L05 --force-if-includes closes the background-fetch hole for bare leases"
world L05
commit "$A" f a1 "a1"; git -C "$A" push -q origin main
commit "$B" f b1 "b1"; git -C "$B" fetch -q origin
out=$(git -C "$B" push --force-with-lease --force-if-includes origin main 2>&1); rc=$?
obs "lease + force-if-includes after fetch (A's commit not integrated): exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
assert "overwrite refused" 1 "$rc"
assert "remote still A's" "$(sha "$A" HEAD)" "$(rsha "$R" main)"

# ---------------------------------------------------------------------------
hdr "L06 ref deletion and what a lease says about it"
world L06
git -C "$A" push -q origin main:refs/heads/feature
out=$(git -C "$A" push origin --delete feature 2>&1); rc=$?
obs "delete exit=$rc: $out"
assert "ref gone on remote" NONE "$(rsha "$R" refs/heads/feature)"
obs "the same delete is a plain refspec ':feature' — one character from 'main:feature'"

# ---------------------------------------------------------------------------
hdr "L07 tag replacement"
world L07
git -C "$A" tag v1; git -C "$A" push -q origin v1
commit "$A" f a1 "a1"; git -C "$A" tag -f v1 >/dev/null
out=$(git -C "$A" push origin v1 2>&1); rc=$?
obs "moved tag without force: exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
out=$(git -C "$A" push --force origin v1 2>&1); rc=$?
obs "moved tag with --force: exit=$rc"
assert "remote tag now equals local" "$(sha "$A" v1)" "$(rsha "$R" refs/tags/v1)"

# ---------------------------------------------------------------------------
hdr "L08 multi-ref push, one ref rejected by a server hook: partial success"
world L08
cat > "$R/hooks/update" <<'EOF'
#!/bin/sh
case "$1" in refs/heads/locked) echo "locked branch" >&2; exit 1;; esac
exit 0
EOF
chmod +x "$R/hooks/update"
git -C "$A" push -q origin main:refs/heads/locked 2>/dev/null   # creation also rejected
git -C "$A" branch -q ok; git -C "$A" branch -q locked
out=$(git -C "$A" push origin ok locked 2>&1); rc=$?
obs "exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
assert "non-atomic: 'ok' was created" "$(sha "$A" ok)" "$(rsha "$R" refs/heads/ok)"
assert "non-atomic: 'locked' was not" NONE "$(rsha "$R" refs/heads/locked)"
git -C "$A" branch -q ok2
out=$(git -C "$A" push --atomic origin ok2 locked 2>&1); rc=$?
obs "--atomic: exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
assert "atomic: 'ok2' NOT created because 'locked' failed" NONE "$(rsha "$R" refs/heads/ok2)"

hdr "L09 --atomic against a server that does not advertise atomic"
world L09
git --git-dir="$R" config receive.advertiseAtomic false
git -C "$A" branch -q x
out=$(git -C "$A" push --atomic origin x 2>&1); rc=$?
obs "exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
assert "push fails closed when atomic unsupported (git exits 128, not 1)" 128 "$rc"

hdr "L10 --signed against a server without push-cert"
world L10
out=$(git -C "$A" push --signed=yes origin main 2>&1); rc=$?
obs "exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
assert "signed push fails when server lacks push-cert (git exits 128, not 1)" 128 "$rc"

# ---------------------------------------------------------------------------
hdr "L11 server hooks: pre-receive sees quarantined objects; rejection leaves no trace"
world L11
cat > "$R/hooks/pre-receive" <<'EOF'
#!/bin/sh
echo "QUARANTINE=${GIT_QUARANTINE_PATH:-unset}" >&2
while read old new ref; do
  # the new object is readable here, but only through the quarantine
  git cat-file -t "$new" >&2
done
echo "rejecting by policy" >&2
exit 1
EOF
chmod +x "$R/hooks/pre-receive"
commit "$A" f a1 "a1"; NEW=$(sha "$A" HEAD)
out=$(git -C "$A" push origin main 2>&1); rc=$?
obs "exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
assert "ref unchanged after pre-receive rejection" "$(sha "$B" HEAD)" "$(rsha "$R" main)"
obs "rejected commit's object in permanent remote store: $(git --git-dir="$R" cat-file -t "$NEW" 2>&1 | head -1)"

# ---------------------------------------------------------------------------
hdr "L12 client killed (SIGKILL) while the server is still processing"
world L12
cat > "$R/hooks/pre-receive" <<'EOF'
#!/bin/sh
sleep 3
exit 0
EOF
chmod +x "$R/hooks/pre-receive"
commit "$A" f a1 "a1"; NEW=$(sha "$A" HEAD)
git -C "$A" push origin main >"$W/push.out" 2>&1 &
PUSHPID=$!; sleep 1; kill -9 "$PUSHPID" 2>/dev/null; wait "$PUSHPID" 2>/dev/null; rc=$?
obs "client exit status after SIGKILL: $rc"
obs "remote ref 1s after kill: $(rsha "$R" main | cut -c1-12) (base was $(sha "$B" HEAD | cut -c1-12), new is ${NEW:0:12})"
sleep 4
obs "remote ref 4s later:       $(rsha "$R" main | cut -c1-12)"
if [ "$(rsha "$R" main)" = "$NEW" ]; then
  obs "RESULT: the update LANDED although the client died and never saw a result"
else
  obs "RESULT: the update did NOT land after the client was killed"
fi
obs "local remote-tracking ref in A: $(sha "$A" refs/remotes/origin/main | cut -c1-12) (client never recorded the new state)"
out=$(git -C "$A" push origin main 2>&1); rc=$?
obs "naive retry afterwards: exit=$rc  output: $(printf '%s' "$out" | tr '\n' '|')"

hdr "L13 when does the client learn the result — before or after post-receive?"
world L13
cat > "$R/hooks/post-receive" <<'EOF'
#!/bin/sh
sleep 3
echo "post-receive done" >&2
exit 3
EOF
chmod +x "$R/hooks/post-receive"
commit "$A" f a1 "a1"
t0=$(date +%s.%N); out=$(git -C "$A" push origin main 2>&1); rc=$?; t1=$(date +%s.%N)
obs "exit=$rc after $(printf '%.1f' "$(echo "$t1 - $t0" | bc -l)")s (post-receive sleeps 3s then exits 3)"
printf '%s\n' "$out" | sed 's/^/    /'
assert "ref updated" "$(sha "$A" HEAD)" "$(rsha "$R" main)"
obs "a failing post-receive hook does not change the push exit status (exit=$rc)"

# ---------------------------------------------------------------------------
hdr "L14 two clients push different fast-forwards at once"
world L14
cat > "$R/hooks/pre-receive" <<'EOF'
#!/bin/sh
sleep 2
exit 0
EOF
chmod +x "$R/hooks/pre-receive"
commit "$A" f a1 "a1"; commit "$B" f b1 "b1"
( git -C "$A" push origin main >"$W/a.out" 2>&1; echo $? >"$W/a.rc" ) &
( git -C "$B" push origin main >"$W/b.out" 2>&1; echo $? >"$W/b.rc" ) &
wait
obs "A exit=$(cat "$W/a.rc") B exit=$(cat "$W/b.rc")"
obs "A output: $(tr '\n' '|' <"$W/a.out")"
obs "B output: $(tr '\n' '|' <"$W/b.out")"
n=0; [ "$(rsha "$R" main)" = "$(sha "$A" HEAD)" ] && n=$((n+1)); [ "$(rsha "$R" main)" = "$(sha "$B" HEAD)" ] && n=$((n+1))
assert "exactly one writer won" 1 "$n"
rcsum=$(( $(cat "$W/a.rc") + $(cat "$W/b.rc") ))
obs "sum of exit codes (1 = one winner and one loser reported): $rcsum"

# ---------------------------------------------------------------------------
hdr "L15 remote moves between validation and execution (TOCTOU)"
world L15
OLD=$(rsha "$R" main)
commit "$A" f a1 "a1"
# 'validation' reads the remote
SEEN=$(git ls-remote "$R" refs/heads/main | cut -f1)
# someone else moves it
commit "$B" f b1 "b1"; git -C "$B" push -q origin main
out=$(git -C "$A" push --force-with-lease=refs/heads/main:"$SEEN" origin HEAD:refs/heads/main 2>&1); rc=$?
obs "exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
assert "lease turned the validate-then-act race into a refusal" 1 "$rc"
assert "remote still B's commit" "$(sha "$B" HEAD)" "$(rsha "$R" main)"

hdr "L16 creating a ref vs updating one: leases mean different things"
world L16
git -C "$A" branch -q newb
out=$(git -C "$A" push --force-with-lease=refs/heads/newb:"$(sha "$A" main)" origin newb 2>&1); rc=$?
obs "lease expecting an existing SHA on a ref that does not exist: exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
out=$(git -C "$A" push --force-with-lease=refs/heads/newb: origin newb 2>&1); rc=$?
obs "lease expecting 'must not exist' (empty expect): exit=$rc"
assert "created with empty-expect lease" "$(sha "$A" newb)" "$(rsha "$R" refs/heads/newb)"
out=$(git -C "$A" push --force-with-lease=refs/heads/newb: origin newb 2>&1); rc=$?
obs "same command again, ref now exists and is up to date: exit=$rc  output: $(printf '%s' "$out" | tr '\n' '|')"

# ---------------------------------------------------------------------------
hdr "L17 wrong destination: pushurl/insteadOf make 'origin' lie"
world L17
EVIL="$W/other.git"; git init -q --bare -b main "$EVIL"
git -C "$A" config remote.origin.pushurl "$EVIL"
commit "$A" f a1 "a1"
obs "fetch URL : $(git -C "$A" remote get-url origin)"
obs "push  URL : $(git -C "$A" remote get-url --push origin)"
git -C "$A" push -q origin main
assert "push went to the pushurl, not the fetch URL" "$(sha "$A" HEAD)" "$(rsha "$EVIL" main)"
assert "the remote named origin was NOT updated" "$(sha "$B" HEAD)" "$(rsha "$R" main)"
git -C "$A" config --unset remote.origin.pushurl
git -C "$A" config "url.$EVIL.pushInsteadOf" "$R"
obs "with url.<x>.pushInsteadOf, 'remote get-url origin' (fetch) = $(git -C "$A" remote get-url origin)"
obs "with url.<x>.pushInsteadOf, 'remote get-url --push origin' = $(git -C "$A" remote get-url --push origin)"

hdr "L18 hook bypass: --no-verify, and push paths that never run pre-push"
world L18
cat > "$A/.git/hooks/pre-push" <<'EOF'
#!/bin/sh
echo "pre-push: BLOCKED" >&2
exit 1
EOF
chmod +x "$A/.git/hooks/pre-push"
commit "$A" f a1 "a1"
out=$(git -C "$A" push origin main 2>&1); rc=$?
obs "normal push with blocking pre-push: exit=$rc"
assert "hook blocked it" "$(sha "$B" HEAD)" "$(rsha "$R" main)"
git -C "$A" push -q --no-verify origin main; rc=$?
obs "--no-verify: exit=$rc"
assert "--no-verify bypassed the hook" "$(sha "$A" HEAD)" "$(rsha "$R" main)"
commit "$A" f a2 "a2"
git -C "$A" send-pack -q "$R" main >/dev/null 2>&1; rc=$?
obs "git send-pack (plumbing): exit=$rc"
assert "send-pack bypassed pre-push without any flag" "$(sha "$A" HEAD)" "$(rsha "$R" main)"
commit "$A" f a3 "a3"
git -c core.hooksPath=/nonexistent -C "$A" push -q origin main; rc=$?
assert "core.hooksPath override disabled the hook" "$(sha "$A" HEAD)" "$(rsha "$R" main)"

hdr "L19 server-side policy is the only non-bypassable layer (and who can edit it)"
world L19
git --git-dir="$R" config receive.denyNonFastForwards true
git --git-dir="$R" config receive.denyDeletes true
commit "$A" f a1 "a1"; git -C "$A" push -q origin main
git -C "$A" reset -q --hard HEAD~1; commit "$A" f a1b "a1b"
out=$(git -C "$A" push --force origin main 2>&1); rc=$?
obs "force push vs receive.denyNonFastForwards: exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
assert "server refused force even with --force" 1 "$rc"
git -C "$A" push -q origin main:refs/heads/tmp
out=$(git -C "$A" push origin --delete tmp 2>&1); rc=$?
obs "delete vs receive.denyDeletes: exit=$rc"
assert "server refused delete" 1 "$rc"

# ---------------------------------------------------------------------------
hdr "L20 push options reach server hooks only if advertised"
world L20
cat > "$R/hooks/pre-receive" <<'EOF'
#!/bin/sh
echo "push-option-count=${GIT_PUSH_OPTION_COUNT:-0} opt0=${GIT_PUSH_OPTION_0:-}" >&2
exit 0
EOF
chmod +x "$R/hooks/pre-receive"
commit "$A" f a1 "a1"
out=$(git -C "$A" push -o ci.skip origin main 2>&1); rc=$?
obs "server not advertising push-options: exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
git --git-dir="$R" config receive.advertisePushOptions true
out=$(git -C "$A" push -o ci.skip origin main 2>&1); rc=$?
obs "server advertising push-options: exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'

hdr "L21 shallow clone push"
world L21
S="$W/shallow"; git clone -q --depth 1 "file://$R" "$S" 2>/dev/null
commit "$S" f s1 "s1"
out=$(git -C "$S" push origin main 2>&1); rc=$?
obs "push from a depth-1 clone (fast-forward): exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
obs "pushing to a NEW branch from a shallow clone:"
git -C "$S" branch -q nb
out=$(git -C "$S" push origin nb 2>&1); rc=$?
obs "exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'

hdr "L22 detached HEAD"
world L22
git -C "$A" checkout -q --detach; commit "$A" f d1 "d1"
out=$(git -C "$A" push origin 2>&1); rc=$?
obs "'git push origin' on detached HEAD: exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
out=$(git -C "$A" push origin HEAD:refs/heads/from-detached 2>&1); rc=$?
obs "explicit HEAD:refs/heads/from-detached: exit=$rc"
assert "explicit refspec creates the branch" "$(sha "$A" HEAD)" "$(rsha "$R" refs/heads/from-detached)"

hdr "L23 unreadable / unwritable remote: error surface"
world L23
chmod -R a-w "$R"
commit "$A" f a1 "a1"
out=$(git -C "$A" push origin main 2>&1); rc=$?
chmod -R u+w "$R"
obs "exit=$rc (running as uid $(id -u); root ignores file modes so this may succeed)"; printf '%s\n' "$out" | sed 's/^/    /'

hdr "L24 protocol version used by push"
world L24
commit "$A" f a1 "a1"
GIT_TRACE_PACKET=1 git -c protocol.version=2 -C "$A" push -q origin main 2>"$W/trace.txt"
obs "packet trace mentions 'version 2': $(grep -c 'version 2' "$W/trace.txt")"
obs "packet trace mentions receive-pack advertisement lines (capabilities): $(grep -c 'report-status' "$W/trace.txt")"
obs "first capability line: $(grep -m1 'report-status' "$W/trace.txt" | sed 's/\x0/ /g' | cut -c1-200)"

hdr "L25 retry after an uncertain outcome is idempotent only when the ref already matches"
world L25
commit "$A" f a1 "a1"; git -C "$A" push -q origin main
out=$(git -C "$A" push origin main 2>&1); rc=$?
obs "re-push of an already-applied update: exit=$rc output: $(printf '%s' "$out" | tr '\n' '|')"
assert "benign retry returns success" 0 "$rc"

hdr "L26 exit 0 while the remote does NOT end up at the pushed SHA"
world L26
cat > "$R/hooks/post-receive" <<'EOF2'
#!/bin/sh
# stands in for any server-side automation or second writer that moves the ref
# after the update was accepted
git update-ref refs/heads/main "$(git rev-parse main~1 2>/dev/null || git rev-parse main)"
EOF2
chmod +x "$R/hooks/post-receive"
commit "$A" f a1 "a1"; commit "$A" f a2 "a2"
PUSHED=$(sha "$A" HEAD)
out=$(git -C "$A" push origin main 2>&1); rc=$?
obs "client exit=$rc, client printed: $(printf '%s' "$out" | tr '\n' '|')"
obs "pushed $PUSHED ; remote now $(rsha "$R" main)"
assert "exit 0 but remote differs from pushed SHA" "differs" "$([ "$(rsha "$R" main)" = "$PUSHED" ] && echo same || echo differs)"
obs "client's own remote-tracking ref says: $(sha "$A" refs/remotes/origin/main) (it believes the push landed)"

hdr "L27 remote rollback (restore from backup) makes an identical push valid again"
world L27
cp -a "$R" "$W/backup.git"
commit "$A" f a1 "a1"; git -C "$A" push -q origin main; NEW=$(sha "$A" HEAD)
rm -rf "$R"; cp -a "$W/backup.git" "$R"      # operator restores an older snapshot
obs "remote after restore: $(rsha "$R" main | cut -c1-12) ; local believes origin/main = $(sha "$A" refs/remotes/origin/main | cut -c1-12)"
out=$(git -C "$A" push origin main 2>&1); rc=$?
obs "re-running the identical push: exit=$rc"
assert "the same push applied twice, nothing at the git layer remembered it was spent" "$NEW" "$(rsha "$R" main)"

hdr "L28 concurrent git processes in one working tree: stale index.lock"
world L28
touch "$A/.git/index.lock"
echo x >> "$A/f"
out=$(git -C "$A" add f 2>&1); rc=$?
obs "git add with index.lock present: exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
rm -f "$A/.git/index.lock"

hdr "L29 bare --force-with-lease with no remote-tracking ref"
world L29
git -C "$A" branch -q solo
out=$(git -C "$A" push --force-with-lease origin solo 2>&1); rc=$?
obs "bare lease creating a branch with no tracking ref: exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
git -C "$A" fetch -q origin
commit "$A" f s1 "s1"; git -C "$A" push -q origin main
git -C "$B" checkout -q -b other; git -C "$B" push -q origin other
git -C "$A" fetch -q origin
git -C "$A" update-ref -d refs/remotes/origin/other 2>/dev/null
out=$(git -C "$A" push --force-with-lease origin main:other 2>&1); rc=$?
obs "bare lease on a ref we hold no tracking ref for: exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'

hdr "L30 client killed during object transfer (large pack)"
world L30
head -c 120000000 /dev/urandom > "$A/blob.bin"; git -C "$A" add blob.bin; git -C "$A" commit -q -m big
NEW=$(sha "$A" HEAD)
git -C "$A" push origin main >"$W/push.out" 2>&1 &
PUSHPID=$!; sleep 0.4; kill -9 "$PUSHPID" 2>/dev/null; wait "$PUSHPID" 2>/dev/null; rc=$?
sleep 2
obs "client exit after SIGKILL at 0.4s: $rc (137 = killed; 0 would mean it had already finished)"
if [ "$rc" = 0 ]; then obs "NOTE: push finished before the kill; result below is not an interrupted-transfer observation"; fi
obs "remote main: $(rsha "$R" main | cut -c1-12) ; base $(sha "$B" HEAD | cut -c1-12) ; new ${NEW:0:12}"
obs "new commit present in remote object store: $(git --git-dir="$R" cat-file -t "$NEW" 2>&1 | head -1)"
obs "leftover quarantine dirs in remote: $(find "$R/objects" -maxdepth 1 -name 'tmp_objdir-*' | wc -l)"
obs "leftover incoming pack files in remote: $(find "$R/objects/pack" -name 'tmp_pack_*' | wc -l)"

hdr "L31 Git LFS: does a push that skips the pre-push hook upload LFS objects?"
if command -v git-lfs >/dev/null 2>&1; then
  world L31
  git -C "$A" lfs install --local >/dev/null 2>&1
  git -C "$A" lfs track '*.bin' >/dev/null 2>&1; git -C "$A" add .gitattributes; git -C "$A" commit -q -m attrs
  git -C "$A" push -q origin main 2>/dev/null
  head -c 200000 /dev/urandom > "$A/one.bin"; git -C "$A" add one.bin; git -C "$A" commit -q -m one
  out=$(git -C "$A" push origin main 2>&1); rc=$?
  obs "normal push (hook runs): exit=$rc"
  obs "pointer commit on remote: $( [ "$(rsha "$R" main)" = "$(sha "$A" HEAD)" ] && echo yes || echo no)"
  obs "LFS objects stored on remote after normal push: $(find "$R/lfs" -type f 2>/dev/null | wc -l)"
  head -c 200000 /dev/urandom > "$A/two.bin"; git -C "$A" add two.bin; git -C "$A" commit -q -m two
  out=$(git -C "$A" push --no-verify origin main 2>&1); rc=$?
  obs "push --no-verify: exit=$rc"; printf '%s\n' "$out" | sed 's/^/    /'
  obs "pointer commit on remote: $( [ "$(rsha "$R" main)" = "$(sha "$A" HEAD)" ] && echo yes || echo no)"
  obs "LFS objects stored on remote after --no-verify push: $(find "$R/lfs" -type f 2>/dev/null | wc -l) (one more than before would mean it uploaded)"
  C="$W/c"; GIT_LFS_SKIP_SMUDGE=0 git clone -q "$R" "$C" 2>"$W/clone.err"; crc=$?
  obs "fresh clone of the pushed state: exit=$crc"; sed 's/^/    /' "$W/clone.err" | head -6
  obs "one.bin in the clone starts with: $(head -c 24 "$C/one.bin" | tr -c '[:print:]\n' '?' | head -1)"
  obs "two.bin (pushed with --no-verify) in the clone starts with: $(head -c 24 "$C/two.bin" | tr -c '[:print:]\n' '?' | head -1)"
  obs "two.bin size in clone: $(wc -c < "$C/two.bin") bytes (200000 = real content; ~130 = unresolved LFS pointer)"
else
  obs "git-lfs not installed; L31 skipped"
fi

say ""
say "## Summary"
say ""
say "- assertions passed: $PASS"
say "- assertions failed: $FAIL"
exit 0
