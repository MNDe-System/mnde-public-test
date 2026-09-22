# F-001, reassessed against the real typed effect

F-001 is the finding that a verified receipt is a signature, and a signature can
be presented twice. It has been open since before there was anything to execute.

Three things have since landed on `main`: the typed `git.push` effect (#45), the
durable single-use claim it consumes (#44 for the store, #45 for the ordering),
and signed execution evidence (#47). This document asks the only question worth
asking now — **is F-001 closed for the `git.push` path?** — and answers it
question by question against the code as merged, rather than against intent.

**The verdict, up front: no, and two of the nine reasons are not code problems.**
Four properties are established in code and under test. One is proven for the
store but not for every failure mode. One is open by design and by an explicit
decision. And one cannot be answered at all yet, because the path has never been
operated.

Every claim below cites the merged tree at `ee4d404` or a named test.

---

## The nine questions

### 1. Can an authorization be used more than once?

**No, on the supported path — with one qualification about which backend is
configured.**

The authority is consumed by `claimAuthority` at
`src/effects/git-push/index.mjs:477`, before anything leaves the process. A
second presentation of the same grant returns `SPENT` and is refused at `:484`.

`test:git-push-effect` covers this with the remote deliberately reset between
attempts, so the replay is refused by the claim rather than by the lease — the
distinction matters, because a lease refusal would prove the wrong thing.

The qualification: that suite's backend is in-memory. It establishes the
*ordering*. Non-rollback and durability come from
[F001-CLAIM-STORE-PROOF.md](F001-CLAIM-STORE-PROOF.md), 22/22 against a real
PostgreSQL 16.13 primary with fsync on, including a spent grant reused under a
new execution id at 32-way concurrency with exactly one winner every time.
Removing `UNIQUE(namespace, grant_id)` drops that to 18/22 — the constraint *is*
the single-use property.

**Established, for a deployment that configures the proven backend.**

### 2. Can the effect happen before the durable claim?

**No.**

`performPush` has exactly one call site in the entire tree,
`src/effects/git-push/index.mjs:507`. The claim is at `:477`. Everything between
them is a refusal: `SPENT` returns at `:484`, and anything that is not `CLAIMED`
— `UNKNOWN`, `NO_BACKEND`, `BACKEND_UNAVAILABLE` — returns at `:491`.

There is no second egress path to reach. The effect module contains no `fetch`,
no `http`, no `net` and no `tls`; every git invocation in
`src/effects/git-push/transport.mjs` goes through a single `execFile` at `:112`,
and of those, only `performPush` mutates anything.

**Established.**

### 3. Can the effect happen through the supported executor without consuming the claim?

**No — same single egress, same gate.** See question 2.

Red-casing is what makes this more than an assertion: with the claim gate
changed to accept any decision, `test:git-push-effect` drops from 27/27 to
23/27. The four cases that break are exactly the replay, crash-recovery and
no-backend ones.

**Established.**

### 4. Can the same grant execute after restart?

**No for process restart. Strongly indicated but not proven for power loss.**

The claim lives in a store outside the executor process, so restarting the
executor does not reset it. `test:git-push-effect` covers an authority claimed
by a run that then died, and it is never re-spent.

The store's own proof covers a PostgreSQL `-m immediate` restart, which skips
the shutdown checkpoint and forces WAL recovery. That document states its own
limit plainly and it is worth repeating here: **restart is not power loss.** A
`-m immediate` restart does not test the disk's write cache, a torn write, or a
host that loses power mid-fsync.

**Strongly indicated. Not proven for the full failure envelope.**

### 5. Can an ambiguous transport failure cause a blind second push?

**No.**

`UNKNOWN` refuses and sends nothing, and is never retried — a retry is exactly
the replay F-001 names, because the claim may have landed. There is no retry
loop anywhere in the effect. An ambiguous outcome is resolved by *reading the
remote*, not by trying again, and the consumed grant stays consumed in every
outcome: `EXECUTED`, `REFUSED`, `RECONCILED_NOT_APPLIED` and `INDETERMINATE`
alike.

This is deliberately at-most-once *attempt*, which costs an authority that may
have produced no effect. That is the intended trade and it should not be
softened later for convenience.

`test:git-push-effect` covers the ambiguous case directly, and
`test:git-push-execution-evidence` covers the evidence side: an unobserved final
state can never verify as `EXECUTED`.

**Established.**

### 6. Can an old datastore restore revive previously consumed authority?

**Yes, inside the boundary as currently drawn. This is open, and it is open by
decision rather than by oversight.**

Whoever can restore the claim database to an earlier snapshot can un-spend a
grant. Hosting it at a managed provider does not change this: the account owner
can still restore. The mitigation in place for v1.0 is a restricted executor
role — the executor login cannot `DELETE`, `UPDATE`, `TRUNCATE` or `DROP`, which
the store proof verifies — with restore and admin authority held outside the
automated system.

So the claim MNDe may make is **"the executor cannot roll the claim store
back"**, and not "nobody can". Those are different sentences and only the first
is true.

Closing this properly needs an external monotonic witness — something that can
attest that a claim existed and cannot itself be rolled back by the same
operator. That is v-next, not v1.0.

**Open, deliberately, with the honest claim narrowed to match.**

### 7. Can a caller substitute repository, remote, branch, source SHA, target SHA, executor, or authorization identity?

**No.**

Every one of those is bound and checked before transport:

- The six signed parameters are validated (`validateGitPushParameters`): full
  lowercase 40-hex SHAs, never abbreviated and never the null SHA; a
  `refs/heads/<name>` target; a scheme on the operator's allowlist; no
  credentials in the URL; no value beginning with `-`.
- `repository` must equal the identity derived from `remote_url`, so the two
  cannot disagree.
- `bindRequestToAuthority` requires the caller's request to equal the signed
  parameters **field for field**.
- The request key set is exact: a request carrying an unrecognized field is
  refused, not ignored. An ignored field is a constraint the caller believed
  they had.
- The executor id must equal this executor's, and the authorization must be an
  executor-bound `mnde.signed-receipt.v2`.
- Neither receipt layer may rest on the authority bundle shipped inside the
  package — the trust-mixing hole #43 closed on the executor and #45 closed
  here. Removing that single check drops `test:git-push-effect` to 26/27 **and a
  demo-signed decision executes a real push.**

**Established.**

### 8. Can the supported production path bypass the typed executor?

**There is no supported production path yet, so this cannot be answered by
testing — only by reading.**

Reading says: the generic path is still hard-disabled.
`src/execution-availability/index.mjs:42` sets `DISPATCH_ENABLED = false`, and
`executor/index.mjs:448` returns `ERR_FRESHNESS_DEPLOYMENT_DISABLED` for every
protected effect regardless of how good the receipt is. The typed effect does
not touch that path.

But the honest statement is the one about operation: **nothing calls
`createGitPushExecutor` outside its tests.** It is inert, and a path that has
never run cannot have been shown not to be bypassed in practice.

**Not yet answerable. This is the single largest gap.**

### 9. Does the final signed evidence correspond to the actual observed remote state?

**Yes.**

Exit code 0 is the subprocess's opinion. The ref is read back independently at
`src/effects/git-push/index.mjs:513`, and that observation is what the evidence
records. Evidence may say `EXECUTED` only when the observed SHA equals the
approved new SHA, and that rule runs **twice** — when the body is built and
again when it is verified — so a record claiming `EXECUTED` while its own
observed SHA disagrees is refused even with an intact signature.

`test:git-push-execution-evidence` covers this at 49 cases, red-cased three
ways: accepting every signature scores 34/49, dropping the coherence rule 42/49,
dropping the credential-to-body identity check 47/49. The sharpest case rewrites
*both* the approved and observed SHAs so the forgery is internally consistent,
leaving only the signature to catch it.

**Established.**

---

## Where that leaves F-001

| # | Question | Status |
| --- | --- | --- |
| 1 | Authorization reused | Established, given the proven backend |
| 2 | Effect before claim | Established |
| 3 | Effect without consuming claim | Established |
| 4 | Same grant after restart | Strongly indicated; power loss unproven |
| 5 | Blind retry on ambiguity | Established |
| 6 | Datastore restore revives authority | **Open by decision** |
| 7 | Identity or parameter substitution | Established |
| 8 | Bypass of the typed executor | **Not yet answerable — never operated** |
| 9 | Evidence matches observed state | Established |

**F-001 is NOT closed, not even narrowly.** It remains Category A.

It would be easy to write "F-001 is closed for the supported v1.0 `git.push`
execution path" — six of nine questions are cleanly established and a seventh is
close. That sentence would still be false, for one blunt reason: **no deployment
has ever run this.** A correct design that has never been operated is not a
closed finding, and the whole point of this finding is that the gap between
"verified" and "actually happened" is where replay lives.

### The exact remaining blockers

1. **Operate the path once, end to end, against a provisioned claim database.**
   This is the blocker. Until it happens, questions 1 and 8 rest on code reading
   and an in-memory backend rather than on a real run.
2. **Decide the power-loss question for the chosen database** — either accept
   `-m immediate` as sufficient evidence for v1.0 and say so, or test the
   harder failure mode.
3. **Question 6 stays open into v1.0 as a stated limit, not a silent one.** The
   claim MNDe ships with must be "the executor cannot roll the claim store
   back". An external monotonic witness is v-next.

Blocker 1 is the one that moves F-001. Blockers 2 and 3 narrow what may be
claimed once it does.

## What must not be said

- Not "F-001 is closed." Not yet, and not for effects other than `git.push`
  ever, on this evidence.
- Not "nobody can roll the claim store back." Only the executor cannot.
- Not "the design is proven." The design is *built and tested*. Proof of the
  deployed property needs the deployment.
- Not that an ALLOW decision implies execution occurred or is permitted.
