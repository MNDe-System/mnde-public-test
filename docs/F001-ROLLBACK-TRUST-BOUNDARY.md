# F-001 rollback resistance: design and trust boundary

Answers F-001 question Q6 ("old datastore restore revives spent authority?") for the
`git.push` executor. Companion to [F001-CLOSURE-REPORT.md](F001-CLOSURE-REPORT.md), which
holds the test evidence.

## The problem, stated exactly

The PostgreSQL claim row (`mnde_claim.claims`) was the only record that an authorization
was spent. Whoever administers the database can restore a snapshot taken before the claim.
After that, a re-issued authorization with the same `grant_id` (new `execution_id`) is
`CLAIMED` again and pushes a second time. PostgreSQL `fsync`, the namespace lock and the
table grants do not prevent this: they constrain the executor login, not the administrator,
and a restore replaces the table wholesale. Reproduced at `3f0e3a5` (control run in the
closure report, case R1).

One partial barrier already existed by accident: the execution-start record is created
with exclusive-create keyed by `execution_id`, so replaying the *same* signed authorization
collided there, after the claim and after a credential had been acquired. It did not cover
a new execution id on a spent grant, which is the case F-001 names.

## The design

An executor-local **spent ledger** (`src/freshness/local_spent_ledger.mjs`), in
`<MNDE_GIT_PUSH_EVIDENCE_DIR>/spent-ledger/`:

| Property | How |
| --- | --- |
| Keyed by grant and by execution | one file per `(namespace, grant_id)` and one per `(namespace, execution_id)`, name = SHA-256 of the key |
| Created exclusively | `open(..., "wx")`: a second creation fails with `EEXIST` |
| Durable before the push | file `fsync`, then directory `fsync`, then the execution-start record, then the write credential, then the push |
| Consulted first | before the claim store and before any credential: a request the ledger knows is refused with no network contact |
| Detects a forgetful database | ledger says spent but the store has no record (`lookup` not found), or the store says `CLAIMED` for something the ledger already holds: `ERR_LEDGER_ROLLBACK_DETECTED` |
| Fails closed | unreadable, malformed, unwritable, or **missing next to existing execution history** is `ERR_LEDGER_UNAVAILABLE`; it is never re-initialized over state |
| Quarantine | a detected rollback writes `QUARANTINE.json`; every later request (re-checked on each use, so a long-lived Hub honours it) is refused with `ERR_LEDGER_QUARANTINED` until an operator who has investigated deletes the file |

Order inside `executeGitPush` (the part that must not be reordered):

```
verify authorization -> bind request -> LEDGER CHECK (no network)
 -> read-only credential -> read remote pre-state -> fast-forward check
 -> DATABASE CLAIM -> LEDGER COMMIT -> write credential -> START RECORD -> PUSH
 -> read back -> signed evidence
```

## Why this and not something larger

| Option | Benefit | Downside | Verdict |
| --- | --- | --- | --- |
| Executor-local ledger (chosen) | independent of the database administrator; no new service; ~110 lines; fails closed | does not survive loss/restore of the executor host's own state; state lives where the executor lives | **Chosen**: smallest design that removes the database administrator from the trust path |
| External monotonic witness (signed counter/transparency log held by a third party) | survives restore of every host the operator controls | a new independent service, key custody, availability dependency, an unspecified protocol; nothing in the repository implements it | Correct long-term answer to "all local state restored"; **not built**, see Residual risk |
| Database triggers / append-only table / `fsync` settings | none against a snapshot restore | a restore replaces the files the trigger lives in | Rejected: does not address the threat |
| Replicate claims to a second database | detects divergence | the second database needs a different administrator, otherwise it is the same trust domain; adds failover and consistency problems | Rejected for v1 |

## Trust boundary

Trusted not to collude, as separate roles:

1. **Claim-database administrator.** May restore or alter the database arbitrarily. After this
   change that no longer revives authority on its own: the executor refuses and quarantines.
2. **Executor host administrator** (the OS user that runs the executor and owns the evidence
   directory). Holds the ledger. Can delete or restore the ledger directory.

A rollback is **undetected** if, and only if, both of the following hold at once: the database
is restored to a state before the claim, **and** the executor's evidence directory (including
`spent-ledger/`) is restored to the same earlier moment, for example a whole-VM snapshot
restore. That is one trust domain being rolled back as a unit, and nothing local can see it.
Likewise an administrator who deletes `spent-ledger/` *and* the `*.started.json` files, which
makes the directory look like a new deployment.

If all independent state is compromised there is no remaining authority record. The honest
statement is: MNDe then provides at-most-once only as far as the remote's own state allows. The
`--force-with-lease=<ref>:<old-sha>` guard still refuses a replay while the ref has moved past
the authorized pre-state, but that is a property of the remote, not an authority.

## Operating requirements

* The database administrator and the executor-host administrator must be different people (or
  at least different credentials with no shared restore path).
* Back up the executor's evidence directory only to storage the database administrator cannot
  roll back, and never restore it independently of the database without reading this document.
* Provisioning a **replacement executor host** for a namespace that already has claims requires
  copying `spent-ledger/` from the old host first. Starting empty beside existing history is
  refused; starting empty on a truly new directory is accepted, which is the one residual
  silent-acceptance case (a wiped host is indistinguishable from a new one).
* After `ERR_LEDGER_ROLLBACK_DETECTED`: stop, find out who restored the database and when,
  reconcile every execution since the restore point against the remotes, and only then remove
  `QUARANTINE.json`.

## Not covered

Power loss and OS crash (see the closure report), a witness, and the multi-host/failover case.
