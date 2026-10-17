# F-001 power-loss test runbook (requirement D)

**Status: tooling built and exercised with a simulated cut; NO real power-loss result exists.** A `SIGKILL` is not a
power cut: it does not exercise the disk cache, the filesystem journal, PostgreSQL WAL recovery from a hard stop, or the
witness's fsync on real storage. This runbook turns the real test into four commands per boundary. It must be run by an
operator with physical access to the hardware under test and recovery access (console or a second machine).

## What the test establishes

At a chosen boundary every durable write that was acknowledged before it (PostgreSQL claim, executor spent-ledger,
witness entry, execution-start record) must still be present after a hard power loss and reboot, the consumed
authorization must be refused afterwards with **no** new push, and an unknown external outcome must stay
`INDETERMINATE`. It tests the machine, filesystem and disk under test; it does not test a different machine.

## Boundaries (what each pause means)

| `F001_PAUSE_AT` | Paused after | Durable records that must survive | Remote at pause | Corresponds to |
| --- | --- | --- | --- | --- |
| `fs-after-start-record` | start record file and directory fsynced; push not yet spawned | db, ledger, witness, start | approved pre-state | harness C6: effect not sent |
| `witness-after-consume` | the witness answered CONSUMED | db, ledger, witness | pre-state | spend recorded everywhere, nothing sent |
| `post-receive` | the remote applied the push; the client is still waiting | db, ledger, witness, start | **approved SHA** | harness C8: effect sent, outcome unknown |
| `fs-evidence-before-rename` | signed evidence fsynced as `*.tmp`, not renamed | db, ledger, witness, start | approved SHA | evidence-persistence crash |

## Preconditions (all on the disk and machine under test)

1. A disposable PostgreSQL 16 cluster with the F-001 schema and a restricted executor login, TLS, `fsync=on`, `synchronous_commit=on`
   (`docs/F001-CLOSURE-REPORT.md` section 7). Not the production database.
2. The unprivileged users `mnde-exec` and `mnde-witness` and a Node 24 binary both can execute (`/opt/node24/bin/node`).
3. `TMPDIR` pointing at the persistent disk under test (not a RAM-backed `/tmp`), and `F001_POWER_STATE` an absolute path on that same disk.
4. A way to cut power that is not a shutdown (switch, PDU port or unplugging), and a way to see the machine boot.
5. `F001_PG_DIR` set as for the normal harness. Do **not** set `F001_SIMULATE_POWER_CUT`.

## Procedure, per boundary

```
# 1. Run to the boundary. The harness prints ">>> PAUSED at <boundary>" and blocks.
export TMPDIR=/mnt/disk-under-test/tmp F001_POWER_STATE=/mnt/disk-under-test/f001-power-state.json F001_PG_DIR=...
F001_PAUSE_AT=fs-after-start-record node --no-warnings tests/f001-closure/closure.mjs P1

# 2. When (and only when) PAUSED is printed: cut power. Hard power-off, no shutdown.
# 3. Power on. Start PostgreSQL. Do not start the witness yourself; the verifier starts it from its persisted data directory.
# 4. Verify:
F001_VERIFY_POWER_STATE=/mnt/disk-under-test/f001-power-state.json node --no-warnings tests/f001-closure/closure.mjs P2
```

`P2` reads the persisted state, restarts the witness (taking over its stale lock and re-verifying the whole hash-chained log;
it refuses to start on any corruption), checks which of the four records survived, reads the remote, replays the same
authorization, and confirms: no listed record lost; the remote is where the boundary implies; the replay is `REFUSED`; the
replay sent nothing; and an effect with no evidence is classified `INDETERMINATE`, not success. It prints one JSON object
with every observation. Repeat for each boundary. Keep each `results.json`, the state file, the PostgreSQL log and `dmesg`/`journalctl -b -1`.

## Pass / fail

* **PASS** only if `P2` passes for all four boundaries on real power cuts **and** `pg_test_fsync` on the database volume
  reports durable `fdatasync`/`fsync` rates consistent with the device (a disk that lies about flushes can pass once and lose data later).
* **FAIL** if any listed record is missing, the remote moved on replay, or an unknown outcome is reported as success.
* A passing result applies to that hardware, filesystem and mount options only. Repeat after changing any of them.
  Windows directory flush is documented as not equivalent to Linux; do not generalize.

## What this does not cover

Torn writes in a witness running on a different machine (run this procedure on the witness host too, with `kill` of the executor replaced by
a cut of the witness host), disk failure, and the case where the witness host and the executor host lose power together and
one comes back from a backup. Backups are a rollback surface: see `F001-WITNESS-DEPLOYMENT.md`.
