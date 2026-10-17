# F-001 closure report

**Verdict: BLOCKED.**

The software defects found were fixed and the tests that can run here pass. F-001 cannot be
declared closed because mandatory evidence cannot be produced from this environment (section 4).
Nothing below is simulated and then called proven; emulated or simulated items are labelled.

## 1. What was tested, and on what

| Item | Value |
| --- | --- |
| Pre-remediation commit (control) | `3f0e3a599ee73d39ba22bb9596a2e8d39caf6328` |
| Remediation commit (all evidence below) | `75f7575e34d34d8e42f9a9b396ffb930f05bf165` (+ test-hook fix and docs in the commit that adds this report) |
| Runtime | Node v24.22.0 (the repo requires >=24; the sandbox default is 22.22 and fails 5 suites for that reason) |
| Database | PostgreSQL 16.15, disposable, TLS (`verify-full`), `fsync=on`, `synchronous_commit=on`, data checksums, restricted `NOINHERIT` executor login bound to one namespace |
| Remote | local bare git repository over `file://`; GitHub-App cases use a **local emulator** (`tests/f001-closure/ghemu.mjs`), not GitHub |
| Entry point exercised | the production CLI `bin/mnde-git-push.mjs`, as a separate OS process, real `pg` adapter, real signing and verification |

Reproduce (disposable cluster setup is in section 7):

```
node --no-warnings tests/f001-closure/closure.mjs                       # all 30 cases
F001_SRC=/path/to/3f0e3a5-checkout node --no-warnings tests/f001-closure/closure.mjs R1   # control
F001_SRC=/path/to/3f0e3a5-checkout node --no-warnings tests/f001-closure/closure.mjs G2   # control
```

Raw results: `docs/evidence/f001/2026-10-17-closure/results.json` (30/30),
`results-control-preremediation-R1.json`, `results-control-preremediation-G2.json`,
signed evidence `T01-evidence.signed.json`, `G1-evidence.signed.json`.

## 2. Phase 1 findings (and a correction)

| ID | Finding | Status |
| --- | --- | --- |
| D1 | A GitHub-App **write** token was minted before the claim, so every refused or racing request held one. **Reproduced**: 12 racing presentations of one authorization minted 12 write tokens for 1 winner (control G2). | Fixed |
| D2 | The claim row was the only record of "spent". After a snapshot restore a re-issued authorization (new execution id, same grant) **pushed again**. **Reproduced** on `3f0e3a5` (control R1: `EXECUTED`, 1 extra push). | Fixed |
| D2 correction | My first assessment said local state was never consulted. In fact the exclusive-create start record refused a replay of the *same* execution id, by accident, after the claim and after credential acquisition. It did not cover a new execution id on a spent grant. | Documented |
| D3a | Signed evidence has no execution-start reference and does not name the credential/installation. | **Not fixed** (schema change; see limitations) |
| D3b | The unsigned local outcome record, which `classifyGitPushExecution` reads, is written without `fsync`. A crash can lose the outcome and downgrade the classification to `INDETERMINATE`, which is the safe direction. | **Not fixed** |
| Unproven | Power loss; real GitHub rulesets; independent database administration. | See section 4 |

Production push paths: only `bin/mnde-git-push.mjs` and `src/hub/service.mjs` construct the
executor, and both reach the single `performPush` call (`src/effects/git-push/index.mjs`),
which also requires a claim ticket that exists only for a claim made through the adapter the
executor opened itself. `npm run test:git-push-reachability` (14/14) and `-single-route`
(16/16) pass. `executor/index.mjs` generic dispatch remains hard-closed. The local pre-push
hook is not relied on; the transport also passes `--no-verify`.

## 3. Remediation (commit `75f7575`)

* `src/freshness/local_spent_ledger.mjs` (new): executor-local, exclusive-create, fsynced
  entries per grant and per execution id; consulted before the database; quarantine latch
  re-read on every use. Design and trust boundary: [F001-ROLLBACK-TRUST-BOUNDARY.md](F001-ROLLBACK-TRUST-BOUNDARY.md).
* `src/effects/git-push/index.mjs`: ledger check before any credential; read-only credential
  for the pre-state; ledger commit after the claim; write credential minted only after both;
  then the start record, then the push. All credentials released and scrubbed.
* `src/effects/git-push/credential-provider.mjs`: `acquire({ access: "read" | "write" })`
  (default `write`); minted token must match the requested level exactly or it is revoked.
* Tests: `tests/test_git_push_spent_ledger.mjs` (11), read-credential case in
  `tests/test_git_push_credential_custody.mjs` (18), `test_git_push_isolation` adjusted for the
  new first durable barrier, `tests/support/hub_observation_hooks.mjs` updated for the new
  `acquire` signature (caught by the Hub suite; 18/18 again).

## 4. Why the verdict is BLOCKED

| Mandatory item | Result | Exact reason |
| --- | --- | --- |
| Disposable **protected GitHub** repository; authorized protected push; reuse fails there | **BLOCKED** | No such repository, no GitHub App key/installation, no human approver key exist in this session. The only GitHub credential present is an **admin `GH_TOKEN` held by the agent** (acceptance matrix C2); pushing with it would be the C2 violation, not evidence. |
| Valid physical approval | **BLOCKED** | Needs the human approver device/key. |
| Direct unauthorized push **denied by GitHub** | **BLOCKED** | Needs real rulesets exercised from a non-admin identity. G8 shows only that a holder of no credential is refused by the emulator. |
| Operating-system / VM crash with durable-state recovery | **BLOCKED** | Cannot crash the host from inside it. Process `SIGKILL` at every boundary was run (below); a PostgreSQL restart and a database restore were run. Neither is an OS crash or power loss; the `fsync` behaviour of the underlying disk is untested. |
| GitHub API timeout (real) | **BLOCKED** | Emulated only (G4, G6, G7). |
| Independent database administration | **BLOCKED** | The database ran on the executor's own machine; the owner role is the same operator. Mitigated, not met, by the ledger. |
| External rollback witness | **Not built** | Rollback of the database **and** the executor's evidence directory together (a whole-VM snapshot) is undetected. |

To unblock: run `docs/F001-PROOF-PROTOCOL.md` with a disposable protected repository, a GitHub
App, a non-admin agent identity and an independently administered database; run
`tests/f001-closure/closure.mjs` against that database; add a power-loss test on the target
platform; and decide on the witness.

## 5. Results by test (commit `75f7575`, all in `results.json`)

"Real" = real process, real PostgreSQL, real SIGKILL. "Emulator" = local GitHub-App/git-HTTP emulator.

| ID | Required test | Kind | Result |
| --- | --- | --- | --- |
| T01 | Authorized push, signed evidence, offline verify | real | PASS: `EXECUTED`; 1 DB row; ledger grant+exec entries; start record; verifier `ok:true` |
| T02 | Repeated execution of consumed authorization x3 (remote reset so only the claim can stop it) | real | PASS: 3x `ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT`; 0 extra pushes |
| T03 | 100 concurrent claims, one authorization | real | PASS: `CLAIMED` x1, `ALREADY_SPENT` x99 |
| T04 | 100 concurrent `executeGitPush` in one executor; 12 concurrent CLI processes | real | PASS: 1 `EXECUTED`, 99 refused; remote received 1 push. Processes: 1 `EXECUTED`, 10 spent, 1 `REMOTE_MOVED`; 1 push |
| C1 | Crash before claiming | real SIGKILL | PASS: 0 DB rows; retry executes once; next retry refused |
| C2 | Crash during claim commit (txn open, COMMIT unsent) | real SIGKILL | PASS: 0 rows; retry executes once; next retry refused |
| C2b | Crash during commit (COMMIT written, reply unread) | real SIGKILL | PASS: observed committed; recovery refused; 0 pushes (consistent either way by construction of the test) |
| C3 | Crash after claim commit ack | real SIGKILL | PASS: 1 row; recovery refused; 0 pushes; `NOT_STARTED` |
| C3b | Lost commit acknowledgement | **simulated**, not a crash | PASS: lookup finds claim, `SPENT`, 0 pushes |
| C4 | Crash before ledger entry | real SIGKILL | PASS: recovery refused (DB); 0 pushes |
| C5 | Crash before start-record persistence | real SIGKILL | PASS: refused; 0 pushes; `NOT_STARTED` |
| C6 | Crash after start-record persistence | real SIGKILL | PASS: refused; `INDETERMINATE`; remote at pre-state; 0 pushes |
| C6b | Crash immediately before `git push` spawn | real SIGKILL | PASS: same as C6 |
| C7 | Crash during push (receive-pack blocked, client killed) | real SIGKILL | PASS: `INDETERMINATE`; remote at pre-state; refused; reconciliation reads pre-state |
| C8 | Crash after remote success, before evidence | real SIGKILL | PASS: remote at approved SHA; `INDETERMINATE`; refused; reconciliation reads approved SHA; exactly 1 push total |
| C9 / C9b | Crash during evidence persistence (before / after rename) | real SIGKILL | PASS: remote at approved SHA; refused; 1 push total |
| C10 | Crash before client response | real SIGKILL | PASS: classification `EXECUTED`; refused; 1 push total |
| C11 | Executor restart after completed push | real | PASS: refused; `EXECUTED` |
| B1 | Wrong ref, wrong repository, changed target SHA, changed old SHA, wrong remote URL, stale authorization | real | PASS: all refused before any claim (0 DB rows, 0 remote contacts); genuine request then executes once. Stale: `ERR_AUTHORITY_EXPIRED` |
| B2 | Ledger directory lost beside existing history | real | PASS: `ERR_LEDGER_UNAVAILABLE`, not re-initialized |
| R1 | **Physical snapshot taken before consumption, restored after** | real (`pg_basebackup`) | PASS: rows 1 -> 0 after restore. Re-issued same-grant authorization: `ERR_LEDGER_ROLLBACK_DETECTED`, 0 pushes. Same authorization: refused. Fresh authorization while quarantined: `ERR_LEDGER_QUARANTINED`. After an operator removes the latch: executes |
| R1 control | Same test on `3f0e3a5` | real | **Vulnerability reproduced**: re-issued same-grant authorization `EXECUTED`, 1 extra push (same-execution replay was refused, by the start-record collision) |
| G1 | github-app happy path | emulator | PASS: mints `read` then `write`; both revoked; evidence verifies offline |
| G2 | 12 concurrent presentations | emulator | PASS: 12 read tokens, **1 write token**, 1 push. Control `3f0e3a5`: **12 write tokens**, 1 push |
| G3 | Credential failure (token endpoint 500) | emulator | PASS: refused, 0 DB rows, retry after recovery executes |
| G4 | API timeout before execution | emulator | PASS: refused after 11 s, 0 rows, retry executes |
| G5 | Write-token mint fails after the claim | emulator | PASS: refused, authority spent, nothing sent, `NOT_STARTED`, replay refused |
| G6 | Transport timeout after a possibly applied push | emulator | PASS: remote read-back decides `EXECUTED`; replay refused; 1 push |
| G7 | Push applied, remote then unreachable | emulator | PASS: `INDETERMINATE` (exit 2), signed evidence `INDETERMINATE` verifies offline, replay refused, reconciliation shows approved SHA, 1 push |
| G8 | Direct push by a holder of no credential | emulator | PASS (weak: says nothing about GitHub rulesets) |
| Hub restart | | not run against PostgreSQL | `test:hub` 18/18 with the claim double only |

Regression suites on Node 24 at this commit: effect 27/27, single-route 16/16, evidence 49/49,
isolation 9/9, f001-proof-tools 16/16, spent-ledger 11/11, reachability 14/14,
credential-custody 18/18, first-run 6/6, hub 18/18. `git_push_cli` is 34/35: case N builds the
package and needs `typescript` from `npm ci`, which was not run. The pre-existing claim-store
proof (`deployment/freshness/claim-store-proof.mjs`) was also run: 21/21, 1 skipped (restart
case; superseded by R1).

## 6. Offline receipt verification

`scripts/verify-git-push-evidence.mjs <file> --authority-bundle … --root-fingerprint …
--expected-executor-id … --expected-environment-id …` returned `ok:true` for the T01 and G1
envelopes (copies in the evidence directory) and for the G7 `INDETERMINATE` envelope. The
verifier needs no key, network or claim store. Signed evidence contains: execution id, grant id,
authorization receipt hash, authority digest, executor/environment/key/credential ids,
repository, remote URL, target ref, expected old SHA, approved new SHA, observed before/after
SHA, claim decision/namespace/record digest, outcome, reason code, timestamp, signature.
**Missing from the signed body**: an execution-start reference and the GitHub App/installation
identity (D3a). Evidence for operations whose result is unknown is recorded as `INDETERMINATE`
and nothing more is invented.

The remote branch state was verified by `git ls-remote` against the bare repository after every
case (the `reconcile` step in the harness). No GitHub branch was read or written.

## 7. Reproducing the disposable database

```
initdb -D data -A scram-sha-256 -U owner --data-checksums     # as the postgres user
# postgresql.conf: ssl=on, fsync=on, synchronous_commit=on, wal_level=replica, max_wal_senders=4, max_connections=300
# pg_hba.conf:     hostssl all all 127.0.0.1/32 scram-sha-256 ; hostssl replication all 127.0.0.1/32 scram-sha-256
psql -f deployment/freshness/postgres.sql                      # as owner
psql -v executor_password=… -v namespace=f001-closure-ns -f deployment/freshness/provision-executor-login.sql
npm i --no-save pg
# claim-config.json in F001_PG_DIR: host,port,database,user,namespace,passwordFile,caFile (see src/freshness/postgres_claim.mjs)
```

## 8. Remaining limitations (not hidden)

1. Whole-host rollback (database and executor evidence directory restored together) is undetected.
   A wiped executor directory looks like a new deployment and is accepted.
2. Power loss and OS crash untested; `fsync` honesty of the disk is assumed.
3. Static credential kinds (token file, ssh key, `none`) have one credential for read and write;
   the read/write split applies to the `github-app` kind only.
4. Signed evidence does not yet name the credential or the execution-start record (D3a); the
   unsigned outcome record is not fsynced (D3b).
5. `INDETERMINATE` outcomes require an operator to read the remote; no automated reconciler exists.
6. Everything GitHub-side was emulated; GitHub's own behaviour (rulesets, rate limits, token
   semantics, timeouts) is unverified.
7. The harness is not in `npm test`; it needs a database and writes undeletable claim rows.
