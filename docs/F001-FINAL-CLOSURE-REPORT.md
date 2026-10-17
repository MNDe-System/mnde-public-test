# F-001 final closure report

## 1. Executive summary

**Verdict: BLOCKED. F-001 is not closed.**

Everything provable without the operator's infrastructure now passes on one exact commit,
including a full CI run on that commit. Closure is blocked by four things this session cannot supply
and one thing that is genuinely not met:

* **NOT MET (design gap, reproduced):** whole-system rollback. Restoring the claim database **and**
  the executor's evidence directory together revives a consumed authorization (harness scenario `W0`:
  the replay `EXECUTED` and a second push reached the remote). An external witness is required; it is
  designed, not implemented, and implementing it needs operator approval.
* **BLOCKED (no infrastructure):** the real GitHub proof (Hub + GitHub App + protected repository),
  physical approval, power loss / OS crash, independent database administration, and positive
  verification that the designated agent has no write route.
* **Gap (not fixed):** signed evidence lacks an execution-start reference and the GitHub App/installation identity.

No live push was made, no administrator token was used, and no production system was touched.

## 2. Exact tested commit

| Item | Value |
| --- | --- |
| Tested commit | `c252ae4aa6517546a5f0b89a5732bb6ff6a712c5` (PR #60 head when the evidence was produced) |
| Working tree | clean (`git status --porcelain` empty); harness field `tree_dirty_paths: []` |
| Baseline | `3f0e3a599ee73d39ba22bb9596a2e8d39caf6328` (pre-remediation) |
| Node | v24.22.0 (repo requires >= 24) |
| PostgreSQL | 16.15 (Ubuntu), TLS `verify-full`, `fsync=on`, `synchronous_commit=on`, data checksums |
| OS | Linux 6.18.44 (Firecracker VM), single machine |
| Commits in PR #60 | `75f7575` fixes, `4447c72` Windows/CI, `36c151c`/`8d504c6` harness+test, `06a88bd` readiness, `c252ae4` suite cleanup; the commit that adds this report is docs/evidence only |

This report and the evidence files are committed after `c252ae4`; that commit changes only `docs/`
(verify: `git diff --name-only c252ae4 HEAD`). CI for that docs-only head is on the PR and is not
asserted here.

## 3. Trust model

Roles that must not collude: **approver** (approval key), **executor operator** (executor key, GitHub
App key, claim login), **database operator** (owner role, backups, restore), **witness operator**
(proposed, not deployed), **agent** (Hub API token only, no push credential). Details in
`F001-PROOF-PROTOCOL.md` section 0 and `F001-ROLLBACK-TRUST-BOUNDARY.md`. Declared threat model:
a database administrator may restore any database state; the executor-host state is trusted unless
a witness is deployed. **Under that model requirement F (whole-system rollback) is not met.**

## 4. Current architecture

`bin/mnde-git-push.mjs` and `src/hub/service.mjs` are the only constructors of the executor
(`grep createGitPushExecutor`); both reach the single `performPush` call (`src/effects/git-push/index.mjs:906`),
which also needs a claim ticket minted only for a claim made through the adapter the executor opened itself.
Order inside `executeGitPush`: interlock and profile, authorization verify, request binding, **spent-ledger
check (no network)**, read-only credential, remote pre-state, fast-forward check, **PostgreSQL claim**
(`UNIQUE(namespace, grant_id)` and `PRIMARY KEY(namespace, execution_id)`), **ledger commit (fsync file + directory)**,
**write credential**, **start record (fsync)**, push, read-back, signed evidence.
Verified by reading: ledger quarantine is re-read on every use and in `readiness()`; a missing, malformed or
unwritable ledger is `ERR_LEDGER_UNAVAILABLE`; no code path reads `GH_TOKEN`/`GITHUB_TOKEN`; the transport
environment is built from empty.

## 5. Defects identified

| ID | Defect | Reproduced at | Status |
| --- | --- | --- | --- |
| D1 | GitHub-App write token minted before the claim; 12 racing requests got 12 write tokens | `3f0e3a5` (control G2) | Fixed |
| D2 | Database restore let a re-issued authorization for a spent grant push again | `3f0e3a5` (control R1) | Fixed |
| D4 | Ledger opened its directory read-only to fsync: `EPERM` on Windows | CI `6f92967` | Fixed `4447c72` |
| D5 | Hub readiness ignored a quarantined ledger | code review | Fixed `06a88bd` |
| D6 | Cached ledger object did not re-read the quarantine latch | unit test | Fixed before first push of the test |
| D3a | Signed evidence lacks execution-start reference and credential/app identity | design | **Open** (section 16) |
| D3b | Unsigned local outcome record is not fsynced (failure direction is safe: downgrades to `INDETERMINATE`) | review | **Open** |
| F | Whole-system rollback revives authorization | `W0` | **Open** (section 14) |

## 6. Remediation performed

`src/freshness/local_spent_ledger.mjs` (new); ledger and credential ordering in `src/effects/git-push/index.mjs`;
`access: read|write` in `credential-provider.mjs`; readiness; harness `tests/f001-closure/`. Test changes that alter an
expectation, with the reason: `test_git_push_cli` case B no longer asserts `observed.before` because a replay is now
refused before the remote is read (still asserts `ALREADY_SPENT`, claim `SPENT`, no effect, no push);
`test_git_push_isolation` accepts `ERR_LEDGER_UNAVAILABLE` as well as `ERR_EXECUTION_START_NOT_RECORDED` when the evidence
directory is unusable, because the ledger is now the first durable barrier. No security assertion was removed.

## 7. CI results (exact heads)

| Head | Guardrails (Windows) | Release contract | Note |
| --- | --- | --- | --- |
| `c252ae4` | **success** (run `38991817024`, job `117275652208`) | **success** (job `117275652474`) | the candidate; PASS |
| `76e158e` | attempt 1 failed (`test:sidecar-pe`, `ERR_SYSTEM_SATURATED`); **attempt 2 success** (run `38990966726`) | success | same commit, no code change between attempts |
| `156e4cb` | attempt 1 failed (`test:sidecar-pe`); **attempt 2 success** (run `38991048888`) | success | same commit, no code change between attempts |
| `4447c72` | failed only `test:git-push-cli` case B (fixed in `8d504c6`) | success | confirms the Windows fsync fix |

The `sidecar-pe` and `issuance-guard` failures were `ERR_SYSTEM_SATURATED`, the sidecar's own load-shedding guard,
in suites that do not touch this change; my added suite's end-of-run repository deletion was a plausible contributor and
was removed (`c252ae4`). That attribution is an inference; the evidence is that both failed heads passed on re-run with identical code, and that `c252ae4` passed.

## 8. Full local test results (`c252ae4`, Node 24.22.0)

`npm test` (112 suites): **112/112 PASS** (log: `/tmp/claude-0/alltests3.log`, not committed; reproduce with the command in section 18).
Includes git-push effect 27, CLI 35, single-route 16, reachability 14, credential-custody 18, spent-ledger 12, evidence 49,
isolation 9, first-run 6, f001-proof-tools 16, Hub 18, freshness boundary, CI contract, SBOM.

## 9. Real PostgreSQL test results

`tests/f001-closure/closure.mjs` at `c252ae4`: **35 scenarios, 34 PASS, 1 KNOWN_GAP (`W0`), 0 FAIL**
(`docs/evidence/f001/2026-10-17-closure/results.json`). Highlights: 100 concurrent claims -> 1 `CLAIMED` (T03); 100
concurrent `executeGitPush` -> 1 `EXECUTED` (T04); 12 CLI processes -> 1 push; two executors with separate ledgers racing
-> 1 push (X1). Control runs against `3f0e3a5`: `results-control-preremediation-R1.json`, `-G2.json`.

## 10. Real GitHub test results

**BLOCKED.** Not run. All GitHub-path scenarios (G1-G8) use a local emulator and are labelled so. See
`F001-LIVE-TEST-READINESS.md`. Read-only pre-flight on 2026-10-17: pending action reproduced (ref unmoved);
agent-environment probe exit 1 (push-named `GH_TOKEN`/`GITHUB_TOKEN` present, probe HTTP 401 so permissions unknown);
repository-controls read failed with HTTP 401 and is therefore **inconclusive, not a pass**
(`preflight/agent-env.json`, `preflight/controls.json`).

## 11. Physical approval results

**BLOCKED.** Requires the approver's device and key.

## 12. Crash and power-loss results

Process `SIGKILL` at every required boundary (C1-C10), executor restart (C11), PostgreSQL restart/restore: **PASS** (section 9).
Cases: before claim, before/at COMMIT (transaction open, COMMIT written but reply unread, ack received), before ledger, before/after start record,
before `git push` spawn, during push, after remote success before evidence, during evidence persistence (tmp / renamed), before client
response. Each recovery refused reuse, sent nothing new, classified `NOT_STARTED`/`INDETERMINATE`/`EXECUTED` correctly, and an
unknown outcome stayed `INDETERMINATE` until the read-only reconciliation compared the remote. **OS crash and power loss: BLOCKED**
(cannot be induced from inside the VM; procedure in `F001-LIVE-TEST-READINESS.md` section 5).

## 13. Database rollback results

**PASS (database-only).** R1: physical `pg_basebackup` snapshot before consumption, restore after: a re-issued authorization for the
same grant is `ERR_LEDGER_ROLLBACK_DETECTED` with 0 pushes, the executor quarantines, a fresh authorization is
`ERR_LEDGER_QUARANTINED` until an operator removes the latch, then executes. Control at `3f0e3a5` executed the second push.

## 14. Whole-system rollback results

**NOT MET.** `W0` (database + ledger/evidence directory restored together): replay `EXECUTED`, second push received. Documented in
`F001-ROLLBACK-TRUST-BOUNDARY.md`. Proposed fix: option B, a remote append-only ledger with a retention lock in a separate
administrative domain, compared against a witness service and hardware counters in
`F001-EXTERNAL-WITNESS-PROPOSAL.md`. **Not implemented; needs operator approval.** `W0` must flip to REFUSED, and an end-to-end
restoration test must pass, before any claim of rollback resistance.

## 15. Credential separation and database administration evidence

* Executor database login (`D1`, **PASS**): 21 statements refused by the server (DELETE/UPDATE/TRUNCATE/direct INSERT/SELECT of history, rebind namespace, CREATE ROLE, ALTER ROLE SUPERUSER, SET ROLE owner, DROP SCHEMA, ALTER TABLE, CREATE/REPLACE FUNCTION in the schema, GRANT, CREATE DATABASE, `pg_read_file`, `COPY ... PROGRAM`, ALTER SYSTEM, ALTER DATABASE, replication slot, backup start, `pg_basebackup`); role flags all false; `bound_namespace()` still works.
* **Independence NOT demonstrated:** the database ran on the executor's machine and the harness ran as root, which can read, replace and restore the data directory. Administrative independence is **BLOCKED** pending a separately administered primary.
* Agent credentials: **BLOCKED / failing.** Agent session holds push-named tokens (section 10). Positive verification of effective identity and permissions was not obtained.

## 16. Signed receipt verification

Offline verifier: genuine evidence (T01, G1, G7 `INDETERMINATE`) verifies; 9 tampered or forged variants (changed outcome, approved SHA, observed SHA, executor id, removed/flipped signature, truncated JSON, extra field, wrong root fingerprint) are all rejected (`X3`).
**Phase 8 evaluation:** the body already binds authorization receipt hash, authority digest, execution and grant ids, executor/environment/key/credential ids, repository, remote URL, ref, expected old and approved new SHA, observed before/after, claim decision/namespace/digest, outcome and reason. **Missing:** (a) execution-start record reference, (b) GitHub App id, installation id and credential access level/scope. Both exist in the local record (`push_credential`, the start file). The verifier uses exact key sets, so adding them requires a **new schema string** (`mnde.git-push-execution-evidence.v2`: `execution_start {record_sha256, started_at}`, `credential {kind, access, scope, issuance_id, expires_at}`, `ledger {ledger_id}`), the verifier accepting v1 and v2, v1 receipts verifying unchanged, and no token material ever included. **Not implemented**; until then requirement J is met for the fields that exist and **not met** for these two.

## 17. Remaining risks

Whole-system rollback (section 14); power loss and disk `fsync` honesty untested; static credential kinds (token file, ssh key, none) have one credential for read and write; unsigned outcome record not fsynced; no automated reconciler for `INDETERMINATE`; GitHub-side behavior (rulesets, tokens, real timeouts) unverified; a repository administrator can edit rulesets; a wiped executor directory looks like a new deployment; the harness is not in `npm test`; `ERR_SYSTEM_SATURATED` makes Windows CI sensitive to load.
Adversarial review (all failed securely unless noted): two executors racing (X1), restart reuse (C11), database rollback (R1), **whole-system rollback (W0: succeeded; known gap)**, ledger deletion/corruption (X2), wrong branch/repository/SHA/stale (B1), forged/malformed evidence (X3), network partition / delayed API / lost response (G3-G7, C3b), direct credential access (P3 in `test_git_push_cli`). **Not tested because the witness does not exist:** witness unavailability, replay, rollback. **Not tested end to end:** stale approval and missing authorization anchors at the Hub (covered by `test_hub` and `test_policy_engine`, with doubles only).

## 18. Independent reproduction commands

```
git checkout c252ae4aa6517546a5f0b89a5732bb6ff6a712c5 && node --version        # 24.x
npm ci && npm test                                                              # expect 112/112
# disposable PostgreSQL 16 with TLS and the schema: see F001-CLOSURE-REPORT.md section 7
npm i --no-save pg
F001_PG_DIR=<dir> node --no-warnings tests/f001-closure/closure.mjs            # expect 34 PASS + W0 KNOWN_GAP
F001_SRC=<checkout of 3f0e3a5> F001_PG_DIR=<dir> node --no-warnings tests/f001-closure/closure.mjs R1 G2   # control
node scripts/verify-git-push-evidence.mjs <evidence.signed.json> --authority-bundle <bundle> --root-fingerprint <fp> --expected-executor-id <id> --expected-environment-id <env>
```

## 19. Evidence paths

`docs/evidence/f001/2026-10-17-closure/` : `results.json`, `results-control-preremediation-R1.json`, `results-control-preremediation-G2.json`, `T01-evidence.signed.json`, `G1-evidence.signed.json`, `preflight/agent-env.json`, `preflight/controls.json`.
Docs: `F001-CLOSURE-REPORT.md` (earlier report), `F001-ROLLBACK-TRUST-BOUNDARY.md`, `F001-EXTERNAL-WITNESS-PROPOSAL.md`, `F001-LIVE-TEST-READINESS.md`.

## 20. Requirement scorecard and verdict

| | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| A | One approval authorizes only its exact action | **PASS** (local remote) | B1, `test_git_push_effect`, single-route |
| B | Concurrent attempts cannot both acquire authority | **PASS** | T03, T04, X1, G2 |
| C | Consumed authorization not executable after restart | **PASS** | C11, T02 |
| D | Crash before/during/after execution does not authorize another | **PASS** process crash; **BLOCKED** OS crash/power loss | C1-C10; section 12 |
| E | Database restoration alone cannot revive | **PASS** | R1 vs control |
| F | Whole-system rollback cannot silently revive | **NOT MET** | W0 |
| G | Direct GitHub push denied for the non-admin agent | **BLOCKED** | no live proof; C2 fails; controls unreadable |
| H | Authorized GitHub execution succeeds through MNDe | **BLOCKED** | emulator only (G1) |
| I | Replay after success refused | **PASS** locally; **BLOCKED** on GitHub | T02, G6 |
| J | Signed evidence accurately describes the operation | **PARTIAL**: accurate for existing fields; start reference and app identity absent | T01, G1, G7, X3; section 16 |
| K | Independent verification reproduces | **PASS** offline verifier; third-party reproduction not done | X3, section 18 |
| L | Required CI passes on the final exact head | **PASS** for `c252ae4`; the docs-only report commit has its own run | section 7 |

**F-001 verdict: BLOCKED.** It does not qualify for closure.

## 21. Minimum operator checklist

1. **Remove push credentials from agent sessions**, create a non-admin agent identity holding only a Hub API token, and run `check-agent-environment.mjs --probe-github` as that agent until it exits 0. (G, C2)
2. **Provide infrastructure:** Hub host, GitHub App installation and key, executor key and credential, and an independently administered PostgreSQL primary (someone other than the executor operator holds owner, backup and restore rights). Run `claim-store-proof.mjs` and `closure.mjs` against it. (H, E, section 15)
3. **A rulesets reader:** an identity that can run `check-repository-controls.mjs` (section 1b of the protocol) and a sacrificial `mnde-proof/denial-<id>` ref for the three denied pushes from the non-admin identity. (G)
4. **Approve in your own words** a named live run (L0-L9 in `F001-LIVE-TEST-READINESS.md`) on `refs/heads/mnde-proof/physical-hub` plus a sacrificial replay ref, naming the commit and Hub host; the approver performs the physical approval on their own device. (H, I, physical approval)
5. **Power-loss test** on the real Hub hardware: cut power at the C6 and C8 pause points, boot, confirm replay refusal and reconciliation. (D)
6. **Decide the witness:** choose option B and the separate administrative domain, and approve an implementation branch. Then implement, flip `W0` to REFUSED, and run an end-to-end whole-system restoration test. (F)
7. **Approve evidence v2** (section 16) if requirement J must name the execution-start record and the GitHub App.
