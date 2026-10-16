# Evidence inventory, 2026-10-16

What was observed, how, and what it does and does not show. **This is not an F-001
closure package.** F-001 is not closed ([../../../F001-ACCEPTANCE-MATRIX.md](../../../F001-ACCEPTANCE-MATRIX.md)).
It records the read-only checks that could be run without independent infrastructure,
and the acceptance run of the code under test.

No private key, token, password, or credential value appears in any file here. The
agent-environment report lists credential variable **names** only, and the committed copy
withholds names unrelated to GitHub (see its `redaction` field).

## 1. Under test

| Item | Value |
| --- | --- |
| Repository | `MNDe-System/mnde-public-test` |
| PR #58 head (base of this change) | `8feb9959c101cf7765ae708b5c8b7b211935c68f` |
| This change | branch `mnde/guarded-issuance-uc002`, stacked on PR #58 (commit hashes in the PR) |
| `main` at assessment time | `178342be20fcc0e4a74afc3ffef91bd00f5900fd` |
| Node / npm | v24.22.0 / 11.19.1, linux-x64, from nodejs.org, sha256 checked against the published `SHASUMS256.txt` (GPG signature **not** verified) |
| Dependencies | `npm ci` from `package-lock.json` (0 vulnerabilities reported) |
| `pg` driver | **not installed** (see §5) |

## 2. Acceptance run (Node 24.22.0)

Commands, run in order, exit codes recorded by a wrapper using `pipefail`:

| Command | Result |
| --- | --- |
| `npm ci` | exit 0 |
| `npm run ci` = `npm test` + `npm run reviewer-kit` + `npm run check:whitespace` + `npm run test:replay` + `npm run test:conformance` | **exit 0**: `PASS all test scripts (111/111)`, `FINAL VERDICT: PASS`, `PASS whitespace check (538 tracked files)`, `PASS replay verification (11/11)`, `PASS conformance vectors (7/7)`, `PASS CI guardrails` |
| `npm run test:release-identity` | exit 0 |
| `npm run release` | exit 0 |
| `npm run release:verify` (default `HOME=/root`) | **exit 1, 19/20**: `REL-14` failed. See §4. |
| `npm run release:verify` (`HOME=/tmp/claude-0/fakehome`) | `20/20 REL checks passed`, `PASS release truth`; the wrapper then recorded exit 124 because a child process outlived the test until my 900 s timeout. See §4. |
| `npm run check:issuance-guard-mutations` | exit 0: `all 11 mutations are caught` |

Suites that matter to this change, from the same run: `test:issuance-guard` 53/53,
`test:approvals` 20/20, `test:sidecar-pe` 9/9, `test:hub` 18/18, `test:f001-proof-tools` 16/16,
`test:signed-policy-bundle` 16/16, `test:production-signing` 23/23, `test:conformance` 7/7,
`test:git-push-effect` 27/27, `-single-route` 16/16, `-isolation` 9/9, `-cli` 35/35,
`-execution-evidence` 49/49, `-reachability` 14/14, `-credential-custody` 17/17,
`test:pack-security`, `test:shipped-surface-bypass`, `test:conformance-installed-artifact`,
`test:ci-contract`, `test:sbom` (all PASS).

Hashes of the full logs (not committed: 142 KB of test output; reproduce with the commands above):

| Log | sha256 |
| --- | --- |
| `ci-final.log` | `3ea90cd7cb2b45a06e7ad868ee6eb88f0b92659901164f77c5f7f9ce445961c9` |
| `mutations.log` | `669417f632b5d55ac0f63663b518ff4a1115f1ef65c7670e728e8db094d004bb` |
| `release-verify.log` | `3fbe89100c2871cd8c6e828d945a5e61ed268ceb9e294d061a6a05c7e737668b` |
| `release-verify-nonroot-home.log` | `8d73d7fcdb875e2ebea6ddeaa3dd6d6766bb2cc3caad901f7a3b8912011ffd9b` |
| `acceptance-final.txt` | `9ee99ff5ccde231612160b3b3bbe076a4db4c27a979f3eec957e8ed4e98a84ba` |

## 3. Read-only observations committed here

| File | sha256 | Tool and exit | OBSERVED | INFERRED / not shown |
| --- | --- | --- | --- | --- |
| `agent-environment.json` | `ad8ab13f4448528d4203694d52774720d2269bd3593afc8f0eb420221b0004bd` | `check-agent-environment.mjs --probe-github`, exit **1** | `GH_TOKEN` and `GITHUB_TOKEN` set; the token reports `push: true, admin: true` on the repository; no git credential helper configured | That the agent could push (it did, to its own branches). Credentials held elsewhere are invisible to the tool. **Fails criterion C2.** |
| `repository-controls.json` | `5c953037d3a7104c913374912a26ab7058d6fd5a9d85f8e4e96cc247c0e02bbc` | `check-repository-controls.mjs`, exit **0** | `physical-hub`: rules `update`, `deletion`, `non_fast_forward`; sole bypass actor Integration `5105189`; no human bypass. `main`: `pull_request`, `non_fast_forward`, `deletion`, `required_status_checks`; **zero** bypass actors | That a push would be denied. No push was attempted. Admins can edit rulesets. |
| `pending-action.json` | `88ea117e131f26cf424baf8c485fa6acf4b1b8a1e5e2db76738d817ff339679f` | `prepare-pending-action.mjs` | Live tip `dec31d90dc8dd129533e37b5d86cdeddde7dac5e`; deterministic payload commit `2b88c631448714b5830224b2cdfbf4f2c0e14e0c`; two independent preparations gave the same SHA; remote ref unchanged afterwards | Nothing was approved or pushed. |

Further observations from GitHub's repository APIs (read-only GETs, not stored as files):

- Ruleset ids `24445426` and `24445420` (both `created_at` 2026-10-04) and `19596100` (`main protection`), all `enforcement: active`.
- `GET /repos/.../activity` for `refs/heads/mnde-proof/physical-hub`: `branch_creation` by user `mnde-system-2` at 2026-10-01T19:57:35Z; `push` by `mnde-execution-gate[bot]` at 2026-10-01T20:21:17Z (`50bfa16b5b`→`47d6fffbd9`), 2026-10-02T01:38:18Z (`47d6fffbd9`→`ff55bd322f`) and 2026-10-02T05:52:49Z (`ff55bd322f`→`dec31d90dc`).
- `mnde-proof/f001-live-d44946bf` and `f001-race-d44946bf` (2026-09-24): pushes **and force-pushes** by user `mndesystems-ship-it`. These predate the rulesets and were human-pushed.
- The 10-01/02 App pushes **predate** the rulesets (2026-10-04). GitHub shows who pushed what and when; it does not show whether each went through the executor's claim path. The MNDe-side artifacts for those runs were not available to this assessment.

Sandbox-environment identity: the session's `gh`/git token authenticates as `mndesystems-ship-it` with `admin: true`.

## 4. Anomalies, classified

| Observation | Classification | Basis |
| --- | --- | --- |
| `test_production_signing`: "invalid signature (tampered attestation)" failed once (22/23) in an earlier full run, passed 3/3 alone | **Test defect, fixed** (TF-001) | The tamper overwrote the first two hex characters with `00`; a signature already starting `00` is unchanged (about 1 in 256). Not KI-005. |
| `REL-14` fails with `HOME=/root` | **Environment false positive** | REL-14 flags any shipped file containing `homedir()`. In this sandbox that is `/root`, a substring of ordinary text such as `authority/root.key.pem`. The six flagged files were not modified by this work. With a non-colliding `HOME`, `20/20` pass. GitHub's runner uses `/home/runner`; PR #58's `Release contract` check passed there. |
| After the REL checks pass, `release:verify` does not exit and a sidecar process survives | **Test-harness cleanliness issue in this sandbox**, not investigated further | A leaked sidecar from the first run also held the default port and made REL-18 fail once in the second run until I stopped it by PID. Related to KI-001 (fixed ports). Not reproduced on GitHub CI. I did not change the harness. |
| `git`: `fatal: expected 'acknowledgments', received 'packfile'` printed during a toolkit test | Benign noise from a seed push to an empty bare repository; suppressed in the test | The existing suites do not print it |

## 5. What was attempted and not done

| Attempt | Outcome |
| --- | --- |
| Rehearse the 22-case claim-store harness against the sandbox's local PostgreSQL 16 | Started the cluster, applied the schema and provisioning SQL, then the permission classifier **denied** the `npm install --no-save pg` + harness run. I did not work around it. Dropped the rehearsal database and role, stopped the cluster, restored `postgresql.conf` and `pg_hba.conf` byte-for-byte from backups, removed the copied certificate. A rehearsal on the executor's own machine would not have counted as the independent proof regardless. |
| Direct push to a protected ref to demonstrate denial | Not attempted. The session's token is an admin token, and a successful push to the proof ref is permanent. |
| The end-to-end F-001 run | Not run. Needs an Approver key, an App installation, an executor OS identity, and an independent database. |

## 6. Remaining limitations of this evidence

- Everything about the claim store at the commit under test rests on **test doubles** here. The real-PostgreSQL results in the repository's documents are from 2026-09-21/26 at earlier commits against a self-hosted, non-independent database, and were **not reproduced**.
- No MNDe-side artifact from any real GitHub push is included.
- The mutation checker shows the tests are sensitive to removal of the fix; it does not show the fix is sufficient.
- Node 24.22.0 on Linux only. Windows CI behaviour (KI-005) and Windows directory-flush durability were not exercised.
