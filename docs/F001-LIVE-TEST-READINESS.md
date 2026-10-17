# F-001 live GitHub test: readiness and approval request

**Status: prepared, NOT executed. No live push is authorized.** This is the next required test
after the real-PostgreSQL harness: one real push through the MNDe Hub using the GitHub App,
against the repository's `refs/heads/mnde-proof/physical-hub` ref, followed by replay/denial
checks. It follows [F001-PROOF-PROTOCOL.md](F001-PROOF-PROTOCOL.md) and
[MNDE-HUB.md](MNDE-HUB.md); this page records what this session verified and what it could not.

## 1. What was verified read-only on 2026-10-17

| Check | Result |
| --- | --- |
| Pending action reproduces (`prepare-pending-action.mjs`, unauthenticated read of the remote) | **Reproduced.** Old SHA `dec31d90dc8dd129533e37b5d86cdeddde7dac5e`, source commit `2b88c631448714b5830224b2cdfbf4f2c0e14e0c`, ref `refs/heads/mnde-proof/physical-hub`; identical to 2026-10-16. The ref has not moved. |
| C2: agent holds no push credential (`check-agent-environment.mjs --probe-github`) | **FAIL (exit 1).** `GH_TOKEN` and `GITHUB_TOKEN` are present in this agent session and named push-capable; the GitHub probe returned HTTP 401, so their permissions are unknown. C2 needs exit 0 *as the agent in the deployed topology*. Output: `docs/evidence/f001/2026-10-17-closure/preflight/agent-env.json`. |
| C1 configuration (`check-repository-controls.mjs`) | **Not observed.** HTTP 401 listing rulesets from this session. The 2026-10-16 reading (`docs/evidence/f001/2026-10-16/repository-controls.json`) is the only configuration evidence, and is a day old. |
| A deployed Hub, GitHub App key, executor key/credential, approval key, claim-database login | **None exist in this session.** No `MNDE_*` configuration is set. I cannot start the existing Hub here and did not try. |

No administrator token was used to read, write or bypass anything.

## 2. What must exist before the live run (operator-supplied)

1. A Hub host (per `MNDE-HUB.md`) with Node 24.14.1+, git, `pg`, the reviewed checkout, and the configuration in its "Installation and configuration" section: `MNDE_HUB_OPERATORS`, `MNDE_HUB_DATA_DIR`, `MNDE_SIDECAR_AUTH_TOKENS_FILE`, `MNDE_PE_POLICY_BUNDLE`, `MNDE_PE_AUTHORITY_BUNDLE`, `MNDE_PE_APPROVAL_TRUST_ANCHORS`, `MNDE_AUTHORITY_BUNDLE`, `MNDE_RECEIPT_SIGNING_KEY`, and the git.push startup variables (`MNDE_GIT_PUSH_*`, `MNDE_VERIFY_*`, `MNDE_EXECUTOR_*`).
2. `MNDE_GIT_CREDENTIAL_CONFIG` of kind `github-app` (`schema: mnde.git-credential-config.v1`, `app_id`, `installation_id`, `private_key_file`, `api_base_url`, `repositories: ["https:github.com/MNDe-System/mnde-public-test"]`). With this build the Hub mints a **read** token for the pre-state and a **write** token only after the claim and ledger entry.
3. The independent PostgreSQL primary (section 5 below) and `MNDE_CLAIM_CONFIG`.
4. `MNDE_GIT_PUSH_EVIDENCE_DIR` on persistent storage. **New in this build:** it now also holds `spent-ledger/`. Back it up with the database in mind (see `F001-ROLLBACK-TRUST-BOUNDARY.md`); a replacement host needs a copy of `spent-ledger/`.
5. A **non-admin** agent identity with only a Hub API token (the Hub design: the agent has an API credential, not the push credential). The agent session must pass `check-agent-environment.mjs` with exit 0.
6. The App installed on the repository with the App-only update ruleset for the ref still in force; re-run `check-repository-controls.mjs` from an identity that can read rulesets and attach the output.

## 3. The live run, in order (do nothing until approved)

| Step | Who | Action | Stop condition |
| --- | --- | --- | --- |
| L0 | Observer | `git rev-parse HEAD`, Node version; confirm the Hub runs the PR #60 commit named in the closure report | commit mismatch |
| L1 | Observer | `check-agent-environment.mjs`, `check-repository-controls.mjs` | any non-zero exit |
| L2 | Observer | `prepare-pending-action.mjs` again; the six values must match section 1 | ref moved |
| L3 | Non-admin | Direct push denial on a **sacrificial** ref (`mnde-proof/denial-<id>`), three attempts, recorded verbatim | any attempt succeeds |
| L4 | **Approver, own device** | `authorize-git-push.mjs` for exactly the six values — this is the approval | — |
| L5 | Agent → Hub | `POST /v1/actions` with a fresh UUID; `GET /v1/receipts/:id` | non-`EXECUTED` outcome: stop, do not resubmit |
| L6 | Observer | `verify-git-push-evidence.mjs` offline; GitHub activity shows one `push` by the App bot, no `force_push` | mismatch |
| L7 | Database operator | read-only observation of the claim row (protocol step 6) | row missing or later than the push |
| L8 | Agent → Hub | resubmit the same request: expect `ERR_GIT_PUSH_REMOTE_MOVED`/spent, no new claim row | any second push |
| L9 | Sacrificial `replay-<id>` ref | replay after the owner resets the ref: expect `ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT` | — |

The push to `physical-hub` is **permanent**: its rulesets forbid deletion and force-moves for everyone.

## 4. Approval requested — not yet given

I will not run any of section 3 until you reply, in your own words, approving a named run, for example:
*"Approved: L0–L9 on `refs/heads/mnde-proof/physical-hub` and `mnde-proof/replay-<id>`, Hub at <host>, commit <sha>."*
Approval of one run does not extend to another, and I will not hold the approval key.

## 5. Minimum steps for the three open items

**Physical approval (Approver).** On their own device, holding the approval key and no executor key, App key or database credential: confirm the six values from L2, run `authorize-git-push.mjs` (L4), hand `request.json` to the Hub caller. Record who the approver is and that the device is separate from the executor host.

**Power-loss test (Executor operator, on the real Hub hardware).** Not testable from inside a VM. Minimum: (a) on the production storage and filesystem, run the closure harness cases C4–C9 against the real device; (b) repeat C6 and C8 but cut power (hard power-off, not shutdown) at the pause points (`fs-after-start-record`, and the held post-receive hook), then boot and confirm: the claim row, the ledger entries and the start record are present or absent exactly as the harness predicts, the replay is refused, and the remote matches reconciliation; (c) run `pg_test_fsync` on the database volume and record it. Record the result as the Q4 decision (accept or reject `-m immediate` plus this test as sufficient).

**Independent PostgreSQL verification (Database operator).** A primary administered by someone who is not the executor operator and cannot be restored by them: apply `postgres.sql` and `provision-executor-login.sql`; write down who can restore, promote or alter; run `claim-store-proof.mjs` (21 cases + the restart case with `MNDE_CLAIM_PROOF_RESTART_COMMAND`); run `tests/f001-closure/closure.mjs T01–T04 C1–C3 R1` pointing `F001_PG_DIR` at it (R1 needs the operator to supply a snapshot/restore step in place of `pg_basebackup`); provide the section-3 privilege query and `SHOW fsync; SHOW synchronous_commit; SELECT pg_is_in_recovery();`.
