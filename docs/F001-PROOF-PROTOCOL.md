# F-001 independent execution proof: operator protocol

**Status: written, NOT executed.** Nothing in this document has been run end to end.
Parts of it that can be run read-only were run on 2026-10-16 and their output is in
`docs/evidence/f001/2026-10-16/`. Every step that needs infrastructure or authority this
repository's CI and the authoring session do not have is marked **[OPERATOR]**.

Purpose: establish, with a real effect and evidence a stranger can check, that an AI agent
cannot push to a protected ref except through MNDe's authorization boundary. The criteria
this must satisfy are the rows of [F001-ACCEPTANCE-MATRIX.md](F001-ACCEPTANCE-MATRIX.md).
It extends [FIRST-PRODUCTION-GIT-PUSH.md](FIRST-PRODUCTION-GIT-PUSH.md), which is the
how-to for the executor itself; this document is the what-to-prove and how-to-record-it.

## 0. Roles, and why they must be different people or machines

| Role | Holds | Must NOT hold |
| --- | --- | --- |
| **Approver** | the approval (receipt-signing) key; runs `authorize-git-push.mjs` | the executor key, the App key, DB credentials |
| **Executor operator** | executor key + root-signed credential, the GitHub App private key, the claim-store login (password + CA file); runs `mnde-git-push` under a dedicated OS identity | the approval key, DB owner rights, restore rights |
| **Database operator** | the claim database owner role; provisions the schema and login; can run read-only observation queries | the executor key, the App key, the approval key |
| **Agent** | an API credential for the Hub (if the Hub is used) | any GitHub push credential, any admin token |
| **Observer** | read access to evidence and to GitHub's activity record | write access to anything |

The proof is only as independent as this separation. If one person holds two of the
first three rows, say so in the report and classify the affected criteria
PARTIALLY ESTABLISHED. The claim database in particular is **not independent** if the
executor operator can restore it (Q6): record who can.

Stop conditions: stop and report if any pre-flight in §1 fails, if the remote tip moved
since preparation, or if any step produces an unexpected exit code. Do not retry an
authorization after a non-zero exit; issue a new one.

## 1. Pre-flight (read-only) [run by the Observer]

Record the exact commit and versions first.

```bash
git rev-parse HEAD && node --version && npm --version     # Node must be 24.x
npm ci && npm test                                         # must be green; keep the log
```

**1a. The agent holds no push credential (criterion C2).** Run this *as the agent*, in the
agent's real environment:

```bash
node scripts/f001/check-agent-environment.mjs --probe-github MNDe-System/mnde-public-test
```

Required: exit `0` and `github_probe.token_permissions_on_repository.push` not `true`.
On 2026-10-16 in the authoring session this exited `1` with `push: true, admin: true`
(`agent-environment.json`). That is the expected result for a developer-grade agent
session and it **fails** C2. Fix the topology; do not edit the checker.

**1b. Repository controls (criterion C1, configuration half).**

```bash
node scripts/f001/check-repository-controls.mjs \
  --repo MNDe-System/mnde-public-test --ref refs/heads/mnde-proof/physical-hub --expected-app-id 5105189
```

Required: exit `0`. This reads rulesets only. It confirms the App-only update rule, no
deletion, no non-fast-forward, no human bypass, and an unbypassable `main`. Read its
`cannot_observe` list: it cannot see a denied push, organization-level rulesets it cannot
read, or that repository admins can edit rulesets.

**1c. Prepare the pending action (read-only).**

```bash
node scripts/f001/prepare-pending-action.mjs \
  --remote-url https://github.com/MNDe-System/mnde-public-test.git \
  --target-ref refs/heads/mnde-proof/physical-hub --workdir <empty dir>
```

It prints the six values the Approver will sign and a deterministic payload commit.
Run it twice on two machines; the `source_commit` must match. The ref is read from the
remote now; if it moves before approval, prepare again.

## 2. Direct push is denied (criterion C1, behavioural half) [OPERATOR]

A configuration read is not a denied push. Do the denial from a **non-admin** identity
that is not the App (a throwaway user with write access is ideal):

> **Do this against a sacrificial ref, not the real proof ref.** If the control were
> misconfigured, a successful push to `physical-hub` would be permanent: the same
> ruleset that blocks force-moves would block undoing it. Ask a repository admin to
> add a ruleset on `refs/heads/mnde-proof/denial-*` identical to the two F-001.1
> rulesets, create `mnde-proof/denial-<id>` once, then run:

```bash
git push origin <any-descendant-sha>:refs/heads/mnde-proof/denial-<id>        # expect: rejected
git push --force origin <older-sha>:refs/heads/mnde-proof/denial-<id>         # expect: rejected
git push origin :refs/heads/mnde-proof/denial-<id>                            # expect: rejected
```

Record the three rejections verbatim (GitHub's message names the rule). Save as
`direct-push-denial.json`: `{ "ref": ..., "identity": ..., "attempts": [{ "command": ..., "result": ..., "exit": ... }] }`.
Then run `check-repository-controls.mjs --ref refs/heads/mnde-proof/denial-<id>` and
attach it. If any attempt **succeeds**, stop: C1 is failed and the control is broken.

Also record, honestly, that a repository or organization **administrator** can disable
the rulesets. If the acceptance decision is that this is unacceptable, the fix is to
move the rulesets to the organization with no admin override, or to accept the limit in
writing.

## 3. The independent claim database [OPERATOR: Database operator]

Do not use a database on the executor's machine. Do not use one the executor operator can
restore. A local container does **not** satisfy this step; say so if one is used for a
rehearsal.

1. The Database operator applies `deployment/freshness/postgres.sql` as the owner, then
   `deployment/freshness/provision-executor-login.sql` with the agreed namespace
   (`-v namespace=<MNDE_GIT_PUSH_NAMESPACE>`), over `hostssl ... scram-sha-256` only.
2. The Database operator records, in writing, who can: restore a backup, promote a
   replica, change `pg_hba.conf`, and read/alter `mnde_claim.*`. List names or roles.
3. The executor operator writes `claim-config.json` (`host, port, database, user,
   namespace, passwordFile, caFile`, nothing else) and sets `MNDE_CLAIM_CONFIG`.
4. The executor operator runs the existing 22-case harness against the **independent**
   primary, once, before it holds any real claim (it writes rows that cannot be deleted):

   ```bash
   npm install --no-save pg          # the driver is not a package dependency
   MNDE_CLAIM_CONFIG=/abs/claim-config.json node deployment/freshness/claim-store-proof.mjs
   ```

   Required: all cases PASS. For the restart case the Database operator provides
   `MNDE_CLAIM_PROOF_RESTART_COMMAND` (a `pg_ctl restart -m immediate`); a `SKIP` is not a
   pass. Keep the full output.
5. Database operator evidence (they run it, not the executor):

   ```sql
   \du mnde_executor
   SELECT has_table_privilege('mnde_executor','mnde_claim.claims','DELETE')   AS can_delete,
          has_table_privilege('mnde_executor','mnde_claim.claims','UPDATE')   AS can_update,
          has_table_privilege('mnde_executor','mnde_claim.claims','TRUNCATE') AS can_truncate,
          has_table_privilege('mnde_executor','mnde_claim.claims','SELECT')   AS can_select;
   SHOW fsync;  SHOW synchronous_commit;  SELECT pg_is_in_recovery();
   ```

   Required: all four privileges `false`; `fsync` and `synchronous_commit` `on`; not in recovery.

## 4. The end-to-end run

Two refs, because a replay on the protected ref is refused by the **lease** (the remote has
moved) and cannot be reset (nobody may force-move it), so it can never show the **claim**
refusing. The sacrificial ref is resettable by its owner and can.

| Ref | Used for | Properties |
| --- | --- | --- |
| `refs/heads/mnde-proof/physical-hub` | the exact approved push; direct-push denial context | App-only update; no deletion or force-move by anyone. **The push is permanent.** |
| `refs/heads/mnde-proof/replay-<id>` | replay, concurrency, claim-vs-lease | created by a human, resettable by that human; the App must be installed on the repo |

**Step 1. Prepare** (§1c). **Step 2. Deny** (§2).

**Step 3. Approve [OPERATOR: Approver, on their own device].** Look at the six values and
nothing else. Running this command is the approval of exactly this push:

```bash
node scripts/authorize-git-push.mjs --remote-url <url> --target-ref <ref> \
  --expected-old-sha <old> --source-commit <new> --subject <approver id> --out request.json
```

**Step 4. Execute [OPERATOR: Executor operator], once.** Under the dedicated OS identity,
with the production environment from `prepare-git-push-trust`:

```bash
node bin/mnde-git-push.mjs request.json | tee result.json ; echo "exit $?"
```

Expect exit `0` and `"outcome":"EXECUTED"`. Any other exit (`2` INDETERMINATE, `5`, `6`, `7` evidence failure) is a stop: record it and follow `GIT-PUSH-CLI.md` "What an operator does after a non-zero exit". Never re-run the same request after a non-zero exit expecting a different result.

**Step 5. Verify the evidence offline [Observer, any machine, no network].**

```bash
node scripts/verify-git-push-evidence.mjs <signed_evidence_path from result.json> \
  --authority-bundle <published bundle> --root-fingerprint <fingerprint obtained out of band> \
  --expected-executor-id <id> --expected-environment-id <env>
```

**Step 6. The claim system observes the operation [OPERATOR: Database operator].**
Read-only, as the owner. Record the output and its timestamp:

```sql
SELECT namespace, execution_id, grant_id, claimed_at,
       record->>'executor_id'  AS executor_id,
       record->>'receipt_hash' AS receipt_hash,
       record->>'aplus_digest' AS aplus_digest
FROM mnde_claim.claims WHERE namespace = '<namespace>' ORDER BY claimed_at;
```

Required: exactly one row for this grant; `execution_id`, `grant_id`, `executor_id` and
`receipt_hash` equal the signed evidence; `claimed_at` is **earlier** than the `recorded_at`
in the evidence and earlier than GitHub's push time. Save as `claim-observation.json`
(`{ "observed_by": ..., "at": ..., "rows": [...] }`).

**Step 7. GitHub's own record [Observer].**

```bash
gh api "repos/MNDe-System/mnde-public-test/activity?ref=refs/heads/mnde-proof/physical-hub&per_page=20" > github-activity.json
```

Required: one `push` entry whose `after` equals the approved new SHA, by the App's bot
login, no `force_push`.

**Step 8. Collect.**

```bash
node scripts/f001/collect-evidence.mjs --evidence <signed.json> --authority-bundle <bundle> \
  --root-fingerprint <fp> --expected-executor-id <id> --expected-environment-id <env> \
  --pending pending-action.json --started-marker <git-push-<id>.started.json> --cli-result result.json \
  --claim-observation claim-observation.json --direct-push-denial direct-push-denial.json \
  --github-activity github-activity.json --expected-pusher-login "<app>[bot]" --out f001-evidence.json
```

`complete` must be `true`. Missing inputs make it `false` and name themselves.

**Step 9. Replay refused by the lease (protected ref).** Run `mnde-git-push request.json`
again with the **same** file. Expect exit `1`, `ERR_GIT_PUSH_REMOTE_MOVED`, nothing sent,
no new claim row. This shows replay fails, but only that.

**Step 10. Replay refused by the claim (sacrificial ref).** Repeat Steps 3-4 on
`replay-<id>`. Then the owner of that ref resets it to the old SHA with their own account
(`git push --force-with-lease=<ref>:<new> origin <old>:<ref>`) and the Executor operator
re-runs the **same** `request.json`. Expect exit `1`, `ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT`,
`claim.decision` `SPENT`, the ref **unchanged**. Also: a new execution id on the spent
grant, and the spent execution id under a new grant: both `SPENT`.

**Step 11. Concurrency.** On a fresh sacrificial ref, 8 processes present one
authorization at once (`xargs -P 8` over `mnde-git-push request.json`). Required: exactly
one `EXECUTED`, the rest refused with nothing sent, and exactly **one** claim row. Note that
most losers will be refused by the lease, not the claim (the docs say so); the row count and
the single push are the assertions. Repeat 3 times.

## 5. Failure and recovery [OPERATOR]

Only on sacrificial refs.

| Case | How | Required |
| --- | --- | --- |
| Claim store unreachable | Database operator stops the primary or blocks the port; Executor operator runs a **new** authorization | exit `1`, `ERR_GIT_PUSH_CLAIM_NOT_ESTABLISHED`, remote untouched, no row |
| Wrong TLS CA | executor config whose `caFile` does not verify the server | TLS verification fails and the claim is not established: expect exit `1` / `ERR_GIT_PUSH_CLAIM_NOT_ESTABLISHED`, or exit `4` if the file is unreadable. Record which; either way nothing is sent and no row is written |
| Restart of the primary (`-m immediate`) | Database operator, between two authorizations | the earlier claim row survives; a replay is `SPENT` |
| Crash between claim and push; crash during push | **no safe live injection exists**; covered by `test:git-push-effect` and `test:git-push-cli` with doubles | state this; do not claim it for the live path |
| Power loss | not testable here | state **NOT ESTABLISHED** |

## 6. What to publish, and what never to

Publish: `f001-evidence.json`, the signed evidence, `result.json`, `claim-observation.json`,
`direct-push-denial.json`, `github-activity.json`, the harness output, the pre-flight JSON,
the authority bundle and the root fingerprint, with the sha256 of each. Never publish: any
`*.pem` private key, `claim-password`, `git-credential.json`, `request.json` before it is
spent, or `authority/root.key.pem`. Run `grep -r "BEGIN .*PRIVATE" <package>` before upload.

## 7. Mapping to the matrix

| Step | Moves |
| --- | --- |
| 1a | C2 |
| 1b, 2 | C1 |
| 3 | database criteria; Q1, Q6 (documents the restore authority) |
| 4-5, 7-8 | C3, C4, C6, C7 |
| 6 | C9 |
| 9-11 | C5, Q1 |
| §5 | C10, Q4 (partly) |
| execution-start marker present in the collector input | C8 (durability of the marker itself is not proven by its presence) |

F-001 closes only when every mandatory row is `ESTABLISHED` on independent infrastructure
and the two accepted limits (Q4 power loss, Q6 owner restore) are stated in the claim.
