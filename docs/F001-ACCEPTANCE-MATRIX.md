# F-001 acceptance matrix

Assessed 2026-10-16 at the tip of branch `mnde/guarded-issuance-uc002` (stacked on PR #58 head
`8feb9959c101cf7765ae708b5c8b7b211935c68f`), Node v24.22.0. Companion to [F001-REASSESSMENT.md](F001-REASSESSMENT.md), which holds the
nine questions and their history; this matrix adds the ten push-test criteria and the
independent-database criteria, and says for each what is established, by what, and
what exact action closes it.

**F-001 is NOT closed.** No row below that matters for closure is `ESTABLISHED`
against independent infrastructure, and the one hard blocker (an independently
administered claim database plus a production-trust run) cannot be satisfied from this
environment.

Status words: **ESTABLISHED** (demonstrated, and the evidence meets the written
criterion), **PARTIALLY ESTABLISHED** (demonstrated in part, or on weaker
infrastructure than the criterion requires), **NOT ESTABLISHED**, **BLOCKED** (cannot
be attempted without something this environment does not have).

Evidence tags: **[run]** I ran it today; **[read]** I read the code or live configuration
today; **[doc]** a repository document records it and I did not reproduce it. A
**[doc]** result is not evidence that it holds at this commit.

## A. The nine documented questions (F001-REASSESSMENT.md)

| # | Question | Status | Supporting evidence | What closes it |
| --- | --- | --- | --- | --- |
| Q1 | Authorization usable more than once? | **PARTIALLY ESTABLISHED** | Ordering and refusal on replay: `test:git-push-effect`, `-single-route`, `-cli` pass on Node 24 **[run]**, but with an in-memory/file-backed claim double. Real-store behaviour (22/22; 32-way concurrency; removing `UNIQUE(namespace, grant_id)` drops it to 18/22) is **[doc]**, 2026-09-21 at `714b8ff`, against a self-hosted PostgreSQL, not re-run at this commit. | Run `claim-store-proof.mjs` at the commit under test against the independent database (protocol §3). |
| Q2 | Effect before the durable claim? | **ESTABLISHED** (code) | One call site for `performPush`; claim ticket required; static reachability guard `test:git-push-reachability` 14/14, `-single-route` **[run]**. | None for MNDe's own code. In-process hostile code is out of scope by construction (see Q8). |
| Q3 | Effect without consuming the claim? | **ESTABLISHED** (code) | Same single egress. Red-case results recorded **[doc]**; suites pass **[run]**. | As Q2. |
| Q4 | Same grant after restart / power loss? | **PARTIALLY ESTABLISHED** | Process restart: tested **[run]** (crash-before/after claim in `test:git-push-effect`, CLI kill tests). `-m immediate` restart on PostgreSQL: **[doc]**. Power loss: **never tested** (docs say so). | A decision (accept `-m immediate` as sufficient for v1.0 and say so) or a real power-loss/torn-write test on the chosen host. |
| Q5 | Ambiguous transport failure → blind second push? | **ESTABLISHED** (code) | No retry loop; `UNKNOWN` sends nothing; at-most-once attempt; `test:git-push-effect`, `-cli`, `-execution-evidence` **[run]**. | None. The cost (a consumed authority with maybe no effect) is the intended trade. |
| Q6 | Old datastore restore revives spent authority? | **NOT ESTABLISHED** (open by decision) | Executor login cannot `DELETE/UPDATE/TRUNCATE/DROP` (**[doc]**, harness). The database owner can restore a backup. No witness exists (`PRODUCTION-TRUST-BOUNDARY.md`: "No such design exists"). | Ship with the narrowed claim *"the executor cannot roll the claim store back"*, or design an external monotonic witness. |
| Q7 | Substitution of repo/remote/ref/SHAs/executor/authorization? | **ESTABLISHED** (code) | Field-for-field binding, exact key sets, demo-authority trust-mixing refused; `test:git-push-effect`, `-isolation` **[run]**. | None. |
| Q8 | Production path bypass of the typed executor? | **PARTIALLY ESTABLISHED** | For MNDe's own code: `mnde-git-push` CLI and Hub are the only callers (`test:git-push-cli` case K, `-reachability`) **[run]**. Never operated with production trust material against a production remote. **This session's agent holds an admin token (below), so the premise is false here.** | Operate once (protocol), and enforce credential separation (C2). |
| Q9 | Evidence corresponds to observed remote state? | **ESTABLISHED** | `EXECUTED` requires read-back SHA == approved SHA, enforced at build and verify; `test:git-push-execution-evidence` 49 cases **[run]**; the collector verified evidence from a real executed push and rejected a tampered copy (`test:f001-proof-tools`) **[run]**. | None. |

## B. The ten GitHub-push acceptance criteria

| # | Criterion | Status | Evidence (observed vs inferred) | What closes it |
| --- | --- | --- | --- | --- |
| C1 | Direct unauthorized push is denied | **PARTIALLY ESTABLISHED** | **Observed [read]:** ruleset "F-001.1 App-only proof updates" allows only integration `5105189` to **update** `refs/heads/mnde-proof/physical-hub`; "F-001.1 proof safety" forbids deletion and non-fast-forward with **no** bypass actors; `main` requires a PR, 1 approval and the `Guardrails` check with **no** bypass actors (`docs/evidence/f001/2026-10-16/repository-controls.json`, `check-repository-controls.mjs` exit 0). **Not observed:** an actual denied push. The rulesets were created 2026-10-04, **after** the 2026-10-01/02 App pushes. **Inferred, with a stated hole:** a repository admin can edit or disable rulesets, so this holds against non-admin identities only. | Operator performs the denied push in protocol §4 step 2 from a **non-admin** identity and records the refusal; and decide whether admin-held rulesets satisfy the criterion. |
| C2 | The agent does not hold production push credentials | **NOT ESTABLISHED** in this environment | **Observed [run]:** `GH_TOKEN` and `GITHUB_TOKEN` are set; probed against `MNDe-System/mnde-public-test` the token reports `push: true, admin: true` and authenticates as `mndesystems-ship-it` (`agent-environment.json`, exit 1). I pushed branches with it. The Hub design (**[doc]** `MNDE-HUB.md`: "the agent has an API credential, not the GitHub push credential") is the intended separation, but no Hub deployment was observed. | Run `check-agent-environment.mjs --probe-github` **as the agent in the deployed topology** and get exit 0. Remove admin/push tokens from agent sessions. |
| C3 | An approved exact push succeeds through MNDe | **PARTIALLY ESTABLISHED** | **Observed [read], GitHub's own record:** `physical-hub` was created by a human on 2026-10-01 and updated three times by `mnde-execution-gate[bot]` (2026-10-01T20:21, 2026-10-02T01:38, 2026-10-02T05:52). The older `f001-live-*`/`f001-race-*` proofs (2026-09-24) were pushed, **and force-pushed**, by a human account, so they are not evidence of an enforced boundary. **Not available to me:** the MNDe-side artifacts (signed evidence, claim rows, execution records) for those pushes. | Run the protocol end to end and collect the artifacts; or supply the artifacts from the 10-01/02 runs to `collect-evidence.mjs`. |
| C4 | Effect matches the authorized commit and destination | **PARTIALLY ESTABLISHED** | Code rule ESTABLISHED (Q9). For the 10-01/02 pushes: GitHub shows the before/after SHAs, but without the signed evidence and the approver's request I cannot bind them to what was approved. A pending action is now prepared and reproducible (below). | Protocol §4 step 7 with `--pending` and `--github-activity`. |
| C5 | A reused authorization fails | **PARTIALLY ESTABLISHED** | Tests with a claim double **[run]**; against a real PostgreSQL primary: 2026-09-26 **[doc]** (self-hosted, older commit). Not run against independent infrastructure. | Protocol §3 and §4 steps 8-9. |
| C6 | Evidence carries the required identities and action binding | **PARTIALLY ESTABLISHED** | **Observed [run]:** signed evidence binds executor id, environment id, key id, credential id, grant id, execution id, authorization receipt hash, authority digest, authority bundle fingerprint, repository, remote URL, target ref, expected old SHA, approved new SHA, observed before/after SHA, claim decision/namespace/record digest, outcome, reason code, timestamp. **Gap [doc + read]:** it does **not** name the GitHub App or installation (`PRODUCTION-TRUST-BOUNDARY.md`: "Signed evidence does not yet name the credential"). That identity exists only in the local record and in GitHub's own push record. | Decide whether the evidence schema adds credential kind/scope (a schema change), or accept GitHub's activity record as the corroboration. |
| C7 | Evidence signatures verify offline | **ESTABLISHED** | `verify-git-push-evidence.mjs` needs no key, network or claim store; 49 evidence cases + the collector on a real executed push **[run]**. | None. |
| C8 | Execution-start durability meets the documented requirement | **PARTIALLY ESTABLISHED** | The documented sequence (exclusive create, write, file fsync, close, directory fsync) is implemented and fault-injected (write/sync/close/dir-sync failures consume the authority and send nothing; `test:git-push-cli` 35/35 **[run]**). **Documented limits:** no power-loss test; Windows directory-flush durability is "not a demonstrated guarantee equivalent to Linux". | Decide the target platform; test on it; or accept and state the limit. |
| C9 | The independent claim system observes the operation | **BLOCKED** | No independent database exists in this environment: no `MNDE_CLAIM_CONFIG`, no connection variables, no credentials. A local PostgreSQL 16 exists but is on the executor's own machine, which the written criterion excludes. I attempted a local rehearsal of the harness and it was denied by the permission classifier (it needed an `npm install` of the `pg` driver); I did not work around that and restored the sandbox. | An independently administered primary and a restricted login (protocol §3), and the operator's read-only observation (protocol §4 step 6). |
| C10 | Failure and recovery follow documented behaviour | **PARTIALLY ESTABLISHED** | Crash-before-claim, after-claim-before-transport, after-transport-before-response, outage, timeout, lost acknowledgement, inconsistent lookup: tested with doubles **[run]**; real-store outage case **[doc]** 2026-09-26. | Protocol §5 against the independent primary. |

## C. Independent PostgreSQL criteria

| Criterion | Status | Evidence | What closes it |
| --- | --- | --- | --- |
| Database ownership separation | **BLOCKED** | The runbook's own layout makes the executor host's `postgres` the owner and says so. | An operator who is not the executor operator owns the primary and its volumes, snapshots, backups and failover. |
| Executor role restrictions | **PARTIALLY ESTABLISHED** | Schema grants **[read]** (`postgres.sql`, `provision-executor-login.sql`: `LOGIN NOINHERIT NOSUPERUSER`, `EXECUTE` on 3 functions, nothing else). Server-side refusal of `DELETE/UPDATE/TRUNCATE/INSERT/SELECT/DROP`: **[doc]** 22/22 at `714b8ff`. | Run the harness against the independent primary. |
| Credential separation | **BLOCKED** | Needs the deployment topology. | Executor OS identity holds only its key, the App key, the claim password; approver key on a different device (`FIRST-PRODUCTION-GIT-PUSH.md` "After the first run"). |
| Claim uniqueness, concurrency, single use | **PARTIALLY ESTABLISHED** | 2/8/32-way concurrency, one winner: **[doc]**. Constraint `UNIQUE(namespace, grant_id)` **[read]**. | As above. |
| Namespace isolation | **PARTIALLY ESTABLISHED** | Server-side `bound_namespace()` mapping **[read]**; foreign-namespace claim refused **[doc]**. | As above. |
| Restart behaviour | **PARTIALLY ESTABLISHED** | `-m immediate`: **[doc]**. | Set `MNDE_CLAIM_PROOF_RESTART_COMMAND`. |
| Backup/restore and failover risk | **NOT ESTABLISHED** | Q6. Failover "was not exercised" (**[doc]**). | Decision on the witness; a documented failover test. |
| Power loss | **NOT ESTABLISHED** | Never tested. | Q4. |

## D. What I prepared (all read-only)

| Artifact | Purpose | Result today |
| --- | --- | --- |
| `scripts/f001/check-agent-environment.mjs` | C2 | exit 1: push+admin token present (**[run]**) |
| `scripts/f001/check-repository-controls.mjs` | C1 (configuration) | exit 0 against the live repo (**[run]**) |
| `scripts/f001/prepare-pending-action.mjs` | the exact action awaiting approval | prepared, reproducible, nothing pushed (**[run]**) |
| `scripts/f001/collect-evidence.mjs` | evidence inventory | verified a real executed push, rejected a tampered one; reports NOT_PROVIDED for everything absent (`test:f001-proof-tools` 16/16) |
| [F001-PROOF-PROTOCOL.md](F001-PROOF-PROTOCOL.md) | the operator procedure | written, **not executed** |

## E. The pending action, exactly

Nothing has been pushed. If an authorized operator wishes to run the demonstration, this
is the single action that needs approval, as prepared by `prepare-pending-action.mjs`
(`docs/evidence/f001/2026-10-16/pending-action.json`):

| Field | Value |
| --- | --- |
| Remote URL | `https://github.com/MNDe-System/mnde-public-test.git` |
| Target ref | `refs/heads/mnde-proof/physical-hub` (App-only update ruleset; no deletion or force-move by anyone) |
| Expected old SHA | `dec31d90dc8dd129533e37b5d86cdeddde7dac5e` (the live tip at preparation time; re-read before approving, it must still match) |
| Source commit (approved new SHA) | `2b88c631448714b5830224b2cdfbf4f2c0e14e0c` (one harmless payload commit, `proofs/f001-acceptance-payload.txt`, fixed author/committer/date, a direct descendant of the old SHA) |
| Approval required from | the operator who holds the approval (receipt-signing) key, via `scripts/authorize-git-push.mjs` |
| Also required | the operator's trust material, a GitHub App installation, and the independent claim store |

I have not simulated an approval and have not marked this executed.

## F. Verdict

F-001 stays **open**. In order of what moves it: (1) an independent claim database and a
production-trust run (C9, Q1, Q8); (2) agent/credential separation (C2); (3) the decisions on
Q4 and Q6; (4) the evidence naming the credential (C6). Items 3 and 4 narrow what may be
claimed once item 1 is done; they do not substitute for it.
