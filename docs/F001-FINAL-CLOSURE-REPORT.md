# F-001 final closure report

## 1. Executive verdict

**BLOCKED. F-001 is not closed and this report does not claim it is.**

The engineering that could be done and proven in this environment is done and passes on one exact commit:
the external spend witness now defeats the whole-system rollback (`W0`) that previously revived a consumed
authorization, signed evidence v2 records the execution-start record, GitHub App identity and witness entry, and the
suite and a 46-scenario real-infrastructure harness pass with executors running as an unprivileged OS user.

It stays BLOCKED for reasons that only the operator can change: there is no real GitHub proof (no protected
repository, no GitHub App, no physical approval, no non-admin agent identity), no real power-loss test, no
independently administered PostgreSQL or witness, and the witness itself has no rollback protection. See the scorecard (section 20).

## 2. Final implementation commit and environment

| Item | Value |
| --- | --- |
| Tested code commit | `f14a78652281285d2ad58c95f26a5195e4412f19` (PR #60; harness field `tree_head`, `tree_dirty_paths: []`) |
| The commit that adds this report and the evidence | docs and evidence only (verify: `git diff --name-only f14a786 HEAD` lists only `docs/`) |
| Baseline (pre-remediation) | `3f0e3a599ee73d39ba22bb9596a2e8d39caf6328` |
| Node / PostgreSQL / OS | v24.22.0 / 16.15 with TLS, `fsync=on`, `synchronous_commit=on` / Linux 6.18.44 (Firecracker VM, one machine) |
| Executor identity in the harness | OS user `mnde-exec` (not root); witness as `mnde-witness` (0700 data directory) |
| Remote in the harness | local bare repositories over `file://`; GitHub-App cases use a **local emulator**, not GitHub |

## 3. Threat model and trust boundary

`F001-THREAT-MODEL.md` (architecture map, adversary table, PostgreSQL and OS privilege models),
`F001-ROLLBACK-TRUST-BOUNDARY.md`, `F001-WITNESS-DEPLOYMENT.md` (including the witness's own limits).
Declared model: the database operator may restore any database state; the executor host is trusted *unless* a witness is deployed in a
third administrative domain; the witness operator is assumed not to roll the witness back. Under that model whole-system rollback
of database + executor is refused. Rollback of the witness, or collusion of all three domains, is **not** covered.

## 4. Vulnerability reproduction (old implementation)

* Database-only restore: re-issued same-grant authorization executed a second push at `3f0e3a5` (`results-control-preremediation-R1-G2.json`, `R1`).
* Write tokens before the claim: 12 racing presentations minted **12** write tokens for 1 winner at `3f0e3a5` (`G2` control).
* **Whole-system rollback (`W0c`)**: at the current code with the witness disabled, restoring PostgreSQL *and* the executor's ledger/evidence directory lets the same grant execute a second push, which reached the remote. This is the control that gives `W0` meaning.

## 5. External witness design

Option B as documented in `F001-EXTERNAL-WITNESS-PROPOSAL.md` (append-only, first-writer-wins log in a separate administrative domain). Reference
implementation `deployment/witness/witness-server.mjs`, client `src/freshness/spend_witness.mjs`, protocol `mnde.spend-witness.v1`:
`POST /v1/consume` keyed by `grant_id` and by `execution_id` per namespace; hash-chained JSONL log fsynced before `CONSUMED`; Ed25519
responses over a domain-separated canonical body, bound to a request nonce and pinned by the client; bearer token bound to one
`(executor_id, namespace)`; server refuses to start on any log that does not verify; stale locks of dead processes are taken over.
State machine: `UNSEEN -> CONSUMED` at the witness, `CONFLICT`, and client-side `UNKNOWN`/`UNAVAILABLE`. A separate `RESERVED` state was deliberately not added:
consumption is itself the irreversible boundary and a reservation would only add a state that can strand an authority.
Executor order: ledger check -> **witness preflight** -> read-only credential -> remote pre-state -> **database claim** -> ledger commit ->
**witness consume** -> write credential -> start record -> push -> read-back -> signed evidence. Configured means required;
`MNDE_WITNESS_REQUIRED=true` makes absence a refusal; readiness and the Hub reflect the witness.

## 6. Proof that W0 no longer authorizes replay

`W0` (real PostgreSQL physical snapshot + executor ledger/evidence restored; **two** restored executors replay at once): both `REFUSED`
(`ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT` and `ERR_GIT_PUSH_WITNESS_ALREADY_CONSUMED`), 0 pushes reached the remote, witness log unchanged, witness entry
n=23 returned by the witness's signed `lookup` (`docs/evidence/f001/2026-10-17-closure/W0-witness-lookup.signed.json`). `W4`: the witness is `SIGKILL`ed
and restarted between the spend and the rolled-back replay; the replay is still refused. Unit level: `test:git-push-spend-witness` includes the same
scenario with a control that reproduces the gap without a witness.
**Limit:** the witness here runs on the same machine as the executor. This proves the mechanism and that the executor's identity cannot touch the
witness (`S1`), not that the witness is administratively independent.

## 7. Concurrency proof

`T03` 100 concurrent claims -> 1 `CLAIMED`; `T04` 100 concurrent executes in one executor -> 1 push, 12 CLI processes -> 1 push; `X1` two executors, separate ledgers -> 1 push;
`W1` two executors with **separate PostgreSQL databases**, separate ledgers and evidence directories, 8 processes -> exactly 1 push and 1 witness entry;
`G2` 12 racers -> 1 write token (old code: 12); `W8` 100 concurrent consumes over TLS -> 1 `CONSUMED`, 63 `CONFLICT`, 36 `UNKNOWN`.
The 36 `UNKNOWN` are connections the reference server refused at its 64-connection cap; the client fails closed on them. No second spend resulted.
Operators should size that cap.

## 8. Durability proof

Process `SIGKILL` at every boundary (before claim, claim commit open/written/acknowledged, before ledger, before and after the start record, before `git push`,
during the push, after remote success, during evidence persistence, before the reply) plus the witness boundaries `W3` (before, during, after the consume).
Each recovery refused reuse and sent nothing; unknown outcomes stayed `INDETERMINATE`. **This is not power-loss evidence.** The real test needs hardware:
tooling is built and exercised only with a simulated cut (`P1`/`P2`, `F001-POWER-LOSS-RUNBOOK.md`).

## 9. Live GitHub authorization proof

**BLOCKED.** Not run. `F001-LIVE-TEST-READINESS.md` holds the full approval-request table; the unfilled fields are operator-supplied. No admin token was used and nothing was pushed to GitHub.

## 10. Physical Hub approval proof

**BLOCKED.** Needs the approver's own device and key.

## 11. Direct-push denial proof

**BLOCKED.** This session holds `GH_TOKEN`/`GITHUB_TOKEN` and a `github.com` proxy rewrite (`preflight/agent-credential-exposure.json`) and an earlier permissions probe returned HTTP 401
(`preflight/agent-env.json`), which is inconclusive, not a pass. `G8` shows only that an unauthenticated direct push to the emulator is refused.

## 12. Evidence integrity proof

v2 (`F001-EVIDENCE-V2.md`, `src/effects/git-push/evidence.mjs`): adds `execution_start` (sha256 of the durable start file), `push_credential` (kind, access, scope, App id, installation id, expiry; no token material)
and `witness` (id, key id, sequence, entry digest), signed over a domain-separated input; v1 still verifies. `test:git-push-evidence-v2` (10 cases) and `X3` reject: altered start digest or time, credential kind/access/scope/App id,
witness entry/sequence, action digest, receipt hash, executor, outcome, approved SHA, wrong domain, v1/v2 label confusion, extra or missing fields, unknown versions, wrong root, untrusted issuer, and evidence presented as authorization.
`G1-evidence.signed.json` (emulator) carries `app_id 424242`, `installation_id 777`, `access write`, the start digest and witness entry 31. What the verifier does **not** prove: that the ref moved, that the start file still exists, or that the witness entry exists; each is a separate observation.

## 13. Independent verification

The offline verifier needs no network or keys. `F001-REPRODUCTION-GUIDE.md` lets another engineer rebuild the environment and repeat everything. **No independent third party has reproduced it.**

## 14. PostgreSQL separation proof

`D1` (21 server-refused administrative and history-altering statements as the executor login, including `pg_basebackup`, `ALTER SYSTEM`, `COPY ... PROGRAM`, replacing the claim function) and `S1` (15 OS-level attempts as `mnde-exec` against PostgreSQL and the witness) all refused; legitimate claims still work.
**Not shown:** that the database administrator is a different person or machine (this is one machine; root can reach everything).

## 15. Full testing matrix

| Layer | Result at `f14a786` | Evidence |
| --- | --- | --- |
| `npm test` (115 suites) | **115/115 PASS** | Node 24.22.0, clean tree |
| New suites | spend-witness 17, git-push-spend-witness 9, git-push-evidence-v2 10, spent-ledger 12 | `tests/` |
| Closure harness | **46/46 PASS** (0 failed, 0 known-gap) | `results.json` |
| Controls on `3f0e3a5` (`R1`, `G2`) | vulnerabilities reproduce | `results-control-preremediation-R1-G2.json` (its `tree_dirty_paths` lists the `node_modules` symlink only) |
| Scenario groups | T01-T04, B1/B2, C1-C11, R1, X1-X3, D1, S1, W0/W0c, W1-W6/W8, G1-G8 | `results.json` |
| Simulated power cut tooling | `P1`/`P2` pass for 4 boundaries with a SIGKILL standing in for the cut | not committed as a result; **not power-loss evidence** |

## 16. CI results

| Head | Guardrails (Windows) | Release contract |
| --- | --- | --- |
| `f14a786` | see section 22 | success (job `117290072640`) |
| `b5bfdba` | failed: only the three new witness suites, `EPERM: operation not permitted, fsync` (directory fsync), fixed in `f14a786` | success |
| `c252ae4`, `9550117` | success | success |

## 17. Remaining limitations

1. **Witness rollback / collusion of all domains** is not detected. Design for a second witness or anchored heads is in `F001-WITNESS-DEPLOYMENT.md`; not implemented.
2. The witness is not yet deployed in an independent administrative domain; the harness runs it beside the executor.
3. Power loss and disk-flush honesty untested on hardware; Windows directory flush is not shown equivalent.
4. GitHub-side behaviour, rulesets, a real physical approval and a non-admin agent were not exercised.
5. Static credential kinds (token file, ssh key, none) have one credential for read and write.
6. `INDETERMINATE` outcomes need an operator; the reference server's connection cap makes a large burst produce `UNKNOWN`s (fail closed).
7. The unsigned local outcome record is not fsynced (safe direction: downgrades to `INDETERMINATE`).
8. A repository administrator can edit rulesets.

## 18. Reproduction commands

`F001-REPRODUCTION-GUIDE.md`.

## 19. Operator approvals and run IDs

None. No live push, ruleset change, credential change, production database or Hub change, or witness deployment was made or approved.

## 20. Requirement scorecard

| | Requirement | Status | Basis |
| --- | --- | --- | --- |
| A | Exact authorization | **PASS** (local remote) | B1, effect/single-route suites |
| B | Concurrency | **PASS** | T03, T04, X1, W1, W8, G2 |
| C | Restart never revives spent authority | **PASS** | C11, T02, W4 |
| D | Crash and power loss | **PARTIAL**: process-crash PASS; real power loss **BLOCKED** | C1-C10, W3; runbook and tooling only |
| E | Database-only rollback | **PASS** | R1 vs control |
| F | Whole-system rollback | **PARTIAL**: mechanism proven for database + ledger + executor restore (W0, W4, with control W0c); witness rollback and witness independence not covered | section 6, 17 |
| G | Direct push denied for the non-admin agent on GitHub | **BLOCKED** | section 11 |
| H | Approved execution succeeds through MNDe on GitHub | **BLOCKED** | emulator only (G1) |
| I | Replay refused | **PASS** locally; **BLOCKED** on GitHub | T02, G6, W0 |
| J | Signed evidence binds action, start record, executor, witness, App | **PASS** (local/emulator); live evidence **BLOCKED** | section 12 |
| K | Independent verification | **PARTIAL**: offline verifier and reproduction guide exist; no independent reproduction; no administrative separation | sections 13, 14 |
| L | CI on the final exact head | see section 22 | |

## 21. Rationale

BLOCKED rather than PASS because G, H and the live half of I and J have no evidence; D has no real power-loss evidence; F is proven only against the declared threat
model and the witness is neither independently administered nor itself rollback-protected; K lacks independent reproduction. Nothing here was downgraded: each is a
missing requirement, not a known-harmless issue.

## 22. CI on the final head, and the minimum operator checklist

CI on `f14a786`: recorded on PR #60 (Guardrails run `38996483923`); this report does not assert a result it could not observe at writing time.

Minimum operator actions, in order:
1. Remove push credentials from agent sessions; create a non-admin agent identity (Hub API token only); get `check-agent-environment.mjs` to exit 0 with a **positive** permissions probe. (G)
2. Deploy the witness in a third administrative domain (`F001-WITNESS-DEPLOYMENT.md`); set `MNDE_WITNESS_CONFIG` and `MNDE_WITNESS_REQUIRED=true` on the executor. Decide on a second witness / anchored heads. (F, K)
3. Provide an independently administered PostgreSQL primary; run `claim-store-proof.mjs` and the harness against it. (K)
4. Supply the Hub host, GitHub App id and installation, executor identity, and a rulesets reader; fill the table in `F001-LIVE-TEST-READINESS.md`; **approve a named run in your own words**; the approver performs the physical approval on their device. (G, H, I, J live)
5. Run `F001-POWER-LOSS-RUNBOOK.md` on the real hardware: four boundaries, a real power cut each. (D)
6. Have a second engineer follow `F001-REPRODUCTION-GUIDE.md`. (K)
