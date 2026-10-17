# F-001 threat model and privilege model

Goal: **one authorization permits at most one exact execution**, enforceable independently of the AI agent requesting the action.
Scope: the `git.push` effect (`bin/mnde-git-push.mjs`, `src/hub/service.mjs`, `src/effects/git-push/`). Not exactly-once: if a push
succeeds and anything after it fails, MNDe never repeats the push; the outcome stays `INDETERMINATE` until someone reconciles.

## Architecture map

```
Agent --API token--> Hub --policy/approval--> signed authorization (grant, execution id, exact action digest)
   (no push credential)                                   |
                                                          v
Executor (own OS user): verify -> bind to request -> LEDGER check -> WITNESS preflight -> read-only credential
   -> remote pre-state -> DATABASE CLAIM -> LEDGER commit -> WITNESS consume -> write credential
   -> START RECORD -> PUSH -> read back -> SIGNED EVIDENCE (v2)
Durable state changes: PostgreSQL claim | executor spent-ledger | witness log | start record | evidence files
Boundaries crossed: agent|Hub, Hub|executor (signed authorization), executor|PostgreSQL (restricted login),
executor|witness (token + pinned key + TLS), executor|GitHub (App token minted per execution), approver|everything (own device)
```

## Adversaries and what stops them

| Adversary / event | Control | Evidence |
| --- | --- | --- |
| Agent alters any approved parameter | exact key-set binding of the signed action to the request | harness B1, `test_git_push_effect` |
| Agent replays an authorization, concurrently or later | PostgreSQL `UNIQUE(namespace, grant_id)` + `PRIMARY KEY(namespace, execution_id)` claim; ledger; witness | T02-T04, X1, W1, W8 |
| Process dies at any step | at-most-once ordering; ledger, claim and witness are written before the effect; start record before the push | C1-C10, W3 |
| Database administrator restores an old snapshot | executor-local ledger detects the forgotten spend and quarantines | R1 |
| Database **and** ledger/evidence restored together | external spend witness refuses the consumed grant | W0 (control W0c reproduces the gap) |
| Witness unreachable / forged / replayed / stale | preflight refuses before anything is spent; unverifiable consume is `UNKNOWN`, never retried | `test_spend_witness`, W2, W5, W6 |
| Executor identity tries to rewrite history | restricted database login; witness data readable only by the witness user; append-only protocol | D1 (21 statements), S1 (15 OS attempts) |
| Agent obtains a GitHub write route elsewhere | executor-only GitHub App credential, minted per execution, `contents:write` only after the durable claim | G2 (12 racers, 1 write token); **live check not done** |
| Forged or altered evidence | Ed25519 signature under a root-pinned executor credential; v2 domain separation; exact key sets | X3, `test_git_push_evidence_v2` |

## Privilege model

**PostgreSQL.** Owner role: owns the schema, applies `deployment/freshness/postgres.sql`, can restore backups; it must not be the executor operator.
Executor login `mnde_executor`: `LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`, `USAGE` on the schema, `EXECUTE` on
exactly `bound_namespace()`, `first_claim(jsonb)`, `lookup_claim(jsonb)`; no table privilege, no ownership, no role switching. Its namespace binding
is a table row it cannot change. The three functions are `SECURITY DEFINER` with a pinned `search_path`. Test `D1` attempts 21 administrative and
history-altering statements as that login (including `pg_basebackup`, `ALTER SYSTEM`, `COPY ... PROGRAM`, replacing the claim function, replication slots)
and all are refused by the server; the legitimate claim path still works.
**Not shown:** that the database administrator is a different person from the executor operator (organizational), or a different machine (this rig is one machine).

**OS.** The harness runs executors as `mnde-exec` and the witness as `mnde-witness` (0700 data directory). `S1`: `mnde-exec` cannot list or read the
PostgreSQL data directory, the database owner password, the witness data, signing or TLS keys; cannot append, truncate, delete or rename the witness log;
cannot signal PostgreSQL or the witness; cannot stop PostgreSQL or move its data directory. Root can do all of it: administrative independence needs separate
machines or accounts (`F001-WITNESS-DEPLOYMENT.md`).

**GitHub.** The agent identity must hold no write credential: no PAT, App key, installation token, deploy key, credential helper, or reachable SSH agent
(`scripts/f001/check-agent-environment.mjs` must exit 0 *as the agent in the deployed topology*, with a **positive** permissions probe; an HTTP 401 probe is
inconclusive). The executor holds the App key; the Hub minimizes it to a per-execution, single-repository token.
This sandbox session is not that topology: it holds `GH_TOKEN`/`GITHUB_TOKEN` and a proxy rewrite for `github.com`
(`docs/evidence/f001/2026-10-17-closure/preflight/agent-credential-exposure.json`), so requirement G cannot be demonstrated here.

## Residual risks

Witness rollback or collusion of all independent domains (`F001-WITNESS-DEPLOYMENT.md`); power loss and disk flush honesty (`F001-POWER-LOSS-RUNBOOK.md`);
a repository administrator can edit rulesets; static credential kinds do not separate read from write; `INDETERMINATE` needs a human; Windows directory flush is not
shown to equal Linux; the harness is not part of `npm test`.
