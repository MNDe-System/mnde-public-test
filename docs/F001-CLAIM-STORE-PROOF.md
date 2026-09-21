# F-001 claim store: deployment proof

**Status: the claim store is proven. F-001 is not closed.** Those are different
statements and this document keeps them apart.

First run: 2026-09-21, against PostgreSQL 16.13, from `main` at `714b8ff`.
Harness: `deployment/freshness/claim-store-proof.mjs`.

## Why this exists

F-001 is the one that matters: **a verified receipt is a signature, and a
signature can be presented twice.** Nothing in a receipt makes it single-use.
MNDe's answer is that authority has to be spent somewhere that cannot be rewound,
and that answer lives in exactly two files — `deployment/freshness/postgres.sql`
and `src/freshness/postgres_claim.mjs`.

Until this run, neither had ever been executed. The SQL had never been applied to
a server. The adapter had never opened a connection: its only tests pass it
invalid configuration and check that it refuses. A design nobody has run is a
design nobody has tested, and this one is load-bearing for every production claim
MNDe intends to make.

## What the run establishes

22 of 22 cases, with the adapter **unmodified**, against a real primary over
verified TLS, as a restricted `NOINHERIT` non-owner login.

**An authority is spent exactly once.**

- A fresh authority is `CLAIMED`, and the acknowledgement echoes the submitted
  record field for field. A status flag that does not echo the record is not
  treated as authority.
- Replaying the same `execution_id` is `ALREADY_SPENT`.
- **A new `execution_id` reusing a spent `grant_id` is `ALREADY_SPENT`.** This is
  the case F-001 names. A receipt presented a second time under a fresh execution
  id does not buy a second claim, because the grant is what carries the authority
  and the grant is what gets spent.
- 2, 8, and 32 concurrent claims of one grant each produce **exactly one**
  `CLAIMED`. 16 concurrent claims of one `execution_id` likewise. Losers come back
  `ALREADY_SPENT` or throw; a throw becomes `UNKNOWN` upstream and sends nothing,
  which is safe. What never happens is a second claim.
- A claim survives a `-m immediate` restart, which skips the shutdown checkpoint
  and forces WAL recovery.

**The executor login cannot roll the store back.** Tested by issuing each
statement directly as that login, not by trusting the adapter to refrain:
`DELETE`, `UPDATE`, `TRUNCATE`, direct `INSERT` bypassing `first_claim`, direct
`SELECT`, `DROP SCHEMA`, rebinding its own namespace, and granting itself a second
namespace are all refused by the server. A claim for a foreign namespace is
refused server-side even when submitted directly, so the adapter's own
client-side namespace check is defence in depth rather than the boundary.

## What it does NOT establish

Read this section before quoting the one above.

- **It does not close F-001, and it does not enable execution.** The claim store
  is one of four pieces. The narrow typed effect does not exist; nothing calls
  `openExecutorClaimBackend`; the claim is not yet taken before transport. The
  executor still refuses every protected effect with
  `ERR_FRESHNESS_DEPLOYMENT_DISABLED`, and that is still correct.
- **"The executor cannot roll it back" is not "nobody can."** Whoever owns the
  database can restore a backup. Keeping restore and admin authority outside the
  automated system is a deployment requirement this proof assumes, not one it
  verifies. A stronger claim needs an external monotonic witness.
- **Restart is not power loss.** `-m immediate` forces WAL recovery but does not
  exercise a disk that lies about flushing. `fsync` and `synchronous_commit` were
  `on`, and the adapter refuses a server where `fsync` is not `on`, but no
  hardware-level durability claim is supported here.
- **No managed provider was tested.** This ran against a self-hosted PostgreSQL
  16.13. Whether Neon, Supabase, or RDS permit this schema as written — the
  `SECURITY DEFINER` functions, the separate owner, the restricted login, and a
  readable `fsync` setting — is **unknown and untested**. Check before choosing
  one.
- **No failover was tested.** The adapter refuses a server where
  `pg_is_in_recovery()` is true, but a mid-operation promotion or partition was
  not exercised.

## The proof bites

A proof that passes against a broken store proves nothing, so the harness was run
against two deliberately broken deployments.

| Broken deployment | Result |
| --- | --- |
| `UNIQUE(namespace, grant_id)` removed from the schema | 18/22 — the grant-replay case and all three concurrency cases fail |
| Executor login granted table-level `SELECT/INSERT/UPDATE/DELETE/TRUNCATE` | 10/22 — the rollback section fails |

The first is worth reading twice: dropping one constraint reproduces F-001
exactly. One grant, spent repeatedly.

## Running it

The harness is deliberately **not** in `npm test`. It needs a provisioned
PostgreSQL primary and the `pg` driver, neither of which exists in CI, and it
writes rows that are by design impossible to delete. Run it once against a
freshly provisioned claim database, before that database is used for anything,
and keep the output.

1. Apply `deployment/freshness/postgres.sql` **as the database owner**, which must
   not be the executor login.
2. Provision the restricted login exactly as the comments at the foot of that file
   prescribe — a dedicated, non-owner, non-superuser, `NOINHERIT` login, bound to
   one immutable namespace, granted `USAGE` on the schema and `EXECUTE` on the
   three functions and nothing else. Do not grant table writes, schema ownership,
   role switching, or snapshot privileges.
3. Require TLS for that login in `pg_hba.conf` (`hostssl … scram-sha-256`). The
   adapter sets `rejectUnauthorized: true` and will not connect otherwise.
4. Write the config file and point `MNDE_CLAIM_CONFIG` at its absolute path. Every
   field is required and no extra field is permitted: `host`, `port`, `database`,
   `user`, `namespace`, `passwordFile`, `caFile`. The password and CA files are
   separate absolute paths.
5. Install `pg` in the executor runtime. It is not a dependency of this package —
   the adapter imports it dynamically so that non-deployment paths never load it.

```
MNDE_CLAIM_CONFIG=/abs/path/claim-config.json \
  node ./deployment/freshness/claim-store-proof.mjs
```

To include the durability case, also set `MNDE_CLAIM_PROOF_RESTART_COMMAND` to a
command that restarts the server with `-m immediate`. Left unset, that case
reports `SKIP` rather than passing quietly.

## What is next for F-001

In order, and none of it is started:

1. **Decide the first narrow typed effect.** This is the open design decision, and
   it is not a coding task. Dispatch will not be a restored `run()` callback:
   arbitrary JavaScript cannot be shown to be idempotent, single-effect, or free
   of a second egress path. It has to be a narrow typed effect that derives its
   request from signed fields.
2. Promote claim derivation and the claim protocol out of
   `experiments/exp-001-stage2/src/freshness.mjs` into `src/`, where a caller can
   reach them.
3. Take the claim **before** transport, and never send on `UNKNOWN`.
4. Re-run this proof against the chosen production database, including a managed
   provider if one is chosen.
