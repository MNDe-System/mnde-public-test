# PostgreSQL one-use claims

`deployment/freshness/postgres.sql` defines the claim schema and uniqueness boundary. `provision-executor-login.sql` provisions a restricted executor login. `src/freshness/postgres_claim.mjs` opens the configured primary over verified TLS, checks that it is not a replica and has `fsync=on`, and uses `synchronous_commit=on` for each claim transaction. It never reports `CLAIMED` before commit acknowledgment. Ambiguous acknowledgments cannot authorize a push.

`MNDE_CLAIM_CONFIG` names an absolute-path JSON file with `host`, `port`, `database`, `user`, `namespace`, `passwordFile`, and `caFile`. The password and CA file paths are absolute. Keep the password and all real configuration outside the source repository. A missing or unhealthy backend refuses dispatch; no in-memory production fallback exists.

Run `npm run test:postgres` only with a disposable test primary prepared for the proof script. Set `MNDE_CLAIM_PROOF_DISPOSABLE=1` after verifying the target; the command refuses without it. Its qualification covers the real SQL and adapter, including uniqueness, replay, restricted login, TLS expectations, and restart behavior where its configured harness supports them. Provision the schema and restricted login using the supplied SQL before this test. Local unit tests use isolated claim doubles and do not prove PostgreSQL or power-loss durability. Do not point the proof command at production infrastructure.

Database owners can roll back or restore claims; protecting that authority is an operational requirement outside this software guarantee. Hardware power-loss qualification, storage controller behavior, and filesystem rollback remain open.
