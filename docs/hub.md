# Hub operation

Configure the variables in `deployment/hub/hub.env.example` using real paths outside the repository. The sample systemd service binds Node to the source entrypoint and expects separately mounted durable data. Provision operator API tokens, signed policy, approval anchors, authority bundle, executor signing identity, GitHub credential configuration, and PostgreSQL claim configuration before use.

The Hub listens on `127.0.0.1` and starts locked. `GET /healthz` reports process liveness; `GET /readyz` returns success only while active. Authenticated `GET /v1/status` reports `LOCKED`, `ACTIVE`, or `DEGRADED`. An authenticated operator uses `POST /v1/unlock` or `/v1/lock` with `{}`. Missing dependencies leave the service degraded or prevent startup, with no protected effect available.

`POST /v1/actions` accepts one JSON object with `id` (UUID), `action: "git.push"`, `repository`, `remote`, `remoteUrl`, `targetRef`, `expectedOldSha`, and `sourceCommit`. Unknown fields or actions, malformed JSON, and duplicate JSON keys are refused. Duplicate IDs return a conflict. The caller identity is taken from its verified bearer token.

`REVIEW` actions can receive existing signed approvals through `POST /v1/actions/:id/approve`; an operator can cancel through `/v1/actions/:id/refuse`. The Hub cannot mint approval artifacts. `GET /v1/receipts/:id` returns the authorization and, when present, the separate signed execution evidence. It does not return the GitHub credential. An `EXECUTING` record after restart is reported as `INDETERMINATE`; it is never automatically retried.

Each boot writes a new locked epoch. The executor checks this epoch itself before credential acquisition and again before dispatch. Locking during an action waits for admitted work to release its credential before the lock is acknowledged; an already-dispatched network effect cannot be recalled.
