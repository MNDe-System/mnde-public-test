# Release architecture

`bin/mnde-hub.mjs` starts `src/hub/service.mjs`. The Hub uses bearer authentication from `src/sidecar-auth/index.mjs`, strict JSON parsing, durable action records in `src/hub/state.mjs`, and signed policy evaluation in `src/hub/authorization.mjs`. It accepts only typed `git.push` action parameters. A request ID is caller-chosen and cannot be reused to mint fresh authority.

The policy engine and signed policy bundle produce `ALLOW`, `REFUSE`, or an approval-required state exposed by the Hub as `REVIEW`. Approval artifacts are verified against configured trust anchors. The Hub then issues an executor-bound signed authorization, distinct from an execution result.

`src/effects/git-push/index.mjs` is the protected effect gate. It verifies authority and exact effect fields, checks the executor-side lock, obtains the configured credential, reads the remote pre-state, takes a one-use PostgreSQL claim, durably records execution start, checks the lock again, and calls the typed Git transport. It observes post-state and persists signed execution evidence. The direct `bin/mnde-git-push.mjs` command uses this same gate.

`tools/verify.mjs` verifies authorization offline. `scripts/verify-git-push-evidence.mjs` verifies signed execution evidence offline. Historical `ecs.receipt.v2` replay verification still uses the preserved `preflight/`, `orbit/`, `arm/`, and `ram0na/` engines. Those engines are compatibility dependencies, not alternate production effects.

Production source imports neither `tests/` nor the test claim adapters. Test doubles are loaded only by test preloads. No generic executor, sidecar, MCP server, or shell execution surface is included.
