# Protected `git.push`

The only supported production effect is a typed move of one remote ref from the authorized old SHA to the authorized source commit. The signed authority binds repository identity, remote name and URL, target ref, expected old SHA, source commit, executor identity, environment, request/grant identity, and expiry. The executor verifies that the configured local repository and remote agree with those fields and that the source commit is suitable before a push is possible.

The executor owns credential acquisition through `MNDE_GIT_CREDENTIAL_CONFIG`. Supported provider behavior is implemented in `src/effects/git-push/credential-provider.mjs`; credentials never come from the API request. The typed transport builds fixed Git arguments, uses no shell, and does not expose arbitrary Git commands.

The remote is checked before the claim. The PostgreSQL one-use claim is acknowledged before a durable execution-start record; the final lock check precedes the protected Git dispatch. Post-state is read independently of Git's exit code. Outcomes are `EXECUTED`, `REFUSED`, `RECONCILED_NOT_APPLIED`, `INDETERMINATE`, or `EFFECT_EXECUTED_EVIDENCE_FAILURE`. All preserve their meanings from the source revision. A spent or ambiguous authority is never automatically retried.

`bin/mnde-git-push.mjs` accepts one request file and calls this same executor once. It is useful for an operator-issued authorization from `scripts/authorize-git-push.mjs`. `scripts/prepare-git-push-trust.mjs` provisions new trust material **outside the repository** and invokes `scripts/trust-enroll-executor.mjs` as a child process. Real private keys and GitHub credentials must stay outside this source tree.

Signed execution evidence records the approved effect, observed pre/post state, claim, outcome, and executor signature. Verify it with `scripts/verify-git-push-evidence.mjs` and independently pinned trust material. An authorization receipt answers whether policy approved the action; it does not establish whether the push happened.
