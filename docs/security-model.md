# Security model and limits

The threat boundary is an authenticated caller attempting a malformed, unapproved, replayed, misbound, or locked `git.push` through MNDe. The Hub authenticates and evaluates policy; the executor independently verifies signed authority, exact effect parameters, lock epoch, credential scope, remote pre-state, and a durable one-use PostgreSQL claim before dispatch. The executor controls the GitHub credential. API responses and normal event logs omit secrets and raw Git stderr.

This boundary assumes operational credential exclusivity. Any other valid credential with equivalent GitHub write authority can bypass MNDe. Root or administrator compromise, malicious policy administrators, OS tampering, compromised GitHub authority, physical extraction of unencrypted storage, database rollback, storage rollback, and power-loss behavior are outside the current software proof. The system does not establish universal non-bypassability. It supports `git.push` only.

The claim is spent before a protected effect. If the effect is ambiguous, the authority is not retried. A durable execution-start record supports recovery classification; an interrupted action can remain `INDETERMINATE` and requires human reconciliation against the remote and claim store. A confirmed remote change with missing signed evidence is reported distinctly as `EFFECT_EXECUTED_EVIDENCE_FAILURE`.

See `SECURITY_CLAIMS.md` for claims scoped to this release. Do not store real private keys, bearer tokens, PostgreSQL passwords, GitHub App material, or runtime evidence in this repository.
