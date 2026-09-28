# `mnde-git-push`: the production caller of the typed `git.push` executor

`mnde-git-push` is the one supported way to run MNDe's typed `git.push` effect in
production. It is a thin adapter around `createGitPushExecutor()`
(`src/effects/git-push/index.mjs`). It reads one request file, loads the
executor's startup configuration from the deployment environment, calls
`executeGitPush()` once, and prints the executor's result as one line of JSON.

**The CLI contains no authorization logic.** It never decides whether a push may
happen. Authorization, request binding, the durable single-use claim, the claim
ticket, the typed transport, the post-state read-back and the signed execution
evidence all run inside the executor, exactly as they do without the CLI.
`git.push` still executes only through `createGitPushExecutor()`.

**The CLI never retries.** Each invocation calls `executeGitPush()` at most once.
A failed, refused or ambiguous push is reported and left alone. Another attempt
needs a new authorization, because the claim store refuses a second use of the
same authority (see "What an operator does after a non-zero exit").

## Command

```
mnde-git-push <request.json>
```

It takes exactly one argument, the path to a request file. There are no flags and
no subcommands, and it never prompts.

It is a separate binary rather than `mnde git-push` on purpose. The process that
holds the executor's signing key then loads only the executor and its startup
loader, not the onboarding CLI (`bin/mnde.mjs`) and its discovery and
config-rewriting code. That keeps the executor process small and lets a static
test list everything it imports.

## Request file

The file is the `executeGitPush()` request, unchanged. It must have exactly these
seven fields: no more, no fewer.

```json
{
  "repository": "ssh:github.com/example-org/example-repo",
  "remote": "origin",
  "remoteUrl": "ssh://git@github.com/example-org/example-repo.git",
  "sourceCommit": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
  "targetRef": "refs/heads/main",
  "expectedOldSha": "9c1185a5c5e9fc54612808977ee8f548b2258d31",
  "authorization": { "schema_version": "mnde.signed-receipt.v2", "...": "the executor-bound signed authorization envelope, verbatim" }
}
```

(The SHAs above are placeholders. Real values are full, lowercase 40-hex commit
IDs, and `repository` is the canonical identity of `remoteUrl`, as
`canonicalRepositoryIdentity()` in `src/effects/git-push/validate.mjs` derives it.
All six values must match the signed parameters in `authorization`.)

- The CLI refuses the file before loading any key if it is unreadable, is not
  JSON, is not an object, or has any field other than those seven. It checks the
  field names against the executor's own list (`REQUEST_KEYS`), not a copy.
- The CLI does not coerce, fill, expand or infer anything. An abbreviated SHA
  stays abbreviated and the executor refuses it. Nothing fetches remote state to
  complete a request.
- Startup settings cannot be named in the request. A request that includes
  `claimBackend`, `executorSigner`, `trustedRootFingerprint`,
  `authorityBundlePath`, `allowedSchemes`, `MNDE_CLAIM_CONFIG` or any other extra
  field exits `3` before the executor is constructed.

## Required production configuration

All of it comes from the environment of the process that runs the CLI, set by
whoever deployed the executor. None of it can come from the request.
Every variable below is required unless it is marked optional. Paths must be
absolute. There are no defaults, no development fallbacks, and no demo keys.

| Variable | Meaning |
| --- | --- |
| `MNDE_PROFILE` | Must be `production`. |
| `MNDE_CLAIM_CONFIG` | Absolute path to the claim-store config read by `src/freshness/postgres_claim.mjs`. The CLI checks that the file exists and is not writable by other users; the executor's own adapter opens and validates it. See `docs/F001-CLAIM-STORE-PROOF.md`. The `pg` driver must be installed in the executor runtime. |
| `MNDE_GIT_CREDENTIAL_CONFIG` | Absolute path to the push credential configuration (`mnde.git-credential-config.v1`): which kind of credential the executor uses and which repositories it is scoped to. The only source of push credentials; there is no fallback. See `docs/PRODUCTION-TRUST-BOUNDARY.md`. |
| `MNDE_GIT_PUSH_REPO_PATH` | The local repository holding the objects to push. |
| `MNDE_GIT_PUSH_NAMESPACE` | The claim namespace. It must equal the namespace the claim-store login is bound to, or every claim fails closed. |
| `MNDE_GIT_PUSH_EVIDENCE_DIR` | Where local and signed execution evidence and start records are written. |
| `MNDE_VERIFY_AUTHORITY_BUNDLE` | Published authority bundle (JSON). Same variable as `executor/index.mjs`. |
| `MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT` | Out-of-band root fingerprint pinning that bundle. |
| `MNDE_VERIFY_ENVIRONMENT_ID` | Expected environment id. |
| `MNDE_VERIFY_EXPECTED_EXECUTOR_ID` | Expected executor id. |
| `MNDE_EXECUTOR_ID` | This executor's id. Must equal `MNDE_VERIFY_EXPECTED_EXECUTOR_ID`. |
| `MNDE_EXECUTOR_PRIVATE_KEY` | Executor Ed25519 private key, outside the package, not group/world-writable, no symlinks in its path. |
| `MNDE_EXECUTOR_CREDENTIAL` | Root-signed executor credential for that key. |
| `MNDE_EXECUTOR_ENVIRONMENT` | This executor's environment. Must equal `MNDE_VERIFY_ENVIRONMENT_ID`. |
| `MNDE_GIT_PUSH_ALLOWED_SCHEMES` | Optional. Comma-separated remote URL schemes. Unset means the executor default, `https,ssh`. |
| `MNDE_GIT_PUSH_TRANSPORT_ENV` | Optional. Absolute path to a JSON object of transport variables for git. Only `PATH` and `GIT_SSL_CAINFO` are accepted (`ALLOWED_TRANSPORT_ENV` in `src/effects/git-push/transport.mjs`); anything else, including `HOME`, `SSH_AUTH_SOCK` and `GIT_SSH_COMMAND`, is refused, because credentials come only from `MNDE_GIT_CREDENTIAL_CONFIG`. |

The executor key and credential are loaded by the existing
`assertExecutorIdentityReadiness()`, which verifies the credential against the
configured bundle and proves the key matches it before the executor is built. The
key is never printed and never copied. If any of this fails, the CLI exits `4`
before an executor exists.

Startup also refuses, with exit `4`: MNDe's shipped demo root or an authority
named `local`/`demo` (`ERR_GIT_PUSH_DEMO_TRUST_MATERIAL`); an executor key that
is also one of the authority's keys (`ERR_GIT_PUSH_TRUST_ROLE_REUSE`); and, on
POSIX, a trust file that is inside the local repository or the package, not
owned by the executor's user (configuration may be root-owned), writable by
others, or for the executor key, readable by others
(`ERR_GIT_PUSH_TRUST_FILE_INSECURE`). On Windows the permission part is not
checked; see `docs/PRODUCTION-TRUST-BOUNDARY.md`.

## Production invocation

```
MNDE_PROFILE=production \
MNDE_CLAIM_CONFIG=/etc/mnde/claim-config.json \
MNDE_GIT_PUSH_REPO_PATH=/srv/mnde/work/example-repo \
MNDE_GIT_PUSH_NAMESPACE=mnde-prod-git-push-01 \
MNDE_GIT_PUSH_EVIDENCE_DIR=/var/lib/mnde/git-push-evidence \
MNDE_GIT_CREDENTIAL_CONFIG=/etc/mnde/git-credential.json \
MNDE_VERIFY_AUTHORITY_BUNDLE=/etc/mnde/published-authority-bundle.json \
MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT=<root fingerprint, from out of band> \
MNDE_VERIFY_ENVIRONMENT_ID=prod \
MNDE_VERIFY_EXPECTED_EXECUTOR_ID=mnde:org:prod:executor:gitpush:01 \
MNDE_EXECUTOR_ID=mnde:org:prod:executor:gitpush:01 \
MNDE_EXECUTOR_PRIVATE_KEY=/etc/mnde/keys/executor-gitpush-01.pem \
MNDE_EXECUTOR_CREDENTIAL=/etc/mnde/keys/executor-gitpush-01.credential.json \
MNDE_EXECUTOR_ENVIRONMENT=prod \
mnde-git-push /var/spool/mnde/requests/push-1234.json
```

## Output

stdout is always exactly one line of JSON with `schema`
`mnde.git-push-cli-result.v1`. `exit_code` in it always equals the process exit
status. When the executor ran, the fields come straight from its result:

```json
{
  "schema": "mnde.git-push-cli-result.v1",
  "exit_code": 0,
  "outcome": "EXECUTED",
  "ok": true,
  "executed": true,
  "reason_code": null,
  "detail": null,
  "executor_invoked": true,
  "effect_attempted": true,
  "execution_id": "…",
  "grant_id": "…",
  "executor_id": "mnde:org:prod:executor:gitpush:01",
  "authorized": { "repository": "…", "remote": "origin", "remote_url": "…", "source_commit": "…", "target_ref": "refs/heads/main", "expected_old_sha": "…" },
  "observed": { "before": "…", "after": "…" },
  "claim": { "namespace": "…", "backend_kind": "remote-postgresql", "decision": "CLAIMED", "note": null, "record_digest": "…" },
  "evidence_path": "/var/lib/mnde/git-push-evidence/git-push-….json",
  "signed_evidence_path": "/var/lib/mnde/git-push-evidence/git-push-….signed.json",
  "signed_evidence": { "schema_version": "mnde.git-push-execution-evidence-envelope.v1", "...": "…" }
}
```

The local evidence record is not copied to stdout in full, because it holds git's
stderr, which can contain remote URLs or credential-helper output. It stays in the
file at `evidence_path`. `signed_evidence` is the portable, offline-verifiable
record, and it excludes stderr by design.

When the executor did not run (exit `3` or `4`), `outcome` is `INVALID_INPUT` or
`STARTUP_FAILED`, with a `reason_code` and a `detail`. Nothing is written to
stderr, apart from anything Node itself prints on a crash.

## Exit codes

| Exit | Outcome | Meaning |
| --- | --- | --- |
| 0 | `EXECUTED` | The remote was read back at the approved SHA. The only success. |
| 1 | `REFUSED` | Nothing was sent. The authority may or may not have been spent: see `claim.decision`. |
| 2 | `INDETERMINATE` | A push was sent and the remote's state could not be confirmed. A human reconciles against the remote. |
| 3 | `INVALID_INPUT` | Usage error, or the request file was unreadable, not JSON, or had the wrong fields. The executor was never constructed. |
| 4 | `STARTUP_FAILED` | Configuration missing or unusable, or the executor refused to construct. Nothing was sent. |
| 5 | `INTERNAL_ERROR` | Unexpected exception. If `executor_invoked` is `true`, treat it like `2`: the push may have started. |
| 6 | `RECONCILED_NOT_APPLIED` | A push was sent and did not land, and the remote was read back unchanged. The authority is spent. |
| 7 | `EFFECT_EXECUTED_EVIDENCE_FAILURE` | The remote was observed at the approved SHA, but required signed evidence generation or durable persistence failed. `executed: true`, `ok: false`; the authority is spent. This is an MNDe completion failure, not a failed push. |

Exit `0` requires both the confirmed remote effect and a completed signed artifact.
For exit `7`, `observed.after` retains the approved SHA and `evidence_error.stage`
distinguishes `generation` from `persistence`; the reason code is
`ERR_GIT_PUSH_EVIDENCE_GENERATION` or `ERR_GIT_PUSH_EVIDENCE_PERSISTENCE`.
There is no network retry on either failure. Reconcile and preserve any returned
signed envelope; do not submit the same push again to repair evidence.

The signed artifact is written to an exclusively created temporary file in the
evidence directory, file-fsynced, closed, renamed to a unique final name, then
directory-fsynced. Any new evidence-directory ancestors and their links in the
existing parent are also flushed when created. A path is acknowledged only when
all required operations succeed. After a rename followed by a directory-flush
failure, a valid file may exist, but `signed_evidence_path` is null because its
durability was not acknowledged. The returned envelope still describes the
observed effect with the existing `EXECUTED` evidence schema; exit `7` describes
MNDe's failure to complete persistence, so offline verification is unchanged.
Handled failures attempt to remove the temporary file. If cleanup itself fails,
or the process dies before cleanup, a `.tmp` file can remain; it is not an
acknowledged signed artifact.

The local unsigned diagnostic record remains a best-effort direct write: it is
not atomically replaced or fsynced and is not the required success artifact.
The start record remains exclusive and file-fsynced; this change does not claim
to prove its power-loss recovery classification. Filesystem, OS and storage must
honor successful flushes and same-directory rename semantics. Windows uses a
read/write directory handle for flushing; unsupported flush operations fail
closed rather than being skipped. Existing evidence-directory parents must
already be durably provisioned. Hardware power loss, remote durability, backup
rollback and PostgreSQL durability are not proven by these filesystem calls.

An authorization that says ALLOW never produces exit `0` by itself. Only the
executor's observed `EXECUTED` outcome with completed signed-evidence persistence does.

## What an operator does after a non-zero exit

Do not re-run the same request expecting a different result. If the authority was
claimed, it is spent, and the claim store refuses it with
`ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT` even when the remote is back in the approved
pre-state. For `2` and `5`, reconcile what the remote actually holds and use
`classifyGitPushExecution()` on the evidence directory. Anything further needs a
new authorization.

## Security boundary

```
mnde-git-push
  → createGitPushExecutor()             constructed once, from deployment config only
  → executeGitPush(request)             called once
      → production posture, authorization verification, request binding
      → durable single-use claim (claim store opened by the executor itself)
      → claim ticket → typed git.push transport
      → observed post-state → signed execution evidence
```

What the CLI does not do, each enforced by `npm run test:git-push-cli`:

- It never imports the transport, the claim module or the claim adapter, never
  starts a process, and never names `git`. Case K reads its imports.
- It constructs the executor once and calls `executeGitPush()` once per
  invocation. Every case counts both calls through a test-only preload.
- It never supplies a claim backend and has no fallback store. Missing claim
  configuration, or a claim config file that does not exist, exits `4` before
  the executor exists (cases E and F1). Unreachable claim storage is refused by
  the executor with nothing sent (case F2).
- It never supplies a push credential and there is no fallback to ambient ones.
  A missing credential configuration exits `4` (case P1); a credential scoped to
  another repository refuses before the claim, so the same authority can then
  execute (P2); ambient tokens, askpass, ssh settings, `HOME` and injected git
  config never reach the push, observed from the remote's own hook (P3); demo
  trust, a reused key and insecure trust files refuse startup (P4, P5).
- Request input cannot select or change startup configuration (case J).

The suite runs the CLI as a child process against real git repositories. A
post-receive hook in the remote counts every push it receives, so "nothing sent"
is measured at the remote. The claim store in CI is a file-backed test double.
The same cases were also run by hand against a real PostgreSQL claim store; see
the 2026-09-26 CLI addendum in `docs/F001-REASSESSMENT.md`.

## What this does not settle

Adding this CLI gives F-001 a supported production caller. **By itself it does
not close F-001.** These remain separate questions:

- **Power loss.** Claim durability has been shown across an `-m immediate`
  restart, not across loss of power.
- **Database-owner restore.** The executor login cannot roll the claim store
  back. The database owner can restore an old backup and revive spent authority.
- **Credential custody and in-process code.** Code running inside the executor
  process could start `git` itself. The executor now takes its push credential
  only from `MNDE_GIT_CREDENTIAL_CONFIG` and gives it only to the git processes
  that talk to the remote (`docs/PRODUCTION-TRUST-BOUNDARY.md`). Whether nothing
  else holds a credential for the repository is still a deployment property.
