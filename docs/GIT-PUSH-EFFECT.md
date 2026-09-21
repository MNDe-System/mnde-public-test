# `git.push` — the first narrow typed production effect

**Status: built, tested, and reachable only by a deployment that configures it.
F-001 is NOT closed.** Those are different statements and this document keeps
them apart.

Written 2026-09-21, against `main` at `f50dd8f`.

## What it is

One capability: move one branch on one remote from one exact commit to one exact
commit, when a signed authorization said so and that authority has not been spent
before.

```js
executeGitPush({
  repository,        // canonical repository identity, derived from remoteUrl
  remote,            // the remote name the local repository has configured
  remoteUrl,         // the remote's URL
  sourceCommit,      // full 40-hex commit to push
  targetRef,         // refs/heads/<branch>
  expectedOldSha,    // full 40-hex commit the remote must currently be at
  authorization      // mnde.signed-receipt.v2 envelope
})
```

Every one of those fields must equal the value inside the signed authorization.
The caller supplies nothing the approver did not see, and a request carrying an
unrecognized field is refused rather than having it ignored — an ignored field is
a constraint the caller believed they had.

## Why a subprocess is acceptable here

The distinction is not "subprocess or no subprocess". It is:

| | |
| --- | --- |
| A process-execution capability | `execute(command, args)` |
| A `git.push` capability | `executeGitPush({ repository, sourceCommit, targetRef, expectedOldSha, authorization })` |

The second is what exists. The executable is fixed (`git`), the operation is
fixed (`push`), and the argv is assembled entirely by MNDe from values that
already passed validation. There is no shell — no `sh -c`, no `cmd /c`, no
PowerShell, no command-string construction — no caller-supplied refspec, and
nowhere for a caller to put a flag.

The argv is exactly:

```
git push --no-verify --force-with-lease=<target-ref>:<approved-old-sha> -- <remote-url> <approved-new-sha>:<target-ref>
```

Not present, and refused if they ever appear: `--force`, `--mirror`, `--all`,
`--delete`, `--prune`, `--receive-pack`, `--exec`, and `-c` config overrides.

**Why git rather than an API.** The contract MNDe needs is an atomic
compare-and-swap on a ref. GitHub's REST ref-update endpoint takes no
expected-old-SHA: it can refuse a non-fast-forward, which is strictly weaker,
because a ref that moved forward under us would still be overwritten. The git
wire protocol carries the old SHA in the update command itself. The exact-state
guard is the reason for the subprocess, not an accident of it.

`--force-with-lease` is an exact-state guard, not a direction guard — it would
permit rewriting history that happened to still sit at the leased SHA. So the
fast-forward requirement is checked separately, before transport.

## The order of operations, and why the order is the whole design

Everything above the claim is a read. Everything below it is irreversible.

1. `MNDE_PROFILE=production`, and the executor production posture is satisfied
   (configured authority bundle that loaded and is not demo material, pinned root
   fingerprint, expected executor id, environment id).
2. The authorization verifies: authentic, `mnde.signed-receipt.v2`,
   executor-bound, ALLOW in its own signed body, credential and keys still
   unrevoked *now*, not expired, executor id equal to ours.
3. **Neither layer rests on the authority bundle shipped in the package.** The
   outer envelope can be production-signed while the inner policy decision falls
   back to the demo authority and the whole thing still reports verified. That is
   the trust-mixing hole closed on the executor in #43, and it is closed here too.
4. The authorization is for `git.push`.
5. The signed parameters are exactly the six expected keys, full lowercase 40-hex
   SHAs (never abbreviated, never the null SHA), a `refs/heads/<name>` target, a
   transport scheme on the operator's allowlist, no credentials in the URL, no
   value beginning with `-`, and a `repository` that matches the identity derived
   from `remote_url`.
6. The caller's request equals the signed parameters, field for field.
7. The local repository's configured remote points at the authorized URL.
8. Both approved SHAs exist locally and are commits.
9. The remote's current ref is read independently and equals `expected_old_sha`.
10. `expected_old_sha` is an ancestor of `source_commit`.
11. **The authority is durably spent.** Nothing is sent unless the claim comes
    back `CLAIMED`. `SPENT` refuses. `UNKNOWN`, `NO_BACKEND` and
    `BACKEND_UNAVAILABLE` all refuse and send nothing — and `UNKNOWN` is never
    retried, because the claim may have landed and a retry is exactly the replay
    F-001 names.
12. Only then, the push.

## After the push, the remote decides

Exit code 0 is the subprocess's opinion. The ref is read back independently and
that observation is what the evidence records. There are four outcomes because
there are genuinely four things that can be true:

| Outcome | Meaning |
| --- | --- |
| `EXECUTED` | the ref is at the approved source commit |
| `REFUSED` | nothing was sent |
| `RECONCILED_NOT_APPLIED` | sent, did not land, the remote read back cleanly at the approved pre-state |
| `INDETERMINATE` | the ref is at a third SHA, or could not be read — a human has to reconcile it |

An ambiguous transport failure is **not** retried. The remote is inspected and
the outcome is decided from what it says. In every case the consumed grant stays
consumed: the safety property is at-most-once *attempt*, which deliberately costs
an authority that may have produced no effect. The alternative — re-spending on
uncertainty — is F-001.

## What this does NOT establish

Read this section before quoting the ones above.

- **F-001 is not closed.** The claim store is proven
  (`docs/F001-CLAIM-STORE-PROOF.md`, 22/22 against PostgreSQL 16.13) and the
  ordering is now built and tested, but no deployment has run this path against
  that store. Until a real deployment does, this is a correct design that has not
  been operated.
- **The test suite's claim backend is in-memory.** It implements the same
  protocol and the same at-most-once semantics, so it proves the ORDERING — that
  nothing is sent on anything but `CLAIMED`, and that a second presentation of
  the same authority is refused. It proves nothing about durability or
  non-rollback. Those are the separate proof's job.
- **The execution evidence is UNSIGNED.** It is a faithful record of what
  happened, written to the evidence directory, but it is not offline-verifiable
  the way a decision receipt is and must not be described as one. Signing it
  needs the executor's receipt-signing key on the dispatch path.
- **The generic execution path is untouched.** `executor/index.mjs` still refuses
  every protected effect with `ERR_FRESHNESS_DEPLOYMENT_DISABLED`, and nothing
  here reaches it. An ALLOW receipt is still evidence of a policy decision, not
  permission to act.
- **This is inert unless configured.** Outside `MNDE_PROFILE=production` it
  refuses. Inside it, it refuses without a trust root, an executor identity, an
  environment id and a claim backend. There is no flag that turns it on; the
  configuration is the gate.

## The transport environment

Built from empty rather than filtered, so a variable that is not named does not
exist in the subprocess. Git's own config is neutralized — `GIT_CONFIG_NOSYSTEM`,
and global and system config pointed at a path that is never created, which git
reads as empty — so that an operator's `~/.gitconfig` cannot install an alias, a
credential helper, or a `url.*.insteadOf` rewrite that changes where the push
lands. Prompts are disabled, because a hung push is a push whose outcome is
unknown.

Two things are inherited, and they are plumbing rather than policy. `PATH`,
because git resolves itself and its transport helpers through it and a hardcoded
guess breaks every invocation on any non-standard install. On Windows, a short
list of platform variables (`SystemRoot`, `TEMP`, `PATHEXT` and their kind)
without which sockets, temporary files and executable resolution do not work at
all. Neither changes what git executes or where it pushes, and an attacker who
can set `PATH` in the executor's own environment can already replace the
executor.

The operator may set exactly five variables, each for a stated reason: `PATH`,
`HOME`, `SSH_AUTH_SOCK`, `GIT_SSH_COMMAND`, `GIT_SSL_CAINFO`. Anything else is a
startup error. `GIT_PROXY_COMMAND`, `GIT_EXTERNAL_DIFF`, `GIT_DIR`,
`GIT_WORK_TREE`, `LD_PRELOAD` and their kind are absent by construction.

## The proof bites

A suite that passes against a broken build proves nothing, so it was run against
three:

| Broken build | Result |
| --- | --- |
| The claim gate accepts any claim decision | 23/27 — the replay, crash-recovery and no-backend cases fail |
| The fast-forward requirement removed | 26/27 |
| The repo-local inner-trust refusal removed | 26/27 — **and a demo-signed decision executes a real push** |

The third is the one to read twice. Without that check, a receipt whose policy
decision was signed by the authority bundle that ships inside the npm package
moves a real branch on a real remote.

## What is next

1. Operate it once, end to end, against the provisioned claim database — the
   thing neither this suite nor the claim-store proof does.
2. Sign the execution evidence, so an effect is offline-verifiable the way a
   decision is.
3. Re-run `deployment/freshness/claim-store-proof.mjs` against the chosen
   production database, including a managed provider if one is chosen.
