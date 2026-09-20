# Release automation

[`.github/workflows/release.yml`](../.github/workflows/release.yml) performs the
machine-checkable parts of
[`release-publication-runbook.md`](release-publication-runbook.md) and then stops
and waits for a human. It has never been executed; nothing has been published,
tagged, or attested.

The human's only job is the approval click. Everything either side of it is
automated and re-proved by code.

## The run, end to end

| Stage | Job | Permissions | What happens |
| --- | --- | --- | --- |
| Before the click | `build` | `contents: read` | Refuses a tag that already exists, confirms the approval gate is really configured, runs the whole guardrail suite, builds the release, runs the release-truth proof, then re-derives and records every digest. |
| The click | `publish` | gated on the `release` environment | GitHub holds the job until a required reviewer approves the run. |
| After the click | `publish` | `contents: write`, `id-token: write`, `attestations: write` | Re-checks that all three artifacts still hash to the recorded values, attests build provenance, creates the tag at the built commit, and publishes the release with its assets. |
| After publication | `verify-published` | `contents: read` | Downloads every published asset through its own URL and re-derives the digest from the wire. |

`build` cannot tag, publish, or attest: it holds no write permission. Every
outward-facing effect lives in `publish`, and `publish` does not start until
somebody approves it. `tests/test_ci_contract.mjs` asserts that shape, so it
cannot be quietly removed.

## One-time setup — the workflow is inert without it

`environment: release` is **not** an approval gate on its own. If the
environment has no required reviewer, the gated job simply runs. Configure it
once:

1. **Settings → Environments → New environment**, named exactly `release`.
2. **Required reviewers** → add the maintainer(s) allowed to release. This is
   the approval click.
3. **Deployment branches and tags** → *Selected branches* → `main`.

Step 3 matters more than it looks. `workflow_dispatch` runs the workflow
definition from whichever ref is dispatched, so without a branch policy a
release could be started from a branch carrying a modified workflow. The branch
policy is what stops the gated job from being reached that way.

The `build` job calls `npm run release:verify-approval-gate` and fails closed if
the environment is missing, has no required-reviewer rule, has an empty reviewer
list, or cannot be read. A release is never prepared against a gate that would
wave it through.

## Cutting a release

1. **Actions → Release → Run workflow**, on `main`, and type the version exactly
   as it appears in `package.json` (for example `0.1.1`). A mismatch aborts
   before anything is built.
2. Wait for `build`. Read the digest block it prints at the end of the
   **Release gate (pre-approval)** step — version, source commit, and the SHA-256
   of the tarball, `SHA256SUMS.txt`, and `release-manifest.json`. That block is
   what the approval covers.
3. Approve the run when prompted. Everything up to here is reversible: no tag,
   no release, no attestation exists yet.
4. `publish` and `verify-published` finish unattended. If either fails, the run
   goes red and the published state is whatever the logs say it is — read them
   before touching anything.

The version tag is always `v<version>` derived from `package.json`. There is no
separate tag input, because `package.json` is the one authoritative source of
release identity (see [`RELEASE.md`](RELEASE.md)).

## What the approval actually buys

- Nothing outward-facing happens before the click. The pre-click job has no
  write permission at all.
- What gets published is byte-identical to what was verified. The post-approval
  gate re-checks the tarball, `SHA256SUMS.txt`, and `release-manifest.json`
  against the digests recorded before the click, so an artifact swapped while
  the run was parked is refused.
  `tests/test_release_publication_gate.mjs` proves that refusal by substituting
  each of the three files in turn.
- The published bytes are the built bytes. `verify-published` re-downloads every
  asset and re-derives its digest from the wire, and it runs in a job that
  cannot write, so the code that checks the result cannot also patch it up.
- The tag names the commit that was actually built, and the published assets are
  bound to it by `release-manifest.json`.
- A build made from a dirty working tree is refused outright: its manifest would
  name a commit that cannot reproduce it.

## What it does not buy

- **Reproducible builds.** Nothing here proves a second build of the same commit
  produces the same bytes.
- **A signed artifact.** The tarball carries no detached signature. Build
  provenance is the only signed statement about it.
- **Four-eyes review**, while one person is both dispatcher and reviewer. GitHub
  can forbid self-review only where there is somebody else to approve; with a
  single maintainer the gate is a deliberate pause, not independent review. The
  precheck prints a note when self-review is permitted.
- **A machine-readable SBOM.** `SBOM.md` is generated from the tree by `npm run
  sbom` and re-derived by `npm run test:sbom`, which this workflow runs as part
  of `npm test` - so a release cannot be built from a commit whose SBOM has
  drifted. What is still missing is a CycloneDX or SPDX document, a signature
  over it, and attaching it as a release asset.
- **npm registry publication.** The package is `private` and is never pushed to
  a registry; the tarball asset is the only distribution.

## Build provenance

The `publish` job runs `actions/attest-build-provenance`, which records a signed
statement that this repository's workflow produced the tarball's exact digest.
It runs before the release is created, so no published byte exists without
provenance.

Anyone can check a downloaded tarball against it:

```bash
gh attestation verify mnde-public-test-<version>.tgz --repo mndesystems-ship-it/mnde-public-test
```

## When something fails

- **`tag ... already exists`** — the version was released before. Per the
  runbook, a corrected release goes out under a new version number; a tag is
  never reused.
- **`the 'release' environment ...`** — the approval gate is not configured. Fix
  the environment; do not remove the check.
- **A gate check fails after approval** — treat the run as compromised, not as
  flaky. The digests recorded before the click and the bytes present after it
  disagreed. Nothing was published: the gate runs before the attestation and
  before `gh release create`.
- **`verify-published` fails** — the release exists but does not match what was
  built. Follow the runbook's rollback section: stop distribution, record the
  failed digest and the reason, preserve the evidence, and publish a correction
  under a new version.

## Tooling

`build/release-publication.mjs` holds the logic, so it can be tested instead of
living as shell inside YAML. It has no dependencies, never publishes anything,
and `gate` / `verify-published` / `verify-approval-gate` are read-only.

| Command | Purpose |
| --- | --- |
| `npm run release:verify-approval-gate -- --repo <owner/name>` | Prove the approval environment requires a human. |
| `npm run release:gate -- --release-dir release --expect-version <v> --expect-commit <sha>` | Re-derive and cross-check every digest in a built release directory. |
| `npm run release:notes -- --release-dir release --tag <tag> --out <file>` | Render the release body from `release-manifest.json`. |
| `npm run release:verify-published -- --repo <owner/name> --tag <tag>` | Re-download published assets and compare digests. |

`npm run test:release-publication-gate` runs the hostile tests for all of it.
