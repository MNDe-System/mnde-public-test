# Supply Chain Security

This document describes the current supply chain posture and gaps for MNDe Public Test. It does not claim SLSA compliance, reproducible builds, or signed-release maturity.

## Current Evidence

- The runtime package has no third-party npm dependencies; TypeScript 5.9.3 is
  pinned as a development-only build dependency in `package-lock.json`.
- `SBOM.md` is generated from the working tree by `npm run sbom` and re-derived
  and compared by `npm run test:sbom`, which runs in the default suite. A stale
  version, hash, asset or lockfile entry fails the build.
- Tests are enumerated in `tests/expected-test-scripts.json` and run through `scripts/run-all-tests.mjs`.
- The repository license restricts evaluation use.

## Dependency Pinning

The root lockfile pins the development dependency tree. The packaged runtime has
no external dependency tree. If dependencies are added later:

- Commit lockfile updates.
- Record each dependency in [LICENSES.md](LICENSES.md).
- Regenerate [SBOM.md](SBOM.md) with `npm run sbom`. `npm run test:sbom` fails
  until the committed file matches the tree, so this cannot be forgotten.
- Review transitive licenses and security advisories.

## Implemented Release Controls

- Local npm release artifact generation.
- SHA-256 checksum generation.
- Release manifest generation.
- Source commit binding in packaged release identity and the release manifest.
- Package identity tests.
- Generated SBOM enforced in CI (`npm run test:sbom`).
- Clean packaged-install verification outside the repository.
- Content-based private-key exclusion during packaging and private-key exclusion tests.

These controls create and verify local release candidates. They do not publish
anything.

## Automated Release Controls (implemented, never executed)

[`.github/workflows/release.yml`](.github/workflows/release.yml) automates the
publication runbook behind a GitHub Environment approval gate. It is manual
dispatch only, and it has never been run: no release has been published, no tag
created, and no provenance attestation produced.

What the workflow implements:

- Release approval gate. The job holding write credentials does not start until
  a required reviewer on the `release` environment approves the run. The job
  that builds and validates holds no write permission.
- Confirmation that the approval gate is configured, checked before the build
  runs and failing closed if the environment is missing, unprotected, or
  unreadable.
- Re-verification, after the approval and before anything is published, that the
  tarball, `SHA256SUMS.txt`, and `release-manifest.json` still hash to the values
  recorded before the approval.
- Build provenance attestation for the tarball via
  `actions/attest-build-provenance`, produced before the release is created.
- Tag creation bound to the exact commit that was built, and refusal to reuse an
  existing tag.
- Post-publication re-verification: every published asset is downloaded through
  its own URL and its digest re-derived from the wire, in a job that holds no
  write permission.
- Refusal to release a build made from a dirty working tree, or a version other
  than the one in `package.json`.

All GitHub Actions in both workflows are pinned to full commit SHAs.
`tests/test_ci_contract.mjs` asserts that pinning, the approval gate, and the
post-approval digest re-check; `tests/test_release_publication_gate.mjs` proves
the gate refuses a substituted artifact. See
[docs/release-automation.md](docs/release-automation.md) for the environment
configuration the gate depends on.

## Not Implemented

- Any published release. Nothing has been published, so no public checksum,
  release asset, or provenance attestation exists yet. The workflow above can
  produce them; it has not been run.
- Release artifact signing. The tarball carries no detached signature;
  provenance attestation is the only signed statement about it.
- Reproducible-build proof.
- A machine-readable SBOM. `SBOM.md` is generated from the tree and enforced by
  CI, but it is Markdown: there is no CycloneDX or SPDX document, it is not
  signed, and the release workflow does not attach it as a release asset.
- Desktop installer production.
- Installer signing.

## Dependency Security

The packaged runtime has no third-party npm dependencies. The development build
uses TypeScript, so development dependency vulnerabilities remain in scope. This
does not cover:

- Node.js runtime vulnerabilities.
- Operating system packages.
- External signer commands.
- Upstream MCP servers.
- Any future installer tooling, if introduced.
- Future dependencies.

## Supply Chain Gaps

Remaining gaps before enterprise or government use:

- Signed release artifacts.
- Public release provenance in practice: the attestation step exists but has
  never produced an attestation, because nothing has been released.
- Reproducible-build proof.
- General-purpose automated dependency and repository-wide secret scanning.
- Maintainer access-control documentation.
- A machine-readable, signed SBOM attached to a published release. Generation
  and drift-checking are implemented; the standard-format, signed and published
  artifact is not.
- Vulnerability response process for third-party dependencies.

The release approval process is no longer a gap: it is implemented as the
environment gate described above, though it has not yet been exercised on a real
release.
