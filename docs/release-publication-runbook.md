# Release publication runbook

This runbook prepares and verifies the npm release artifacts. It does not grant
authorization to publish, tag, push, sign, or upload anything.

[`.github/workflows/release.yml`](../.github/workflows/release.yml) automates
the steps below and halts on a GitHub Environment approval gate before it tags
or publishes; see [`release-automation.md`](release-automation.md). This runbook
remains the specification of what must happen and the procedure to follow by
hand. The workflow has never been run.

## Preconditions

- The working tree is clean and on the intended `main` commit.
- `package.json` contains the expected package version.
- The verified release environment uses Node.js 24.14.1.
- CI passes for the source commit.
- A maintainer has explicitly authorized publication.

## Validate and build

Run from the repository root:

```bash
npm ci
npm test
npm run reviewer-kit
npm run check:whitespace
npm run release
npm run release:verify
```

The dedicated `release/` directory must contain exactly:

- `mnde-public-test-<version>.tgz`
- `SHA256SUMS.txt`
- `release-manifest.json`

## Inspect artifacts

- Confirm the tarball and manifest version match `package.json`.
- Confirm the manifest source commit matches the intended `main` commit.
- Record each artifact's exact filename, file size, and recomputed SHA-256.
- Compare the tarball SHA-256 with both `SHA256SUMS.txt` and
  `release-manifest.json`.
- Inspect the package and confirm it contains no private keys, `.mnde-test`
  state, or reviewer-kit output.
- Install the tarball outside the repository in a clean directory and confirm
  these commands execute:

```bash
npm init -y
npm install ./mnde-public-test-<version>.tgz
npx mnde-sidecar version
npx mnde-sidecar init
npx mnde-sidecar doctor
npx mnde-sidecar smoke
```

## Prepare publication

Only after validation and explicit maintainer authorization:

- Create the version tag.
- Attach `mnde-public-test-<version>.tgz`, `SHA256SUMS.txt`, and
  `release-manifest.json`.
- Include the source commit and the Node and npm versions.
- Include the SHA-256 values.
- State that no desktop installer exists.
- Include the packaged installation and smoke-test commands above.

Signing and public provenance are not implemented; do not claim either.

## Verify after publication

- Download every asset through its public URL.
- Recompute the digest and compare it with the published metadata.
- Install the downloaded tarball in a clean directory.
- Run `version`, `init`, `doctor`, and `smoke`.
- Confirm the release metadata matches the tag and source commit.
- Confirm the release page resolves and does not return a missing page.

## Roll back a failed publication

- Stop distribution if any verification fails.
- Do not silently replace an artifact under the same version.
- Record the failed artifact digest and the reason for failure.
- Preserve the artifacts, logs, and other evidence needed for investigation.
- Publish a corrected release only under a new version number.
