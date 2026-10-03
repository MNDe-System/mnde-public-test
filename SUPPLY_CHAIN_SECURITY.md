# Release supply chain

The source revision for this initial release baseline is `178342be20fcc0e4a74afc3ffef91bd00f5900fd` from `MNDe-System/mnde-public-test`. This repository has a new, independent Git history. Source modules are copied from that revision, preserving their security-sensitive paths and behavior; the package, test runner, and documentation are release-specific.

Node.js 24 or newer is required. `pg` is an explicit production dependency pinned by `package-lock.json`. `npm ci` installs exactly the locked tree. `npm test` runs the release unit/security suites, and `npm run build` checks package identity, lock consistency, and entrypoints. `npm run test:postgres` is a separate live proof against a disposable PostgreSQL test primary.

The npm package file list is narrow and excludes tests, private keys, runtime state, experiments, generic executors, sidecars, desktop code, and generated evidence. The package is marked private while this baseline is evaluated. No release publication, tag, provenance attestation, reproducible-build certification, or production qualification is claimed by this document.
