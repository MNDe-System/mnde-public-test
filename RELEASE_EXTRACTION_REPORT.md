# OFFICIAL MNDe RELEASE EXTRACTION REPORT

## Provenance and result

- Source repository: `MNDe-System/mnde-public-test`
- Source revision: `178342be20fcc0e4a74afc3ffef91bd00f5900fd`
- Release repository: local `mnde/`, branch `release/extract-official-baseline`
- Release version: `0.1.0`
- Inventory: 146 tracked files; 109 byte-identical at the same paths as the pinned source revision, 20 adapted at the same paths, and 17 new release files. The moved test bootstrap helper is counted as a new path. All 64 selected production and compatibility source files are byte-identical to the pinned revision.
- No remote, push, tag, deployment, Pi change, production PostgreSQL connection, credential rotation, or GitHub App permission change was made.

## Included files

The supported entrypoints are `bin/mnde-hub.mjs` and `bin/mnde-git-push.mjs`. The release retains the traced source under `src/hub/`, `src/effects/git-push/`, `src/freshness/`, `src/execution-authority/`, `src/authority-signing/`, `src/crypto/`, the required `src/custody/` modules, `src/policy-engine/`, `src/policy-bundles/`, `src/activation/`, and `src/sidecar-auth/`, plus `src/executor-posture-preflight.mjs`, `src/execution-availability/index.mjs`, `shared/`, and the two offline verification tools. Historical offline verification retains `preflight/engine.ts`, `orbit/engine.ts`, `arm/engine.ts`, and `ram0na/engine.ts`.

Trust and verification scripts are `scripts/authorize-git-push.mjs`, `prepare-git-push-trust.mjs`, `init-production-authority.mjs`, `trust-enroll-executor.mjs`, and `verify-git-push-evidence.mjs`. The runtime spawn from trust preparation to executor enrollment was checked. Deployment SQL, the PostgreSQL proof harness, Hub service and sanitized examples, conformance vectors, public demo compatibility authority data, selected tests, release documents, and the retained `LICENSE` are included.

## Deliberate exclusions

`brand/`, `cosmetic/`, `desktop/`, `policy-editor/`, `reviewer-kit/`, `research/`, `audit/`, `examples/`, `templates/`, `sample-policies/`, `installer/`, `mcp/`, `shell/`, `sidecar/`, `mnde-local-sidecar.mjs`, generic `executor/`, unrelated `src/` modules, old package build and publication machinery, experiments, generated `dist/`, development test state, and untracked source work are absent. They are not in the supported Hub/typed-push import or runtime call graph. The historical verification engines are included despite their older names because the offline verifier imports them.

## Changes from the source revision

- Production source: **64 files byte-identical** to the selected Git revision; no production import-path, authorization, claim, cryptographic, receipt, or effect behavior change.
- Dependency: explicit, locked production `pg@8.23.1`; baseline package omitted this runtime driver.
- Package: focused `mnde@0.1.0`, two direct source entrypoints, narrow file list, and release build/import checks. The package excludes tests, private material, runtime state, and the live database proof harness.
- Tests: copied relevant production/security suites, moved the development key bootstrap helper under `tests/support/`, added the release-boundary test, replaced monorepo `dist/` and generic-executor assertions with checks of the actual release package, and included the required policy fixture. Test-only claim hooks remain under `tests/support/` and are absent from the packed runtime. Eight copied test files and one fixture support file were adapted for release-local paths and boundaries.
- Deployment proof: comment corrections and a `MNDE_CLAIM_PROOF_DISPOSABLE=1` guard; no claim SQL or adapter semantic change.
- Documentation: development-wide and stale documents were replaced with release-specific architecture, Hub, Git push, approval, PostgreSQL, deployment, receipt, security, limitation, and promotion guidance. The evaluation-only `LICENSE` was retained unchanged.

## Verification

- `npm ci` from the release lockfile: passed.
- `npm run build`, including import closure and npm package contents: passed.
- Static import scan: 105 code files and 563 import references resolved; no production import to source development work or test adapters. The runtime spawn from trust preparation to executor enrollment was also checked.
- Package dry run: 100 files, no tests or private key material. The package file list names the shared source files explicitly so locally generated signing keys cannot enter the tarball.
- Full release suite after release test and package cleanup: **26/26 suites passed; 383 checks passed, 0 failed, 5 checks skipped on Windows**. The skipped checks exercise Unix file permissions and are not applicable on Windows.
- Independent local clone with no borrowed working-tree files: `npm ci`, `npm run build`, and the complete suite all passed again (26/26 suites; 383 passed, 0 failed, 5 checks skipped on Windows). The clone installed 14 locked packages; 105 code files and 563 import references resolved; the dry-run package contained 100 files.
- Secret scan of all staged files: 1,282 keyword hits grouped by file and inspected for credential-shaped data; matches were field names, documentation, public verification data, placeholders, or synthetic test values. No real private key, bearer token, GitHub App credential, database password, production connection string, claim data, or runtime evidence was found. The fake private-key text in a negative test explicitly contains `not-a-real-key`; public key and historical signature vectors remain for verification.
- Machine-path scan: no path to this workstation or to the development checkout occurs in release code or tests. Synthetic Windows and Unix paths in negative tests remain as fixtures. Mentions of `mnde-public-test` identify source provenance or demo authority IDs, never runtime file paths.
- Local test execution left ignored `node_modules/`, `.mnde-test/`, `grant-nonce-store.d/`, and `shared/receipt_keys/` in the checkout. None is committed or included in the release package. The host's automatic command review rejected cleanup of those generated directories, so they remain local-only.
- Real PostgreSQL primary: **not run**. No disposable test primary was identified. The separate guarded `npm run test:postgres` qualification command is provided.

## Security review and limitations

The only shipped callers of the typed executor are the Hub and `mnde-git-push` CLI. No supported alternate `git.push` route was found. The CLI uses the same executor-side claim and lock path. No production source imports the test claim backend. The public authority files are demo/compatibility material; the release-boundary test verifies that production startup rejects their root fingerprint. Operator trust, signing keys, GitHub credentials, PostgreSQL password/CA files, and runtime evidence must be provisioned outside this repository.

Production credential exclusivity is required: another valid GitHub write credential bypasses this software gate. Root/administrator compromise, OS tampering, physical extraction of unencrypted storage, database or filesystem rollback, and sudden-power-loss behavior remain outside current qualification. The retained license requires a separate written agreement for production use.

## Remaining qualification blockers and verdict

There is no blocker to the **code release baseline**. A disposable PostgreSQL primary was not available, so schema provisioning, restricted login, verified TLS, live single-use claims, and restart behavior still need the separate `npm run test:postgres` qualification. Sudden-power-loss and hardware durability checks, production credential exclusivity, and production provisioning also remain open. **READY FOR RELEASE BASELINE; PRODUCTION QUALIFICATION INCOMPLETE.**
