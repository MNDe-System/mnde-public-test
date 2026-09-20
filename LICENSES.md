# License Inventory

This inventory is based on files present in the repository and the root `package-lock.json`. It is not a legal opinion.

The attribution and NOTICE columns are judgments and are maintained by hand. The derived facts in this file - package versions, the third-party package set, and asset hashes - are checked against the tree by `npm run test:sbom`, which fails the build when they drift. See [SBOM.md](SBOM.md), which is generated rather than written.

## Repository License

| Item | License | Copyright owner | Attribution requirements | NOTICE requirements | Status |
| --- | --- | --- | --- | --- | --- |
| Root repository | Custom MNDe Public Testing License | MNDe Systems / repository owner as stated by project context | Preserve license text when sharing under permitted evaluation terms | No separate NOTICE file identified | Known |

The root [LICENSE](LICENSE) restricts use to evaluation and forbids sale, sublicensing, embedding, and production use without a separate written agreement.

## Packages and Dependencies

| Package | Version | License | Supplier | Copyright owner | Attribution requirements | NOTICE requirements | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mnde-public-test` | `0.1.1` | Custom MNDe Public Testing License | MNDe project | MNDe project | Preserve repository license | None identified | Known |
| `@mnde/executor` | `0.1.0` | Custom MNDe Public Testing License via `../LICENSE` | MNDe project | MNDe project | Preserve repository license | None identified | Known |
| `typescript` | `5.9.3` | Apache-2.0 | Microsoft (npm registry) | Microsoft Corporation | Apache-2.0 attribution applies on redistribution; not redistributed here | Apache-2.0 NOTICE obligation applies only on redistribution; not redistributed here | Known |

Root `package-lock.json` resolves one third-party npm package, `typescript`, declared in `devDependencies`. It is a build-time dependency: `npm ci` installs it in this repository, npm does not install it for anyone who consumes the published package, and the published `files` list (`dist`, `README.md`) does not contain it. `package.json` declares no runtime `dependencies`.

## Assets

| Asset | License | Copyright owner | Attribution requirements | NOTICE requirements | Hash |
| --- | --- | --- | --- | --- | --- |
| `brand/mnde-wordmark.svg` | Covered by repository license unless separately licensed | MNDe project | Preserve repository license | None identified | `sha256:6ae4e78e306afdb3efd2b85385a1efc25b4208f35777c0c87eb2c577f3a80fc0` |
| `brand/mnde-mark.svg` | Covered by repository license unless separately licensed | MNDe project | Preserve repository license | None identified | `sha256:aa96f8bb8e92e8dcdcaf3c4d275ef1882f24c361ea91578c9ec5fdb2b65c4cf8` |
| `brand/mnde-mark-mono.svg` | Covered by repository license unless separately licensed | MNDe project | Preserve repository license | None identified | `sha256:eb8cdbbdcb14f2029f10a67a6c8041e4e6ccb574e9dd586469e007e64d55db32` |
| `brand/favicon.svg` | Covered by repository license unless separately licensed | MNDe project | Preserve repository license | None identified | `sha256:122d062dac790b8324386a7edd6a893bb8284e6c976e93897537e5537dc4afc2` |

## Fonts

No external font files are present. The dashboard uses system monospace fonts in CSS.

## Icons and Images

No third-party icon library or image dependency is present. The dashboard favicon is an inline SVG data URI. Brand SVG files are local repository assets.

## Documentation Sources

Documentation appears to be original repository content. No copied third-party policy, terms, or documentation source is identified. Future documentation imported from external sources must be added to this inventory.

## Unknown or Custom Licenses

| Item | Issue | Required follow-up |
| --- | --- | --- |
| Root license | Custom evaluation-only license | Review before external redistribution or commercial use. |

## NOTICE Status

The one third-party dependency in the root lockfile, `typescript`, is Apache-2.0. The Apache-2.0 NOTICE obligation (section 4(d)) attaches to redistribution of the work or of a derivative work. `typescript` is a build-time dependency and is not redistributed by this repository, so no NOTICE file is required today. Create `NOTICE` before shipping any Apache-2.0 or similarly attributed dependency inside a published artifact.
