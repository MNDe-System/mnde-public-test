# Release promotion workflow

1. Develop in `MNDe-System/mnde-public-test`.
2. Run functional, security, and adversarial validation there.
3. Select a candidate by its exact source revision.
4. Promote only validated production changes into this official release repository.
5. Install and run this repository's full release suite independently, including the live PostgreSQL gate when a disposable primary is available.
6. Review the release commit, dependency lockfile, package contents, documentation, and extraction report.
7. Tag an approved release only after review and applicable qualification.
8. In a future version, require MNDe itself to authorize promotion into this repository.

This repository holds the supported build, run, deploy, verify, test, and release paths. It is not a copy of the development monorepo.
