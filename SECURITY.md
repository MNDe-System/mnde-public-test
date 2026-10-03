# Security policy

This release contains the MNDe Execution Firewall for the typed `git.push` effect. Report vulnerabilities through the repository owner's private security reporting channel when one is established; do not include real credentials or private keys in a public issue.

The supported boundary is the Hub and typed executor path described in [docs/security-model.md](docs/security-model.md). It depends on signed trust material, a restricted PostgreSQL primary, durable local storage, and operationally exclusive GitHub write credentials. It does not provide OS-wide enforcement or protection against administrator, root, or operating-system compromise.

Security changes should include a regression test for the affected boundary. An `ALLOW` receipt is authorization evidence, not execution evidence. An ambiguous push must not be retried automatically. See [SECURITY_CLAIMS.md](SECURITY_CLAIMS.md) for claims and limits.
