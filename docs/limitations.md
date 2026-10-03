# Known limitations

- The supported production effect is `git.push` only. Other actions have no release execution path.
- GitHub credential exclusivity is an operational condition. Another credential with equivalent write authority can bypass MNDe.
- Root, administrator, service-account, operating-system, or GitHub account compromise is outside this software boundary.
- Physical extraction of unencrypted storage is not addressed.
- PostgreSQL owners can restore or roll back claim data. Storage controller, filesystem, and evidence-directory rollback remain concerns.
- Sudden power loss has not been qualified on production hardware; a database restart test is weaker than power-loss testing.
- An interrupted or ambiguous push requires human reconciliation. No automatic retry is provided.
- Live PostgreSQL restricted-login, TLS, uniqueness, and restart qualification is separate from the local unit suite.
- The retained evaluation license requires a separate written agreement for production use.
