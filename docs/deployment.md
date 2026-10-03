# Deployment outline

1. Install Node.js 24 or newer, Git, and the locked npm dependencies with `npm ci` from this repository.
2. Provision a durable private Hub data directory and a separate evidence directory. Configure the PostgreSQL claim schema and restricted executor login from `deployment/freshness/` on an approved primary.
3. Generate authority and executor trust outside the repository. Provision a signed production policy bundle, approval trust anchors, receipt signer, executor credential, and GitHub push credential with exclusive write authority for the protected repository.
4. Fill the paths and identifiers in `deployment/hub/hub.env.example`; use the systemd service as a starting point for a reviewed deployment. Never commit the filled environment file, password file, PEM private key, API tokens, or runtime evidence.
5. Start the Hub on loopback, inspect `LOCKED` and readiness, then use an authenticated operator token to unlock. Submit a typed request with the exact remote ref and SHA values.
6. Verify authorization and execution evidence separately and reconcile ambiguous outcomes manually.

The example service assumes Linux and a mounted data volume. Its paths are deployment examples, not development-machine paths. The Hub remains locked after reboot. A missing mount, claim primary, signing material, policy, trust anchor, or credential must leave execution unavailable. Production acceptance additionally requires live PostgreSQL qualification, credential-exclusivity review, and hardware power-loss testing.
