# Cryptography and key roles

This release preserves the source revision's canonical JSON, receipt and execution-evidence formats, and Ed25519 signature behavior. SHA-256 is used for hashes and fingerprints. Cryptographic primitives live under `src/crypto/`, with authority, policy, receipt, approval, and executor identity verification in their respective modules.

Production authority, receipt, and executor signing material must be provisioned outside the repository. The executor identity key is separate from authority keys. Trust roots must be pinned independently of the bundle host. The two public files in `authority/` are **demo compatibility material only**; production startup rejects their known root fingerprint and local/demo authority identifiers.

The offline authorization verifier is `tools/verify.mjs`. Signed `git.push` execution evidence has its own verifier, `scripts/verify-git-push-evidence.mjs`. An authorization signature does not attest that the effect happened. No FIPS validation, HSM custody, or external cryptographic audit is claimed.
