# Security Model

MNDe is a pre-execution authority layer. Integrated tools ask MNDe before execution. MNDe returns a decision and produces verifiable evidence.

This document describes the security boundary for onboarding and auto-wiring.

## Protected Invariants

Onboarding must never weaken:

- deterministic decisions
- signed receipts
- receipt schema validation
- policy hashing
- replay verification
- trust-anchored authority verification
- fail-closed behavior
- refusal reasons
- offline verification

Onboarding code is not allowed to special-case reviewer flows or bypass authority checks.

One of those invariants needs stating precisely, because the short form overstates
it. **When the runtime is healthy, MNDe preserves specific refusal reasons. When
runtime health cannot be established, MNDe fails closed with the applicable
runtime-health refusal instead of continuing evaluation** — so a caller may
receive `ERR_RUNTIME_DEGRADED` or `ERR_SYSTEM_SATURATED` in place of a more
specific result such as `APPROVAL_EXPIRED`. The same qualification applies to
deterministic decisions: determinism holds for a given request *and* a healthy
runtime, and an unhealthy one refuses rather than deciding. It never produces an
ALLOW. See
[Runtime Health Refusals](production-readiness.md#runtime-health-refusals-take-precedence-over-decision-specific-refusals).

## Authority Separation

The authority system owns decisions, receipts, signatures, replay, trust anchors, and policy hashes.

Onboarding owns local discovery, wiring plans, backups, restore, and policy drafts.

These are separate concerns. A successful onboarding run does not mean a policy is trusted or active. It means supported clients have been configured to route tool calls through MNDe.

## Auto-Wiring Threat Model

Auto-wiring introduces these risks:

- modifying the wrong config file
- corrupting a config file
- double-wrapping an already protected server
- losing the original upstream command
- leaving a user without an obvious restore path
- giving a false impression that all execution paths are protected

The implementation reduces those risks by using deterministic discovery, explicit `--apply`, backups, backup metadata, manifests, post-write verification, and `mnde uninstall`.

## Fail-Closed Expectations

Malformed configs are not wired.

Missing configs are not created.

Already-wrapped servers are skipped.

If post-write verification fails, the original config is restored.

If the sidecar is unavailable at execution time, the proxy must not forward the tool call as if it were allowed.

## Offline Behavior

Discovery, planning, policy drafting, backup, restore, and onboarding tests run without network access and without live MNDe services.

Receipt verification remains independently offline when the verifier has the trusted authority bundle for the receipt being checked.

## Remaining Limits

MNDe only protects integrated paths. It does not provide kernel enforcement or operating-system-wide process control.

Auto-wiring currently supports known MCP config formats. Unknown tools and unsupported clients require manual integration.

The generated policy draft is not production policy. It requires human review before use.

Production deployments still need authority operations such as key custody, rotation, revocation, identity binding, approval signing, and audit retention.

## Key Custody and Production Trust Roots

Signing material has to live somewhere. MNDe separates *where keys live* (custody) from *how evidence is verified* (the authority bundle), so verification never depends on the signer's environment.

- **Custody is pluggable and opt-in.** `MNDE_KEY_CUSTODY` selects the provider. Unset or `local-demo` (the default) uses ephemeral in-process keys for development and demos. `file-backed-production` is an opt-in mode that loads a published bundle plus role private keys from outside the codebase. Documented future slots — AWS KMS, Azure Key Vault, GCP KMS, HSM/PKCS#11 — implement the same interface so the private key never leaves the custody boundary.
- **Local-demo is not production custody.** Demo keys are ephemeral, self-asserted, and non-durable. They exist to exercise the sign/verify loop, not to anchor production trust.
- **Verification depends on the public authority bundle, not on custody.** A verifier holds the trusted root fingerprint out of band, confirms the `mnde.authority.bundle.v1` root matches it, checks the root-signed bundle signature, rejects a stale bundle, and looks up signing keys honoring validity windows and revocation. This is fully offline and identical regardless of which custody provider produced the signatures.
- **Private keys do not need to leave the custody provider.** Bundles and receipts carry only public material. MNDe-controlled custody, receipt, and error paths are designed and tested not to emit configured private keys, tokens, or signing material. Operators must still keep secrets out of request content, external tooling, screenshots, and general host logs.
- **Fail closed.** Missing, malformed, unsigned, stale, or unverifiable custody configuration refuses rather than degrading to demo keys.
- **Live receipt signing is opt-in.** `MNDE_RECEIPT_SIGNING_MODE=custody` signs live sidecar receipts through the custody provider after the deterministic receipt is built. The decision engines remain separate from custody and do not import signing code. If custody signing cannot complete, the sidecar refuses the request and returns no receipt rather than emitting a legacy-signed receipt.

See [Key Custody](key-custody.md), [Live Receipt Signing](live-receipt-signing.md), and [Authority Bundle](authority-bundle.md) for formats, configuration, and the threat model.

## Trust Root Host-Filesystem Boundary (H1)

**Known trust boundary — not a bug.**

MNDe assumes the pinned trust root on the host filesystem is protected by the operator's machine, OS permissions, and deployment controls. If an attacker can replace the trust root and run MNDe under that altered root, the host is already inside the trust boundary.

Pilot deployments accept this boundary.

Production deployments should support stronger root custody options such as installer-pinned fingerprints, hardware-backed storage, OS keychain binding, or enterprise MDM deployment.

This is a declared scoping decision, not an implementation gap. The production pre-flight (`MNDE_PROFILE=production`) fails closed if dev-key material is detected and requires an explicitly configured external bundle, which reduces but does not eliminate the host-filesystem dependency for the initial trust anchor.
