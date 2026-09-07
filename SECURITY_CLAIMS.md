# Security Claims

This file records security-related statements that appear in the repository and the evidence that supports or limits them. It is a private beta claim-control document, not a compliance certification.

## Claim Review

| Claim | Supporting evidence | Implementation files | Tests proving it | Documentation proving it | Fully supported? | Safe wording |
| --- | --- | --- | --- | --- | --- | --- |
| MNDe is a pre-execution authority layer. | The sidecar and integrations ask before running routed actions. | `mnde-local-sidecar.mjs`, `src/policy-engine/`, `executor/index.mjs`, `mcp/mnde-mcp-proxy.mjs`, `mcp/mnde-mcp-server.mjs` | `test:executor`, `test:mcp`, `test:mcp-proxy`, `test:sidecar-pe` | `README.md`, `docs/execution-firewall-overview.md`, `docs/integration-guide.md` | Yes, for routed integrations. | MNDe is a pre-execution authority layer for actions routed through an MNDe integration. |
| REFUSE does not execute. | Executor and proxy paths return before calling or forwarding the action on REFUSE. | `executor/index.mjs`, `mcp/mnde-mcp-proxy.mjs`, `mcp/mnde-mcp-server.mjs` | `test:executor`, `test:mcp`, `test:mcp-proxy`, `test:shell` | `executor/README.md`, `mcp/README.md`, `docs/production-readiness.md` | Yes, for routed integrations. | Routed REFUSE decisions are not run or forwarded by the tested integrations. |
| MNDe prevents unauthorized execution. | Policy gates can refuse routed requests before execution. | `src/policy-engine/index.mjs`, `src/execution-gate/index.mjs`, `executor/index.mjs`, `mcp/mnde-mcp-proxy.mjs` | `test:policy-engine`, `test:execution-gate`, `test:executor`, `test:mcp-proxy` | `docs/execution-firewall-overview.md`, `docs/production-readiness.md` | No, if stated globally. | MNDe prevents execution only for unauthorized requests routed through an enforcing MNDe integration. |
| Receipts verify offline. | Verifiers recompute hashes/signatures without a running sidecar. | `tools/verify.mjs`, `tools/verify-receipt.mjs`, `src/policy-engine/receipt.mjs`, `src/execution-gate/verify-signed-receipt.mjs` | `test:receipt-verifier`, `test:policy-receipt`, `test:production-signing`, `test:execution-gate-signing` | `docs/execution-receipt-spec-v1.md`, `docs/trust-anchored-verification.md` | Yes, when required authority evidence is available. | Receipts verify offline when the verifier has the required trusted authority evidence. |
| Tampering is detected. | Hash and signature checks fail on modified receipts, results, ledgers, policy bundles, and authority bundles. | `src/execution-gate/`, `src/policy-engine/receipt.mjs`, `src/policy-bundles/index.mjs`, `src/custody/bundle.mjs` | `test:execution-gate-signing`, `test:signed-execution-result`, `test:execution-ledger`, `test:signed-policy-bundle`, `test:custody` | `docs/execution-receipt-spec-v1.md`, `docs/signed-execution-result-v1.md`, `docs/key-custody.md` | Yes, for covered artifact formats. | Tampering with supported signed artifacts is detected by the corresponding verifier. |
| Configured executor identity is bound into every live receipt without authority-only fallback. | The immutable live signing context signs the receipt hash with the executor key before custody countersigning; signing failures emit no receipt. | `mnde-local-sidecar.mjs`, `src/authority-signing/index.mjs`, `src/custody/executor-identity.mjs` | `test:executor-live-sidecar`, `test:executor-key-path-security`, `test:layered-receipt-verification` | `docs/executor-bound-receipts.md` | Yes, for the tested sidecar receipt paths when executor identity is configured and custody signing is available. | A configured executor produces `executor_and_authority` live receipts or the request/startup fails closed; this is not third-party witnessing or tenant isolation. |
| MNDe fails closed on malformed or missing authority evidence. | Startup and verification reject missing, stale, revoked, malformed, or substituted authority material. | `src/authority-signing/preflight.mjs`, `src/custody/index.mjs`, `src/custody/bundle.mjs` | `test:trust-root`, `test:custody`, `test:production-signing`, `test:external-signer` | `docs/key-custody.md`, `docs/production-readiness.md` | Yes, for tested custody and pre-flight paths. | Tested custody and trust-root paths fail closed on invalid authority evidence. |
| Private keys and tokens never appear in receipts, logs, or errors. | Tests cover custody output, production signing, bearer proxy, and signed result evidence scans. | `src/custody/`, `src/sidecar-auth/index.mjs`, `executor/bearer.mjs`, `src/execution-gate/signed-result.mjs` | `test:production-signing`, `test:custody`, `test:proxy-auth`, `test:signed-execution-result` | `docs/key-custody.md`, `docs/live-receipt-signing.md`, `docs/security-model.md` | Partially. Tests cover MNDe-controlled paths, not arbitrary host logs or user-supplied request content. | MNDe-controlled receipt, custody, auth, and verifier paths are designed and tested not to emit private keys or bearer tokens; operators must keep secrets out of request content and external logs. |
| Sidecar auth protects callers. | Bearer auth can reject missing, malformed, and wrong tokens before evaluation. | `src/sidecar-auth/index.mjs`, `mnde-local-sidecar.mjs`, `mcp/mnde-mcp-proxy.mjs` | `test:auth`, `test:proxy-auth` | `docs/mnde-policy-engine-production-spec-v1.md`, `docs/operational-dashboard.md` | Partially. Auth is optional and off by default. | Optional bearer auth can gate machine callers when explicitly enabled; it is not the final enterprise identity model. |
| Production mode refuses demo custody. | Pre-flight rejects production profile without valid custody or with demo/dev material. | `src/authority-signing/preflight.mjs`, `scripts/init-production-authority.mjs` | `test:trust-root`, `test:authority-init` | `docs/key-custody.md`, `docs/production-readiness.md` | Yes, for current pre-flight rules. | `MNDE_PROFILE=production` refuses configured demo/dev custody paths covered by the pre-flight tests. |
| Enterprise identity is supported. | Docs describe future/off-by-default identity features; current auth is bearer-based. | `src/sidecar-auth/index.mjs`, `sidecar/auth_authority.mjs`, `src/identity/` | `test:auth`, `test:identity-assertion`, `test:executor-lifecycle` | `docs/operational-dashboard.md`, `docs/identity-assertion-v1.md` | No, if stated as complete enterprise identity. | Enterprise identity features are future/off by default; current support is local/pilot caller auth and identity assertion verification slices. |
| Government readiness or procurement readiness. | No implementation or documentation package proves this. | Not applicable. | Not applicable. | `ACCESSIBILITY.md`, `COMPLIANCE_SUMMARY.md` document gaps. | No. | Do not claim government readiness. |
| AI safety. | Deterministic policy enforcement and receipt logging exist for routed actions. | `src/policy-engine/`, `src/execution-gate/`, `executor/index.mjs` | `test:policy-engine`, `test:execution-gate`, `test:executor` | `docs/production-readiness.md`, `docs/execution-firewall-overview.md` | No, if stated broadly. | MNDe provides deterministic pre-execution policy decisions and evidence for routed actions; it is not a general AI safety system. |
| Strict agent containment. | Strict executor mode independently refuses unregistered tools and escape-class capabilities, snapshots the operator manifest, and requires matching evidence in the verified signed receipt. | `src/containment/index.mjs`, `executor/index.mjs`, `src/policy-engine/sidecar-adapter.mjs` | `test:containment` | `docs/containment-profile.md` | Partially. It covers routed actions only and does not provide OS/network isolation. | Strict mode refuses escape-class capabilities for actions routed through an enforcing MNDe integration and bound to a valid operator manifest; OS/network containment remains required. |
| npm package/pack does not ship recognized secrets. | The prepack build and the extracted npm tarball are content-scanned for supported private-key and secret formats, each with its own matching rule (see below); the build fails closed on a finding and the pack-boundary test asserts an empty result over the real tarball bytes. Detection is deliberately conservative and non-exhaustive. | `build/lib/package-secret-scan.mjs`, `build/build-package.mjs`, `build/secret-scan-allowlist.json` | `test:package-secret-scan-hostile`, `test:pack-security`, `test:private-key-scan-hostile` | `SECURITY_CLAIMS.md` (Package-Boundary Secret Scanning) | Partially. Covers supported formats only, by the specific rule per detector; it is not exhaustive secret detection. | The npm build and extracted pack artifact are scanned for supported PEM/DER/JWK/PuTTY private-key formats, selected recognizable provider tokens, and conservatively detected credential assignments, each by its own rule (textual markers, structured/embedded JSON, complete-file DER, populated PuTTY bodies, and recognized secret-bearing assignments); detection is not exhaustive. |

## Unsupported Wording to Avoid

Do not use these statements unless future evidence is added:

- "Prevents unauthorized execution."
- "All execution is verified."
- "Every tool call is protected."
- "Secure by default."
- "Enterprise ready."
- "Government ready."
- "Production hardened."
- "Certified."
- "Compliant."
- "Safe AI."
- "Blocks all attacks."
- "No secrets can ever appear anywhere."

## Required Rewrites

| Unsupported wording | Replace with |
| --- | --- |
| "Prevents unauthorized execution." | "Prevents unauthorized execution for requests routed through an enforcing MNDe integration." |
| "All execution is verified." | "Execution routed through MNDe is verified according to configured policy and available authority evidence." |
| "Every tool call is decided pre-execution." | "Every routed tool call is decided pre-execution." |
| "No secrets in logs." | "MNDe-controlled paths are designed and tested not to emit configured private keys or bearer tokens; operators must keep secrets out of request content and external tooling." |
| "Enterprise identity." | "Future enterprise identity features are optional and off by default; current caller auth is pilot-grade bearer auth when enabled." |

## Current Security Claim Posture

MNDe can defensibly claim:

- Pre-execution authorization for routed integrations.
- Refusal preservation in tested executor, MCP server, MCP proxy, and shell demo paths.
- Signed, tamper-evident receipts and signed execution evidence for supported formats.
- Offline verification when required trust evidence is available.
- Fail-closed behavior for tested malformed input, invalid policy, invalid trust roots, and custody failures.

MNDe should not yet claim:

- OS-wide enforcement.
- Complete enterprise identity.
- General AI safety.
- Standalone or OS-wide AI containment.
- Regulatory compliance.
- Production hardening.
- Government procurement readiness.
- Complete or universal secret scanning of the package artifact.

## Package-Boundary Secret Scanning

The prepack build (`build/build-package.mjs`) and the pack-boundary test
(`test:pack-security`, which extracts a real `npm pack` tarball and scans its
`package/` content directory) run the same content-based scanner
(`build/lib/package-secret-scan.mjs`) over the shipped files and fail closed on
any finding. Each detector applies its own matching rule — the scan is not a
single "anywhere/any-embedding" match:

- **PEM private keys** (`PRIVATE KEY`, `RSA`/`EC`/`OPENSSH`/`ENCRYPTED PRIVATE
  KEY`) are matched textually anywhere in file contents, regardless of filename,
  extension, or nesting.
- **Provider secret tokens** (a conservative, non-exhaustive registry: GitHub,
  GitLab, npm, Slack, Stripe live secret/restricted keys, OpenAI) are matched
  textually anywhere in file contents.
- **JWKs** — private RSA/EC/OKP (`d`) and symmetric `oct` (populated `k`) — are
  detected as structured JSON: the whole file parsed as JSON, JWKs nested inside
  it, JSON strings whose decoded value is a JWK, and complete valid JSON-object
  candidates embedded in surrounding text or JavaScript (bounded, brace-aware
  extraction — not arbitrary JavaScript object-literal parsing).
- **DER private keys** (PKCS#8, PKCS#1 RSA, SEC1 EC) are detected only when a
  *complete file* parses as one via Node's crypto — not from embedded fragments.
- **PuTTY** v2/v3 private-key containers are detected only when a recognizable
  header is present *and* the declared `Private-Lines` body is actually present,
  non-empty, and plausibly Base64 (a truncated header alone is not flagged).
- **Contextual credential assignments** are detected only when a conservatively
  strong (length/diversity/entropy) value is bound to an explicitly
  secret-bearing field name (JSON/dotenv/YAML/simple assignment); this is not
  unrestricted high-entropy scanning of arbitrary content.

Findings never contain the matched secret — only detector id, normalized path,
line, and a truncated SHA-256 fingerprint. An allowlist (`build/`, never shipped)
can suppress only an exact path + detector + full-file-hash match with a written
reason; it can never suppress a private-key-class finding, and a changed file
reactivates the finding.

**Documented limitations (this is not complete or universal secret detection):**

- Detection is not exhaustive.
- Provider token formats change over time; the registry is non-exhaustive.
- Unknown or proprietary credential formats may not be recognized.
- Encrypted or custom binary containers may evade recognition.
- Secrets that are split, encoded, compressed, or obfuscated across values are
  not guaranteed to be detected.
- JWK embedding is detected only for the forms listed above (structured JSON,
  JSON-encoded strings, and complete valid JSON-object candidates in text). It
  does not parse arbitrary JavaScript object-literal syntax, and not every
  possible embedding is covered.
- Runtime logs, user-supplied request content, external systems, and any
  artifact outside the npm package boundary are not covered.
- This is not a substitute for repository, CI, host, or organization-level
  secret scanning.
