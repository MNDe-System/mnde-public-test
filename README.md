> Freshness safety hold: decision delivery and protected executor/MCP dispatch are disabled pending an independently operated claim backend and rollback proof. Health, discovery, and offline receipt verification remain available. `MNDE_EXEC_ID_CACHE` cannot enable dispatch. See [operator changes and evidence](docs/FRESHNESS-BOUNDARY-AUDIT.md).

<p align="left"><img src="brand/mnde-wordmark.svg" alt="MNDe" height="80"></p>

# MNDe Public Test

**When an AI agent takes an irreversible action — moves money, deletes
infrastructure, files a document — MNDe produces a signed receipt that proves
whether that action was authorized, and lets a second party verify the proof
without trusting the operator.**

That second party is the point: an auditor, a controller, a security reviewer in
an incident postmortem. Approval workflows, RBAC, and audit logs record what a
*human* did — none of them prove that an *autonomous agent's* action was allowed
under policy. MNDe's receipt does, and it verifies **offline** against a trust
anchor, so the reviewer never has to take the operator's logs on faith.

> **Status: pilot.** The offline-verification mechanism works today against a
> trust anchor. A *stable, MNDe-published* authority bundle for verification
> outside this repository **does not exist yet** (see [Limitations](#limitations)) —
> that bundle is the next milestone, and until it ships, third-party verification
> is repo-local.

## What It Does

A caller submits a proposed action *before* executing it. MNDe evaluates it
against a policy, returns `ALLOW` or `REFUSE`, and writes a signed receipt. The
caller executes only after an `ALLOW`. The decision, receipt, policy hash,
signature, and replay result can all be inspected — and independently verified —
after the fact.

## What It Does Not Do

- It does not run actions itself. The caller executes only after an `ALLOW`.
- It does not prevent an action that is never submitted to it. Enforcement is cooperative (see [Limitations](#limitations)).
- The bundled policy is small and illustrative, not a complete policy for a specific deployment.

## Components

MNDe sits between the caller's intent and the action. If MNDe returns `REFUSE`, the action is not executed (and, in the proxy, not forwarded).

Three integration paths share the same decision and receipt flow:

- **`@mnde/executor`** ([executor/](executor/)) — wrap a function; `ALLOW` runs it once, `REFUSE` does not. `npm run executor-demo`, `npm run test:executor`.
- **MNDe MCP server** ([mcp/](mcp/)) — expose tools over the Model Context Protocol; each `tools/call` is authorized first. `npm run mcp-demo`, `npm run test:mcp`.
- **MNDe MCP proxy** ([mcp/mnde-mcp-proxy.mjs](mcp/mnde-mcp-proxy.mjs)) — place MNDe in front of an existing MCP server; `tools/call` is authorized before execution, with no changes to the upstream. `npm run mcp-proxy-demo`, `npm run test:mcp-proxy`.

The tests assert that no code path executes (or, in the proxy, forwards) a `REFUSE`d call. The MCP tests check this across process boundaries using a marker file written only when the underlying tool actually runs.

## Quick Start

1. Start MNDe:

   ```bash
   npm run sidecar
   ```

2. Run a protected tool demo (in a second terminal):

   ```bash
   npm run mcp-proxy-demo
   ```

Expected result:

- ALLOW actions execute.
- REFUSE actions do not execute.
- Receipts verify offline.

`npm run sidecar` is a foreground service: it bootstraps local authority keys if needed, validates the environment, prints a `Status: READY` banner, and streams logs until you press Ctrl+C. No manual setup steps are required on a fresh clone.

## Install

No desktop installer or downloadable pilot release is currently published. The
supported public evaluation path is a source checkout. Desktop installers remain
outside the current pilot scope.

Requirement:

- Node.js 24 or later

Clone and verify the source checkout:

```bash
git clone https://github.com/mndesystems-ship-it/mnde-public-test.git
cd mnde-public-test
npm install
npm run reviewer-kit
```

Expected final result:

```text
FINAL VERDICT: PASS
```

Start the sidecar directly with `npm run sidecar`.

`npm run sidecar` automatically creates the local authority assets it needs on first run, so no separate setup step is required. If you prefer to provision those assets explicitly (e.g. for the reviewer kit without starting a sidecar), `npm run tester:init -- TESTER-001` does the same bootstrap.

`tester:init` creates three local-only things:

- `.mnde-test\identity.json`
- `shared\receipt_keys\receipt_signing_private.pem` and `receipt_signing_public.pem`
- `.mnde-test\authority\authority-manifest.json` signed by the local root authority

The signing keys and local tester authority are generated on your machine, ignored by git, and required for live signed receipts created by the reviewer kit. `tester:init` reuses existing local authority material when present and never modifies the committed demo authority or example receipts.

The repository also includes a committed demo authority under `authority/`. It is stable for documentation examples and committed example receipts only.

Receipts do not trust their own embedded key. The verifier checks the signed authority manifest first, then verifies the receipt with an authority-approved key. If keys or authority evidence are missing or invalid, MNDe refuses to start with a clear `ERR_RECEIPT_SIGNING_KEYS_*` or `ERR_AUTHORITY_MANIFEST_INVALID` error instead of crashing during the first decision.

Optional executor identity produces explicit `executor_and_authority` live receipts with no authority-only fallback. Without executor configuration, authority-only receipt bytes remain identical to the existing v1 formats. See [executor-bound live receipts](docs/executor-bound-receipts.md) for configuration, verification, private-key path restrictions, and exact security claims.

Production verification requires a stable MNDe-published authority bundle. Receipts are independently verifiable only when the verifier has the trusted authority manifest and root public key. Unknown authority IDs, unknown key IDs, expired keys, and invalid manifests fail closed.

The repository includes npm release-build tooling. Maintainers can build and
verify a local release candidate with:

```bash
npm run release
npm run release:verify
```

The generated npm tarball, checksum file, and release manifest are local
release-candidate artifacts, not public downloads. See
[`docs/RELEASE.md`](docs/RELEASE.md) for the build and packaged-install contract,
and [`installer/README.md`](installer/README.md) for the current installation
status.

## Verify It Works

Run:

```bash
npm run reviewer-kit
```

Expected final output:

```text
FINAL VERDICT: PASS
```

The reviewer kit is the supported one-command proof path. It starts MNDe, runs the ALLOW and REFUSE examples, verifies receipts, verifies replay, checks hostile input refusal behavior, and proves that a destructive executor action is blocked before execution.

`npm run reviewer-kit` is cross-platform and uses Node.js. Windows PowerShell helper scripts remain available through:

```powershell
npm run reviewer-kit:windows
```

## Verified Behaviors

Each item below is exercised by an automated test or demo script in this repository:

- Fresh clone install
- Tester init
- Reviewer kit
- Safe ALLOW
- Unsafe REFUSE
- Offline receipt verification
- Tamper detection
- Trust-anchored receipt origin
- Deterministic repeat requests
- Executor blocked before execution

## Documented Verification Flow

Run:

```bash
npm run verify-receipt examples/receipts/valid-receipt.json
npm run test:receipt-verifier
npm run test:trust-anchor
npm run test:fresh-setup
```

Expected result: every command exits 0 and prints `PASS` or `FINAL VERDICT: VERIFIED`.

> There is no desktop installer or desktop executable in this release (see [`installer/README.md`](installer/README.md)). The `desktop-smoke` script is a source-development harness that runs only against a separately-provided desktop build; it is not part of the supported pilot artifact.

## Onboard An MCP Client

MNDe includes an offline onboarding command for supported MCP clients.

Preview discovery:

```bash
npm run mnde -- init
```

Preview the exact wiring plan without writing files:

```bash
npm run mnde -- init --dry-run
```

Apply the wiring plan:

```bash
npm run mnde -- init --apply
```

Check recorded wiring and authority readiness:

```bash
npm run mnde -- status
```

Restore original configs:

```bash
npm run mnde -- uninstall
```

Onboarding creates backups before modifying supported MCP configs. It does not activate policy, change authority material, alter receipt signing, or change replay verification.

Details:

- [Onboarding](docs/onboarding.md)
- [Discovery](docs/discovery.md)
- [Wiring](docs/wiring.md)
- [Policy drafting](docs/policy-drafting.md)
- [Security model](docs/security-model.md)

## Integration

See [docs/integration-guide.md](docs/integration-guide.md) for a minimal agent wrapper that calls `POST /v1/decisions` before execution, executes only on `ALLOW`, never executes on `REFUSE`, stores receipts, and verifies them offline.

## Trigger An ALLOW Decision

```bash
npm run reviewer-kit:allow
```

The ALLOW example submits:

```text
read_status
```

## Trigger A REFUSE Decision

```bash
npm run reviewer-kit:refuse
```

The REFUSE example submits:

```text
recursive_delete
```

## Verify A Receipt

```bash
npm run verify-receipt reviewer-kit/artifacts/receipts/allow-receipt.json
npm run verify-receipt reviewer-kit/artifacts/receipts/refuse-receipt.json
```

An included sample receipt can be verified without starting MNDe:

```bash
npm run verify-receipt examples/receipts/valid-receipt.json
```

Expected output:

```text
FINAL VERDICT: VERIFIED
```

## Tester ID

Each tester receives a human-readable Tester ID, such as:

```text
TESTER-001
```

Initialize it with:

```bash
npm run tester:init -- TESTER-001
```

The local installation identifier is generated on this machine and saved under `.mnde-test/`. It is not committed. The Tester ID is included in reviewer-kit requests, generated receipts, logs, and diagnostics so feedback can be tied to a test run without collecting personal information.

MNDe Public Test does not collect personal information, track browsing activity, or transmit data without consent.

## Artifacts

Generated files stay under:

```text
reviewer-kit/artifacts/
.mnde-test\
shared/receipt_keys/
```

Committed example receipts are signed by the committed demo authority under `authority/`. Local reviewer-kit receipts are signed by the generated local tester authority under `.mnde-test/authority/`.

## Feedback

Send:

- Tester ID
- Command run
- Final verdict
- Receipt file, if relevant
- Screenshot or error text
- What you expected
- What happened

See [docs/feedback-workflow.md](docs/feedback-workflow.md).

## Limitations

- The bundled decision policy is small and illustrative: a denylist of patterns plus cost and runtime-drift checks, and a deny-by-default list for the shell example. It is not a complete policy for any specific deployment. See [docs/production-readiness.md](docs/production-readiness.md).
- The manual-approval threshold and the shell `APPROVAL_REQUIRED` decision are gated on a request field (`hold_state`) supplied by the caller. There is no authenticated approver binding yet.
- The `orbit_intent.signatures` field is shape-validated but not cryptographically verified.
- Verification in this repository chains to a locally generated test authority. A published authority bundle for use outside this repository does not exist yet.
- Enforcement is cooperative: MNDe evaluates an action only when the caller routes it through MNDe (executor, MCP server, or proxy). It is not OS-level and does not stop a process that bypasses it.

See [docs/execution-receipt-spec-v1.md](docs/execution-receipt-spec-v1.md), sections 3 and 5, for what the receipt format does and does not guarantee.

## Roadmap

These exist as architecture or concepts in the repository but are not claimed as complete:

- Argument-level shell policy and operator-defined allowlists.
- Production MNDe Policy Engine behavior defined in [docs/mnde-policy-engine-production-spec-v1.md](docs/mnde-policy-engine-production-spec-v1.md).
- Authenticated approval (signed approval tokens) for `APPROVAL_REQUIRED`.
- A published authority bundle with documented key rotation.
- Centralized policy and audit management.
- Identity-aware authorization for multi-user deployments.
- **P0 (done)**: Scope-bound, single-use authority grants (`mnde.authority_grant.v1`) —
  principal, tool, tenant, scope, and nonce-bound, replay-protected via a durable atomic
  reservation store. See [docs/authority-grant-v1.md](docs/authority-grant-v1.md). Production
  no longer accepts the legacy unscoped bearer-style grant. Known limitations (weaker principal
  source, no tenant-authentication system, exact-only scope matching, no grant-revocation list)
  are documented in that spec's "Known limitations" section.
- **P1**: A safe key-revocation lifecycle command for `shared/authority-manifest.mjs` authorities — `findAuthorityReceiptKey` now checks `revoked_at`, but nothing writes it; revoking a key today means hand-editing and re-signing the manifest. Needs chronology validation, a re-signed manifest, an audit record, and refusal of unsafe edits (e.g. revoking a key with no successor).

## More Docs

- [First tester onboarding](docs/first-tester-onboarding.md)
- [MNDe CLI v1 spec (first iteration)](docs/mnde-cli-v1-spec.md)
- [Independent receipt verification](docs/independent-verification.md)
- [Minimal agent integration](docs/integration-guide.md)
- [MNDe Guard for OpenClaw spec](docs/openclaw-integration-spec.md)
- [Onboarding](docs/onboarding.md)
- [Discovery](docs/discovery.md)
- [Wiring](docs/wiring.md)
- [Policy drafting](docs/policy-drafting.md)
- [MNDe Policy Engine production spec](docs/mnde-policy-engine-production-spec-v1.md)
- [Onboarding security model](docs/security-model.md)
- [Trust-anchored receipt verification](docs/trust-anchored-verification.md)
- [Production trust model](docs/production-trust-model.md)
- [Production readiness notes](docs/production-readiness.md)
- [Release note: safe MCP onboarding](docs/release-891ceda-onboarding.md)
- [Demo scenarios](docs/demo-scenarios.md)
- [Tester ID implementation](docs/tester-id-implementation.md)
- [Release checklist](docs/release-checklist.md)
- [Security review checklist](docs/security-review-checklist.md)
