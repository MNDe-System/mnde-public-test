# Production Readiness Notes

This document separates public tester evidence from production deployment requirements.

## What the Public Tester Proves

The public tester demonstrates:

- fresh-clone setup
- local tester identity initialization
- pre-execution `ALLOW` and `REFUSE` decisions through the reviewer kit
- signed receipt generation
- offline receipt verification
- replay determinism
- trust-anchored receipt origin validation
- tamper detection
- hostile input refusal behavior
- executor-level blocking before a destructive demo action runs

## What the Public Tester Does Not Prove

The public tester does not prove:

- kernel-level enforcement
- operating-system-wide process control
- prevention of arbitrary processes that bypass integration
- production authentication configuration
- production key custody
- production availability guarantees
- suitability of the demo denylist policy for a real deployment

MNDe is demonstrated here as a pre-execution authority layer. Integrated systems enforce MNDe decisions by asking before execution and running only after `ALLOW`.

## Local Test Authority vs Production Authority

The repository contains two authority paths:

- `authority/`: committed demo authority for example receipts and documentation fixtures
- `.mnde-test/authority/`: generated local tester authority for reviewer-kit receipts

`npm run tester:init -- TESTER-001` creates or reuses the local tester authority. It must not modify the committed demo authority or invalidate committed example receipts.

Production deployments require a stable published authority bundle distributed through a trusted channel. Independent verification depends on the verifier having that trusted root public key and signed authority manifest.

### Runtime profile and trust-root pre-flight (`MNDE_PROFILE`)

MNDe will not enter live enforcement while signing with development keys. A deterministic pre-flight (`src/authority-signing/preflight.mjs`) runs once before the decision server accepts traffic:

- `MNDE_PROFILE` unset or `local` (default): demo/local mode — legacy signing or `local-demo` custody allowed; behavior unchanged; custody is not loaded.
- `MNDE_PROFILE=production`: MNDe **refuses to start** unless `MNDE_RECEIPT_SIGNING_MODE=custody`, `MNDE_KEY_CUSTODY=file-backed-production`, a valid published authority bundle + signing key are configured, no demo/dev key material is detected, and `MNDE_SIDECAR_AUTH=bearer` has a valid bearer token configuration. Failures are fail-closed with distinct trust-root reason codes or a production auth startup refusal; there is no automatic downgrade to legacy/dev-key signing or unauthenticated production decisions.

Required production environment and reason codes are documented in [Key Custody](key-custody.md). Verified by `npm run test:trust-root`.

## Executor Integration Model

MNDe does not execute arbitrary tools by itself. An integrated executor or tool wrapper must:

1. Receive the proposed action.
2. Submit it to `POST /v1/decisions`.
3. Persist the returned receipt.
4. Execute only when the decision is `ALLOW`.
5. Return a denied result when the decision is `REFUSE`.

If a tool bypasses this integration path, MNDe has not evaluated that action.

## Demo Policy Behavior

The public tester uses demo policy logic to make the pre-execution decision flow visible. The demo policy is intentionally small and deterministic. It is not presented as a complete production policy engine.

Receipt generation, authority validation, offline verification, replay verification, and tamper detection are separate proof areas from the demo policy behavior.

## Policy Engine Implementation Slice

The repository now includes an initial MNDe Policy Engine implementation slice under:

```text
src/policy-engine/
```

It is covered by:

```text
npm run test:policy-engine
```

This slice currently supports request validation, policy validation, deterministic rule evaluation, `ALLOW` / `REFUSE` decisions, reason codes, conflict resolution where `REFUSE` wins, no-match refusal, invalid-input refusal, basic policy hashing, basic authority chain hashing, basic decision hashing, and first-pass authority checks for missing or expired authority.

It is not yet the full production PE described in `docs/mnde-policy-engine-production-spec-v1.md`. Signed policy verification, authority signature verification, revocation checking, threshold signer enforcement, simulation mode, lockdown mode, and full production conformance vectors remain production work.

## Fail-Closed Expectations

Production integrations should fail closed when:

- MNDe is unreachable
- a decision response is malformed
- the receipt is missing
- receipt persistence fails when durability is required
- signature or authority validation fails
- replay verification fails
- authentication or authorization is missing

Fail-closed behavior should be tested at the executor boundary.

## Runtime Health Refusals Take Precedence Over Decision-Specific Refusals

This is intended behaviour, not a defect. It is written down because it changes
what a caller sees, and because the guarantee it qualifies is one MNDe states
elsewhere.

**The accurate claim.** When the runtime is healthy, MNDe preserves specific
refusal reasons. When runtime health cannot be established, MNDe fails closed
with the applicable runtime-health refusal instead of continuing evaluation.

So a request that would have been refused `APPROVAL_EXPIRED` can instead come
back `ERR_RUNTIME_DEGRADED` or `ERR_SYSTEM_SATURATED`, and a request that would
have been **allowed** is refused as well. The decision is never wrong in the
dangerous direction — an unhealthy runtime never produces an ALLOW — but the
reason is not decision-specific, because no policy evaluation ran.

### The two guards, and when each fires

Both sit in front of `POST /v1/decisions`, and the watchdog check runs first,
before admission control and before the request is parsed.

**1. The runtime watchdog** (`sidecar/runtime_watchdog.mjs`) ticks every
`MNDE_WATCHDOG_INTERVAL_MS` (default 250 ms) and measures its own scheduling lag.

| Condition | Default | State | Recorded reason |
| --- | --- | --- | --- |
| event-loop lag ≥ `MNDE_WATCHDOG_MAX_EVENT_LOOP_LAG_MS` | 250 ms | degraded | `ERR_EVENT_LOOP_LAG` |
| open sockets ≥ `MNDE_WATCHDOG_MAX_OPEN_SOCKETS` | 256 | degraded | `ERR_SOCKET_ACCUMULATION` |
| event-loop lag ≥ `MNDE_WATCHDOG_FATAL_EVENT_LOOP_LAG_MS` | 2000 ms | fatal | `ERR_EVENT_LOOP_FATAL` |
| open sockets ≥ `MNDE_WATCHDOG_FATAL_OPEN_SOCKETS` | 1024 | fatal | `ERR_SOCKET_ACCUMULATION_FATAL` |

While degraded the decision endpoint answers `ERR_RUNTIME_DEGRADED`; while fatal,
`ERR_RUNTIME_FATAL`. The response carries the watchdog snapshot under
`runtime_degraded`, including the measured lag and the recorded reason, so an
operator can tell which condition fired.

**2. The saturation controller** (`SystemSaturationController` in
`sidecar/receipt_persistence_queue.mjs`) refuses a single request with
`ERR_SYSTEM_SATURATED` and names the input that tripped it in
`saturation_signal`.

| Signal | Threshold | Default |
| --- | --- | --- |
| `inflight` | `MNDE_SHED_INFLIGHT` / `MNDE_MAX_INFLIGHT` | 64 / 128 |
| `event_loop_lag` | `MNDE_MAX_EVENT_LOOP_LAG_MS` | 80 ms |
| `receipt_queue_depth` | 75% of the receipt queue's `max_items` | — |
| `receipt_queue_bytes` | 75% of the receipt queue's `max_bytes` | — |

Note that the two lag thresholds differ on purpose: saturation sheds a single
request at 80 ms, while the watchdog marks the whole process degraded at 250 ms.
A deployment can see `ERR_SYSTEM_SATURATED` under a brief spike and
`ERR_RUNTIME_DEGRADED` under a sustained one.

### These refusals are still evidenced

Both go through the same refusal path as any other REFUSE: a receipt is built,
signed, and enqueued for persistence, and the response is HTTP 200 with
`decision: "REFUSE"`. A health refusal is a signed, verifiable record that MNDe
declined; it is not a dropped request.

One exception is worth knowing. If the receipt queue itself cannot accept the
refusal receipt, the reported `reason_code` is replaced again by the persistence
failure code and `receipt_persisted` is `false`. A caller that needs to know
whether its refusal was durably recorded must read `receipt_persisted` rather
than infer it.

### Recovery is not symmetric

**Degraded clears itself.** On the first tick where no degrade condition holds
and the receipt queue is not in its fail-closed state, the watchdog clears the
degraded flag and decisions resume.

**Fatal does not.** Nothing resets the fatal flag for the life of the process, so
a sidecar that once exceeded a fatal threshold refuses every decision until it is
restarted. That is deliberate — a process that lost 2 seconds of event loop has
demonstrated it cannot be relied on to decide in time — but it means
`ERR_RUNTIME_FATAL` is an operational alert, not a transient condition to wait
out.

### What this means for an integration

- Treat `ERR_RUNTIME_DEGRADED`, `ERR_RUNTIME_FATAL` and `ERR_SYSTEM_SATURATED` as
  refusals, exactly like any other. Do not execute.
- Do not retry them as though they were the specific refusal they replaced, and
  do not infer from them that the underlying request would have been allowed.
- Alert on `ERR_RUNTIME_FATAL` specifically: it does not clear.
- If a deployment needs specific refusal reasons under sustained load, the
  thresholds are configurable — but raising them trades a safety margin for
  reason granularity, and the safe direction is the current one.

## Authentication Considerations

Production use should define:

- which actors may submit decisions
- which actors may activate policy
- which actors may export receipts or audit bundles
- token lifetime and refresh behavior
- expected unauthenticated behavior
- audit logging for administrative actions

The public tester may use local test identity and local authority material. That is not a production authentication model.

MNDe does not currently provide a public login, account, password, password reset, MFA, browser session, or email-verification system. Private beta deployments use local sidecar access or bearer-protected machine access. Public web login requires a separate IdP/OIDC-backed authentication layer before exposing MNDe through a web product.

## Key Rotation Approach

Production authority manifests should support:

- multiple active receipt signing keys
- retired keys for historical receipts
- validity windows
- manifest signatures from the root authority
- documented rotation procedures

Old receipts should remain verifiable when the receipt signing time falls inside the retired key validity window.

## Deployment Considerations

Before production use, evaluate:

- sidecar lifecycle management
- service supervision and restart policy
- log retention
- receipt durability mode
- backup and recovery for receipt stores
- policy release process
- integration tests for every protected executor
- network exposure and local binding rules

## Audit Retention Considerations

Long-term audit packages should preserve:

- receipts
- trusted authority manifests
- root authority public keys
- policy documents or policy hashes
- verifier version
- replay verification reports
- environment and tester/operator identifiers where appropriate

Receipts copied to another machine remain verifiable only when the verifier has the matching trusted authority bundle.
