# Pre-Execution Authorization Layer (Overview)

## What it is

A pre-execution authorization layer receives a proposed action before it runs, evaluates the action against a policy and runtime constraints, and returns a decision. The caller executes the action only after an `ALLOW`.

The decision set is:

- `ALLOW`: execution may continue
- `REFUSE`: execution must not occur

The layer is positioned before the executor. The executor does not perform the action until it receives a valid `ALLOW`.

## Why the enforcement point is before execution

Monitoring observes behavior during or after execution. It can detect events and support investigation, but it cannot prevent the first unsafe operation from running.

Evaluating the action before the executor mutates state enables:

- deterministic allow/refuse decisions
- fail-closed behavior on error
- policy-bound execution
- an auditable record of refusals

Determinism is conditioned on runtime health, and the condition matters enough to
state: when the runtime is healthy MNDe preserves specific refusal reasons, and
when runtime health cannot be established it fails closed with a runtime-health
refusal instead of continuing evaluation. An unhealthy runtime refuses; it never
allows. See
[Runtime Health Refusals](production-readiness.md#runtime-health-refusals-take-precedence-over-decision-specific-refusals).

The invariant the integrations enforce:

```text
The caller does not execute unless the authorization layer returns ALLOW.
```

This invariant holds for actions routed through MNDe. It does not constrain code paths that never call MNDe (see Limitations).

## Decisions and receipts

The authorization layer decides whether an action may proceed. An execution receipt records the decision and the inputs to it.

A receipt provides evidence for:

- the submitted request (as a canonical string)
- the policy reference (policy version and hash)
- the decision and reason code
- the decision hash
- the signature produced by an authority-approved key
- replay verification (recomputing the decision from the receipt)

Receipts without enforcement document decisions but do not prevent actions. Enforcement without receipts can refuse actions but produces no portable evidence.

## Example flow

```text
Agent or automation
  -> proposes a tool call
  -> authorization decision API
      -> ALLOW: executor runs the tool
      -> REFUSE: executor returns a denied result
  -> receipt stored for later verification
```

The executor or tool wrapper is responsible for calling the authorization API before performing work.

## MNDe implementation

MNDe implements this model with:

- a local decision service (the sidecar)
- deterministic request canonicalization
- policy and runtime decision stages
- `ALLOW` and `REFUSE` decisions
- signed receipts
- authority-manifest verification
- offline receipt verification
- replay verification

A verifier checks a receipt against a trusted authority bundle and recomputes the deterministic decision path. It does not need to trust the operator, server, or key material embedded in the receipt.

## Limitations

- The bundled policy is small and illustrative. It is not a complete policy for a specific deployment.
- Enforcement is cooperative: it applies only to actions the caller routes through MNDe. It is not OS-level.
- Verification in this repository chains to a locally generated test authority; a published authority bundle does not exist yet.

See [production-readiness.md](production-readiness.md) for the full list of what the public test does and does not demonstrate, and [execution-receipt-spec-v1.md](execution-receipt-spec-v1.md) for the receipt format and its non-goals.

## Roadmap

- Operator-defined and argument-level policy.
- Authenticated approval for actions that require a human in the loop.
- A published authority bundle with documented key rotation.
- Centralized policy and audit management.
