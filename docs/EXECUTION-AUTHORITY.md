# A decision is not an execution grant

> **ALLOW means "policy approved this request."**
> **ALLOW does not mean "execution happened" or "execution is permitted now."**

These are two different facts, produced by two different components. Conflating
them is the single most dangerous misreading of MNDe, because it turns a signed
receipt into something it was never able to be: a one-time permission to act.

## The two components

| | What it does | What its output means |
| --- | --- | --- |
| **Sidecar** (`/v1/decisions`) | Evaluates policy, signs a receipt, appends it to the execution ledger | A policy decision was made, and here is verifiable proof of what it was |
| **Executor** (`executor/index.mjs`) | Enforces the strict gate, then decides whether MNDe may act | Whether anything actually happened |

The sidecar issues decisions. It does not call GitHub, and it does not perform
effects. The executor is the enforcement point.

## Why a receipt cannot be a grant

A verified receipt is a signature, and **a signature can be presented twice.**
Nothing inside it makes it single-use. After a crash, a restart, or a restore of
executor-local files, the same authentic ALLOW authorizes the same effect again.

That is finding F-001 in [`FRESHNESS-BOUNDARY-AUDIT.md`](./FRESHNESS-BOUNDARY-AUDIT.md).
Closing it requires **durable single-use redemption** in a store the executor
operator cannot roll back — not a stronger signature, and not another gate.

Until that is wired *and proven*, protected execution is disabled.

## What that looks like on the wire

Every decision response states execution availability, refusals included:

```json
{
  "schema_version": "mnde.api.response.v1",
  "decision": "ALLOW",
  "receipt": { "...": "...", "execution_status": "DISABLED" },
  "execution": {
    "dispatchable": false,
    "status": "DISABLED",
    "reason_code": "ERR_FRESHNESS_DEPLOYMENT_DISABLED"
  }
}
```

Two statements, deliberately:

- **`receipt.execution_status`** is inside the signed payload. It is the
  authoritative one. Removing it breaks the signature, and so does adding it to a
  receipt that never had it. Both directions are tested.
- **`execution`** on the envelope is the convenience copy, for operators and
  dashboards. It is unsigned and can be stripped in transit — which is precisely
  why it is not the one that counts.

`execution_status` is present **only while execution is disabled**. It follows the
same conditional-field convention as `approval_enforced` and
`policy_bundle_provenance` in `buildPolicyReceipt`, so receipts issued once
dispatch is live are byte-identical to historical ones and no conformance vector
moves.

### Known gap: the legacy engine

The legacy decision engine's frozen `ecs.receipt.v2` schema deliberately gains no
new field — inventing one in a frozen compatibility schema is a worse trade than
the gap. Legacy receipts therefore carry the marker only in the (strippable)
envelope. This is an evidence gap on an opt-in compatibility path, not a safety
gap: the executor refuses either way, and **nothing reads this field to decide
whether to execute.** The canonical `policy-engine` path, which is the v1 default,
carries the signed marker.

## If you consume `/v1/decisions` directly

Reading `ALLOW` from the API and acting on it is **not** authorization by MNDe. It
is bypassing the enforcement point. The receipt you hold is evidence that policy
approved a request; it says nothing about whether you may perform the effect, and
while execution is disabled it says explicitly that MNDe could not have.

Route protected actions through the executor. If you hold a receipt and want to
know what MNDe actually did, read `executed`, not `decision`.

## Refusal reasons stay specific

A denying policy rule reports itself as such. A replayed execution id reports
`ERR_EXECUTION_ID_REPLAYED`. A request that clears the strict gate and is stopped
only by the deployment hold reports `ERR_FRESHNESS_DEPLOYMENT_DISABLED`.

Collapsing every refusal into one code would make MNDe undiagnosable and would
silence the ledger. An operator has to be able to tell "your policy denied this"
apart from "MNDe is not currently able to act at all."

## What re-enabling requires

Flipping `DISPATCH_ENABLED` in [`src/execution-availability/index.mjs`](../src/execution-availability/index.mjs)
does **not** create an execution path. There is no generic `run()` call site to
restore, and that is intentional: arbitrary JavaScript cannot be shown to be
idempotent, single-effect, or free of a second egress path. A callback named
`read_status` is not thereby read-only — the name is not the code.

Enabling execution means:

1. A durable single-use claim backend, independently administered, with restore
   and admin authority held outside the automated system.
2. A **narrow typed effect** that derives its request entirely from signed fields,
   the way `build_request.mjs` does — not a restored generic callback.
3. The claim taken *before* transport, with no retry and no re-claim.
4. The deployment-proof suite run against real infrastructure — the one row still
   marked **NOT RUN** in the audit's acceptance table.

## Tests that pin this

| Suite | What it proves |
| --- | --- |
| `npm run test:decision-not-execution` | The signed marker verifies, and cannot be stripped or forged |
| `npm run test:executor-fail-closed` | A valid, request-bound ALLOW receipt is evidence, not permission |
| `npm run test:executor-live-sidecar` | A real custody-signed v2 receipt under a pinned root still does not execute |
| `npm run test:executor` | The callback is never entered, on any path |
| `npm run test:freshness-boundary` | Across restarts and snapshot restore, zero provider calls |
| `npm run test:shipped-surface-bypass` | The shipped artifact carries no spawn path and no executor callback in the proxy |

No test in this repository treats an ALLOW decision receipt as permission to
execute. If you find one, it is a bug.
