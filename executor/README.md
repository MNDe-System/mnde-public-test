# @mnde/executor

Authorize a function call through MNDe before running it.

Wrap a function. MNDe is asked first. The wrapped function runs **only** when MNDe returns a receipt that verifies offline, carries an `ALLOW` decision in its own signed body, and is bound to this exact request (execution id + action + parameters, and the expected policy when you declare one). A bare `ALLOW` string is never sufficient — no receipt, an unverifiable receipt, or a receipt issued for a different request fails closed and does not execute. The call returns a signed receipt either way.

```js
import { createMndeExecutor } from "@mnde/executor";

const mnde = createMndeExecutor({ sidecarUrl: "http://127.0.0.1:8787" });

const result = await mnde.execute({
  action: "delete_backups",
  input: { path: "backups/" },
  run: async () => deleteBackups()
});
```

## Behavior

```
Ask MNDe first.
Execute ONLY if the receipt: is present, verifies offline, has a signed ALLOW
  decision, and is bound to this exact request (execution id + action +
  parameters, plus the expected policy hash/version when configured).
Otherwise — REFUSE, missing/unverifiable/mismatched receipt, unreachable sidecar,
  malformed decision, timeout — do NOT execute.
Return and store the receipt (or a fail-closed record) either way.
```

Optional `expectedPolicyHash` / `expectedPolicyVersion` (or `MNDE_EXECUTOR_EXPECTED_POLICY_HASH` / `MNDE_EXECUTOR_EXPECTED_POLICY_VERSION`) reject a receipt decided under any other policy. Offline verification is mandatory and cannot be disabled.

## Result shape

```js
{
  decision: "ALLOW" | "REFUSE",
  allowed: boolean,
  refused: boolean,
  executed: boolean,
  reason: string | null,        // reason_code, e.g. "ERR_FORBIDDEN_ACTION_IN_PARAMETERS"
  result: any,                  // the return value of run(), only on ALLOW
  error: string | undefined,    // set if run() threw (the receipt is still stored)
  receipt: object | null,
  receiptPath: string | null,   // "./mnde-receipts/receipt-<id>.json"
  verified: boolean | null,     // offline receipt verification result
  failClosed: boolean           // true when refused due to error, not policy
}
```

## API

### `createMndeExecutor(config)`

| option | default | meaning |
|---|---|---|
| `sidecarUrl` | `http://127.0.0.1:8787` | MNDe sidecar address |
| `receiptsDir` | `./mnde-receipts` | where receipts are written |
| `testerId` / `installationId` | env or `*-UNASSIGNED` | identity stamped into requests |
| `timeoutMs` | `5000` | decision request timeout (then fail closed) |
| `expectedPolicyHash` / `expectedPolicyVersion` | unset | require the signed receipt to name this policy |
| `expectedSubjectId` | unset | require the signed request subject/caller to match |
| `verifyAuthorityBundle` | unset | published authority-bundle path for custody receipts |
| `verifyTrustedRootFingerprint` | unset | out-of-band root pin for custody verification |
| `verifyEnvironmentId` | unset | expected executor credential environment |
| `verifyExpectedExecutorId` | unset | require this executor id (also rejects authority-only custody receipts) |

Returns `{ execute, wrapTool, verifyReceipt, config }`.

### `mnde.execute({ action, input, run, executionId?, requestOverrides? })`

Asks MNDe for `action` + `input`, then runs `run()` only on `ALLOW`. `executionId`
sets the idempotency key (a repeat is refused). `requestOverrides` deep-merges into
the decision request for advanced shaping (cost, approval state, resources).

### `mnde.wrapTool(name, fn)`

Returns a guarded function: `wrapped(input) -> Promise<result>`. The returned
wrapper does not expose the captured `fn`; callers must avoid retaining or using
separate raw-function references for protected actions.

## The safety claim

> If a tool is wrapped with MNDe, there is no code path where `REFUSE` executes.

In [`index.mjs`](./index.mjs) there is exactly **one** call site for the wrapped
function, reachable only after a verified, exact-request-bound `ALLOW`. REFUSE,
an unreachable sidecar, a malformed decision, a timeout, an identity mismatch,
or an unverifiable receipt all return without calling it.

## ⚠️ The one bypass: direct (unwrapped) execution

Protection comes from **wrapping**, not from importing. Calling a raw function
directly skips MNDe entirely — no decision, no receipt:

```js
// NOT PROTECTED — MNDe is never consulted.
await deleteBackups();

// PROTECTED — MNDe decides first.
await mnde.execute({ action: "delete_backups", input, run: () => deleteBackups() });
```

This is covered explicitly in `tests/test_executor.mjs` (test 8) to prevent
claims that direct raw-function calls are protected.

## Try it

```bash
npm run executor-demo     # ALLOW / REFUSE / fail-closed, end to end
npm run test:executor     # the enforcement test suite

node examples/executor-wrapper/read-status.js
node examples/executor-wrapper/delete-backups-blocked.js
node examples/executor-wrapper/deploy-requires-approval.js
node examples/executor-wrapper/agent-tool-wrapper.js
```

## Scope (v0.1)

This version lives inside the MNDe repo and imports the in-repo request builder
and offline verifier. JavaScript only, local sidecar only. Publishing as a
standalone package means vendoring those two pieces — deliberately out of scope
for v0.1.
