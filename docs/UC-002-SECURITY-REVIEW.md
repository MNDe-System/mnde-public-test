# UC-002 security review: approval gates and guarded issuance

Review date 2026-10-16, Node v24.22.0. Base: PR #58 head `8feb9959c101cf7765ae708b5c8b7b211935c68f`.
This change: branch `mnde/guarded-issuance-uc002`, stacked on PR #58.

Every statement is tagged **OBSERVED** (I ran it or read it in this tree and can
point at a test or file), **DESIGN** (what the code is meant to guarantee), or
**NOT ESTABLISHED**. Where a claim rests on a test, the test is named.

## 1. Verdict

UC-002 is **closed for every in-repo path that issues new authorization**, and
the closure is enforced at the issuance chokepoint rather than remembered by each
caller. It is **not** closed for third-party code that bypasses the issuance
functions (§8), and a separate, newly confirmed weakness in how approvals are
scoped (UC-005) remains open. Historical receipts, including ones issued under the
vulnerable behaviour, still verify (§7).

PR #58 alone was not enough. Reviewing it as a security change found four gaps
(§4). They are fixed in the stacked change, not in #58, so #58 stays small,
reviewed and CI-green.

## 2. The original vulnerability

A policy rule may declare `approval_required: <count>`. The engine enforces it
only when approval trust anchors are supplied (`approvalEnforced =
Boolean(approvalTrustAnchors)`, `src/policy-engine/index.mjs`). With no anchors the
field is skipped.

Failure sequence (OBSERVED, reproduced by `tests/fixtures/legacy-unenforced-approval/generate.mjs`
run against pre-guard code at `178342b`):

1. An operator runs the policy-engine sidecar, or `mnde decide`, with a policy that
   gates `deploy` behind one human approval. They omit or misname the anchors file.
2. Nothing fails. The sidecar boots, `/healthz` is green.
3. An agent submits `deploy` with no approval.
4. The engine skips the gate and returns `ALLOW / OK_ALLOW`. A signed receipt is
   issued. It carries no `approval_enforced` field, so nothing marks the omission.
5. A verifier replays the same engine and agrees. The receipt verifies.

The result is a correctly signed, verifying receipt authorizing an action the
policy author meant to hold for a human. The shipped `examples/policy-engine/sample-policy.json`
demonstrated it: eight test suites and `reviewer-kit:pe` booted it with no anchors
and none of them was enforcing the approval it appeared to define.

## 3. Affected entry points (before this change)

All paths that turn a policy into a receipt: the sidecar's policy-engine mode
(`mnde-local-sidecar.mjs` via `decidePolicyEngine`), `mnde decide` (`bin/mnde.mjs`),
and any direct caller of `buildPolicyReceipt` / `buildPolicyReceiptPayload`. The Hub
(`src/hub/authorization.mjs`) already required *some* anchors value (§4.1).

## 4. Root cause, and what PR #58 missed

Root cause: enforcement was **optional and implicit**. "Configured" meant "truthy",
and the only place that knew a gate existed (the policy) was not the place that
knew whether it could be satisfied (the anchors).

Review of PR #58 found:

| # | Gap in #58 (OBSERVED) | Consequence |
| --- | --- | --- |
| 4.1 | Anchors were never validated; "configured" = `Boolean(x)`. `{}`, `{"approval_keys": []}`, RSA/EC/Ed448 keys, a private key in `public_key` all passed. | The Hub went ACTIVE with a gate nothing could satisfy and no startup error. Fail-closed at decision time, silent at configuration time. Test: `test_hub.mjs` "unusable approval anchors never unlock the Hub". |
| 4.2 | A malformed declaration (`false`, `null`, `0`, `"yes"`, `{}`) was only caught at decision time, and only when anchors existed. | Without anchors it was inert (ALLOW). With anchors it was a rule that could never ALLOW. Either way nobody was told. |
| 4.3 | The check lived in the CLI and the loader. `buildPolicyReceipt*` did not call it. | Any direct caller bypassed it entirely. |
| 4.4 | The evaluator ignores unknown rule keys. | A typo'd gate (`requires_approval`; `sample-policies/*.json` use exactly this, KI-002) left the rule ungated with no error. |

## 5. The fix

`src/policy-engine/issuance-guard.mjs` is the single routine that decides whether a
`(policy, approvalTrustAnchors)` pair may be used for **new** issuance. It is called
from:

- `buildPolicyReceiptPayload` (the one chokepoint; `buildPolicyReceipt`, the Hub and
  `authorize-git-push` all go through it), and
- `loadPolicyEngineConfig` (sidecar, Hub and production pre-flight), so a bad
  configuration fails at startup with a named code, and
- `mnde decide` (to give an exit code and write no file).

The evaluator (`evaluatePolicyRequest`) and `verifyPolicyReceipt` do **not** call it.

### API contract

```js
checkIssuanceConfiguration(policy, { approvalTrustAnchors })
  -> { ok: true } | { ok: false, code, detail }      // never throws, never evaluates
assertIssuanceConfiguration(policy, options)          // throws IssuanceRefusedError(code)
validateApprovalTrustAnchors(anchors)                 // the anchor schema check alone
policyDeclaresApprovalRequired(policy)
```

`approvalTrustAnchors === undefined` means *not configured*. **Any other value,
including `null`, `false`, `0`, `""` and `{}`, means the operator configured
something and it is validated.** A falsy-but-present value is a configuration
error, not "off".

### Validation rules and codes

| Code | Refuses when |
| --- | --- |
| `ERR_PE_APPROVAL_REQUIRED_WITHOUT_TRUST_ANCHORS` | any rule declares `approval_required` (any value) and anchors are `undefined` |
| `ERR_PE_APPROVAL_REQUIRED_MALFORMED` | a rule's `approval_required` is not `true` or a positive safe integer |
| `ERR_PE_APPROVAL_ANCHORS_INVALID` | anchors are not `{ approval_keys: [non-empty] }`; a key lacks a non-empty unique `key_id`; `public_key` is not a parseable **Ed25519** SPKI PEM; or `valid_from`/`valid_until` are not both present, parseable and ordered |
| `ERR_PE_POLICY_UNKNOWN_RULE_KEY` | a rule has a key outside `rule_id, effect, match, authority_required, approval_required, description` |

Field **presence** and **validity** are separate: a declaration is detected by
`Object.hasOwn(rule, "approval_required")`, so a malformed value is still a
declaration and is never read as "no approval needed". Anchors are validated even
when the policy has no approval rule.

An invalid policy that the evaluator already refuses (`INVALID_POLICY`) still
yields a `REFUSE` receipt, not a throw: refusal is not authorization.

### Why historical verification is excluded

`verifyPolicyReceipt` replays `evaluatePolicyRequest` and compares the result with
the signed decision. If the evaluator refused approval-gated policies without
anchors, every receipt issued before this change would fail with `decision drift`.
For an audit product, breaking verification of historical evidence is worse than
the gap being fixed. So issuance and replay are separated at the function boundary,
the guard sits on the issuance side only, and a test pins the evaluator's old
behaviour (`replay: the evaluator's no-anchor semantics are frozen`).

## 6. Caller matrix

Built from `grep` over non-test source (aliases, re-exports, dynamic `import()`,
`require`, barrels) on 2026-10-16. There is no `eval`/`Function`/reflective access.
`package.json` has no `main`/`exports`; `files` is `dist`.

| Caller | Issues new authority? | Approvals required? | Anchors guaranteed? | Guarded now by | Test |
| --- | --- | --- | --- | --- | --- |
| Sidecar policy-engine mode, `decidePolicyEngine` → `buildPolicyReceipt` (`src/policy-engine/sidecar-adapter.mjs`, loaded by `mnde-local-sidecar.mjs`) | Yes | If the policy says so | No (env var, optional) | loader + chokepoint | `test_issuance_guard` real-process ×6; `test:sidecar-pe` |
| `mnde decide` (`bin/mnde.mjs`) → `buildPolicyReceipt` | Yes | If the policy says so | No (flag, optional) | CLI check + chokepoint | `test_issuance_guard` CLI ×3 |
| Hub, `openHubAuthorization.decide` → `buildPolicyReceiptPayload` (`src/hub/authorization.mjs`) | Yes (production) | Yes | Required, but only truthy before | loader + chokepoint | `test:hub` "unusable approval anchors…" |
| `scripts/authorize-git-push.mjs` → `buildPolicyReceiptPayload` | Yes (approver ceremony) | No: fixed constant `GIT_PUSH_APPROVAL_POLICY`, no `approval_required` | n/a | chokepoint (passes trivially) | `test:git-push-*` (unchanged, green) |
| `src/production-posture-preflight.mjs` → `loadPolicyEngineConfig` | No (validates config) | n/a | n/a | loader | `test:production-posture` |
| `verifyPolicyReceipt` → `evaluatePolicyRequest` (`receipt.mjs`) | **No: replay only** | replayed as issued | replayed as issued | **deliberately unguarded** | `replay:*` ×9, `test:conformance`, `test:receipt-verifier` |
| `experiments/exp-001-stage2/tests/_real_receipt.mjs` → `evaluatePolicyRequest` | No (frozen baseline experiment, test-only) | n/a | n/a | n/a, not shipped | n/a |
| Third-party deep import of `evaluatePolicyRequest` | Not a receipt: returns a decision object | caller's problem | caller's problem | **not guarded** | §8 |

A reachability test (`coverage: every non-test caller of buildPolicyReceipt* is on
the reviewed list`) fails when a new issuer appears, so the matrix cannot silently
go stale. A second pins that only `index.mjs` and `receipt.mjs` name the evaluator.

## 7. Compatibility

**Replay (OBSERVED).** `tests/fixtures/legacy-unenforced-approval/` holds two receipts
(`mnde.pe.receipt.v1` and `.v2`) issued by pre-guard code (`178342b`) under the
vulnerable configuration: an approval-gated `deploy`, `ALLOW`, no approval, no
`approval_enforced`. Both verify against their pinned root with the new code, both
fail when tampered, and both fail under a different pinned root. Re-issuing the same
request and policy today is refused. The frozen conformance vectors still pass
(`test:conformance`). The fixtures contain only public material; the signing key was
generated in memory by `generate.mjs` and discarded.

**Behaviour changes for operators (intentional).** These now fail at startup or
issuance where they previously booted: approval policies without anchors; unusable
anchors; a malformed `approval_required`; unknown rule keys. A refused sidecar
configuration answers every decision `REFUSE / ERR_PE_CONFIG_INVALID` with the code
in `policy_engine_error`, and signs a `REFUSE` receipt as evidence of the refusal
(`execution.dispatchable: false`). No `ALLOW` is produced anywhere.

**Finding exposure (new tool).** Because a pre-guard receipt does not record that its
gate was off, verification cannot find affected receipts. `npm run
audit:unenforced-approvals -- <paths>` scans receipt files, JSONL logs and custody
envelopes and flags policy-engine receipts whose embedded policy declares
`approval_required` and which lack `approval_enforced: true`. A v2 receipt names the
deciding rule so the finding can be `CONFIRMED_FROM_RECEIPT_CONTENT`; a v1 receipt does
not, so an ALLOW is reported `POSSIBLE`. It does not check signatures. Leads, not
verdicts.

### Migration plan

| Phase | What | Breaking? |
| --- | --- | --- |
| P0 (this change) | Guard at the chokepoint and loader; audit tool; tests | Startup/issuance refusals listed above |
| P1 | Operators run the audit tool over receipt logs and ledgers; review any `ALLOWED_WITHOUT_ENFORCED_APPROVAL` | No |
| P2 | Any out-of-tree integration that imports `evaluatePolicyRequest` to *authorize* switches to `buildPolicyReceipt*` or calls `checkIssuanceConfiguration` first | Only for such integrations |
| P3 | Add a package `exports` map exposing supported entry points only (UC-004) | **Yes** for deep importers; needs a semver/release note |
| P4 | Make approvals action-bound (UC-005) as an additive, optional scope field enforced when present | No for replay if additive |

## 8. Remaining bypasses and risks

1. **Direct evaluator use (UC-004).** Anyone can import `dist/src/policy-engine/index.mjs`
   (no `exports` map) and treat `ALLOW` as permission. The evaluator returns a
   decision, not a signed receipt, and MNDe's executors accept only receipts, but a
   third-party integration need not. Not fixable without P3.
2. **Approvals are not action-bound (UC-005, OBSERVED).** The verifier binds an
   approval to a tool name and an optional `request_id`, never to parameters; `tool_name:
   "*"` is accepted; an approval is reusable until `expires_at`. Run: an approval
   scoped to `deploy` allowed both `target=staging` and `target=prod` under different
   request ids, and a `request_id`-bound approval allowed the same id with different
   parameters. The Hub path is protected in practice (it accepts only approvals
   scoped to its own action record and keeps the request server-side). The sidecar
   policy-engine path is not, because the caller supplies request and parameters. Pinned
   by `UC-005 (known limit)` tests.
3. **Authority grants without trust anchors (UC-003, OBSERVED in code).**
   `src/policy-engine/index.mjs` accepts request-body authority grants unverified when
   `trustAnchors` is absent ("inert, unchanged legacy behavior"). Production sets
   `rejectLegacyAuthorities`, so it is guarded there; non-production and `mnde decide`
   are not. Same fail-open shape as UC-002, different field.
4. **Receipts do not record that the guard ran.** Old and new receipts of the same shape
   are indistinguishable by content except through the audit tool's heuristic.
5. **The legacy engine's `hold_state` approval is unauthenticated** (README, Limitations).
   Not touched here.
6. **`approval_required` still means "N approvals from any trusted key".** Distinct
   approvers are not required by the engine (the Hub enforces distinct keys itself).

## 9. Evidence

| Claim | Evidence |
| --- | --- |
| New approval-required issuance fails without valid anchors | `test:issuance-guard` "issuance: …" ×8 (53 cases in the suite) |
| No receipt is produced on refusal | `issuance: … throws … and returns NO payload`; CLI cases assert no output file; sidecar cases assert the response and the receipt log contain no `ALLOW` |
| No protected effect executes | the Hub case asserts `executions === 0` and `acquisitions === 0`; additionally the generic executor/proxy remain on the execution hold |
| Policy without approval requirements unaffected | `guard: policy with no approval requirement…`, `sidecar … plain policy…`, `mnde decide … plain policy` |
| File and signed-bundle paths are equivalent | `loader: …` ×7 run every case through both paths |
| No fallback to a looser policy | `loader: every bad anchors file is refused on both paths, none falls back` asserts `policy === undefined` on failure |
| Tests fail when the fix is removed | `npm run check:issuance-guard-mutations`: 11 mutations, 11 caught, including "restore PR #58's check" (11 failing) and "Hub accepts `{}` again" (6 failing) |
| Historical replay intact | `replay: …` ×9; `test:conformance`; `test:receipt-verifier` |
| Full suite | see `docs/evidence/f001/2026-10-16/README.md` for the exact Node 24 commands and results |

What the tests do **not** show: that no *other* caller exists outside this repository,
or that operators have audited their old receipts.
