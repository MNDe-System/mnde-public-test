# Approval workflow: source audit and trust-boundary map

Phase 1 of the approval-and-execution milestone. Read-only: this document
changes no behaviour. Companion to [`APPROVAL-KEY-CUSTODY.md`](APPROVAL-KEY-CUSTODY.md),
which is the Phase 2 design and needs a human decision before any signing code
is written.

Starting point: branch `mnde/sleepy-brown-2kbsuy` (PR #57, `13bbb80`, plus
later commits to this document). Nothing here was run against a live Hub,
production executor, PostgreSQL or GitHub. One finding (F1) was reproduced with
a throwaway in-process test built from `tests/test_hub.mjs`; the script was not
kept, and the steps to repeat it are in F1.

Method: every file in the brief's audit list was read, plus
`src/policy-engine/index.mjs` and `receipt.mjs` (where approvals are counted and
replayed), `src/custody/{bundle,lifecycle}.mjs`, `tools/verify.mjs`, and
`docs/PRODUCTION-TRUST-BOUNDARY.md`. Claims marked **derived** come from reading
code, not from a test that proves them.

## 1. Who may do what today

| Operation | Where it happens | Evidence |
| --- | --- | --- |
| **Create** an approval artifact | Nowhere in shipped code. Tests build them by hand. | `signApproval` callers: `tests/test_hub.mjs`, `tests/test_authenticated_approvals.mjs`, `tests/test_sidecar_pe_mode.mjs` only. No file under `scripts/`, `bin/` or `src/` calls it. |
| **Sign** an approval | `signApproval()`, `src/policy-engine/authenticated-approvals.mjs:110`. The custody provider also has a `signApproval` slot (`src/custody/index.mjs:93`), used by custody tests; the external-signer provider reports it `notConfigured` (`external-signer.mjs:131`). | |
| **Generate** an approval key or the approval trust-anchor file | Nowhere. `prepare-git-push-trust.mjs` and `init-production-authority.mjs` never mention approval keys. The Hub nonetheless refuses to start without `MNDE_PE_APPROVAL_TRUST_ANCHORS` (`src/hub/service.mjs`, config loop). | grep for `approvalKeys` / `approval_keys` in `scripts/`, `bin/`, `src/` (outside custody) |
| **Verify** an approval | `verifyApproval()` / `evaluateApprovals()` (`authenticated-approvals.mjs`), called from the policy engine (`src/policy-engine/index.mjs:417`). It runs (a) when the Hub decides, via `buildPolicyReceiptPayload`; (b) again when any verifier replays a receipt (`receipt.mjs:224`, `now` = the original `evaluated_at`); (c) in the executor, whose `verificationContext` carries the approval anchors (`src/hub/service.mjs`, `createGitPushExecutor({... verificationContext })`). | |
| **Sign execution authority** | `authorization.decide()` in `src/hub/authorization.mjs`, with the Hub's receipt-signing key plus the executor signer (`EXECUTOR_AND_AUTHORITY`). | The Hub process holds both keys. |
| **Create / consume a claim** | The executor, via `src/freshness/claim.mjs` and `postgres_claim.mjs`. | `docs/PRODUCTION-TRUST-BOUNDARY.md` |
| **Request GitHub credentials** | Only `credential-provider.mjs`, imported only by the typed executor. | `tests/test_git_push_reachability.mjs` guard 7a, passing |
| **Execute the external operation** | Only `transport.mjs`, imported only by the executor. | guard 1a, passing |
| **Sign outcome evidence** | The executor's signer, `src/effects/git-push/evidence.mjs`. | |

## 2. The question the brief asks first: is the action already bound?

**The execution is; the approval is not.** Two separate things:

- *The execution authority is exact-action bound.* The signed receipt embeds the
  full `canonical_request` (repository, remote URL, target ref, expected old SHA,
  source commit) and the executor refuses unless all six values equal the signed
  parameters. The Hub also never lets an approval change the request: `approve`
  re-decides the **stored** record (`record.request`), not anything the client
  sends. **Derived** from `src/hub/service.mjs` and the executor's parameter check.
- *The human approval is bound only to a tool name and a request id.*
  `scopeMatches()` compares `scope.tool_name` and, if present, `scope.request_id`.
  A missing `request_id` or `tool_name: "*"` is a wildcard at the engine level.
  The Hub closes the first gap for its own route (it requires
  `scope.request_id === record.id`, `service.mjs`), and a request id is unique per
  Hub, so cross-request replay inside one Hub is already refused. Nothing in the
  signature covers what the human was shown.

**Honest sizing.** I did not find an exploit that this gap enables today. It
matters for three reasons, in decreasing strength: (1) the human's signature
proves "I approved id X", not "I approved this push", which weakens
non-repudiation and any audit of what was authorized; (2) the request id is
chosen by the agent, so an approval that leaks or is replayed to a second Hub or
a restored data directory with the same anchors would authorize whatever that Hub
holds under that id; (3) a client that signs a digest of what it displayed gives
a clean detection point for a display/server mismatch. A digest in the approval
is defense in depth, cheap, and worth doing. It is not a fix for a demonstrated
bypass, and the milestone should not describe it as one.

**Where the digest must be checked.** In the engine's `verifyApproval`, not in a
new Hub-only check, because receipts embed the approvals and the request, so
every offline verifier re-runs the same check. A Hub-only check would leave the
property unverifiable after the fact.

**Strong property worth testing (derived, not tested):** because replay
re-evaluates the embedded request, policy and approvals (`receipt.mjs:195-240`),
a party holding the Hub's receipt-signing key still cannot produce a receipt that
verifies as ALLOW for an `approval_required` rule without approvals signed by a
trusted approval key. If that holds, the approval key, not the Hub, is the root
of "a human said yes". Add as test D4 in the milestone before relying on it.

## 3. Findings

Severity is for the approval workflow specifically.

### F1. High: approving after the request expires degrades the Hub and misreports the outcome

Reproduced in-process. Hub requests expire five minutes after creation
(`service.mjs`, `expires_at`). When an approval arrives after that, `decide()`
throws `ERR_HUB_EXPIRED` (`src/hub/authorization.mjs`), which lands in the
`catch` of `run()`. That catch sets `broken = true`, locks storage, and returns
`phase: "INDETERMINATE"`.

Observed (clock advanced six minutes during the approve call):

```
POST /v1/actions/<id>/approve  -> 200 {"decision":"REFUSE","phase":"INDETERMINATE","retryPermitted":false}
GET  /v1/status                -> {"state":"DEGRADED", ... "receiptSigning":"unavailable"}
POST /v1/unlock                -> 503 ERR_HUB_NOT_READY
stored record phase            -> "REVIEW"
```

Two faults: nothing executed, yet the answer says INDETERMINATE, which the
workflow defines as "an external effect may have happened"; and one slow human
latches the whole Hub until it is restarted. The record on disk still says
REVIEW, so it also never reaches EXPIRED. No existing test covers an expired
review. The fix is small (check expiry before `run`, persist `EXPIRED`, do not
latch `broken` for a pre-execution refusal), but it is Hub authority code, so it
should be its own reviewed PR. Repeat: create a REVIEW request, replace
`Date.now` with `() => real() + 360000` around the approve call.

### F2. High: there is no way to create an approval key, an approval, or the anchors file

See section 1. A new operator cannot run the workflow the Hub's own startup
checks assume, because nothing generates the keys the Hub requires.

### F3. Medium: approval trust anchors come from an unsigned file, not the root-signed bundle

`MNDE_PE_APPROVAL_TRUST_ANCHORS` is a plain JSON file
(`{ approval_keys: [{ key_id, public_key, valid_from?, valid_until? }] }`).
The root-signed authority bundle also has a `keys.approval` list with validity
windows, cross-role uniqueness (`bundle.mjs`, "CROSS_ROLE_KEY_*") and a tested
rotate/retire/revoke lifecycle (`src/custody/lifecycle.mjs`). The two are not
connected, so the better-protected list is unused for approvals. Whoever can
write the anchors file as the Hub's OS user can add an approver; the Hub detects
a change after startup by hashing the file (`authorization.mjs`, `hashes`) and
goes DEGRADED, but does not stop a change made before startup.

Consequence for revocation: removing a key from the file makes past receipts
unverifiable (`APPROVAL_UNTRUSTED_ISSUER` on replay), so revocation must set
`valid_until`, never delete. See the custody document.

### F4. Medium: one `operator` role covers everything

`MNDE_HUB_OPERATORS` is a set of bearer caller ids. A member may lock, unlock,
read all records, read events, refuse, and submit approvals. There is no viewer,
approver or administrator split. A submitted approval still needs a valid
signature, so the bearer is not approval authority (good). But **refusal needs no
signature and the Hub does not record who refused, locked or unlocked**: the
record has no actor field and the event log has no identity. The acceptance
tests for viewer/approver separation (C1, C2) cannot pass until roles exist.

### F5. Medium: the review queue cannot be read

`GET /v1/receipts` returns `view(record)`: id, decision, phase, outcome. No
request parameters. An operator can reach them only by opening each record and
parsing the embedded signed receipt. A CLI needs a small, read-only, server-owned
projection of a REVIEW record (spec section 9.2).

### F6. Low to medium: approval counting is not by distinct approver in the engine

`evaluateApprovals` counts valid approvals. The Hub rejects duplicate `key_id`s
(`service.mjs`), so one key cannot meet a threshold of two. One operator holding
two enrolled keys could, and the engine path used by `mnde decide` has no
distinct-key check at all. Matters only for thresholds above one, which the
solo-developer target does not use. Record it now so a later multi-approver
policy does not inherit it.

### F7. Info: key changes need a restart, and approval keys share a lifecycle with receipt keys

Because the Hub hashes the anchors file, any edit makes it DEGRADED until
restarted (`docs/MNDE-HUB.md` already says to restart after changes). That is
fail-closed and acceptable, but it makes "revocation takes effect" a restart
event, and enrollment cannot be a no-downtime operation. Say so in operator
documentation.

### F8. Info: the Hub is a single-writer, single-instance design

State is one JSON file per action, serialized by an in-memory `busy` flag
(`service.mjs`); `MNDE-HUB.md` says "exactly one Hub per data directory". Nothing
enforces that. Concurrent approval tests (C9) are meaningful only inside one
process; a second instance on the same directory is outside the supported model
and should stay documented as such rather than "solved" with an in-memory lock.

## 4. Brief versus repository

| Brief requirement | Status | Work |
| --- | --- | --- |
| Operator approval CLI | Absent | New |
| Operator key enrollment / rotate / revoke | Absent; root-signed lifecycle library exists | Reuse `src/custody/lifecycle.mjs` |
| Exact-action approval format | Absent; execution already exact-bound | Extend `verifyApproval` compatibly |
| Pending-request retrieval | Absent | Read-only projection (F5) |
| Review / refuse transitions | Present (`REVIEW`, `REFUSED`, `COMPLETED`); no `EXPIRED` | Fix F1 |
| Viewer / approver / admin roles | Absent | F4 |
| Doctor integration | PR #57 doctor covers the executor only | Add approval checks after custody lands |
| Single-use, durable start, evidence, indeterminate semantics | Present and tested | None; do not touch |
| Isolated live acceptance | Not run | Needs a real test App, repo and PostgreSQL |

## 5. Decisions needed before any signing code

These change trust anchors or secret custody, so the brief says to stop for a
human:

1. **Anchor source** (F3): derive approval anchors from the root-signed bundle
   (recommended) or keep a hand-managed file.
2. **Signature domain separation**: prefix the signed bytes (strict, breaks older
   verifiers by failing closed) or add a signed `approval_schema` field and keep
   the signing input (compatible). Recommendation and trade-off are in the
   custody document.
3. **Key storage**: passphrase-encrypted file, with the stated limits on a
   compromised same-user host.
4. **Approval lifetime**: 120 seconds is proposed; the request's own five minutes
   caps it. Decide whether five minutes is long enough for a human (F1).
5. **Where the operator key may live relative to the agent**: same OS user
   (weakest), a separate OS user or container for the agent, or a phone/hardware
   signer (later).

## 6. Adjusted delivery order

The brief's PR A-F stands, with one insertion and one dependency:

- **PR 0 (new): fix F1.** Hub-only, small, independent of everything else, and
  needed before a human approval flow is usable. Needs Hub-owner review.
- **PR A:** this audit and the custody design. Docs only.
- **PR B** is blocked on decisions 1-3. **PR C** (digest verification in the
  engine plus the pending projection) can start after decision 2.
- Roles (F4) belong with PR C, because approval authority and role checks change
  the same Hub routes.

Nothing in PR A-F should add a Git execution path; the static guards in
`tests/test_git_push_reachability.mjs` and case K of `tests/test_git_push_cli.mjs`
already fail if a file other than the reviewed callers constructs the executor.
