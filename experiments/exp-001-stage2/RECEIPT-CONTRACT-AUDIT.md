# Receipt-contract audit (Stage 2 adapter)

**Date:** 2026-09-17. Traced against the pinned tree. No network, no token.
Motivation: the earlier positive test used a **policy-engine** receipt; the design
specifies an **executor-bound `mnde.signed-receipt.v2`**. These are not the same
authority. This audit establishes the difference from the real code, then the
correction it justifies.

## 1. What each receipt type signs; what `verifyAnyReceiptObject` verifies

- **Policy-engine receipt (`mnde.pe.receipt.v1`).** `buildPolicyReceipt`
  ([src/policy-engine/receipt.mjs:89](../../src/policy-engine/receipt.mjs))
  signs `canonicalPayloadWithoutSignature(payload)` with an authority **receipt**
  key. The payload includes `canonical_request` (the full request = A⁺),
  `canonical_policy`, and `decision_output`. `verifyPolicyReceipt`
  ([src/policy-engine/receipt.mjs:151](../../src/policy-engine/receipt.mjs))
  replays the decision and checks the signature. `verifyAnyReceiptObject` routes
  policy schemas here ([tools/verify.mjs:45](../../tools/verify.mjs)).
  **This proves an authority signed an authentic request→decision. It is not an
  execution authority and carries no executor binding.**
- **Executor-bound envelope (`mnde.signed-receipt.v2`).** `signReceiptForDelivery`
  in `EXECUTOR_AND_AUTHORITY` mode
  ([src/authority-signing/index.mjs:206](../../src/authority-signing/index.mjs))
  wraps an inner receipt, signs a **custody attestation** (over the inner
  `receipt_hash`, the `executor_envelope_hash`, and the bundle fingerprint) with
  the receipt key, and attaches an **executor envelope** (a root-issued
  credential + an identity signed by the executor key). `verifyAnyReceiptObject`
  → `verifySignedEnvelope` ([tools/verify.mjs:89](../../tools/verify.mjs))
  requires **both** the attestation (`verifyCustodyAttestation`) **and** the inner
  receipt to verify; with `requireExecutor:true` an authority-only envelope is
  rejected (`ERR_EXECUTOR_REQUIRED`,
  [src/authority-signing/index.mjs:379](../../src/authority-signing/index.mjs)).

## 2. Where the trusted authority key comes from (no self-vouching)

- Policy receipts resolve the public key from a **supplied `authorityBundle`
  anchored by an out-of-band `trustedRootFingerprint`**, or the repo-local
  authority — never from public-key bytes carried in the receipt (the receipt
  holds only `authority_id`/`key_id`/`fingerprint`). A wrong root fingerprint is
  rejected (`tests/test_policy_receipt.mjs` "wrong root").
- v2 envelopes verify the attestation against the **bundle's** receipt key and
  the executor credential against the **bundle root**, both under the caller's
  out-of-band `trustedRootFingerprint`
  ([src/custody/executor-credential.mjs:195](../../src/custody/executor-credential.mjs):
  "the bundle is not self-trusted"). **A key carried only inside the receipt
  cannot vouch for itself.**

## 3. Does the verified material bind subject, action, params, execID, full A⁺?

**Yes** — all live inside the inner receipt's signed `canonical_request`
(`principal.id` = subject, `tool.tool_name` = action, `parameters` = every A⁺
param incl. `expected_source_sha`, `target_ref`, `expected_target_sha`,
`request_id` = execution id). The v2 executor identity **additionally** binds the
inner `receipt_hash` and `receipt_schema_version`
([src/authority-signing/index.mjs:420](../../src/authority-signing/index.mjs)),
so the executor attestation cannot be moved to a different inner receipt.

## 4. Authenticity vs. durable consumption (kept as SEPARATE claims)

Verification proves **authenticity (and, for v2, executor binding) only**. It does
**not** prove the execution id was durably claimed/consumed. `verifyPolicyReceipt`
replays with `consumeAuthorityGrants:false` and "**must NEVER touch the durable
nonce store**"
([src/policy-engine/receipt.mjs:172](../../src/policy-engine/receipt.mjs)). No
verifier path establishes single-use. Durable consumption is the sidecar's
`execution_id_store` — the Stage 1 findings F-001 (off by default) and F-002
(rolled back with the store). **A signature is never replay protection.**

## 5. What mints the production marker; what the adapter checks

`verifyDeclaration` ([src/declaration.mjs](src/declaration.mjs)) mints the
private `PRODUCTION_VERIFIED` brand **only** when
`envelope.schema_version === "mnde.signed-receipt.v2"` **and**
`verifyAnyReceiptObject(envelope, { ...trustedConfig, requireExecutor:true })`
returns `verified:true`, `kind:"custody-signed"`,
`state:"executor_and_authority_verified"`. The adapter's `attemptMerge`
([src/adapter.mjs](src/adapter.mjs)) requires `isProductionVerified` before it
builds or dispatches anything. The wiring brand, the test-only fixture, a plain
`{verified:true}` object, and a **policy-only receipt** all fail this and are
refused (`ERR_NOT_PRODUCTION_VERIFIED` / `ERR_NOT_EXECUTOR_BOUND`) with zero
transport calls.

## Correction applied

The production adapter now accepts only a **verified executor-bound
`mnde.signed-receipt.v2`** declaration — the exact-action execution authority the
design requires. A valid policy decision alone does not gain execution authority.
The returned declaration records `freshness.durably_consumed:false` so nothing
downstream mistakes an approval signature for replay protection. No new receipt
format was invented; the Stage 1 replay store was not touched; F-001/F-002 remain
separate, unproven here.

## Offline reproduction of the authority

A genuine v2 executor-bound envelope is produced offline (no sidecar) by
`tests/_real_receipt.mjs` using the repository's own primitives
(`buildAuthorityBundle`, `issueExecutorCredential`, file-backed custody,
`signReceiptForDelivery` in `EXECUTOR_AND_AUTHORITY` mode) and verified by the
real `verifyAnyReceiptObject`. Private keys are written to an OS temp dir outside
the repository and removed immediately after signing.
