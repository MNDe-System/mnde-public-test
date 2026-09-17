# Recorded gap — signing the observed outcome (Stage 2)

**Date:** 2026-09-17. Recorded per the build spec: *"If that binding cannot carry
the proposed observation reference, record the gap in the design rather than
silently adding unsigned claims to a signed receipt."*

## The gap

The build spec says to **provisionally reuse the existing `mnde.signed-receipt.v2`
executor binding** for the adapter's outcome and **not invent a new signed
outcome format** in this step. The v2 envelope
(`src/authority-signing/index.mjs`) binds:

- an inner receipt (by `receipt_hash`),
- an executor identity/credential,
- the authority attestation.

It has **no field for an external-observation reference** — the observed PR head,
merged state, base SHA, or resulting merge commit that Ledger 3 records. There is
therefore no existing signed slot that ties a *signed outcome* to *observed
external state*.

## What the offline build did (and did not) do

- The adapter (Unit 3) returns an **unsigned attempt record**; the evidence
  record (Unit 2) is **unsigned**. Nothing here forges or wraps a signed receipt.
- We did **not** add an observation reference into a v2 envelope, because that
  would mean attaching unsigned/foreign claims to a signed structure. Per the
  spec, the gap is recorded here instead.

## Options for the live step (design decision, not taken now)

1. Keep the outcome record unsigned and rely on independent provider/observer
   provenance (Ledger 2 provider request id + Ledger 3 independent read) for
   trust — simplest, but the outcome is not itself signed.
2. Extend the signed-receipt schema (a new `mnde.signed-execution-outcome.vN`)
   that binds `{ A⁺-hash, provider_request_id, observed_head, observed_base,
   merge_commit }` under the executor credential — this is *inventing a new
   format*, explicitly out of scope for this step and requiring its own design +
   review.
3. Bind only the observation *digest* into an existing signed structure if a
   forward-compatible extension point exists — to be investigated against the v2
   schema before use.

**No option is chosen here.** This is deferred to the live-step design, alongside
the repo/token provisioning and credential-boundary freeze.
