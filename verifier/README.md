# MNDe Counterparty Receipt Verifier

A single, self-contained HTML file for the **receipt consumer** — an auditor,
controller, or security reviewer who receives an MNDe receipt and needs to
confirm it is genuine **without trusting the operator and without installing
anything**.

## Use it

1. Send the counterparty two things: `mnde-receipt-verifier.html` and the receipt
   `.json`.
2. They double-click the HTML (any current Chrome, Edge, Safari, or Firefox — it
   runs fully offline; no server, no network, no MNDe repo).
3. They drop or paste the receipt. The page shows a verdict and a plain-English
   summary of what the receipt attests.

## Verdicts

- **VERIFIED** — a signing key vouched for by the trusted root produced this
  receipt, and it attests the exact action, request, and policy shown. The
  operator cannot forge it without the authority's private key.
- **TAMPERED / INVALID** — altered after signing, or its contents don't match
  what was signed.
- **UNKNOWN AUTHORITY** — the signature may be valid, but the issuing authority
  is not one this file trusts. Confirm the authority out of band first.
- **NOT A RECEIPT** — the input isn't a well-formed `ecs.receipt.v2` receipt.

## What it checks (and what it deliberately doesn't)

Checks, all offline: root trust (manifest signed by the pinned root), authority
match, signing-key validity + fingerprint, **Ed25519 signature** over the
canonical receipt, request binding (`request_hash`), and policy binding
(`policy_hash`). These answer the counterparty's question: *did the trusted
authority attest this exact action?*

It does **not** re-run the decision engine (decision-hash / replay determinism).
Those deeper, operator-grade checks are in the full MNDe reviewer kit
(`npm run verify-receipt`). The Ed25519 signature is the anti-forgery guarantee;
replay proves the authority *computed* correctly, which is a different question.

The algorithm is a faithful browser port of `tools/verify-receipt.mjs`,
`shared/json.ts`, `shared/policy-trust.ts`, and `shared/authority-manifest.mjs`.
It was cross-checked against the repo's example receipts: `valid-receipt.json`
verifies, and decision-tamper / request-tamper / wrong-authority variants are
rejected.

## Trust root (IMPORTANT)

The trusted **root public key** and **authority manifest** are embedded in the
two `<script type="application/json">` blocks at the top of the HTML. The tool
trusts exactly that root — the same pinned-root model as the MNDe security model.

The version in this repo embeds the **demo** authority (`mnde-public-test-demo`)
so it works out of the box against committed example receipts. **A stable,
MNDe-published production root does not exist yet** (see the repo README's pilot
note). When it ships, regenerate this file by replacing those two blocks with the
published bundle, and have counterparties confirm the root fingerprint shown in
the UI against an out-of-band published value.
