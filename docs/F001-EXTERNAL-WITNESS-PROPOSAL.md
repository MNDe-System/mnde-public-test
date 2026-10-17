# F-001: smallest external witness for whole-system rollback — PROPOSAL

**Status: design only. Nothing here is implemented.** It addresses the one case the
executor-local ledger ([F001-ROLLBACK-TRUST-BOUNDARY.md](F001-ROLLBACK-TRUST-BOUNDARY.md)) cannot:
the claim database **and** the executor's evidence directory (including `spent-ledger/`)
restored together to an earlier moment, or the executor host replaced by an empty one.

## What the witness must provide

One fact the executor's administrators cannot rewind: **"namespace N has made at least k spends,
and the k-th had chain head h."** Rollback is then detectable by comparing local state with that
fact. It does not need to hold authority, keys that sign pushes, or any request content.

## Design

1. **Spend chain (local, new).** Each ledger commit also appends `h_n = SHA-256(h_{n-1} || n || grant_id || execution_id)`; `h_0` is fixed per namespace. `n` and `h_n` are stored in the ledger.
2. **Witness append (new step, after the ledger commit, before the write credential and the start record).** The executor writes the entry `(namespace, n, h_n)` to the witness. The witness accepts only `n = last + 1` whose `h_n` chains from its stored head, and refuses any `n <= last` (a rolled-back executor re-using a number gets a conflict). Re-submitting the identical `(n, h_n)` is idempotent, which makes a crash between ledger commit and append recoverable.
3. **Witness head check (new step, first thing in every request, and at readiness).** The executor reads the witness head `(n_w, h_w)`. If local `n < n_w`, or the local chain's hash at `n_w` differs from `h_w`, or the local ledger is absent while `n_w > 0`: **quarantine** (reuse the existing latch) and refuse.
4. **Fail closed.** Witness unreachable, slow, or answering inconsistently: no push. This is the same posture as the claim store.
5. **Recovery.** The witness keeps every entry (`n`, `h_n`, `grant_id`, `execution_id`), so a replaced host can rebuild `spent-ledger/` from the witness instead of starting empty. That also removes the one silent-acceptance case in the current design (a wiped directory looking like a new deployment).

Ordering after the change:

```
ledger check -> witness head check -> ... -> DB claim -> ledger commit -> WITNESS APPEND
 -> write credential -> start record -> push
```

A rollback of only the final spend cannot have pushed, because the push happens after the witness append.

## Smallest realisation: a write-once object store, not a new service

Use an object bucket in a **separate cloud account/administrative domain** with object versioning
and a compliance-mode retention lock (S3 Object Lock or GCS bucket lock):

* The executor's identity may `put` new objects `witness/<namespace>/<n>-<h_n>.json` and `list`/`get`; it has **no** delete, overwrite, or lock-modify permission.
* "Accepts only `n = last + 1`" is enforced by a conditional create (S3 `If-None-Match: *` / GCS `ifGenerationMatch=0`) on the key for `n`, plus a client check that `n-1` exists with the expected hash.
* The head is the highest `n` in a listing.
* The bucket administrator is the witness operator and must not be the executor-host or database administrator.

Estimated size: ~250 lines in a new `src/freshness/witness.mjs` using plain HTTPS (no SDK, matching the repo's no-dependency stance for `credential-provider.mjs`), one configuration file read like `MNDE_CLAIM_CONFIG`, and an extension of the closure harness (rollback-of-both case). Roughly 3–5 engineering days including tests; one bucket and two IAM identities to provision.

## Options considered

| Option | Detects whole-system rollback | Cost / complexity | Downside | Verdict |
| --- | --- | --- | --- | --- |
| **Object-lock bucket in a separate account (proposed)** | Yes | Lowest: no new service, no new protocol server | Depends on a cloud provider's retention semantics; availability dependency | **Recommended** |
| Small witness HTTP service (monotonic counter + signed receipts) | Yes | A service to build, run, secure and make highly available | Reinvents what object-lock gives for free | Only if no cloud account is acceptable |
| Public transparency log (Sigstore/Rekor-style) | Yes | Heavy; external dependency | Publishes spend metadata; availability and privacy | Rejected for v1 |
| Second database with a different administrator | Partly | Medium | Needs its own consistency/failover story; same-class problem as the first database | Rejected |
| TPM / HSM monotonic counter on the executor host | Only if the counter survives a restore | Hardware-specific | A VM snapshot restore may roll back a virtual TPM; one device, no cross-host recovery | Rejected as the primary mechanism |

## Trust boundary after the change

Three separate administrators must not collude: database, executor host, witness. Whole-system
rollback is detected unless the witness domain is also rolled back or compromised. If all three
are compromised there is no authority record left and MNDe offers only what the remote's
`--force-with-lease` provides.

## Risks and open questions

* **Availability:** a witness outage halts all pushes. Needs an operator runbook and an alert.
* **Provider semantics:** compliance-mode retention must be verified against the chosen provider, including whether any support or break-glass path can shorten retention.
* **Clock:** none of the design depends on wall-clock time; do not add it.
* **Cost of the extra round trip** is one HTTPS write per push; acceptable for a human-approved effect.
* **Decision needed from the operator:** which provider and which separate administrative domain.
