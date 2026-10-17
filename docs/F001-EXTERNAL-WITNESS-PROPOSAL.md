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

---

## Addendum (2026-10-17): evaluation of the three required options and fit with existing MNDe code

**Still design only. Nothing is deployed, nothing in the executor, PostgreSQL or Hub was changed for this.**
Implementation needs explicit operator approval and would be developed on a separate branch with
an end-to-end whole-system-restoration test; until that test passes, F-001 requirement F is **not met**
(the harness scenario `W0` reproduces the gap and must flip to REFUSED).

### Required properties and where each is satisfied

| # | Required property | How the design meets it |
| --- | --- | --- |
| 1 | Bind the claim to authorization id and execution parameters | witness entry carries `grant_id`, `execution_id`, `aplus_digest` (digest of the whole authenticated action), `receipt_hash`, `namespace` |
| 2 | Record consumption at an independent witness | append `(n, h_n)` after the ledger commit |
| 3 | Durable acknowledgment before external execution | the witness append is a hard step before the write credential and the start record; no acknowledgment, no push |
| 4 | Acknowledgment bound to the exact claim | acknowledgment = witness-signed (or object-store-versioned) record over `(namespace, n, h_n, entry digest)`; the executor verifies it before proceeding and stores it in the start record |
| 5 | Reject reused or conflicting identifiers | conditional create on `n`; a duplicate `grant_id`/`execution_id` anywhere in the witness history is refused |
| 6 | Reject stale or inconsistent state | head check at every request: local `n < n_w`, or hash mismatch at `n_w`, or an absent local ledger while `n_w > 0` → quarantine |
| 7 | Fail closed when the witness is unavailable | same posture as the claim store |
| 8 | Executor cannot delete or rewrite history | executor identity has create/list/get only; retention lock on the store |
| 9 | Restoring the executor does not reset witness knowledge | knowledge lives outside the executor's rollback domain; a replaced host rebuilds its ledger from the witness |

A signature alone does not provide 5, 6 or 9; the conditional create and the head comparison do.

### Options compared

| Criterion | **A.** Separate witness service, independently administered machine | **B.** Remote append-only durable ledger (object store with retention lock) | **C.** Hardware-backed monotonic state (TPM NV counter / HSM) |
| --- | --- | --- | --- |
| Security | Strong if the machine and its admin are separate; you own its integrity and patching | Strong; retention semantics enforced by the provider, not by our code | Strong against software rollback of a *physical* device; weak if the host is a VM/snapshot-restorable |
| Hardware | One more always-on machine | None (a cloud bucket) | A Pi has no TPM; needs a TPM/secure-element module and driver, per host |
| Cost | Machine + operations | Cents per month | Module cost + integration |
| Implementation complexity | Highest: protocol server, auth, storage, HA | Lowest: ~250 lines HTTPS client, no server | Medium–high: device-specific, no portable API |
| Availability | Single machine unless replicated | Provider SLA | Local, but one device is a single point of failure; no cross-host recovery |
| Recovery | Needs its own backups, which are themselves a rollback surface | Versioned and locked; host rebuild reads history | A lost device loses the counter; reset is the very attack |
| Cryptographic binding | Witness signs entries (can reuse the existing Ed25519 attestation shape) | Object key encodes `(n, h_n)`; entry body binds the claim; optional signature | Counter value is attested by the device, not bound to claim content without extra protocol |
| Failure behavior | Fail closed on unreachable | Fail closed on unreachable | Fail closed on device error |
| Raspberry Pi Hub compatibility | Yes (client only) | Yes (HTTPS client only) | Poor: needs added hardware |
| Offline operation | None | None | Works offline |
| Backup restoration | Witness backup restore re-opens the problem | Cannot be restored over: retention lock | Device state is not captured by file/VM backups, if physical |
| Administrator compromise | Witness admin can rewrite unless state is itself locked | Bucket admin in a **separate** account is the only trust anchor; compliance-mode retention limits even them | Whoever has physical access to the device |

**Selection: B**, the smallest design that meets properties 1–9 without new infrastructure. A is B plus
an operations burden with no extra security unless its storage is also retention-locked (at which point it
is B). C is the right answer only for an air-gapped deployment that needs offline operation; it does not
survive a VM snapshot restore on a virtualised executor and cannot rebuild a replaced host.
Blockchain, consensus clusters and distributed infrastructure were not considered necessary: a single
write-once log in one separate administrative domain meets the stated property, and a cluster would only
improve availability against the witness, which here is allowed to fail closed.

### Reuse of existing MNDe code (inspected, not modified)

`src/witness/witness.mjs`, `src/authority-checkpoint/checkpoint.mjs` and `src/equivocation/equivocation.mjs`
implement hash-chained, Ed25519-signed checkpoints with `previous_checkpoint_digest`, threshold witness
attestations and equivocation proofs for **authority-bundle history**, offline. They are the right *format
and digest convention* to reuse (canonical JSON + `sha256`, strict field sets, domain-separated roles), but
they are not a consumption witness: they have no append-time conflict check, no network client, and no
fail-closed availability rule. The spend chain should use the same canonical-JSON/digest helpers and a new
schema string (`mnde.spend-witness.entry.v1`) with its own signing domain so a checkpoint can never be
mistaken for a spend entry.

### Rollout plan (needs approval at each gate)

1. **Decision:** provider and the separate administrative domain (operator).
2. **Branch** `f001/spend-witness`: `src/freshness/witness.mjs`, ledger chain fields, executor steps, no change to deployed systems.
3. **Isolated tests:** in-process object-store double with conditional-create semantics; fault cases for unreachable, slow, replayed, rolled-back and forked witness; `closure.mjs` scenario `W0` flipped to expect REFUSED, plus an end-to-end restore of database + ledger + evidence directory.
4. **Staging:** witness bucket and IAM with a throwaway namespace; repeat W0 against the real store.
5. **Production enablement** behind an explicit configuration, with an operator runbook for witness outage and for rebuilding a host from the witness.
