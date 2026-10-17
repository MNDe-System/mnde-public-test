# Spend witness: deployment, operation and trust limits

Protocol and code: `src/freshness/spend_witness.mjs` (client), `deployment/witness/witness-server.mjs` (reference server).
Why it exists: `F001-ROLLBACK-TRUST-BOUNDARY.md` and `F001-EXTERNAL-WITNESS-PROPOSAL.md`. Evidence of effect: closure harness
scenarios `W0`, `W0c`, `W1`-`W8`, `S1`, and `npm run test:spend-witness`, `test:git-push-spend-witness`.

## What it guarantees, exactly

Before any GitHub-changing step the executor asks the witness to **consume** the authorization. The witness appends one
hash-chained entry per authorization, fsynced before it answers `CONSUMED`; a second consume of the same `grant_id` **or**
`execution_id` in the same namespace is a signed `CONFLICT`. Consequently restoring the PostgreSQL database *and* the
executor's spent-ledger *and* evidence directory cannot make a consumed authorization executable again, because the witness
keeps its own state outside that rollback domain. The executor's answer to a conflict is: refuse, send nothing, quarantine.

It does **not** make the remote effect exactly-once, and it does not protect against a rollback or compromise of the witness
itself (below).

## Requirements on the deployment

| Requirement | Why |
| --- | --- |
| The witness runs under an administrative domain the executor operator and the database operator do not control (a different machine or account, different credentials, different backups) | A witness restored together with the executor is just another file in the same rollback domain. This repository's harness runs it on one machine to prove the mechanism; that is **not** independence. |
| The executor holds only a bearer token (`tokenFile`, 0600, owned by the executor user) bound by the server to one `(executor_id, namespace)` | Identity substitution is refused (tested). |
| The server stores token **hashes** (`tokens.json`) and its Ed25519 signing key and TLS key are readable only by the witness user | A copy of the server's files cannot consume or forge. |
| The executor pins the witness public key(s) and the TLS CA in its own root-owned config (`MNDE_WITNESS_CONFIG`) | A key carried inside a response is never trusted. |
| The witness data directory is on storage with real flush semantics and is backed up **only** to storage the executor and database operators cannot write | Backups are a rollback surface for the witness. |
| `MNDE_WITNESS_REQUIRED=true` is set on every executor | Without it, an executor with no witness configuration silently runs with database + ledger protection only (which does not stop whole-system rollback). Configured means required; a broken configuration refuses every push. |

## Configuration

Executor (`MNDE_WITNESS_CONFIG`, JSON, exact keys): `url` (plain `https://host[:port]`), `witness_id`, `caFile`, `tokenFile`,
`witness_keys: [{ key_id, public_key }]` (1-4), optional `timeoutMs`.
Witness (`witness-server.mjs <config>`, exact keys): `host`, `port`, `data_dir`, `witness_id`, `key_id`, `key_file`,
`tls_cert_file`, `tls_key_file`, `tokens_file`. `tokens.json`: `{ "<sha256 hex of token>": { "executor_id", "namespace" } }`.

## Failure behaviour (all fail closed)

| Situation | Executor result | Authority |
| --- | --- | --- |
| Witness unreachable, wrong CA, wrong token, unpinned or invalid signature on the **preflight** | `ERR_GIT_PUSH_WITNESS_UNAVAILABLE`, before the claim | not spent; retry when fixed |
| Preflight fine, the **consume** answer is lost, late, forged or unverifiable | `ERR_GIT_PUSH_WITNESS_OUTCOME_UNKNOWN`, nothing sent | spent in the database and ledger; the witness may or may not have recorded it; never retried; reconcile with `lookup` |
| Witness says `CONFLICT` although the database and ledger said fresh | `ERR_GIT_PUSH_WITNESS_ALREADY_CONSUMED`, executor quarantined | spent; the executor's own state was rolled back |
| Witness log fails verification at startup (edited, missing or duplicated entry, torn line) | witness refuses to start | operator investigation; the server never repairs a log |

## Operations

* **Start / stop.** `SIGTERM` closes cleanly. After a crash the lock file names a dead process and is taken over automatically; a live process's lock is never touched. The whole log is re-verified on every start.
* **Reconciling an unknown outcome.** Use `lookup` with the executor's token: `FOUND` (with the entry digest) means the authorization is consumed and must never be reused; `NOT_FOUND` means the witness has no record, and the authority is still spent locally, so issue a **new** authorization; do not clear the executor's ledger or database.
* **Signing key rotation.** (1) Generate the new Ed25519 key. (2) Add it to every executor's `witness_keys` (both keys pinned) and deploy. (3) Restart the witness with the new `key_id` and key. (4) After all in-flight work, remove the old key from the executor configs. A witness signing with an unpinned key is refused at the preflight, before anything is spent (`W5`).
* **Token rotation.** Replace the hash in `tokens.json` and the executor's `tokenFile`; restart the witness.
* **Replacing the executor host.** Nothing needs to be copied for correctness: the witness already knows every spend. (A future version could rebuild the executor ledger from the witness; today a new host starts with an empty ledger and the witness is the arbiter.)
* **Quarantine.** `QUARANTINE.json` in the executor's `spent-ledger/` is cleared only by an operator who has found out who restored what and when, and reconciled every execution since the restore point against the remotes.

## Trust limits (read before claiming rollback resistance)

1. **Witness rollback.** If the witness operator, or anyone with write access to its disk or backups, restores the witness to an older state, the witness forgets spends, and a whole-system rollback of the executor *plus* that witness revives authority. Nothing in this implementation detects that: an executor that has also been rolled back remembers nothing to compare against.
2. **Compromise of every independent domain** (database operator, executor host, witness operator colluding or all breached) leaves no authority record. MNDe then offers only what the remote's `--force-with-lease` gives (a replay is refused while the ref has moved past the authorized pre-state).
3. **Witness availability** is a hard dependency: an outage stops pushes (by design).
4. A witness co-located with the executor, or administered by the same person, defeats the purpose.

### Design for limit 1 (not implemented; needs a decision)

Make the witness itself rollback-evident by **anchoring its head outside its own rollback domain** and requiring agreement:
the witness publishes each new signed head `(n, head_hash)` to a second, independently administered store, and the executor's
preflight requires the two heads to agree (`n` equal, hashes equal). Minimal forms, cheapest first:
(a) a second witness run by a different party using the same protocol, with the executor requiring **both** to CONSUME (2-of-2; the repository's `src/witness` threshold-attestation code is the format to reuse);
(b) an append-only, retention-locked object store receiving the head after every consume.
A restore of one domain is then visible as a head disagreement, and both must be restored to the same older moment to hide it,
which moves the required collusion from "one operator" to "two operators". Choose (a) or (b), name the second administrative
domain, and approve a branch; nothing here should be called rollback-proof until an end-to-end restoration test of the pair passes.
