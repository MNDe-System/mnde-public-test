# Signed execution evidence v2

`mnde.git-push-execution-evidence.v2` is **additive** to v1 and does not change how v1 evidence verifies.
The offline verifier (`scripts/verify-git-push-evidence.mjs`, `verifyExecutionEvidence`) accepts both.

## What v2 adds

| Field | Meaning | Not |
| --- | --- | --- |
| `execution_start` `{ record_sha256, started_at }` | SHA-256 of the exact bytes of the durable `git-push-<execution_id>.started.json` the executor wrote and fsynced before the push, and its timestamp. `null` when nothing started. | Not proof the push happened. |
| `push_credential` `{ kind, access, scope, app_id, installation_id, expires_at }` | The credential last used: kind (`github-app`, `https-token-file`, `ssh-key-file`, `none`), `read`/`write`/`static`, repository scope, and for a GitHub App its App id and installation id. | Never a token, key, JWT, header or fingerprint. |
| `witness` `{ witness_id, key_id, n, entry_digest }` | The spend-witness entry that recorded this authorization as consumed, or `null` when no witness was configured. | Not a verification of the witness: check the witness's own signed `lookup` against the pinned witness key. |

## Signing and compatibility

* v1 signs `canonical(body)`. v2 signs `"mnde.git-push-execution-evidence.v2\n" + canonical(body)`, so a v2 body can never verify as v1, nor the reverse. A body that claims one version with the other's fields is refused (exact key sets).
* Unknown versions and unknown fields are refused. Nothing is "ignored if not understood".
* The issuer is anchored the same way as v1: the executor credential is root-signed against an out-of-band pinned root fingerprint; a key carried inside the evidence is never trusted on its own.
* Coherence checks run in the builder **and** the verifier: `effect_attempted` requires an `execution_start`; `EXECUTED` requires the observed SHA to equal the approved SHA; `app_id` and `installation_id` appear together; malformed timestamps, digests or sequence numbers are refused.

## What the offline verifier does and does not prove

It proves the named executor, under the pinned root, signed exactly these assertions. It does **not** prove the remote ref moved (re-read the remote), that the start file still exists (compare its digest), or that the witness entry exists (query the witness). Those are separate observations; `INDETERMINATE` stays `INDETERMINATE` until someone reconciles it.

Tests: `npm run test:git-push-evidence-v2` (10 cases) and the real-infrastructure evidence in `docs/evidence/f001/`.
