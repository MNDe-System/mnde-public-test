# MNDe EXP-001 — Stage 1 Preconditions & Limitations

## Pinned system under test

| | |
|---|---|
| MNDe commit | `9295635b6d92cc448b9fefa8524d1a21e8f0e4d6` |
| Branch | `feat/sidecar-graceful-shutdown` |
| Working tree | clean except `experiments/` (this package) |
| Node | v24.14.1 (repo requires `>=24`) |
| Platform | win32 (harness is OS-agnostic; sidecar boot is via MNDe's own test harness) |

## Signing posture per test group

- **A / C / D** run against the sidecar in the **legacy HMAC** signing posture
  (the default of MNDe's own `executor/sidecar-harness.mjs`: `MNDE_PROFILE=local`,
  `MNDE_DECISION_ENGINE=legacy`, `MNDE_RECEIPT_HMAC_SECRET` set by the harness).
  Receipts are real and offline-verifiable (`ecs.receipt.v2`).
- **Crypto self-checks** run under **custody** signing
  (`MNDE_RECEIPT_SIGNING_MODE=custody`, local-demo provider) with real Ed25519
  keys and offline attestation verification (`mnde.signed-receipt.v1`).

## Freshness lever

`MNDE_EXEC_ID_CACHE` selects the durable execution-id dedup directory. **Unset by
default** → durable dedup off (in-process only). Conjunct D exercises both
postures explicitly and records which applied to each test.

## Known limitations of Stage 1

1. **No external effect is tested.** Every "action" gates a local `run()`; no
   GitHub, network, or filesystem mutation is performed or verified. Claims are
   bounded to declared-intent binding.
2. **Legacy vs custody split.** A/C/D use legacy HMAC receipts; the crypto
   substrate is proven separately under custody. A full custody-mode run of A/C/D
   (booting the sidecar in custody with an exported bundle and executor verify
   env) is a reasonable Stage-1b addition; it was not required to establish the
   Stage-1 conjuncts and is not included here.
3. **Rollback is simulated at the store layer.** F-002 reverts MNDe's dedup
   directory to a pre-consumption state directly (deleting the reservation file),
   which is the faithful analogue of a backup/snapshot restore. It does not model
   a specific backup product's semantics.
4. **Custody keys are ephemeral.** The crypto self-checks generate in-process
   authority keys per run; they prove verification logic, not production key
   custody or the published-bundle trust chain end to end.
5. **Single machine.** Concurrency/race behavior of the durable store across
   processes is covered by MNDe's own `test:execution-id-dedup` / `test:nonce-replay`;
   Stage 1 relies on those for the O_EXCL atomicity property rather than
   re-deriving it.

## Clean-room reproduction

A competent outsider should be able to:

1. Clone the repo, check out `9295635b`, `npm ci` (or ensure `node_modules` is
   present), Node ≥ 24.
2. Run `node experiments/exp-001/run-all.mjs`.
3. Compare `results.json` totals (`27 PASS / 2 FAIL / 1 INCONCLUSIVE`) and the
   per-test reason codes in `evidence/*.json`.

No GitHub account, token, network, or original signing key is required. The run
generates its own ephemeral custody keys and its own execution ids. Absolute
paths and machine-specific state are confined to per-run OS temp directories.
