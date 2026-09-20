# MNDe EXP-001 — Spec (Stage 1 scope)

The full formal model is in [`FORMAL-MODEL.md`](FORMAL-MODEL.md): the vector /
`P(E − A) = 0` binding model and the five-conjunct security property

```
SECURE ⇔ enc injective & canonical      (A encoding)
       ∧ V complete incl. external state (B completeness)
       ∧ Null(P) ∩ U = {0}              (C structural binding)
       ∧ fresh(nonce) survives rollback  (D freshness)
       ∧ executor runs enc⁻¹(E) atomically (E atomic execution / G0)
```

## Stage 1 measures the conjuncts that are properties of MNDe as it exists

| Conjunct | Stage 1 | Where |
|---|---|---|
| A encoding | **Tested** | `attacks/a_encoding.mjs` vs `shared/json.ts` |
| B completeness | **Recorded as a capability boundary** (MNDe has no external-state representation) | `FINDINGS.md` F-003 |
| C structural binding | **Tested** | `attacks/c_binding.mjs` vs real executor gate |
| D freshness | **Tested** (replay, restart, rollback, default posture) | `attacks/d_freshness.mjs` vs real sidecar store |
| E atomic execution / G0 | **Deferred to Stage 2** — requires a real external effect that MNDe does not perform | — |
| Credential boundary | **Deferred to Stage 2** — MNDe holds no external credential | — |
| Crypto substrate | **Tested** (custody Ed25519 sign/verify, tamper, untrusted signer) | `attacks/e_crypto_custody.mjs` |

Result states are **PASS / FAIL / INCONCLUSIVE**, reported per conjunct and never
aggregated into a single misleading score. INCONCLUSIVE is never promoted to
PASS. See `RESULTS.md`.

Stage 2 (a separate experiment layer) adds a concrete executor adapter and a real
external target to test E/G0, source/target races, TOCTOU, and the credential
boundary — the gap between *approved declaration* and *guaranteed external
effect* identified in F-003.
