# MNDe EXP-001 — Exact Approval Binding Under Adversarial Execution

A falsifiable security experiment: **does authorization of action X permit only X?**
The goal is to *break* the claim, not confirm it. A FAIL is a valid, useful result.

This directory is a self-contained evidence package. It modifies no MNDe source.

## Staging

- **Stage 1 (this run):** Test MNDe exactly as it exists — an authorization
  sidecar + client-side execution gate that binds a **declared** action to a
  verified, request-bound, single-use receipt gating a local `run()` call. No
  GitHub machinery. Conjuncts **A (encoding)**, **C (structural binding)**,
  **D (freshness)**, plus **custody-mode crypto self-checks**; **B (completeness)**
  recorded as an architectural boundary.
- **Stage 2 (future):** MNDe + a concrete executor adapter + GitHub. That is where
  G0 (atomic execution), source/target races, TOCTOU, and the credential boundary
  live — because those require a real external effect, which Stage 1 deliberately
  does not add.

## Layout

| Path | Contents |
|---|---|
| `FORMAL-MODEL.md` | The vector / `Pd=0` model and the five-conjunct security property |
| `PREFLIGHT.md` | Pre-experiment inspection of MNDe (A–P), incl. the "MNDe never touches GitHub" finding |
| `SPEC.md` | Stage-1 scope + pointer to the formal model |
| `THREAT-MODEL.md` | Roles, trust assumptions, what is in / out of MNDe's boundary |
| `PRECONDITIONS.md` | Pinned commit, environment, signing posture, known limitations |
| `harness/` | Shared test helpers (boot real sidecar, free port, evidence writer) |
| `attacks/` | One script per conjunct (`a_encoding`, `c_binding`, `d_freshness`, `e_crypto_custody`) |
| `evidence/` | Raw per-conjunct result JSON |
| `receipts/` | Receipts captured during the run |
| `results.json` | Machine-readable aggregate (commit-pinned) |
| `RESULTS.md` | Human results report, per conjunct |
| `FINDINGS.md` | One entry per discovered issue |
| `run-all.mjs` | Runs every attack script and writes `results.json` |

## Run

```bash
node experiments/exp-001/run-all.mjs
```

Node ≥ 24, from the repo root, on the pinned commit. No GitHub, token, or network
required.

## Headline result

`30 tests — 27 PASS · 2 FAIL · 1 INCONCLUSIVE` @ `9295635b`. No structural
substitution or encoding collision found; single-use holds only with a durable,
un-rolled-back store; MNDe has no external-state binding (Stage 2). See
`RESULTS.md` and `FINDINGS.md`.
