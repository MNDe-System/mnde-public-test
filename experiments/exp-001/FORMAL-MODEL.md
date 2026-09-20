# MNDe EXP-001 — Formal Model

**Status:** Proposed
**Scope:** Formal frame for the exact-approval-binding claim tested in EXP-001.
**Primary question:** Does authorization of action *X* permit only *X*?

This document states the security property EXP-001 tries to falsify, in a form
that makes each attack in the test matrix a distinct, checkable failure of a
distinct assumption. Its main purpose is to prevent a false summit: the naive
linear model of binding is trivially satisfiable, and the tests that matter are
the ones that model cannot see.

---

## 1. The linear model (the easy part)

Model an execution as a vector over the canonical execution identity:

```
A = [r, p, s, t, o, e]ᵀ
      r = repository
      p = pull request
      s = source commit
      t = target ref
      o = operation
      e = executor
```

Let `A` be the authorized execution and `E` the proposed execution. Define the
difference `d = E − A` and a policy matrix `P`. The binding check is:

```
ALLOW  ⇔  P(E − A) = 0
REFUSE ⇔  P(E − A) ≠ 0
```

The security requirement, in this model, is that no non-trivial
security-relevant change lies in the null space of `P`:

```
∀ d ∈ U, d ≠ 0 ⇒ Pd ≠ 0     ⇔     Null(P) ∩ U = {0}
```

For complete exact binding (`U = V`), this reduces to `Null(P) = {0}`, i.e.
`rank(P) = dim(V)`. For the six-dimensional identity policy, `rank(P) = 6`,
`nullity(P) = 0`, and every single-coordinate mutation (T001–T007) is detected.

**This conjunct is correct and trivially satisfiable.** Use the identity matrix
and it holds. It is also the part of MNDe that is *not novel* — structural field
comparison is table stakes. If EXP-001 stopped here it would prove almost
nothing.

### 1.1 Admissible operations on coordinates

Coordinates are **categorical identities** (repository IDs, 256-bit commit
hashes, ref strings), not magnitudes. Therefore:

- The only admissible per-coordinate relation is **equality**.
- The only admissible aggregate measure is the **Hamming / L0 count** of changed
  protected coordinates, `‖Pd‖₀ = Σᵢ 1[(Pd)ᵢ ≠ 0]`.
- **No continuous norm (L2, L1, L∞) has meaning here.** `‖d‖₂ = 6` for a changed
  target is an artifact of integer encoding, not a distance. Any policy of the
  form `ALLOW if ‖d‖ < ε` for `ε > 0` is a **catastrophic hole** in an
  exact-binding system and is explicitly forbidden. EXP-001 must reject any
  threshold interpretation of the difference vector.

---

## 2. What the linear model cannot see

The linear model expresses the property as a function of `(E, A)` alone. Four
security-relevant failure classes are structurally invisible to any such
function. Each corresponds to a test the model *cannot* represent, and each is
where MNDe either produces a real finding or is exposed as never having held.

### 2.1 Encoding (injectivity & canonicalization)

`Pd = 0` means "same action" **only if** the encoding
`enc: RealAction → V` is injective and canonical. If two distinct real actions
encode to the same vector — e.g. `main`, `Main`, and `refs/heads/main` all map to
`t = 3` — then `d = 0` for a genuinely different action, and the check passes on
a false identity.

- The real property is about `enc`, not `P`.
- **Attacks:** the `H(R)` canonicalization surface; ref/name normalization,
  case-folding, Unicode, encoding collisions.
- **Failure form:** `enc(X) = enc(Y)` with `X ≠ Y`.

### 2.2 Completeness of `V` (latent state)

`Null(P) = {0}` is a statement about a chosen space `V`. The dangerous null space
is not a dropped row of `P` but a **security-relevant field that is not a
coordinate at all.** The six-dimensional vector omits `expected_target_sha`,
which §8 of the experiment says the authorization *should* bind. Consequently
`main` can move `111aaa → 222bbb`, all six coordinates stay equal, `Pd = 0`,
**ALLOW** — against a repository state that no longer exists.

- `rank(P) = 6` is true of a space missing coordinate 7.
- **Attacks:** §8 (target-branch race), any approval-against-state-S1 /
  execute-against-S2 divergence.
- **Failure form:** `E = A` in `V`, but the real actions differ in a field
  outside `V`.
- **Required extension:** `A` must include state coordinates
  (`expected_source_sha`, `expected_target_sha`) so that §7 and §8 become
  `d ≠ 0` events rather than invisible ones.

### 2.3 Time (TOCTOU / the race)

A vector is a snapshot; TOCTOU is a statement about two moments. In §7, authorized
`s = 41` and executed `s = 41` — **the vector is identical, `d = 0`** — yet the
executor merged a different real commit because the PR head moved between approval
and execution. The headline vulnerability of EXP-001 is `d = 0`.

- Any property that is a function of `(E, A)` alone has assumed the race away.
- **Attacks:** §7 (critical race), §9 (TOCTOU).
- **Failure form:** identical vectors at two times bound to different real
  actions.
- **Required primitive (G0):** the executor must perform `enc⁻¹(E)`
  **conditionally and atomically** on expected state (GitHub merge `sha`
  parameter; expected-SHA ref update). If this primitive is unavailable, §7/§8/§9
  are structurally **INCONCLUSIVE** regardless of the algebra.

### 2.4 State & freshness (replay / rollback)

`ALLOW ⇔ Pd = 0` is memoryless. Submit the same `E` twice and it authorizes
**twice**. Single-use requires a stateful predicate:

```
ALLOW  ⇔  (Pd = 0)  ∧  fresh(nonce)
```

`fresh(·)` is external state, and the §12 database-rollback attack targets exactly
it: restore MNDe's DB from before consumption and the "consumed" flag reverts.
Re-authorizing consumed work is **uncertainty converted into ALLOW** — the same
production invariant as *unknown never becomes ALLOW*.

- **Attacks:** T009 (replay), §12 (DB rollback).
- **Failure form:** a consumed authorization treated as fresh after state
  reversion.
- **Required property:** the freshness record must live outside MNDe's own
  rollback domain.

---

## 3. The property EXP-001 actually falsifies

Real exact-binding security is a **conjunction of five claims**, of which the
linear algebra is the easiest and the only trivially satisfiable one:

```
SECURE  ⇔  enc is injective & canonical                  (encoding      → §2.1)
        ∧  V contains every security-relevant field,
             including latent repository state            (completeness  → §2.2)
        ∧  Null(P) ∩ U = {0}                             (linear model  → §1)
        ∧  fresh(nonce) survives rollback                 (freshness     → §2.4)
        ∧  executor performs enc⁻¹(E) atomically          (G0 primitive  → §2.3)
```

| Conjunct        | Property                              | Attacked by            | If it fails                          |
|-----------------|---------------------------------------|------------------------|--------------------------------------|
| Encoding        | `enc` injective & canonical           | `H(R)` collisions      | `d = 0` on a different action        |
| Completeness    | every relevant field ∈ `V`            | §8 target-state race   | `d = 0` against stale state          |
| Linear binding  | `Null(P) ∩ U = {0}`                   | T001–T007 mutations    | mutated field slips the check        |
| Freshness       | `fresh(nonce)` survives rollback      | T009 replay, §12       | consumed auth re-authorizes          |
| Atomic exec     | executor runs `enc⁻¹(E)` atomically   | §7 race, §9 TOCTOU     | approved snapshot ≠ executed action  |

**Standard-crypto tests are separate.** T008 (byte flip → signature failure),
T010 (no authorization), and T011 (agent self-signs) verify the signature
primitive, not MNDe's binding semantics. They belong in the harness self-check
and must not inflate the headline result. "12/12 PASS" that mixes crypto
table-stakes with binding claims overstates what was shown.

---

## 4. Consequences for sequencing

The two conjuncts that can invalidate the whole experiment before the matrix is
meaningful are **Atomic exec (G0)** and the **§10 credential boundary** (if the
agent has any GitHub write path, every downstream test is theater). Front-load
them so the experiment fails cheap:

```
G0  verify conditional/atomic execution primitive exists
 ↓
§10 prove & freeze the agent has no credential path around MNDe
 ↓
C001 control action succeeds
 ↓
T009 / §12  freshness & rollback (most informative failure)
 ↓
§7 / §8  race & target-state binding
 ↓
T001–T007 structural mutations; T008/T010/T011 harness self-check
```

---

## 5. Result discipline

- Use three states: **PASS / FAIL / INCONCLUSIVE**. Never promote INCONCLUSIVE to
  PASS.
- A missing G0 primitive makes the race/state tests INCONCLUSIVE by construction,
  not PASS.
- Report per-conjunct, not as a single aggregate score. The claim EXP-001 can
  support is narrow: *under the tested GitHub execution model and threat
  assumptions, an authorization bound to action X did not permit the tested
  transformations into action Y* — and only for the conjuncts that reached PASS
  on independently reproducible evidence.

**The identity matrix is a false summit.** `rank(P) = 6` is real but cheap; the
experiment lives in the four conjuncts the vector cannot see.
