# MNDe EXP-001 — Threat Model (Stage 1)

## What MNDe is (as measured, not as marketed)

MNDe is an **authorization sidecar** plus a **client-side execution gate**:

- The sidecar (`mnde-local-sidecar.mjs`, `POST /v1/decisions`) evaluates a
  canonical request against a policy and returns a decision + a receipt.
- The executor (`executor/index.mjs`) binds a verified receipt to the exact
  declared `(action, parameters, executionId[, subject, policy])` and calls a
  developer-supplied `run()` closure **once**, only when the strict gate clears.

MNDe's guarantee ends at "we called `run()` with these authorized declared
parameters." It does **not** extend to any external side effect `run()` performs.

## Stage-1 boundary

```
 in scope for Stage 1
 ┌───────────────────────────────────────────────┐
 │  agent → sidecar(decision+receipt) → executor  │
 │            gate → run()                         │
 └───────────────────────────────────────────────┘
                                     │  out of scope for Stage 1
                                     ▼  (Stage 2: adapter + GitHub)
                            run() → GitHub merge, etc.
```

- **In scope:** encoding/canonicalization, structural binding of the declared
  action, freshness/replay/restart/rollback of MNDe's own authority state, and
  the crypto substrate (signature + trust verification under custody).
- **Out of scope (Stage 2):** the actual external mutation, conditional execution
  against live repository state (G0), source/target races, TOCTOU, and the GitHub
  credential boundary — none of which exist inside MNDe today.

## Roles (Stage 1)

| Role | Holds | Does |
|---|---|---|
| Agent / caller | nothing privileged | constructs a declared request, calls the executor |
| Authority (sidecar) | receipt signing key (legacy HMAC by default; Ed25519 custody when configured) | decides, signs the receipt |
| Executor gate | the receipt + verifier | verifies offline, binds to the exact request, runs `run()` once |

There is **no GitHub write credential anywhere in MNDe.** In Stage 1 there is no
external effect to protect, so the credential-boundary question is deferred to
Stage 2, where the adapter that holds a real token must be isolated from the
agent.

## Trust assumptions

- The offline verifier and canonicalizer are trusted as the system under test
  (they are MNDe's own code; we exercise, not replace, them).
- The stand-in decision endpoint used in conjunct C is **not** a trusted
  component — it is the adversary, replaying a genuine receipt captured from the
  real sidecar against mutated requests. The security claim is that the executor
  gate refuses those, which it does.
- Custody crypto self-checks use ephemeral, in-process authority keys generated
  per run; they prove verification logic, not production key custody.

## Adversary capabilities modeled

- Possession of a genuine ALLOW receipt and the ability to re-present it against a
  different declared action (conjunct C).
- Ability to resubmit an execution id, restart the sidecar, and roll back its
  local dedup store (conjunct D).
- Ability to craft ambiguous / malformed serializations and a foreign signing key
  (conjunct A, crypto self-checks).

## Explicitly NOT modeled in Stage 1

Host compromise, GitHub compromise, authority-key theft, network interception of a
real mutation, and any claim of production readiness. A PASS here is bounded to
the declared-intent binding layer only.
