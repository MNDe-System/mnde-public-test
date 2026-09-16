# MNDe EXP-001 — Stage 1 Findings

Each finding is preserved as observed. **No remediation has been attempted** (per
the experiment protocol: discover → preserve → document → commit baseline, then
remediate separately with the failing test kept as a regression test). Severity
language is deliberately plain and precondition-bound.

---

## F-001 — Durable single-use replay protection is OFF by default

- **Affected conjunct:** D (freshness)
- **Test:** D4 (`attacks/d_freshness.mjs`) · evidence `evidence/D_freshness.json`
- **Severity rationale:** Meaningful for anti-replay, but bounded by
  configuration and by what MNDe claims. MNDe documents durable execution-id
  dedup as **opt-in** via `MNDE_EXEC_ID_CACHE` (`sidecar/execution_id_store.mjs`
  lines 44–50). Within a single process lifetime, an in-process `Set` still
  dedups (D5 PASS). The gap is **across a restart in the default posture**.
- **Precondition:** `MNDE_EXEC_ID_CACHE` unset (the default; confirmed — the
  sidecar boots without it and `execIdDirPath()` returns `null`), and the sidecar
  process restarts between the two submissions.
- **Steps to reproduce:** Boot the sidecar with no `MNDE_EXEC_ID_CACHE`. `POST
  /v1/decisions` with execution id `X` → `ALLOW`. Stop the sidecar. Boot again
  (no cache). `POST` the same id `X` → `ALLOW` again.
- **Expected (idealized single-use):** second submission `REFUSE`.
- **Observed:** `ALLOW` / `OK_ALLOW` on the replay after restart.
- **Security implication:** In default deployments, an execution authorization is
  not durably single-use; a restart (crash, deploy, scale event) reopens a
  previously consumed execution id. Whether this is a *defect* or an *accepted
  posture* depends on whether MNDe intends single-use to be a default guarantee.
  Flagged rather than judged.
- **Remediation attempted:** No. (Candidate direction for Stage-1b, not done
  here: make a durable store mandatory under a production profile, or fail closed
  when unconfigured.)

---

## F-002 — Rolling back the dedup store reverts `Consumed → Unused`

- **Affected conjunct:** D (freshness)
- **Test:** D3 (`attacks/d_freshness.mjs`) · evidence `evidence/D_freshness.json`
- **Severity rationale:** This is the more structural of the two: even with
  durable dedup **enabled** (the secure posture, D1/D2 PASS), the consumption
  record lives entirely in one local filesystem directory with **no anchor
  outside that rollback domain**. Restoring that directory from a backup taken
  before consumption silently un-consumes the authorization.
- **Precondition:** `MNDE_EXEC_ID_CACHE` set (durable dedup ON) **and** an actor
  able to restore the store directory to a pre-consumption state (backup/restore,
  snapshot rollback, volume revert).
- **Steps to reproduce:** Boot with `MNDE_EXEC_ID_CACHE=<dir>`. `POST` id `X` →
  `ALLOW` (a reservation file for `X` appears in `<dir>`). Stop. Delete the
  reservation file for `X` (simulating a restore to before consumption). Boot
  again with the same `<dir>`. `POST` id `X` → `ALLOW` again.
- **Expected:** second submission `REFUSE` (consumption is monotonic).
- **Observed:** `ALLOW` / `OK_ALLOW` — the consumed id re-authorized.
- **Security implication:** MNDe's freshness state is only as durable as the
  local store's rollback domain. Any mechanism that can revert that directory
  (backup restore, filesystem/volume snapshot, container redeploy from an image)
  reverts consumption. To make consumption truly monotonic, the freshness anchor
  must live outside MNDe's own rollback domain (e.g. an append-only external log,
  a monotonic counter service, or a hardware/service token that cannot be
  rewound). Identifying that boundary is the constructive follow-up.
- **Remediation attempted:** No.

---

## F-003 — No representation of external execution state (capability boundary)

- **Affected conjunct:** B (completeness)
- **Classification:** **Architectural capability boundary — recorded as a
  finding, NOT a test failure.** MNDe does not currently claim external-state
  binding, so this is not scored as FAIL.
- **Evidence:** No field for `expected_target_sha` / `expected_source_sha` /
  target SHA / head SHA exists anywhere in MNDe (repository-wide search returns
  only comments and tests). The canonical request (`scripts/reviewer-request.mjs`)
  carries a declared action + opaque `parameters`; the executor
  (`executor/index.mjs`) binds those **declared strings** and then calls a local
  `run()`. Nothing in MNDe observes or compares real external state.
- **Statement of the boundary (verbatim intent):**
  > MNDe has no representation for external execution state such as
  > `expected_target_sha`, therefore exact external-state binding is not provided
  > by the current abstraction.
- **Consequence:** MNDe proves *approved declaration ⇒ gated `run()` on the
  exact declared parameters*. It does **not** prove *approved declaration ⇒ the
  external effect matched that declaration*. That gap — between an authorized
  call and an authorized real-world effect — is precisely Stage 2's subject: a
  concrete executor adapter that translates a bound authorization into a
  **conditional** external mutation (e.g. a GitHub merge gated on the merge
  API's `sha` parameter) and a receipt tied to the observed outcome.
- **Remediation attempted:** No. This is a design decision for Stage 2 (does
  external-state binding belong inside MNDe or inside executor adapters?), not a
  bug to patch.

---

## Non-finding characterizations (for completeness)

- **Executor gate is a binding check, not a consumption ledger** (C, T009-exec,
  INCONCLUSIVE). Re-presenting the identical receipt with the identical execution
  id re-authorizes at the executor. This is correct layering — single-use is the
  sidecar's responsibility (D) — but is documented so no reader mistakes the
  executor gate for a replay ledger.
- **No Unicode normalization** (A, A6). A safe-against-collision characteristic
  today; becomes an adapter requirement in Stage 2 if any adapter normalizes
  identifiers before acting.
