# MNDe — The Two Objections

Every serious buyer of MNDe — a CISO, a controller, an auditor — asks the same two
questions in the first ten minutes. This page answers both honestly. If a claim
here ever drifts ahead of the code, fix the claim, not the reader's memory.

---

## Objection 1 — "What stops the agent from just not calling MNDe?"

**The honest state today: enforcement is cooperative.** MNDe evaluates an action
only when the caller routes it through MNDe — via the executor wrapper, the MCP
server, or the MCP proxy. It is not OS-level or kernel-level. A process that never
submits its action to MNDe is not stopped by MNDe. This is stated plainly in the
[security model](security-model.md) and the README limitations, and we do not
paper over it.

**Why that is acceptable for a pilot:** in the target deployments (an agent given
prod access, or an agent that moves money), the agent's *egress* — the database
client, the payment API call, the deploy step — is a chokepoint the operator
controls. Routing that chokepoint through MNDe is a configuration the operator
makes once, the same way they already route through a proxy, a secrets manager, or
an IAM boundary.

**Where it goes — the un-bypassable path (Rung 1).** MNDe is building toward a
mandated egress boundary where the action is literally un-performable without a
signed, single-use capability. That path is sequenced as CAP-1..5:

| Rung | What it establishes | State |
|---|---|---|
| **CAP-1** | A signed, independently verifiable **execution grant** bound to one ALLOW decision | ✅ shipped (artifact only — see [execution-grant.md](execution-grant.md)) |
| **CAP-2** | *Who* may request a grant | 🔴 roadmap |
| **CAP-3** | **Require** a valid grant at the execution boundary; single-use redemption | 🔴 roadmap |
| **CAP-4** | Prevent bypassing the boundary at the network/deployment layer | 🔴 roadmap |
| **CAP-5** | Remove the remaining standing-credential bypass | 🔴 roadmap |

**One-line answer:** *"Today MNDe is a cooperative gate on the agent's egress —
the same chokepoint you already control. CAP-1 (shipped) is the first rung of an
un-bypassable boundary where the action can't run without a single-use signed
grant; CAP-3 is where that becomes mandatory."*

Do **not** claim un-bypassable enforcement exists today. It does not. Claiming it
is the fastest way to lose a security buyer on question one.

---

## Objection 2 — "Can the operator just forge these receipts?"

**The honest state today: individual receipts are tamper-evident, and witnessed
authority-checkpoint primitives are on `main`, but the live execution ledger is
still operator-signed unless a deployment actually operates an independent
witness flow.** Mutating any signed receipt field breaks the Ed25519 signature,
and verification is offline against a root-anchored trust bundle. The repository
can create and verify authority checkpoints, independent witness attestations,
threshold policies, forks, and equivocation proofs. Production startup does not
yet require those attestations, and the existing ledger checkpoint route remains
`operator-signed-inclusion` by default.

**What already holds against forgery:**

- Receipts are **tamper-evident** — any change to a signed field →
  `SIGNATURE_INVALID`. Escalating a `DELETE` to a `DROP` is a signature break.
- Verification is **offline and root-anchored** — the verifier trusts a pinned
  root fingerprint, not the operator's environment or logs.
- Ledger entries are **signed (v2)** and **Merkle-anchored** with offline
  inclusion proofs; excision-and-rebuild of a single entry is detectable.
- Authority checkpoints and witness attestations have separate key roles and
  trust sources. A verifier can detect conflicting signed authority histories
  when an independent witness retained and presents its attestation.

**What is not yet closed:**

- Shipping witness primitives does not create an independent witness. A party
  controlling the store, ledger key, and every configured witness key can still
  present a rewritten history. The pilot must place the witness key and retained
  attestations with a genuinely independent counterparty.
- Witnessing detects conflicting histories after evidence is compared; it does
  not prevent an insider from producing them, provide consensus, or guarantee a
  trustworthy timestamp.
- The current production startup path does not fail closed on a missing witness
  threshold. Requiring that policy is deployment work, not a property of the
  default product path.

**One-line answer:** *"An individual receipt cannot be silently altered: it is
Ed25519-signed and verified offline against a pinned root. MNDe also ships
witnessed authority-checkpoint verification, but it only makes conflicting
histories externally detectable when a genuinely independent witness operates a
key and retains the attestation; the default live ledger is not automatically
witnessed."*

Do **not** claim "tamper-proof against insiders." Even with an independent
witness, the accurate claim is externally detectable conflicting authority
history, conditional on retained witness evidence.

---

## The meta-rule

Both answers follow the same discipline: **state what holds today, name the gap,
name the specific next rung that closes it.** Buyers in this category have working
bullshit detectors — an honest boundary they can verify beats a bold claim they
can puncture. Credibility is the product.
