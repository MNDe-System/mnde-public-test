# Approval key custody and approval format (design, not implemented)

Status: **PROPOSED. Nothing in this document is implemented.** No signing code
should be written until the decisions in section 12 are made, because they
change trust anchors and secret custody.

Read [`APPROVAL-WORKFLOW-AUDIT.md`](APPROVAL-WORKFLOW-AUDIT.md) first. It records
what exists, which parts of this design depend on it, and the one Hub defect (F1)
that must be fixed before a human approval flow is usable.

## 1. What is being protected, and from whom

A human's approval is the only thing that lets a policy rule marked
`approval_required` become ALLOW. The design goal is: **an AI agent, and anything
that holds only the Hub's bearer token or the executor's GitHub credential, cannot
produce a valid approval.**

| Attacker | Can they approve? | Why |
| --- | --- | --- |
| Agent with no filesystem access to the operator's key | No | Needs a signature from an enrolled key. |
| Holder of the Hub bearer token | No | The token only authenticates the HTTP call. The Hub still requires a valid signature (`tests/test_hub.mjs`, "unsigned and wrong-scope approval cannot execute"). |
| Holder of the executor's GitHub App key or token | No | Different key, different role; cross-role key reuse is rejected when a bundle is verified (`src/custody/bundle.mjs`). |
| Holder of the Hub's receipt-signing key | Not for an `approval_required` rule (**derived, untested**) | Replay re-evaluates the embedded approvals; a forged ALLOW without trusted approvals would drift. Test D4 must prove it. |
| **Agent running as the same OS user as the operator** | **Possibly yes** | See section 4. This is the weak case and this document does not hide it. |
| Whoever controls the approval-anchors file or the root key | Yes | They decide who is trusted. Section 5. |

## 2. Roles and keys

MNDe already recognizes separate key roles: `receipt`, `policy`, `approval`,
`result`, `ledger`, `activation`, `checkpoint` (`AUTHORITY_KEY_ROLES`,
`src/custody/bundle.mjs`), and rejects a bundle in which one key id or one
fingerprint appears in two roles. The brief's four roles map onto those:

| Brief role | Existing mechanism | Key |
| --- | --- | --- |
| A. Policy authority | `policy` and `receipt` roles | Hub-held receipt key; offline policy key |
| B. Approval authority | `approval` role | **New: operator-held key, this document** |
| C. Executor identity | root-signed executor credential | Executor key |
| D. GitHub credential authority | GitHub App private key, via the credential provider | App key |

The approval key never lives on the Hub, never in a source repository, and never
in an agent workspace. The Hub holds only its **public** half in the anchors.

## 3. Operator identity

An enrolled approver is a record bound to a key:

```
operator_id            stable, unique, assigned at enrollment (not free text from the approval)
key_id                 unique across all roles
public_key_fingerprint sha256 of the SPKI public key
valid_from, valid_until  enforced by the verifier (already supported)
```

Today the anchors carry only `key_id`, `public_key`, `valid_from`, `valid_until`.
The `approver` and `issuer` fields inside an approval are free text that the
signing key itself asserts, so **nothing currently binds a key to a person**.
Proposal: the verifier requires `approval.approver === anchor.operator_id` for
the key that signed it. That is a small addition to `verifyApproval`, applies
only to v2 approvals, and makes the audit trail say who, not just which key.

Per-operator *resource* scoping (which repositories a key may approve) is **not**
added to keys. Policy rules already select by repository and require approvals;
putting scope in two places invites disagreement. Authorization stays in policy.

## 4. Key generation, storage and what it does not give you

### Proposal for v1

- Generate an Ed25519 key pair on the operator workstation with `node:crypto`.
- Store the private key **outside every repository**, in a per-user directory
  (default `~/.mnde/operator/` on POSIX, `%LOCALAPPDATA%\MNDe\operator\` on
  Windows), directory mode 0700, file mode 0600.
- Encrypt at rest with a passphrase: `scrypt` (parameters recorded in the file)
  deriving a key for AES-256-GCM, in an MNDe-defined versioned envelope using only
  `node:crypto`. No new dependency.
- Prompt for the passphrase on the terminal at signing time. Never accept it on
  the command line or from an environment variable. Hold the decrypted key in
  memory for the one signature and drop the reference. No temporary file.
- Refuse to sign when standard input and output are not a terminal, and provide
  no `--yes` flag. This is a **speed bump for automation, not a boundary** (below).
- Never print private key bytes, passphrases or file contents; diagnostics print
  the key id and fingerprint only. Tested the way PR #57 tests the doctor.

Why not the obvious alternative of encrypted PKCS#8 PEM? Node can export one
(`cipher`, `passphrase`), which would let `signApproval` keep working unchanged.
As far as I know the PBKDF2 iteration count it uses is a low OpenSSL default that
Node's API does not expose (**medium confidence; measure before choosing**). If a
measurement shows it is adequate, PEM is simpler and interoperable; the envelope
is the fallback, not a requirement.

### What this storage does and does not provide

| Property | Provided? |
| --- | --- |
| Key not readable by another OS user | Yes, by file permissions (POSIX). On Windows, permissions are ACLs that Node cannot check; the runbook uses `icacls` and `doctor` reports it `NOT_VERIFIED`. |
| Stolen disk or backup is not enough | Yes, up to the passphrase strength and the KDF cost. |
| Key is non-exportable | **No.** It is an encrypted file, copyable by anyone who can read it. A hardware or OS-keystore key can be non-exportable; this cannot. |
| Signature requires a human at the keyboard | **Only against naive automation.** |
| Safe if an agent runs as the same OS user | **No.** |

### The same-user host case, stated plainly

If the AI agent runs as the operator's own OS user it can read the encrypted key
file, run the approval CLI inside a pseudo-terminal, read the passphrase from
anything the user types into a process it can observe, or log keystrokes. A
terminal check does not stop that. **Software-only operator approval must not be
described as immune to a compromised same-user host.** Real mitigations, in order
of cost:

1. Run the agent as a different OS user, or in a container or VM that cannot see
   the operator directory. (Operational; the approval CLI refuses a key directory
   readable by group or other.)
2. Sign on a separate device the agent cannot reach: a phone or hardware
   authenticator showing the exact action. This is the stronger design and is the
   reason the signing format below is device-independent.
3. A platform keystore (Windows DPAPI/CNG, macOS Keychain, Secure Enclave). Not in
   v1: Node has no built-in access, so it would need a native module or shelling
   out, both of which expand the shipped surface that `test_git_push_reachability`
   currently pins.

The CLI documentation must state which of these the user is relying on.

## 5. Trust-anchor registration (decision 1)

Enrollment is an administrative act, not something a client can request. A public
key submitted over HTTP is never trusted because it arrived.

**Option A (recommended): root-signed.** Add the operator key to `keys.approval`
of the authority bundle using the existing lifecycle functions, then derive the
approval anchors the engine uses from the verified bundle. Gains: the same
rotate/retire/revoke ceremony as every other key, cross-role uniqueness checks,
validity windows, an offline-verifiable history, and nothing to hand-edit.
Cost: enrollment needs the offline root key, like executor enrollment already
does. For a solo developer that is one more ceremony per key, rare.

**Option B: keep the hand-managed anchors file.** Cheaper to operate, and weaker:
the list is unsigned, readable by whatever can edit files as the Hub's user, and
unconnected to the lifecycle that already exists. Only acceptable for a first
prototype, and it should be labelled as such.

Either way, `mnde operator enroll` produces a public-key bundle for the
administrator to register. It does not edit trust configuration itself.

## 6. Revocation, rotation and expiry

**Revoke by bounding, never by deleting.** Replay verification uses the receipt's
original `evaluated_at` and looks the key up in the anchors
(`authenticated-approvals.mjs`). Removing a key makes every past receipt that used
it fail replay with `APPROVAL_UNTRUSTED_ISSUER`, which would rewrite history.
Instead set the key's `valid_until` to the revocation time. The lifecycle
functions already take the earlier of an existing and a new `valid_until`.

Effective time: a decision made at or after `valid_until` rejects the key. A
signed approval created before revocation but submitted after is rejected. A
receipt issued before revocation remains verifiable and may still be executed
until its own expiry (five minutes today). That window is the stated worst case
and should be shortened by revoking and then locking the Hub.

**Operational note (audit F7):** the Hub hashes the anchors file and goes DEGRADED
on any change until restarted. Revocation therefore fails closed immediately and
recovers on restart.

**Rotation:** enroll the new key, register it, verify a test signature accepted
by the verifier, then set the old key's `valid_until` to the switch time. Two
keys are valid only during that overlap, and the policy's approval count is by
approval, so an overlap must not be used to meet a threshold greater than one
(audit F6).

**Default validity:** one year, a decision for the owner. Shorter limits blast
radius and increases ceremonies. Solo developer, key on a laptop: I would take 90
days only if enrollment can be made painless, otherwise one year.

**Recovery from a lost passphrase or device:** there is none by design. Enroll a
new key and revoke the old one. Pending requests are refused and re-requested.

## 7. Approval format v2 (decision 2)

Fields, all inside the signed body:

```
approval_schema   "mnde.approval.v2"
approval_id       unique
approver          must equal the anchor's operator_id for the signing key
issuer            the enrolling authority id
issued_at, expires_at
scope: {
  tool_name       exact, never "*"
  request_id      required
  action_digest   "sha256:" + hex of the digest defined below
}
signature: { key_id, value }   Ed25519, not part of the signed body
```

**`action_digest`** is a SHA-256 over the canonical JSON (`shared/json.ts`,
`canonicalizeJson`) of the request fields that define the effect: `tool_name`,
`request_id`, the six normalized `parameters`, and `environment`. It is computed
by **one function, in the policy engine**, imported by both the verifier and the
CLI. The agent never supplies a digest. The CLI computes it from the request the
Hub returned, so what the human sees is what is hashed.

**Verification** in the engine's `verifyApproval`, which also runs on every
offline replay. For a v2 approval it recomputes the digest from the request being
decided and requires equality, requires `approver` to match the anchor, and
rejects `tool_name: "*"`. Legacy approvals (no `approval_schema`) take today's
code path unchanged, so historical receipts keep verifying.

**Strict git.push policy:** the Hub requires v2 for `git.push` reviews the way it
already requires `scope.request_id`. A legacy approval is refused on that route.

**Signature domain separation (the open choice).**

| | Prefix the signed bytes with `mnde.approval.v2\n` | Keep the signing input, rely on the signed `approval_schema` field |
| --- | --- | --- |
| Strength | Strict domain separation | Weaker; separation rests on key-role isolation, which bundles already enforce |
| Older verifiers | Fail closed (`APPROVAL_SIGNATURE_INVALID`) | Accept the signature, ignore the digest |
| Cost | Needs a verifier that knows v2 | None |

Recommendation: prefix. The pilot has no published verifier consumers, and "an
old verifier silently ignores the digest" is exactly the failure this change
exists to prevent. Cost is that approvals made with new tooling are unverifiable
by old tooling, which is the safe direction.

**Lifetime:** 120 seconds proposed. Effective expiry is the earliest of the
request expiry, the approval expiry, and the key's `valid_until`. Hub expiry is
five minutes, which is short for a human on a phone; decide whether that should
change, after F1 is fixed so that expiry stops being a Hub-degrading event.

## 8. Refusal

Refusal needs an authenticated, authorized operator but, per the brief, no
signature by default. The Hub must record **who** refused (audit F4). If a
deployment wants non-repudiable refusals, the same v2 format with an explicit
`decision: "REFUSE"` could be added later; it is not in scope for v1.

## 9. Who may do what (roles)

| Role | May |
| --- | --- |
| Viewer | Read requests visible to it and their outcomes |
| Approver | Viewer, plus submit an approval or refusal for permitted actions |
| Administrator | Enroll, rotate, revoke keys; manage policy; lock and unlock |

An administrator does not gain the ability to approve: approvals still need a
signature from an enrolled approval key. The current single `operator` set cannot
express this (audit F4); it changes together with the pending-request API.

## 10. Compatibility

- Legacy `signApproval` and legacy verification are unchanged.
- No existing receipt's signed bytes change.
- v2 is additive in the engine and mandatory only on the new strict route.
- Receipts produced under v2 embed the approval and the request, so a verifier
  that supports v2 can re-check the digest offline.
- A verifier without v2 support rejects v2 approvals (prefix option). Documented,
  intentional.

## 11. Tests this design requires (a subset of the brief's A-F)

Custody: key file never inside a repository; no secret in any output; refuses a
group-readable key directory; refuses non-TTY signing; revoked key fails;
`valid_until` bounding keeps past receipts verifiable (the test that removal
would fail).

Binding: each of repository, remote URL, branch, expected old SHA, source commit
and environment changes the digest and invalidates the approval; the same id with
different parameters fails; replay against another request fails; a legacy
approval fails on the strict route; D4 (a receipt-key holder cannot forge ALLOW
without approvals).

Hub: viewer cannot approve or refuse; late approval returns EXPIRED and leaves
the Hub ACTIVE; refusal records the actor.

## 12. Decisions required from the owner

1. Anchor source: **A (root-signed, recommended)** or B (file).
2. Domain separation: **prefix (recommended)** or compatible.
3. Key storage: passphrase-encrypted envelope (or PEM, if its KDF measures
   adequate), with the same-user limits in section 4 accepted and documented.
4. Approval and request lifetimes.
5. Default key validity (90 days or one year).
6. Whether the first release assumes the agent runs as a **different OS user**,
   and the CLI should refuse a key directory the agent's user can read.

Until 1-3 are answered, the next safe work is the Hub expiry fix and the
read-only pending-request projection, neither of which touches key custody.
