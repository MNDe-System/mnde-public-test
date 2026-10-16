# Authority bundle: what a stranger needs, and a plan to publish it

Assessed 2026-10-16. **A plan only.** No key was generated, rotated, replaced or published,
no live trust root was changed, and nothing here needs a code change to be true today.

Tags: **[read]** read in code or docs today; **[run]** ran today; **[gap]** a real hole;
**[proposal]** my recommendation, not an existing behaviour.

## 1. The question

An auditor holds an MNDe receipt or a piece of signed execution evidence. They do not
trust MNDe's service, logs or operator. What must they hold, and what must be true of
it, for "verified" to mean something?

## 2. What an external verifier needs today [read]

| Needs | Why | Where it comes from now |
| --- | --- | --- |
| The artifact (receipt, custody envelope, execution evidence) | the thing being checked | the operator |
| The authority bundle (`mnde.authority.bundle.v1`) | public keys per role, validity windows, revocation list, root signature | the operator, **or the repo's demo/local authority** |
| The root fingerprint, **from a channel independent of the bundle** | the only trust anchor; a bundle is never trusted on its own say-so (`UNTRUSTED_ROOT`) | **nothing publishes one** [gap] |
| The verifier code at a known revision | the replay logic is the check | this repository |
| For policy-bound receipts: the policy bundle and the approval trust anchors | replay needs them; a receipt marked `approval_enforced` cannot verify without anchors | the operator |
| For execution evidence: the expected executor id and environment id | otherwise the evidence only proves *some* executor under this root | the deployment owner |
| Node 24, no network | verification is offline and deterministic | n/a |

The offline path works today: `npm run verify-receipt`, `npm run verify`,
`scripts/verify-git-push-evidence.mjs`, and the CI gate `scripts/verify-published-bundle.mjs`.
That gate **skips** (exit 0) when its three inputs are unset, because no published bundle
exists; a skip is not a pass.

## 3. The current model, as implemented [read]

- **One root, Ed25519.** The bundle is signed by `root_key`; verifiers pin its SPKI sha256
  fingerprint. `verifyAuthorityBundle` checks the fingerprint matches the key, matches the
  pin, the signature over the canonical bundle, per-key fingerprints, and rejects a key id or
  fingerprint reused **across roles**, then rejects a stale bundle (`not_after`, optional
  `maxAgeMs`).
- **Roles as domain separation.** Keys are listed per role (`receipt`, `policy`, `approval`,
  `result`, `ledger`, `activation`, optionally `checkpoint`) and looked up by role. There is
  no context-string prefix on the signed bytes; separation rests on role-keyed lookup,
  cross-role uniqueness, and a `schema_version` inside every canonical payload. That is
  adequate while every payload is self-describing canonical JSON; it should be stated as the
  design rather than assumed [gap, documentation].
- **Algorithms and formats.** `ED25519` only, signatures hex or base64url over canonical JSON.
  Receipt formats `mnde.pe.receipt.v1/v2`, `mnde.signed-receipt.v1/v2`,
  `mnde.git-push-execution-evidence(-envelope).v1`. Unknown versions fail closed (no
  inference from field presence). Frozen vectors and their sha256 are in `conformance/`.
- **Key rotation within a bundle.** Several keys per role may coexist with overlapping
  `valid_from`/`valid_until`. A signature verifies if its key was valid at the time covered by
  the signed body (`evaluated_at`/`signed_at`), so old receipts keep verifying while the old key
  stays listed.
- **Revocation.** `revocation[]` holds key ids (legacy "revoked for all time") or
  `{ key_id | artifact_hash | release_version, revoked_at, reason_code }`.
  `findBundleKey` returns `revoked_as_of_event` (the signature predates or postdates the
  revocation) and an advisory `revoked_now`. Freshness is explicitly
  `CURRENT_TO_BUNDLE`: a stale bundle cannot show later revocations.
- **Expiry.** Bundle `not_after`; per-key windows.
- **Witnessing.** `src/witness/` and `src/equivocation/` implement threshold-witnessed
  checkpoints that make *two valid histories shown to two parties* detectable
  (`witnessed-authority-checkpoints.md`). It is built and tested (`test:witnessed-authority`,
  70 cases **[run]**) but is not wired to any publication.

## 4. Gaps [gap]

1. **No published bundle and no published root fingerprint.** Third-party verification is
   repo-local. This is the README's stated main pilot gap and it is still true.
2. **No root rotation or succession.** The root is the pin. Changing it means every verifier
   re-pins out of band; nothing in-band links old root to new.
3. **No root-compromise recovery.** There is no way to say "this root is no longer trusted
   after time T" that a verifier holding only the old pin could learn.
4. **Revocation is only as fresh as the bundle in hand**, by design, with no distribution
   channel or maximum-age policy for relying parties.
5. **No transparency.** A compromised or coerced operator can show different (individually
   valid) bundles to different parties. The witness layer addresses this but is not deployed.
6. **Signed evidence does not name the push credential** (`PRODUCTION-TRUST-BOUNDARY.md`), so
   the GitHub App identity is not independently verifiable from the evidence alone.
7. **Domain separation is by convention** (§3). Worth a sentence in the spec and a test that
   no payload type can be mistaken for another.
8. **The bundle schema name is `…bundle.v1` for both conformance vectors** (`manifest.json`
   lists `mnde-authority-bundle-v2` with `schema_version: mnde.authority.bundle.v1`), which is
   confusing for external implementers [read].

## 5. Publication plan [proposal]

Goal: a stranger, with nothing from the operator, can verify a receipt using only
independently obtained public material.

**5.1 What is published, and where.**

| Artifact | Location | Integrity |
| --- | --- | --- |
| `authority.bundle.json` (public material only) | a **separate** public repository (e.g. `mnde-trust`) at a path that includes the authority id and a monotonic serial, plus a stable "latest" pointer file | signed git tags by a key that is **not** the authority root |
| Root fingerprint (one line) | at least **three channels the operator does not solely control**: the trust repo README, the organization profile page, and a third-party-hosted record (a dated, signed announcement); optionally a DNS TXT record | a verifier compares all that they can reach; any disagreement is a stop |
| Verifier revision | the exact commit and a sha256 of the verifier source tree | pinned in the trust repo |
| Conformance vector manifest hash | already in `conformance/manifest.json` | n/a |

The CI gate `verify-published-bundle.mjs` then runs against the **published** files with the
fingerprint taken from a channel other than the bundle, and a skip becomes a failure once a
bundle is published.

**5.2 Ceremony (needs the owner; I did not and will not run it).** Generate the production
root on an offline host or HSM (`MNDE_EXTERNAL_ROOT_SIGNER_*` already supports an external
signer); never write it to a synced folder; sign the bundle; record the fingerprint in the
three channels in one dated, witnessed session; move the root offline. The serving hosts need
only the receipt, ledger and executor keys.

**5.3 Rotation (non-root keys).** Add the new key with `valid_from` before the old key's
`valid_until` (overlap at least one maximum receipt lifetime); re-sign and publish a higher
serial; stop signing with the old key at the overlap; **never delete an old key** from the
bundle (old receipts need it). Revoke only on compromise, with a timestamped
`{key_id, revoked_at, reason_code}` entry.

**5.4 Root rotation and compromise (design, not built).** Proposed new artifact
`mnde.authority.root-succession.v1`: `{ old_root_fingerprint, new_root_fingerprint,
effective_at, signature_by_old_root, signature_by_new_root }`, published alongside the
bundle. A verifier holding the old pin can follow a succession and then re-pin; the witness
layer attests that exactly one succession was published. For a **compromised** root the old
key cannot be trusted to sign its own succession, so recovery is out-of-band by design: a new
pin published in all channels, witnessed checkpoints used to fix the compromise time `T`, and a
verifier policy that accepts pre-`T` receipts only with witness evidence they were observed
before `T`. State plainly that this recovers *future* trust and *some* past trust, not all.

**5.5 Freshness policy.** Issue bundles with a short `not_after` (suggest 30-90 days) and a
re-issue cadence shorter than that; relying parties set `maxAgeMs` for **new** acceptance;
historical audits use the bundle as of the receipt date. Publish revocations as a new serial,
never an edit in place.

**5.6 What an external verifier then does.**

```bash
git clone https://github.com/<trust-repo>.git && git -C <trust-repo> verify-tag <serial-tag>
# fingerprint from >= 3 independent channels, compared by the verifier
node tools/verify.mjs <receipt.json> --authority-bundle <bundle.json> --root-fingerprint <fp>
node scripts/verify-git-push-evidence.mjs <evidence.signed.json> --authority-bundle <bundle.json> \
  --root-fingerprint <fp> --expected-executor-id <id> --expected-environment-id <env>
```

## 6. Local verification improvements considered

None implemented. The existing offline verifiers and the published-bundle gate already
cover local verification, and every candidate improvement either changes a receipt format,
the bundle schema, or trust semantics, which I was told not to do. Candidates for later,
each independently testable: a documented domain-separation test (gap 7); a clearer schema
name for the second conformance vector (gap 8); and a verifier warning when
`revocation_freshness` is `CURRENT_TO_BUNDLE` and the bundle is older than a caller-supplied age.

## 7. Authorization needed before any of this moves

Generating the production root; choosing the channels; creating the trust repository;
publishing any bundle or fingerprint; changing what the executor pins. All are the owner's.
