# Known issues

Problems that are real, recorded deliberately, and carried rather than fixed.

An entry here is a claim that something is safe to defer. Every entry has to say
why. If an entry cannot answer "why is this safe to defer" in terms of the
security contract, it does not belong here — it belongs in
[Unclassified](#unclassified--not-deferred) below, or in a fix.

This file does not decide what MNDe claims. It records what MNDe does not do, so
that a reader comparing the claims to the code finds the gap already named.

Every entry was verified against the code on the date recorded. Re-verify before
relying on one: an entry is a snapshot, not a guarantee that nothing moved.

---

## KI-001 — Test and demo sidecars share one fixed port

**Recorded:** 2026-09-21 · **Component:** `executor/sidecar-harness.mjs`

Several suites start a real sidecar bound to `127.0.0.1:8787`. Two suites that
overlap on that port fail each other, so a red run may be contention rather than
a defect.

**Production impact:** none. The harness states in its own header that it is a
test and demo harness and not part of the executor's public API. A production
sidecar binds `MNDE_BIND_PORT` and an executor points at `MNDE_SIDECAR_URL`;
8787 is a default, not a constant.

**Security impact:** none, on two independent grounds. The harness passes a
per-start nonce and accepts readiness only from a responder that echoes it, so
an unrelated process already holding 8787 cannot silently become the system
under test. And the port is not the enforcement point in any case: the executor
refuses on an ALLOW string alone and requires an offline-verified receipt whose
own signed body says ALLOW and is bound to the request, so a process listening
on a port cannot manufacture an authorization.

**Why it is safe to defer:** it costs CI time and reviewer attention. It cannot
produce a wrong authorization decision, and it cannot make a failing run look
like a passing one.

**Workaround:** run the affected suites sequentially. `npm test` already does.

**Planned remediation:** ephemeral ports plus a bind retry in the harness.

**Target release:** unscheduled.

---

## KI-002 — The sample policies advertise an approval field no engine reads

**Recorded:** 2026-09-21 · **Component:** `sample-policies/`

`sample-policies/strict-production.json` and `sample-policies/balanced-ops.json`
list tools under a `requires_approval` key. No `.mjs` or `.ts` file in the
repository reads that key. Only `policy-editor/mnde-policy-editor.html`
understands it, converting it into engine rules on import.

**Production impact:** none directly — these files are policy-editor inputs, not
engine inputs, and no engine loads them.

**Security impact:** a reader who opens a file called "Strict Production", sees
`deploy_update` and `modify_config` listed as requiring approval, and assumes an
engine enforces that, is wrong. The risk is a mistaken belief about a guarantee,
not a bypass of one.

**Why it is safe to defer:** nothing in the enforcement path loads these files,
so no deployment's behaviour depends on this being fixed.

**Workaround:** treat `sample-policies/` as policy-editor input only. An engine
policy is the bundle the editor produces, not the sample.

**Planned remediation:** move them under a directory named for what they are, or
ship their compiled engine-schema equivalents alongside them.

**Target release:** unscheduled.

---

## KI-003 — The root manifest declares no licence

**Recorded:** 2026-09-21 · **Component:** `package.json`

The root `package.json` has no `license` field. `executor/package.json` declares
`SEE LICENSE IN ../LICENSE`; the root does not.

**Production impact:** tooling that reads licence metadata from the manifest —
SBOM consumers, dependency scanners, procurement review — sees nothing declared.
`SBOM.md` reports it honestly as "Not declared in package.json" rather than
supplying the repository licence on the manifest's behalf.

**Security impact:** none.

**Why it is safe to defer:** a `LICENSE` file exists and governs. This is a
metadata gap, not a licensing gap.

**Workaround:** read `LICENSE`.

**Planned remediation:** `"license": "SEE LICENSE IN LICENSE"`, matching the
executor manifest. Left undone deliberately: it is a legal-facing string and the
maintainer's call, not a mechanical fix.

**Target release:** unscheduled.

---

## KI-004 — The release workflow has never completed a run

**Recorded:** 2026-09-21 · **Component:** `.github/workflows/release.yml`

Two independent things stop it, and fixing either alone is not enough.

The `release` GitHub Environment does not exist, so `release:verify-approval-gate`
fails the build job closed with "the 'release' environment does not exist ... so
the publish job would run unapproved".

And `package.json` is at `0.1.1` while the tag `v0.1.1` already exists on `main`
with a published release behind it. The workflow refuses to reuse an existing
tag, and the release gate requires the dispatched version to equal
`package.json`, so a dispatch cannot route around it without a version bump.

**Production impact:** no release can be cut through the approval-gated path.
The two existing releases were tagged and published by hand, before this
workflow existed.

**Security impact:** none. Both failures are refusals. Nothing publishes
unapproved; the gate errs toward not releasing.

**Why it is safe to defer:** it blocks releasing, not running. Nothing already
deployed depends on it.

**Workaround:** none that preserves the guarantee. Publishing by hand is what
this workflow exists to replace.

**Planned remediation:** create the environment with a required reviewer and a
`main` deployment-branch policy, bump the version, then dispatch once to
exercise the path end to end.

**Target release:** before any release is cut through automation.

---

## Unclassified — not deferred

These are **not** known-issue entries. Each is a real finding whose
classification depends on a decision that has not been made, and each is listed
here so that the decision is visible rather than implied by silence.

Nothing may be moved from this section into the list above without the reason it
is safe to defer written out.

### UC-001 — The executor has no production posture gate

**Recorded:** 2026-09-21 · **Component:** `executor/index.mjs`

`assertTrustRoot` and `assertProductionPosture` are invoked from exactly one
place, `mnde-local-sidecar.mjs`. Under `MNDE_PROFILE=production` the sidecar
refuses to start on demo key material, without caller authentication, or without
an enforced signed-bundle policy engine.

The executor has no equivalent. Its verification inputs — authority bundle,
pinned root fingerprint, environment id, expected executor id — are all optional
and unset by default, and the executor-bound receipt schema is required only
when an expected executor id is configured. Left at defaults, verification falls
back to the repo-local demo authority and reports `REPO_LOCAL_AUTHORITY`. That
bundle ships inside the package, so the fallback resolves in a real install and
not only in a source checkout.

The production verification path is correct and does reject the demo manifest.
The gap is that nothing requires a deployment to be on it, and no startup error
says so.

**What it is not:** the authority id in a receipt cannot traverse paths — the
loader reads two fixed bundles and filters by matching id, and each manifest is
signature-verified against its own root key. No private key material is tracked
or shipped, and two separate guards scan the pack for private keys. This is not
a forgery path.

**Why it is unclassified:** protected execution is disabled, so this cannot
produce an unauthorized execution today. It is a blocker for a v1.0 that claims
a production execution path, and a deferrable gap for a v1.0 that claims
decisions, receipts and offline verification with execution held closed. The
scope decision has not been made.

### UC-002 — `approval_required` is inert without configured trust anchors

**Recorded:** 2026-09-21 · **Component:** `src/policy-engine/index.mjs`

A rule's `approval_required` is enforced only when approval trust anchors are
configured (`approvalEnforced = Boolean(approvalTrustAnchors)`), and anchors come
from one place, `MNDE_PE_APPROVAL_TRUST_ANCHORS`. With that unset, every
`approval_required` has no effect and the request is allowed, and the receipt
carries no `approval_enforced` field to mark the omission.

The source documents this as deliberate and a test asserts it as intended
behaviour.

**Why it is unclassified:** it is a configuration-dependent fail-open on the one
field whose purpose is to hold an action until a human signs off, which is a
Category A shape. It is also documented, tested and intentional, which is not.
Whether v1.0 may ship a policy field that silently does nothing when
unconfigured is a contract decision, not an engineering one.

The fix, if it is wanted, fails closed at startup rather than per decision:
refuse to load a policy that declares `approval_required` when no approval trust
anchors are configured.
