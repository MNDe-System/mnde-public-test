# Known issues

Problems that are real, recorded deliberately, and carried rather than fixed.

An entry here is a claim that something is safe to defer. Every entry has to say
why. If an entry cannot answer "why is this safe to defer" in terms of the
security contract, it does not belong here — it belongs in
[Unclassified](#unclassified--not-deferred) below, or in a fix.

A finding that gets fixed is not deleted. It moves to
[Resolved](#resolved) with the commit that closed it, so the record that the gap
existed survives the fix.

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

## KI-005 — Live-sidecar suites fail intermittently on `windows-latest`

**Recorded:** 2026-09-22 · **Component:** `.github/workflows/ci.yml`
(`Guardrails`) and the suites that start a live sidecar

Four runs across three days went red with one or two suites failing — a
different set each time, drawn every time from the suites that start a real
sidecar, on trees that pass everywhere else.

| Run | Head | Failing suites | Score |
| --- | --- | --- | --- |
| 212 | `3d070a8` on `main` | `test:freshness-boundary` | 98/99 |
| 256 | `ee4d404` on `main` | `test:ledger-auth` | 101/102 |
| 258 | `83abd54` on `chore/bump-0.1.2` | `test:sidecar-pe` | 101/102 |
| 262 | `b2c01c2`, same branch | `test:ledger-auth`, `test:sidecar-pe` | 100/102 |

Two of those are `main`'s own merge commits, and each one carried a **tree
byte-identical to the one that had just passed green** on its pull request
branch — `git rev-parse <commit>^{tree}` gives `1369cc5` for both `3d070a8` and
`fc836a21` (run 211, green, five minutes earlier), and `2e77ca2` for both
`ee4d404` and `ce6234f` (run 255, green). Same tree, one green and one red. The
other two are the four-file version bump in `chore/bump-0.1.2`, which changes no
code any failing suite reaches. Every suite named above starts a real sidecar and
talks to it over HTTP.

That branch going red twice in a row is worth answering directly, because two in
a row is what a real regression looks like. It is not one, on three independent
grounds: the same branch carrying the same lockfile change passed four times on
2026-09-21 (runs 234, 241, 249 and 253); `test:ledger-auth` also failed on `main`,
which does not carry that change; and the only mechanism by which a lockfile
could reach a sidecar suite — the `bin` entries it corrects — is ruled out by
reading, because `executor/sidecar-harness.mjs:65` spawns `process.execPath`
directly against `mnde-local-sidecar.mjs` rather than through any installed bin
shim. A `npm ci` from that lockfile on Linux links only `tsc` and `tsserver` and
runs 102/102.

One of the four names the mechanism outright. Every failure in `test:sidecar-pe`
asked for a specific approval refusal code and got the runtime's instead:

```
[FAIL] PE mode + missing approval -> REFUSE APPROVAL_REQUIRED
+ 'ERR_RUNTIME_DEGRADED'
- 'APPROVAL_REQUIRED'
```

That is the sidecar's own event-loop watchdog declining to evaluate policy
because the runtime looked unhealthy — correct production behaviour, reached for
the wrong reason. A shared Windows runner stalled the event loop past the
degraded threshold, and the watchdog does not clear for the life of the process,
so every later assertion in the suite failed too.

`test:ledger-auth` and `test:freshness-boundary` are consistent with the same
mechanism and do not prove it. Neither prints a reason code, so each records a
downstream effect rather than a cause: in `test:ledger-auth` the decision came
back carrying no ledger metadata at all, and the proof read that depended on it
then returned 404. **Confirmed for `test:sidecar-pe`; the leading explanation,
not an established one, for the other two.**

**This is not [KI-001](#ki-001--test-and-demo-sidecars-share-one-fixed-port).**
That entry is about two suites contending for a fixed port, and `npm test` runs
suites strictly sequentially precisely so they cannot. Here each suite has the
machine to itself and still loses the event loop; run 262's two failures were
minutes apart in the same sequential pass, not concurrent.

**Production impact:** none. The watchdog thresholds are production posture and
they did what they are for. What this affects is CI.

**Security impact:** none observed, and the reason is worth keeping. These suites
assert the *specific* reason code rather than merely that a refusal occurred, so
a degraded runtime makes them fail rather than pass for the wrong reason. A
suite that asserted only "this was refused" would have gone green here while
measuring nothing. Any new refusal assertion should keep that shape.

**Why it is safe to defer:** it turns green runs red, never red runs green. It
cannot produce a wrong authorization decision, and on the evidence above it
cannot make a failing run look like a passing one.

**What it costs:** with strict status checks and a required `Guardrails` check, a
run that lands on a stalled runner blocks a merge until the branch is updated and
CI runs again. Budget for that when cutting a release rather than reading it as a
regression.

**Workaround:** update the branch and let CI run again on the new head. Do not
re-run a job to make a red disappear without first reading which suites failed
and why; the four above name a different set each time, and a real regression
looks nothing like that.

**Planned remediation:** undecided, and deliberately so. Raising the watchdog
thresholds is not on the table — the threshold is the control. The two options
that weaken nothing are to have the sidecar harness record the runtime-health
transition and report it, so a red run says "the runner stalled" in one line
instead of needing a log read, or to carry it as it is. Neither is authorised.

**Target release:** unscheduled.

---

## Unclassified — not deferred

These are **not** known-issue entries. Each is a real finding whose
classification depends on a decision that has not been made, and each is listed
here so that the decision is visible rather than implied by silence.

Nothing may be moved from this section into the list above without the reason it
is safe to defer written out. A finding leaves this section in one of two ways:
it is classified, with that reason written out, or it is fixed — and a fixed one
moves to [Resolved](#resolved), not out of the file.

UC-001 left by the second route. See [Resolved](#resolved).

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

---

## Resolved

A finding recorded here and later fixed stays in the file. Deleting it would
remove the evidence that the gap existed, which is exactly what a reader
auditing MNDe's claims needs to see. Each entry keeps the original finding
word for word and adds what closed it.

### UC-001 — The executor had no production posture gate

**Recorded:** 2026-09-21 · **Resolved:** 2026-09-21 in `f50dd8f` (#43) ·
**Component:** `executor/index.mjs`

#### The finding, as recorded

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

#### What closed it

`src/executor-posture-preflight.mjs`, called from `createMndeExecutor`, is the
consumer-side half of the discipline the sidecar already had. Under
`MNDE_PROFILE=production` — read through `parseRuntimeProfile`, so a missing or
unknown value never implies production — construction **throws** unless all of
the following are true:

- an authority bundle is explicitly configured, and
- that bundle actually loaded (a configured-but-unreadable bundle is a
  violation, not a silent fallback), and
- the bundle is not dev or demo key material, and
- a root fingerprint is pinned, and
- an expected executor id is configured with executor binding required, and
- an environment id is configured.

It refuses with `ERR_EXECUTOR_PRODUCTION_TRUST_ROOT_REQUIRED`,
`ERR_EXECUTOR_PRODUCTION_DEMO_TRUST_ROOT` or
`ERR_EXECUTOR_PRODUCTION_EXECUTOR_BINDING_REQUIRED`. Outside an explicit
production profile it is inert, so development and test behaviour is unchanged.

The same change closed a second hole found while red-casing the first: a
production-signed, executor-bound envelope could carry an **inner** decision
signed by the repo-local demo authority and still report `verified: true` with
an outer `ROOT_PINNED_AUTHORITY_BUNDLE` trust source. Under production posture
the executor now refuses a verification result whose outer **or inner** layer
rests on `REPO_LOCAL_AUTHORITY`, and `tools/verify.mjs` qualifies the CLI
verdict on either layer. That required the production signing key, so it was
trust-mixing and misconfiguration rather than remote forgery — but it was real,
and the original entry did not know about it.

**What it does not do.** It does not enable execution. A fully verified,
correctly bound ALLOW receipt still returns `REFUSE` with
`ERR_FRESHNESS_DEPLOYMENT_DISABLED`. F-001 is untouched by this: the posture
gate decides *whose* signature the executor will accept, not whether a
signature may be presented twice.

**Scope note.** The entry's "why it is unclassified" paragraph turned on a
decision that has since been made: v1.0 will include a real production execution
path, so the finding was Category A rather than deferrable, and it was built
instead of classified.
