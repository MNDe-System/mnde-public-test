# Product-experience audit and plan: the first-run `git.push` experience

Scope: what a solo developer or small team meets when they try to put MNDe in
front of an AI agent's Git push. Written from the repository at the commit that
introduced this file. Everything marked **verified** was read in source or run;
everything marked **not verified** was not. Nothing here was run against a live
Hub, a production executor, PostgreSQL, or GitHub.

Method: documentation and source read first (`README.md`, `docs/MNDE-HUB.md`,
`docs/FIRST-PRODUCTION-GIT-PUSH.md`, `docs/GIT-PUSH-CLI.md`, `docs/KNOWN-ISSUES.md`,
`bin/`, `src/effects/git-push/`, `src/hub/`, `src/onboarding/`, `desktop/`),
then repository-wide searches for the components the brief names, then the
static security guards in `tests/test_git_push_reachability.mjs` and
`tests/test_git_push_cli.mjs`.

## 1. Architecture inventory

| Component | Exists | Tested | Deployed | Production-ready | Notes |
| --- | --- | --- | --- | --- | --- |
| Policy engine, signed receipts, offline verifier | Yes (`src/policy-engine`, `src/execution-gate`, `tools/verify*.mjs`) | Yes, many suites | Local sidecar only | Pilot. Stable published authority bundle does not exist yet (README). | |
| Execution Firewall = decision + gate | Yes (`mnde-local-sidecar.mjs`, 1,988 lines) | Yes | Local | Pilot | README banner says protected execution is on hold "pending durable single-use redemption". That sentence predates the typed `git.push` executor and does not say it excludes it. |
| Preflight / Orbit / ARM / RAMONA | Yes (`preflight/`, `orbit/`, `arm/`, `ram0na/`) | Not individually audited here | Not verified | Not verified | Not read in depth. Not imported by the `git.push` CLI, startup or executor files that were read. |
| Typed `git.push` executor | Yes (`src/effects/git-push/`) | Yes: effect, CLI (35), isolation, single-route, reachability (14 static), evidence, credential custody, first-run | Not verified | Operator runbook exists; F-001 stays open (`docs/FIRST-PRODUCTION-GIT-PUSH.md`) | The strongest part of the product. |
| GitHub App credential provider | Yes (`credential-provider.mjs`, kind `github-app`) | Yes (custody suite) | Real App created by hand per runbook; not verified here | Per runbook | Mints a per-push installation token and revokes it. |
| PostgreSQL claim store | Yes (`src/freshness/postgres_claim.mjs`, `deployment/freshness/`) | CI uses a test double; a real PG 16 run is recorded in `docs/F001-*` | Not verified | Open items in `docs/KNOWN-ISSUES.md` / F-001 | `pg` is an operator-installed runtime adapter, not a dependency. |
| Single-use authorization | Yes (claim + grant nonce + executor-bound receipts) | Yes | n/a | As above | |
| Evidence and verification | Yes (`evidence.mjs`, `scripts/verify-git-push-evidence.mjs`, `verifier/*.html`) | Yes | n/a | Offline verify works | A browser verifier page exists (`verifier/mnde-receipt-verifier.html`); not evaluated. |
| MCP server / proxy | Yes (`mcp/`) | Yes | n/a | Proxy fails closed; execution on hold per README | `mnde init` rewrites MCP client configs to put the proxy in front. |
| Client discovery for onboarding | `claude-desktop`, `cursor`, `project-mcp` only (`src/discovery/index.mjs`) | Yes (`test:onboarding`) | n/a | Works on fixtures | **No Codex, no Claude Code, no Gemini.** |
| Hub service | Yes: headless Node service, loopback `127.0.0.1:8790`, typed `git.push` only (`src/hub/`) | Yes (17 tests; PG replaced by a test adapter) | Not verified | **Prototype.** Pi hardware, real PG/TLS, systemd, power-loss are listed acceptance blockers in `docs/MNDE-HUB.md` | `GET /v1/events` is observational, capped at 100, lost on restart. |
| Approval of a push | Library only: `signApproval()` in `src/policy-engine/authenticated-approvals.mjs`; `scripts/authorize-git-push.mjs` for the first run | Yes (library, Hub test) | n/a | n/a | **I found no shipped CLI or UI that produces an approval artifact for the Hub's `/approve` route** (grep-based; confidence medium). |
| Desktop dashboard | Yes: one static file, reads the **sidecar's** status endpoints (`desktop/dashboard.html`) | `test:dashboard` | Served by the sidecar | Read-only | It does not read the Hub or the `git.push` executor. |
| Physical button, OLED, GPIO, device pairing, device discovery | **No.** Only a prose "future work" paragraph in `docs/MNDE-HUB.md` | No | No | n/a | Do not describe as present. |
| iPhone / mobile interface, notifications | **No** | No | No | n/a | |
| Codex / Claude / Gemini activity hooks, agent activity reporting | **No** | No | No | n/a | Searches for `gemini`, `codex.*hook`, `claude.*hook` found nothing relevant. |
| Approval inbox, activity timeline, evidence explorer UI | **No** | No | No | n/a | |
| Installer | **No.** Source checkout only (`installer/README.md`) | Release-contract CI job | No | n/a | |
| CI | Yes (`.github/workflows/ci.yml`, Windows runner, Node pinned to 24.14.1) | n/a | n/a | n/a | Newer Node 24.x trips an undici teardown assert in fetch-based suites (documented). |
| Diagnostics | `mnde-sidecar doctor` (sidecar only); **nothing for `git.push` before this change** | | | | |

## 2. Product-experience audit

The first real experience is `docs/FIRST-PRODUCTION-GIT-PUSH.md`: ten numbered
steps, three scripts, a hand-built GitHub App, a hand-built PostgreSQL 16 server
with TLS, and thirty-plus environment variables. It is honest and careful. It is
also an operator procedure, not a product.

What the user cannot currently do, with evidence for each:

1. **Know whether their setup works before spending a one-use authorization.**
   The only test is to run the push. A bad claim config, an unreadable
   credential file or an expired executor credential surfaces as `STARTUP_FAILED`
   or a refusal after the user has already approved something.
2. **See the exact proposed operation and say yes or no.** Approval is "run
   `authorize-git-push.mjs` with six values". There is no request inbox and no
   refusal path a human can take; the Hub's refuse route is for operators.
3. **Watch what an agent is doing.** No agent reports into MNDe; only an agent
   that calls the Hub or CLI is visible, and then only through a 100-event
   observational buffer.
4. **Read evidence without JSON.** Verification is a script and an HTML page.
5. **Connect Codex, Claude Code or Gemini.** `mnde init` only edits MCP client
   configs for three clients, and that path wraps MCP tools; it does not put the
   typed `git.push` executor behind an agent's `git push`.
6. **Tell what the README is claiming.** The top banner says execution is
   disabled; the runbook walks to a real push.

## 3. Ranked usability problems

Ranked by (damage to a first-time developer) x (likelihood), then by how cheaply
and safely it can be fixed.

| # | Problem | Evidence | Fix class | Security risk of fixing |
| --- | --- | --- | --- | --- |
| 1 | No pre-flight check: setup mistakes are discovered by attempting a push | `bin/mnde-git-push.mjs` has no diagnose mode; failures are exit 4 after approval | Read-only diagnostic | Low if it reuses the executor's own startup and `readiness()` and cannot execute. **Done in this change.** |
| 2 | Executor credential expires after 7 days by default and nothing warns | `prepare-git-push-trust` default TTL; runbook step 1 | Same diagnostic | Low. **Done in this change.** |
| 3 | No human-facing approval step (inbox, exact-action view, approve/refuse) | grep: no approval-producing CLI or UI | New surface bound to existing `signApproval`/Hub `/approve` | **High**: it holds or invokes an approval key. Needs its own design and key-custody review. |
| 4 | Agent integrations absent: nothing makes an agent's push go through the executor | discovery lists 3 MCP clients | Per-agent integration work | High: the claim that a path is enforced requires removing other credentials (`MNDE-HUB.md`: "does not make MNDe non-bypassable"). |
| 5 | The desktop dashboard shows sidecar health, not `git.push` / Hub state | `desktop/README.md` endpoint list | Hub-backed status page | Medium: must stay read-only and credential-free. |
| 6 | Conflicting top-level status messaging (execution "disabled" vs a documented real push) | `README.md` banner vs runbook | Documentation | None, but it must be reconciled by the maintainer who knows the intended claim. Not changed here. |
| 7 | Evidence is JSON plus scripts | `verifier/`, `scripts/verify-git-push-evidence.mjs` | Evidence view over the existing verifier | Medium: must show only what the verifier checked. |
| 8 | Installation is a source checkout, `npm install --no-save pg`, hand-built PG | `installer/README.md`, runbook step 3 | Packaging / scripted PG provisioning | Medium: "do not migrate production state without reviewed plans". |
| 9 | No timeline: Hub events are capped, observational and lost on restart | `docs/MNDE-HUB.md` | Durable event log | Medium: events must stay non-authoritative. |
| 10 | OLED / buttons / pairing / mobile are future work | `MNDE-HUB.md` | Hardware program | High: GPIO must use the same lock mechanism; never a second one. |

## 4. Security impact assessment

Preserved by this change: fail-closed authorization, independent execution,
exact-action binding, single-use claims, executor-owned credentials, durable
records, signed receipts, offline verification, role separation.

The increment adds one process, `mnde-git-push-doctor`. Its boundary is enforced
by tests, not by intention:

- It constructs the executor (`createGitPushExecutor`, one site) and calls its
  `readiness()` (one site). It never calls `executeGitPush`. Both facts are
  asserted statically (`test_git_push_doctor.mjs`, K) and dynamically: a
  test-only preload counts executions across the child process and the suite
  requires zero, zero pushes received by the remote, and no change to the claim
  directory, evidence directory, working tree or remote ref.
- It adds no spawn, no network call of its own, no file write, and no read of a
  push credential. `readiness()` is the query the Hub already runs for `/readyz`
  (`SELECT mnde_claim.bound_namespace()` plus a durability check). It writes no
  claim.
- It names no credential-config variable and imports neither the credential
  provider nor the transport, so guards 1 and 7 of
  `test_git_push_reachability.mjs` pass unchanged (14/14).
- It does change one guard: `test_git_push_cli.mjs` case K asserts which files
  may name `createGitPushExecutor`. The doctor library is added to that list
  explicitly, with its own guard test. A reviewer should read that diff line.
- Output carries variable names, executor and environment ids, a 16-character
  root fingerprint prefix, expiry times, and the executor's own error text,
  which is additionally scrubbed of PEM blocks and GitHub token shapes. Tests
  plant a secret in a password file and the executor key and assert neither
  appears in stdout or stderr.
- **A false-assurance risk is the real hazard.** A green diagnostic can be
  mistaken for "protected". The report therefore never prints "protected" or
  "secure", marks what it cannot test as `NOT_VERIFIED` (live credential,
  and the existence of other credentials that bypass MNDe), and a test asserts
  the wording.

Residual: doctor connects to the configured claim database with the executor's
own login. That is a read-only query, but it is a connection to production state
if the environment points at production. It is run by the operator, in the
operator's shell, with the operator's configuration.

## 5. Phased plan

Order follows the brief (P0 -> P3) and the dependency that nothing downstream
should be built before the enforced path is real.

**P0, first-run reliability** (no new authority surface)
1. `mnde-git-push-doctor` (this change).
2. Reconcile the README status banner with the `git.push` path. Maintainer
   decision: what is the claim?
3. A scripted, reviewed `mnde-git-push` environment check inside
   `prepare-git-push-trust` output (print the doctor command as the next step).
4. Hub: expose the same doctor report on an authenticated read-only route.
   Needs a decision on whether status belongs in `/v1/status`.

**P1, one connected surface** (needs key-custody design first)
5. Approval tool: an authenticated way to see one request's exact bound values
   and sign or refuse it, built on `signApproval` and the Hub's existing
   `/approve` route. Design review of where the approval key lives is the
   prerequisite, not a footnote.
6. Hub-backed status/inbox page, read-only except through (5).
7. Durable, non-authoritative event log; timeline over it, with an evidence
   class on every row (REQUESTED / AUTHORIZED / REFUSED / EXECUTED / VERIFIED /
   INDETERMINATE), never merging authorization and execution.

**P2, developer efficiency**
8. Evidence view over the existing verifier, showing exactly the properties it
   checks.
9. Agent integrations, one at a time, each with an "installed vs enforced"
   distinction. Enforced requires the repository to refuse every other pusher.
10. Structured, safe refusal responses to agents, mapped from existing codes.

**P3, polish**: mobile approval, notifications, OLED/GPIO via the same lock,
localization, optional compact rendering.

Rule from the brief that applies here: do not start P2/P3 while a P0 security or
installation blocker is open. F-001 remains open per the runbook.

## 6. The smallest increment, and what it improves

`mnde-git-push-doctor` answers "what would stop my push?" before any authority
is spent: it separates `NOT_CONFIGURED`, `FAILED`, `ATTENTION`, `READY` and
`NOT_VERIFIED`, names the fix for each, and states plainly that passing is not
a protection claim. See [`GIT-PUSH-CLI.md`](GIT-PUSH-CLI.md#diagnosing-your-setup-mnde-git-push-doctor).

What it does **not** do: it does not make the first run shorter, does not
create any trust material, does not touch the approval problem (#3), and does
not measure anything about users. Claimed improvement is limited to: a class of
setup mistakes now fails with a named fix before an authorization is consumed.
No user study was run.

## 7. Measurement (not done; proposed)

To support the brief's definition of done, the following should be measured with
real first-time developers, locally, without third-party telemetry: time from
checkout to first doctor pass; time from doctor pass to first verified push; the
number of failed attempts and their reason codes (already structured as exit
codes 1-7 and `reason_code`). None has been measured.
