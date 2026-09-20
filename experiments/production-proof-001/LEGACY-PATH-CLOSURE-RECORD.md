# Legacy Path Closure Record — Production Proof 001, Phase 2 (F-001)

Date: 2026-09-18. Branch: `codex/production-proof-phase2-f001`.
Frozen source under proof: `exp-001-stage2-frozen` = `7de01634ca7b7e180574c756472885cffadc187f`.

**Status: F-001 NOT globally closed. Bounded holding action completed and
documented.** This is the Phase 2 deliverable required by the spec (§26). It
records exactly what was closed, what was hardened, and one systemic finding that
is a separate decision. It asserts no production readiness and does not advance
past Gate 2 to a global-closure claim.

Read alongside the detailed audit: [`f001/AUDIT.md`](f001/AUDIT.md).

---

## 1. What was established (bounded)

### 1a. Product path: upstream spawn + forwarding removed (audit E05/E06)
The MCP proxy (`mcp/mnde-mcp-proxy.mjs`) previously started an operator-configured
upstream with inherited environment **before** authorization and forwarded
discovery/lifecycle messages without consuming a claim. It is now a deployment-hold
stub: no child process, no transport, no credential client, no forwarding callback.
Discovery exposes only a local `mnde_proxy_status` tool; every protected tool call
refuses fail-closed with `ERR_FRESHNESS_DEPLOYMENT_DISABLED`.

Evidence: [`f001/test_f001_proxy.mjs`](f001/test_f001_proxy.mjs) +
[`f001/test_f001_local_status.mjs`](f001/test_f001_local_status.mjs) — **5 pass / 0 fail**.
Before/after captures under [`f001/evidence/`](f001/evidence/) (`f001-before` 0/4,
`f001-after` 4/0).

### 1b. Shipped-surface: raw upstream-spawn capability removed (audit E07/E14)
The published npm artifact no longer contains the raw MCP stdio **client**
(`mcp/stdio-client.mjs`, which spawns an arbitrary command with inherited
environment), the ungated demo upstream (`mcp/example-upstream-server.mjs`), the
simulated shell server (`mcp/shell-mcp-server.mjs`), or the three demo drivers
(`scripts/mcp-demo.mjs`, `scripts/mcp-proxy-demo.mjs`, `scripts/shell-demo.mjs`).
No shipped bin or runtime path (`mnde`, `mnde-sidecar`, the gated MCP server)
imports any of them; the exclusion orphans nothing shipped.

Change: `build/build-package.mjs` `EXCLUDE_FILES`.
Guard: [`tests/test_shipped_surface_bypass.mjs`](../../tests/test_shipped_surface_bypass.mjs)
(`npm run test:shipped-surface-bypass`) builds the package and asserts these files
are absent, that the shipped proxy contains no `spawn`/`child_process`/
`createStdioClient`/`createMndeExecutor`, that no shipped module imports the raw
client, and that the genuine product surface still ships — **5 pass / 0 fail**.

### 1c. Stale product tests reconciled to the deployment-hold contract
Two proxy/server suites that asserted the pre-disable "ALLOW forwards / executes"
contract were reconciled to assert the current, stronger deployment-hold contract
(discovery reveals no upstream; nothing is forwarded; a refused call never runs the
tool; refusal receipts still verify offline). No genuine refusal / non-execution /
verification assertion was removed.
- `tests/test_mcp_proxy.mjs` — **8 pass / 0 fail** (was 4/8).
- `tests/test_mcp_server.mjs` — **6 pass / 0 fail** (was 5/6).

Stage 2 offline suite unchanged: **82 pass / 0 fail**, exit 0 (not modified;
`exp-001-stage2` frozen per IRR).

## 2. Systemic finding (separate decision — NOT caused by Phase 2)

The frozen commit `7de0163` ("disable unproven dispatch and isolate freshness
claim boundary") **globally disables the decision path**: the sidecar
`/v1/decisions` endpoint returns `REFUSE / ERR_FRESHNESS_DEPLOYMENT_DISABLED` for
every request, before the policy engine is reached. Direct probe at the frozen
commit:

```
read_status decision = REFUSE  reason = ERR_FRESHNESS_DEPLOYMENT_DISABLED  engine = undefined
```

Consequence: a broad set of product test suites is **red at the frozen commit
itself**, because they still assert the pre-disable ALLOW/execute/receipt/reason-code
contract. This redness is **intentional (dispatch is deliberately disabled) and
pre-existing** — it is not introduced by Codex's Phase 2 proxy stub, and it is not
limited to the proxy. Measured on a fresh clone at `7de0163`, in the first 40 of 95
suites the run reached, at least these were red:

| Suite | Result at 7de0163 | Proxy-related |
|---|---|---|
| execution-ledger | 29/30 | no |
| ledger-anchor | 16/17 | no |
| ledger-auth | 20/22 | no |
| production-signing | 21/23 | no |
| authority-init | 5/6 | no |
| engine-default | 5/6 | no |
| sidecar-auth | 9/12 | no |
| executor-live-sidecar | 5/12 | no |
| sidecar-pe | 0/8 | partly |
| MCP server | 5/6 | yes (now reconciled → 6/6) |
| MCP proxy | 4/8 | yes (now reconciled → 8/8) |

**Implications, stated plainly:**
- The IRR-001 / IRR-002 "82 PASS / 0 FAIL" result covers **only** the
  `exp-001-stage2` offline suite. The frozen commit does **not** pass its own full
  product `npm test`, by design.
- These failures are stale-contract failures against an intentional disable, not
  newly introduced regressions.

**This is a decision, not something Phase 2 should silently resolve:** either (a)
re-baseline the entire product suite to the disabled-dispatch contract (green but
blesses permanent disable across security tests), or (b) treat the redness as the
signal that dispatch must be re-enabled **behind the mandatory claim-consuming
executor boundary** — which is the real F-001 goal and, per the audit, requires
deployed credential-custody/claim infrastructure not present in this repository.
No option was taken here; the finding is recorded for that decision.

## 3. What remains open (from `f001/AUDIT.md`)

- **E07/E10 direct-import source capability.** The raw stdio client and the
  injectable offline adapter still exist in the **source checkout** for demos and
  tests. Removing them from the package (§1b) does not remove them from code with
  the same OS rights; the audit is explicit that a same-process wrapper or flag
  would not isolate authority.
- **E13/E18/E22 deployment-level.** The DB-claim backend, external signer
  (`spawnSync`), and real provider credential custody have **unproven** deployment
  behavior; the repository ships no deployed executor service, ACL evidence, or
  independent claim infrastructure.
- **F-002 and target/base-state binding** remain outside this patch.

## 4. Gate 2 decision (spec §27)

> Gate 2: legacy path remains capable of bypass → stop, remove bypass.

The legacy **upstream-forwarding** bypass is removed from both the product proxy
(§1a) and the published package (§1b), and locked by a guard. But per §3, a global
"legacy path cannot produce the protected effect" claim is **not** established
(direct-import and deployment-level paths remain, and there is no enabled mandatory
claim-to-executor boundary). **Do not record F-001 as globally closed or advance to
Phase 3 on the basis of this record.** The bounded holding action is complete.

## 5. Reproduce

```bash
node experiments/production-proof-001/f001/test_f001_proxy.mjs
node experiments/production-proof-001/f001/test_f001_local_status.mjs
node tests/test_mcp_proxy.mjs
node tests/test_mcp_server.mjs
npm run test:shipped-surface-bypass
node experiments/exp-001-stage2/run-tests.mjs   # unchanged: 82/0
```

## 6. Changes in this record's scope

Modified: `mcp/mnde-mcp-proxy.mjs` (Codex, stub), `mcp/README.md` (Codex, hold
notice), `build/build-package.mjs` (shipped-surface exclude), `tests/test_mcp_proxy.mjs`
and `tests/test_mcp_server.mjs` (reconciled), `package.json` +
`tests/expected-test-scripts.json` (register the guard).
Added: `tests/test_shipped_surface_bypass.mjs`, `experiments/production-proof-001/f001/*`
(Codex evidence), this record.
No Stage 2 test was changed. Nothing was committed or pushed by this record.
