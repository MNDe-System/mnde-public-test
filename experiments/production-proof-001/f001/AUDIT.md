# F-001 Phase 2 investigation and bounded remediation

Date: 2026-09-18. **F-001 remains OPEN under the supplied closure criteria.**

The disabled MCP proxy had an alternate authority path: it started an arbitrary
configured upstream with inherited environment authority before authorization,
then forwarded discovery, resource/prompt inspection and lifecycle messages
without consuming a claim. A real proxy process and a harmless local upstream
reproduced this; no refusal was removed, no claim mechanism was mocked, and no
GitHub request or live credential was used. This is a demonstrated process and
credential-transfer weakness, **not evidence of a completed GitHub merge**.

The remediation removes upstream creation and forwarding from the proxy. The
same four assertions now pass. The remaining direct-import capability and absent
deployment boundary prohibit a global closure claim. Disabling execution does
not deliver the requested enabled, mandatory claim-to-executor architecture.

## 0. Safety and source state

| Item | Observed before code changes |
| --- | --- |
| Repository | `C:\Users\Shadow\Downloads\INsol\mnde-public-test` |
| Remote | `https://github.com/MNDe-System/mnde-public-test.git` (fetch and push) |
| Starting branch | `codex/exp001-freshness-boundary-20260917` |
| Starting HEAD / IRR evidence commit | `2f941741b8b44f177ead69610595f510efc30873` |
| Starting status | `git status --porcelain=v1` empty |
| Frozen tag dereferenced | `exp-001-stage2-frozen^{}` = `7de01634ca7b7e180574c756472885cffadc187f` |
| Phase 2 branch | `codex/production-proof-phase2-f001`, created from starting HEAD |
| Node / npm / Git | `v24.14.1` / `11.11.0` / `2.53.0.windows.2` |
| Execution environment | Windows, PowerShell; same host as IRR-001 |
| Baseline command | `node experiments/exp-001-stage2/run-tests.mjs` |
| Baseline result | 82 PASS, 0 FAIL, exit 0; 13 / 12 / 8 / 3 / 14 / 19 / 5 / 8 |

The initial baseline was run before code investigation. A second, captured run
before remediation has byte-identical stdout to IRR-001, SHA-256
`f3da25ef51bd36fcd726ac567dade7b2fde3afec7086b22a84e742883c1a7f89`.
SQLite emits its existing experimental warning. No install was needed.

No tag creation/movement, history rewrite, commit, push, real credential reads,
or live provider calls occurred. Existing Stage 1, Stage 2 and IRR-001 bytes were
preserved. The supplied request ends at “Run the F-001 test before remediation”;
its opening instruction also explicitly authorizes remediation and verification.

## 1. Protected execution class

Stage 2's concrete action is `github.pull_request.merge`. `buildMergeRequest`
constructs `PUT /repos/{owner}/{repo}/pulls/{number}/merge` from a verified
declaration, carrying the approved head SHA and merge method. **There is no
enabled production GitHub HTTP transport or provider-token loader in this
checkout.** Its public `createAdapter().attemptMerge()` refuses unconditionally.

For this audit, a protected execution is a production-capable transfer of control
to a caller-supplied `run` callback through `createMndeExecutor().execute`, or to
an operator-configured upstream through the MCP proxy's
`createStdioClient` / `upstream.request` / `upstream.notify` path, where that
callback or upstream can perform the protected mutation. Starting the configured
upstream is part of authority acquisition: its startup code already runs with
the parent's privileges and inherited environment. It need not wait for
`tools/call`. The narrower Stage 2 merge is one possible upstream action, not an
implemented live provider integration established by this repository.

Policy evaluation, receipt/grant signing, local receipt/index/ledger writes,
configuration installation and simulated shell output are not GitHub merges or
protected tool dispatch. They are enumerated below because they possess local
authority or can be mistaken for execution. Arbitrary signer executables and
external upstream implementations cannot be certified from their names.

## 2. Audit method and execution-path matrix

Audited the tracked source by content, not filenames alone: process/network
primitives, `run`/dispatch calls, environment/credential reads, exports, local
mutations, retries, timers and workers. `evidence/source-inventory.json` binds
295 tracked source/script files to post-fix hashes and candidate line numbers.
It is an index, not a proof of exhaustive dynamic behavior. Manual tracing
covered `bin`, `scripts`, `executor`, `mcp`, `src`, `sidecar`, the top-level
sidecar, `audit`, `shared`, `arm`, `orbit`, `ram0na`, experiments and tests.
Build inclusion was checked in `build/build-package.mjs`; arbitrary dynamic
operator commands remain explicitly unknown.

The following two tables join by ID and together provide each route's entry,
file, exported symbol, caller, next call, authorization, claim, consumption,
authority, final effect, production/direct/legacy/test reachability, failure
behavior and classification. Paths are repository-relative. A `DEAD` label is
relative to **protected provider execution**, not a claim that a local evaluator
or receipt writer never runs. No enabled production route earns `PROTECTED`.

| ID | File / entry / exported symbol | Caller → next call → terminal operation | Authorization / claim / consumption |
| --- | --- | --- | --- |
| E01 | `mnde-local-sidecar.mjs`, `handleDecision` (not exported), `/v1/decisions` and decision aliases | HTTP route → strict input/admission/auth checks → `fail(ERR_FRESHNESS_DEPLOYMENT_DISABLED)` → receipt/response | Sidecar caller auth; no atomic claim; no consumption or provider dispatch |
| E02 | `src/execution-gate/index.mjs`: `evaluateExecutionGate`, `authorizeAndSign`, `replayExecutionGate` | Importer → schema/hash/hard gates → receipt builder / signer | Policy/principal/approval checks; no Stage 2 claim; returns evidence, not a provider call |
| E03 | `executor/index.mjs`: `createMndeExecutor`, returned `execute` and `wrapTool` | Importer / MCP server → `askMnde` → offline receipt verification → `authorizeExecution` → refusal | Exact action/input/execution ID and configured trust bindings; no claim; no `run()` invocation remains |
| E04 | `mcp/mnde-mcp-server.mjs`: `handleToolCall` (not exported) | stdio tools/call → `mnde.execute({run:()=>tool.run(args)})` → E03 refusal | E03; callback never reached; no consumption |
| E05 | `mcp/mnde-mcp-proxy.mjs`, startup (not exported), PRE-FIX | Config/wiring → `createStdioClient(upstreamCommand,upstreamArgs,{})` → `spawn` → arbitrary upstream startup | **None** before spawn; no claim; no consumption |
| E06 | Same proxy, `handle` / `gateToolCall`, PRE-FIX | Agent → allowlisted `upstream.request` / lifecycle `upstream.notify` → `child.stdin.write` → arbitrary upstream handler; tools/call instead used E03 | Inspection/lifecycle had **no** authorization/claim; unknown methods had allowlist refusal; tools/call callback blocked by E03 |
| E07 | `mcp/stdio-client.mjs`: exported `createStdioClient` | Direct source/package importer → `spawn`; returned `request`/`notify` → `child.stdin.write` | No authorization or claim parameter/check/consumption |
| E08 | `experiments/exp-001-stage2/src/adapter.mjs`: `createAdapter` / `attemptMerge` | Any importer → constant refusal | No authority acquired; no callback/backend read or claim; no terminal mutation |
| E09 | `tests/support/offline_freshness_adapter.mjs`: `createOfflineAdapter` in supplied tests | Stage 2 tests → `buildMergeRequest` → `deriveClaimRecord` → `claimAuthority` → recording transport | Production-verification brand; claim before callback; SQLite single INSERT for supported model; no production credentials |
| E10 | Same `createOfflineAdapter`, arbitrary privileged direct import | Caller supplies transport and backend → same pipeline → arbitrary transport callback | Verification requires caller-configured anchors; backend is injectable, so no mandatory trusted durable store for this use |
| E11 | `experiments/exp-001-stage2/src/declaration.mjs`: `verifyDeclaration` / `testOnlyVerifiedDeclaration`; `build_request.mjs`: `buildMergeRequest` | Importer → snapshot, layered verification, private brand → frozen request construction | Verification and identity binding; no consumption, credential loading or dispatch; test-only brand insufficient for adapter |
| E12 | Stage 2 `freshness.mjs`: `claimAuthority`; `claim_store.mjs`: SQLite/file/in-memory backend factories | Offline adapter/tests → health → claim → at most one uncertainty lookup | Model claim uses namespace and independent execution/grant uniqueness; no provider egress; unsafe file model retained for atomicity negative control |
| E13 | `src/freshness/postgres_claim.mjs`: `openExecutorClaimBackend` | Unwired direct factory → config → dynamic `pg` import → TLS primary → SQL `first_claim` → COMMIT | Rejects arguments/config substitution; server namespace; durable ack intended; no production dispatcher caller |
| E14 | `mcp/guarded-tools.mjs`: `defaultGuardedTools`; `mcp/example-upstream-server.mjs` handlers; `shell-mcp-server.mjs`: `runCommand` | MCP demo/server or direct import → demo callback → marker file / simulated result | Shell policy/signature check for simulation; example raw server intentionally ungated; **no actual shell or GitHub transport** |
| E15 | `sidecar/replay_engine.mjs`: `replayReceiptDeterministically`; sidecar replay handlers; `audit/node_runtime.ts`: `executeDeterministicPipeline` | Replay HTTP/tests → verify → deterministic engine → compare hashes / receipts | Receipt authenticity; replay may disable local execution-ID enforcement; no provider callback or tool invocation |
| E16 | `sidecar/deterministic_worker_pool.mjs`: `DeterministicWorkerPool`; `deterministic_worker.mjs` | Sidecar queue → Worker message → deterministic evaluator; timeout/replacement → worker state handling | Work scheduling only; no protected dispatcher in worker; no claim; no external mutation retry |
| E17 | `src/custody/index.mjs`, `executor-identity.mjs`, `authority-signing/index.mjs`, `src/grants/issue.mjs` exported loaders/signers | Sidecar/startup/admin/importer → load keys → sign receipt/grant/ledger | Key/trust/identity checks; keys exist before any claim; signs evidence, does not mutate GitHub |
| E18 | `src/custody/external-signer.mjs`: `createExternalSignerCustody`; `root-signer.mjs`: `createExternalRootSigner` | Custody/admin caller → returned `sign` → `spawnSync` operator executable | Signing response verified, but executable starts before output verification; no execution claim; arbitrary implementation outside repo |
| E19 | `src/execution-ledger/sidecar.mjs`: `recordReceiptInLedger`, `anchorNow`; receipt stores/index, policy activation, audit bundle | HTTP/admin/timer → filesystem/SQLite/signing → local ledger/index/config/bundle writes | Relevant endpoint auth and storage checks; no Stage 2 claim; no protected tool dispatch |
| E20 | `src/wiring/index.mjs`: `wrapServer`, `applyPlan`, `uninstall`; sidecar CLI/launcher/harness and reviewer scripts | Operator CLI → client config writes / fixed sidecar startup / loopback HTTP | Operator-local trust; `wrapServer` copies original env before claim; not itself provider dispatch; wires E05/E06 |
| E21 | `sidecar/graceful_shutdown.mjs`: `createGracefulShutdown` / phase callbacks | Sidecar shutdown → `phase.run(signal)` → quiesce/flush/close | Lifecycle callbacks, not tool callbacks; no protected action queue found |
| E22 | Deployed GitHub credentials, upstream SDKs, independent executor OS/service identities | Operator deployment → unknown external clients/services | No deployment manifest proving exclusive provider credential custody or a mandatory enabled dispatcher |

| ID | Authority acquisition / final effect | Production reachable | Direct import access | Legacy reaches | Tests reach | Failure behavior | Classification before → after |
| --- | --- | --- | --- | --- | --- | --- | --- |
| E01 | Signing context at startup; receipt/response only | Yes, endpoint; not protected effect | Script starts server | Yes, both engines | Yes | Refuses approval | DEAD → DEAD |
| E02 | Optional supplied signing PEM; signed evidence only | Yes, exported | Yes | Yes | Yes | Schema/key errors refuse; pure ALLOW not dispatch | DEAD → DEAD |
| E03 | Sidecar bearer before request; caller retains raw callback authority | Yes, exported | Yes | Yes | Yes | Valid approval still refuses; no callback call site | DEAD → DEAD |
| E04 | Demo tool references exist before authorization; E03 blocks invocation | Yes, stdio | Script starts server; demo exports separate | Yes | Yes | Protected tool callback unreachable | DEAD → DEAD |
| E05 | Entire inherited env/OS rights at spawn; startup executes | **Yes** before; no spawn after | Script startup | Yes, wiring/proxy | New local surrogate | No claim boundary before startup | **BYPASS → DEAD** |
| E06 | Already-running credential-bearing upstream; request/notification may act | **Yes** before; local status only after | Script startup | Yes | New and existing tests | Allowed method names did not prove effect-free handlers | **BYPASS → DEAD** |
| E07 | `process.env` plus supplied env and parent OS privileges at `spawn`; raw process/stdio | **Yes, shipped exported helper**; no post-fix proxy caller | **Yes** | Demos/raw callers | Yes; explicit direct-import characterization | No claim refusal; process failures only | **BYPASS → BYPASS**, privileged caller capability |
| E08 | None; no transport | Public source experiment; excluded from package | Yes | No | Yes | Constant refusal even for valid declarations and fake backends | DEAD → DEAD |
| E09 | Synthetic keys/recording callback; temp claim-store writes | No, test harness, excluded from package | Test source available; E10 covers repurposing | No | Yes | Missing/uncertain/spent claim refuses | TEST-ONLY → TEST-ONLY (this harness use only) |
| E10 | Caller-owned arbitrary transport and backend; possible raw side effect | Not a shipped entry; possible from source with caller authority | **Yes** | No product import found | Injection exists by design | Caller backend can acknowledge without durable consumption | **BYPASS → BYPASS**, conditional privileged source capability |
| E11 | Public verification anchors; no provider secret | Source API only | Yes | Verifiers shared | Yes | Forged/copy/policy-only brands cannot dispatch | DEAD → DEAD |
| E12 | Local SQLite/file permissions; claim writes only | Source experiment; no production imports | Yes | No | Yes | At-most-once model; uncertainty sends nothing | DEAD → DEAD (provider effect); tested claim mechanism |
| E13 | `MNDE_CLAIM_CONFIG`, password/CA files; SQL service authority before claims | No wired executor; exported factory shipped | Yes | No | Invalid-config tests only | Config/primary/DB failure refuses; integration unproven | UNKNOWN → UNKNOWN (deployment) |
| E14 | Marker/exec-log path env; local file write / simulated status | Shipped demos, not protected external class | Yes | Yes | Yes | No guarantee on direct demo calls; not real deletion/restart/shell | DEAD → DEAD (protected external class) |
| E15 | Local evaluator/signing/storage; no provider client | Replay routes yes | Yes | Yes | Yes | Replay mismatch/errors reported, no redispatch | DEAD → DEAD |
| E16 | Worker shares runtime/storage trust; evaluation only | Yes | Class exported | Legacy evaluator | Yes | Timeout/failure yields evaluation failure | DEAD → DEAD |
| E17 | Env-configured role/executor PEM or signer closures; signatures | Yes | **Yes**, if same OS access | Yes | Synthetic fixtures | Key validation fails closed; not claim consumption | DEAD → DEAD for merge; authority accessible before claim |
| E18 | Operator argv and inherited OS/env authority at `spawnSync` | Yes when configured | **Yes** | Custody/admin | Synthetic signer tests | Signature verification cannot undo process side effects | **UNKNOWN → UNKNOWN** for arbitrary external executable behavior |
| E19 | File permissions and ledger signer; local operational writes | Yes | Yes | Yes | Yes | Storage/auth failures; independent of tool claim | DEAD → DEAD |
| E20 | Operator config/OS rights; preserves env in client config; local start/config writes | Yes | Yes | Yes | Yes | Not a claim boundary; patched proxy does not read forwarded upstream config | DEAD → DEAD for own operations; E05/E06 audited separately |
| E21 | Trusted runtime closures/local persistence handles | Yes | Export accepts callbacks | Yes | Yes | Deadline/flush failures surfaced | DEAD → DEAD |
| E22 | Provider credentials/OS/service deployment unobserved | Unknown | Unknown | Unknown | No | Not established | **UNKNOWN → UNKNOWN** |

E07 is not called by the patched proxy, but it is not honestly TEST-ONLY: the
build copies `mcp/`, and the public helper executes a supplied command. The
direct-helper experiment demonstrates local execution without a claim.
E10 likewise cannot acquire production authority by magic, but can be paired
with it by a privileged importer. Moving a module, adding a boolean flag or
testing `NODE_ENV` would not isolate authority from code with the same OS rights.
No other in-repository GitHub HTTP mutation client was found. That observation
does not resolve E18/E22 or prove completeness of an external deployment.

## 3. Authority ownership audit

| Source | Loader / who receives it | Available before claim? | Direct or unprotected access / agent access | Callback and test differences |
| --- | --- | --- | --- | --- |
| Upstream API/GitHub token supplied via client environment | `wrapServer` preserves `raw.env`; old proxy → `createStdioClient` merges `process.env` → child | **Yes**, startup | Child and same-user code could read it; protocol agent need not read token to trigger a handler. Patched proxy never creates child; parent environment custody still not proven | Child startup and handlers receive inherited env; tests use only `MNDE_F001_SYNTHETIC_AUTHORITY`, record a boolean |
| Provider token in upstream-owned config/SDK | Arbitrary configured upstream | Potentially | Repository cannot inspect external implementation or file ACLs; environment filtering alone would be insufficient | No such live client was configured or accessed |
| Sidecar bearer | `executor/bearer.mjs`: `resolveBearerToken` / `bearerAuthHeader`; executor captures it before `askMnde` | Yes | Exported helper and env readable in same process; authority is sidecar API, not itself GitHub | Sent only on decision HTTP; no run callback receives it from executor; patched proxy does not load it |
| Receipt/policy/approval/result/ledger/activation PEMs and passphrases | `createFileBackedProductionCustody` reads `MNDE_*_SIGNING_KEY` and role passphrases; `loadSigningConfig` returns provider closures | Yes, startup | Public loaders usable with same config/filesystem access; opaque handles protect API representation, not same-user file access | Signer callbacks hold keys, not protected-tool callbacks; tests generate fixture keys |
| Executor signing key | `loadExecutorSigner` → `readSecureExecutorPrivateKey` → `sign` closure; sidecar readiness | Yes | Outside-repo/symlink/permission checks exist; same authorized OS identity can call exported loader. Agent separation is deployment-dependent | Signs executor envelope, not provider API; synthetic credentials in tests |
| Root / external signer | `createFileRootSigner`, `createExternalRootSigner`, `createExternalSignerCustody` | Yes | Public factories, configured executable, inherited environment; external process effects unknown | Sign callback receives canonical payload; output verified after execution |
| Execution grants | `issueExecutionGrant`, grant verifiers, policy-engine nonce store | Issuance precedes execution by design | Signed artifact is transferable data, not a provider credential; raw signer access is separately material | Tests inject verifier/signer; policy grant nonce consumption is not Stage 2 execution+grant atomic consumption |
| Claim DB credentials | `openExecutorClaimBackend` reads config/password/CA; driver closure receives credentials | Yes, required to consume claim | Exported loader, operator files, no exclusive executor OS boundary demonstrated | Injection rejected; only invalid-config tests ran, no real DB connection |
| Local filesystem/process rights | Node process, `spawn`/`spawnSync`, operational writers | Always before claim | Same-user imported code has them; module-private brands cannot remove these rights | Temporary marker/claim files demonstrate mechanism without protected provider authority |

## 4. Refusal versus structural isolation

At the frozen baseline, sidecar `handleDecision` ends in
`ERR_FRESHNESS_DEPLOYMENT_DISABLED` (`mnde-local-sidecar.mjs:1116`), executor
`execute` ends in the same refusal (`executor/index.mjs:355`), and Stage 2
`attemptMerge` is a refusal-only body (`adapter.mjs:7`). **Removing these returns
alone does not expose a hidden executor**: the respective execution call sites
are absent. Existing verifier checks remain useful, but authentic receipts do
not imply claim consumption.

In contrast, old proxy lines 146–161 allowed lifecycle/discovery/inspection to
use an already-authoritative client. Its unknown-method refusal was load-bearing
for custom requests; removing it would broaden direct forwarding. The normal
tools/call gate did not protect startup or permitted methods. See the preserved
`evidence/proxy-before.mjs`. The fix removes the client import, creation,
forwarding methods, and callback, rather than adding another method-name guard.

No production enable flag exists in the new proxy. Its local status tool returns
constant state, never forwards arguments and never obtains upstream authority.
Direct helper/signing imports remain capabilities of privileged code; this patch
does not claim process isolation, credential isolation, or an enabled dispatcher.

## 5. Mechanically testable invariant

For any future enabled production path reaching the merge request's transport or
an authority-bearing upstream tool, `verifyDeclaration` must validate a current,
executor-bound signed ALLOW against deployment-owned trust configuration. The
fixed `buildMergeRequest` must derive from that authenticated snapshot.
`deriveClaimRecord` binds namespace, execution ID, grant ID, subject, executor ID,
receipt hash and canonical A+ digest. A trusted backend must atomically consume
both independent namespace-scoped execution/grant identities and acknowledge
durability **before control or usable provider authority reaches execution**.

| Condition | Required behavior |
| --- | --- |
| Missing/invalid claim or no trusted backend | No authority-bearing dispatch |
| Reused execution or grant ID, including changed action | SPENT, no dispatch |
| Subject/executor/action/namespace mismatch or forged brand | Refuse before dispatch |
| Expired or revoked authority | Revalidate at the actual execution boundary; refuse |
| Concurrent attempts | At most one acknowledged atomic claim and dispatch attempt |
| Lost claim ack / uncertain lookup / unavailable backend | No dispatch, no automatic retry |
| Crash after consumption, before/after send | Consumption remains spent; uncertain effect never resent |
| Legacy entry/direct imports | No usable provider capability without that mandatory boundary |

This target invariant is **not implemented as an enabled production service**.
The current mechanically tested hold is narrower: starting the proxy and sending
any listed message must yield **zero upstream starts, zero credential transfers,
zero upstream messages**. Protected tools refuse. Local status is not protected
execution. Stage 2 model expiry/claim/race tests validate their specified model;
verification-time expiry is not revalidation at a later live dispatch.

## 6–7. Reproduction, remediation, evidence and verification

`test_f001_proxy.mjs` launches the unchanged real proxy with
`recording-authority.mjs` as its operator-configured upstream. The fixture writes
local JSONL events, reports only whether a synthetic value was present, and
returns minimal protocol responses. No security code is disabled and no
production claim is replaced. The vulnerable routes have **no claim call at all**.

Four assertions fail before the fix: startup isolation, credential transfer,
inspection/lifecycle forwarding, and zero authority acquisition during blocked
tool/custom calls. The last test failed on its first startup pre-fix, so its
second restart was not reached pre-fix; both restarts run and pass post-fix.
These tests are unchanged between recorded before and after runs.

Only production code changed: `mcp/mnde-mcp-proxy.mjs`. Removed its upstream and
executor dependencies and all forwarding. It answers initialization/ping and
advertises one local `mnde_proxy_status` tool. All protected tools refuse locally;
resources/prompts/custom methods refuse; notifications are ignored. It does not
claim a signed receipt (`receiptPath:null`, `verified:false`). No test was deleted
or relaxed. Historical documentation is preserved; `mcp/README.md` receives a
current-status notice.

| Evidence directory under `evidence/` | Result | Meaning |
| --- | --- | --- |
| `stage2-before` | 82/0, exit 0 | Frozen offline suite reproduced before remediation |
| `f001-before` | **0 pass / 4 fail, exit 1** | Alternate authority acquisition/forwarding demonstrated |
| `f001-after` | **4 pass / 0 fail, exit 0** | Same assertions, zero upstream events |
| `local-status-after` | 1/0, exit 0 | Status contract, invalid arguments, ignored upstream config, production mode and alternate-call refusal |
| `freshness-after` | 14 + 4 + 2 = **20/0**, exit 0 | Existing unmodified model/sidecar/executor/MCP freshness tests |
| `stage2-after` | **82/0**, exit 0 | Same per-file counts and stdout hash as before and IRR-001 |
| `direct-helper-after` | Characterization ran, exit 0; **BYPASS remains** | Direct imported raw helper starts synthetic authority-bearing process without claim; not a passing security assertion |
| `legacy-compatibility` | Old proxy suite: baseline **4/8 pass**, patched **2/8 pass**, both exit 1 | Historical enabled-execution assertions remain unchanged. Two additional failures are deliberate upstream-discovery removal and absent signed receipt; four enabled-forwarding failures pre-existed |

Each capture has exact command/cwd/time, raw stdout/stderr, actual child exit
code and SHA-256 hashes. The legacy comparison driver exits 0 when it successfully
collects both runs; individual exit **1** results are explicitly printed in its
stdout. It ran in two fresh temporary clones, preserving both test outputs and
avoiding overwriting working-tree receipt evidence. No full CI pass is claimed.

Re-run security checks from repo root:

```text
node --test experiments/production-proof-001/f001/test_f001_proxy.mjs experiments/production-proof-001/f001/test_f001_local_status.mjs
node tests/run-freshness-boundary.mjs
node experiments/exp-001-stage2/run-tests.mjs
```

Use `capture.mjs` with a **new** label to preserve a new run. Existing evidence
names use exclusive creation and cannot be overwritten by the capture helper.

## Closure decision and remaining work

**Do not close F-001 or advance on the basis of this record.** E05/E06 are
remediated by removing the capability. E07/E10 retain privileged direct-call
capabilities. E13/E18/E22 have unproven deployment behavior. No enabled mandatory
claim-consuming production authority boundary has been identified.

Closure requires a deployment-defined protected executor/service identity that
exclusively owns the real provider credential, denies raw clients and signing
or test helpers access to that authority, binds current authorization to an
independent atomic claim, and exposes only the constrained dispatch operation.
Its actual credential/OS/network/service controls must be tested against direct
imports, upstream startup, alternate messages and restore/replay/concurrency.
The repository does not supply that deployed service, its ownership/ACL evidence,
or independent claim infrastructure. Inventing flags or a same-process wrapper
would not establish the requested boundary. F-002 and target/base-state binding
also remain outside this patch's proof. No production readiness is asserted.
