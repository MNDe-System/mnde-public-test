# Freshness boundary follow-up — 2026-09-17

Source: local repository `C:\Users\Shadow\Downloads\INsol\mnde-public-test`, starting commit `10a7edc19615368e9506931e808f2dafe6091182`. No GitHub calls, provider calls, live tokens, or pushes were used.

**F-001 closed for the disabled paths listed below whose restart tests pass.** This is closure by refusing dispatch, not delivery of an enabled production execution service. **F-002 deployment proof pending.** Live dispatch remains disabled. A claim with no resulting effect is acceptable; exactly-once effects are not claimed.

## Verified starting state and findings

The original Stage 2 runner passed all 82 tests before edits. Its SQLite backend does perform one INSERT with independent unique execution and grant indexes. That fixes the earlier two-file atomicity mechanism defect for SQLite; it does not make a database on the executor computer independent infrastructure.

The old `requireProductionBackend` checked only `claimBackend.production === true`. A caller could inject a permissive object or omit the option altogether. The Stage 1 cache helper returned true when unset, and the generic executor had no durable claim between verifying a receipt and invoking `run()`. The proxy forwarded unknown methods and notifications outside its tools/call gate. Stage 2 also extracted receipt fields after awaiting verification of a caller-owned mutable object.

## Dispatch-path audit

| Entry/path | Before this change | Current boundary | Restart evidence |
| --- | --- | --- | --- |
| Stage 1 sidecar `/v1/decisions`, legacy engine | Optional local execution-ID cache; unset allowed evaluation/approval; local restore could reopen IDs | Approval delivery returns `ERR_FRESHNESS_DEPLOYMENT_DISABLED` before engine evaluation, regardless of cache | Actual sidecar processes, unset/missing/corrupt cache, repeated authority, both starts refuse |
| Stage 1 sidecar `/v1/decisions`, policy engine | Same optional cache before engine selection | Same unconditional refusal | Actual policy-engine sidecar processes, same cases |
| `createMndeExecutor().execute()` | Verified request-bound receipt could invoke arbitrary `run()` without claim | No `run()` call site remains; even authentic v2 ALLOW is refused | Separate OS executor processes using authentic v2 receipt; executor-local snapshot restore; zero callbacks |
| `wrapTool()` | Delegated to execute; marker was descriptive only | Delegates to disabled execute | Same underlying path; marker cannot restore removed callback call site |
| MCP server tools/call | Through generic executor | Refused by disabled executor/sidecar | Real stdio server processes restarted; executed=false |
| MCP proxy tools/call | Through generic executor | Refused; zero upstream tools/call | Real stdio proxy processes restarted with recording upstream |
| MCP proxy unknown requests / notifications | Forwarded without execution gate | Unknown requests refused; only initialized/cancelled notifications forwarded | Unknown write and tools/call notifications tested; zero upstream calls across restarts |
| Stage 2 public `createAdapter()` | Injectable transport/backend and caller-controlled production flag | Always returns refusal; never examines or invokes supplied callbacks/backend | Substitution tests plus Stage 2 disabled factory; stateless refusal cannot be reopened by local restore |
| Stage 2 offline adapter | Previously mixed into public adapter | Located only under `tests/support/`; injectable model with recording transports, no production imports | SQLite process race/crash/restart/restore tests |
| Health/readiness, offline receipt verification, pure policy/gate evaluation | Read-only inspection/evaluation | Preserved; pure ALLOW decisions are not dispatch authorization | Health assertions, existing receipt/gate/signing tests |
| MCP discovery and standard resource/prompt inspection | Read-only upstream operations | Explicit allowlist retained; trusted upstream must honor protocol semantics | Discovery tested; arbitrary custom methods refused |
| Shell MCP demo and example upstream demo | Simulated shell/tool effects, no protected external provider transport | Remain demonstrations, not a production execution authority path | Not used to assert F-001 or F-002 closure |

The sidecar issues decisions; it does not itself call GitHub. Disabling approval delivery closes its original freshness finding without relying on consumers to interpret a new metadata flag. Generic callbacks labelled `read_status` are also disabled: their name cannot establish that arbitrary JavaScript is read-only. Read-only verifier APIs and discovery remain available.

## Verification to claim to request

The executor-bound v2 envelope is cloned and recursively frozen **before the first await**. The same snapshot is verified and extracted. The trusted verification configuration is independently snapshotted. Signature verification requires both the authority/custody layer and executor layer, explicit expected executor identity and environment, and signed ALLOW. Policy-only receipts, plain `{verified:true}`, copied brands, and test fixtures cannot acquire the verified WeakSet membership.

The canonical request contains subject (`principal.id` or `actor.user_id`), execution ID, grant ID, action, repository, PR, approved source SHA, target ref, expected target SHA, and merge method. These are authenticated through the inner receipt's signed canonical-request hash and the custody-attested inner-receipt hash. Executor identity/environment, credential identity, and that receipt hash are bound by the executor signature; the custody signature binds the executor envelope hash. The root-signed credential binds the executor key and validity/capabilities.

The claim derives `execution_id`, `grant_id`, `subject`, and `executor_id` from that frozen verified object; `receipt_hash` comes from the authenticated custody attestation without a weaker fallback. `aplus_digest` is SHA-256 over canonical JSON of the extracted A+ (distinct from the full canonical request digest). Caller-supplied flags and supplied claim records cannot override these derivations in the model adapter. Missing/null/empty/non-string grant IDs, absent/null/conflicting execution IDs and conflicting grant aliases refuse. Reusing either identity remains spent even with different action data. Claim rows never expire into reusable authority.

Repository/target pin, root fingerprint/public bundle, environment, expected executor, namespace, clock, and revocation inputs are **trusted executor configuration**, not signed receipt fields. A supplied namespace is captured at verification and checked at derivation; the legacy Stage 2 model permits an unbound namespace for its old fixtures, but the public adapter is disabled regardless. The prospective PostgreSQL deployment binds each database login to one namespace on the server. Changing that mapping, moving to an empty namespace, or using new credentials to replay old authorities is forbidden operationally; namespace migration needs a separately reviewed migration preserving all spent identities.

Current executor credential validity and receipt-key validity/revocation are checked in addition to historical signature verification. Explicit signed authority expiry is honored; absent expiry does not create an independent grant TTL. Trusted revoked-grant lists and bundle key revocations deny new authority. Revocation is only current to the configured bundle/list. A brand is a snapshot, not a continuous freshness/revocation subscription: revalidation at the actual claim boundary, authenticated current revocation distribution, and a trusted clock are required before enabling live code. No current dispatch path can exploit that gap because all are disabled.

The isolated test adapter builds and freezes exactly `PUT /repos/{owner}/{repo}/pulls/{number}/merge` with `{sha, merge_method:"merge"}`, then claims before calling its recording transport once. It never retries. Expected target SHA is evidence only; that request does not enforce base-branch binding, a separate unresolved limitation.

## Backend and deployment trust boundary

No existing independent claim service or deployment proof was found among the repository's claim implementations. No live credential discovery or infrastructure access was attempted. The new **unwired PostgreSQL deployment adapter** is `src/freshness/postgres_claim.mjs`; provisioning SQL is `deployment/freshness/postgres.sql`. This code is not an assertion that infrastructure exists or that PostgreSQL integration has passed.

`openExecutorClaimBackend()` accepts no arguments: injected clients, config objects, and backend objects are rejected. A trusted executor startup would read an absolute `MNDE_CLAIM_CONFIG` file, with strict fields: `host`, `port`, `database`, `user`, `namespace`, `passwordFile`, `caFile`. Password and TLS CA files are separate, absolute paths controlled by the executor operator. TLS verification is mandatory. The `pg` driver must be installed and pinned in the deployment runtime; it was not installed or contacted in this task. No production dispatcher imports this factory, and no environment variable enables dispatch.

The SQL supplies a single transactional INSERT, independent unique constraints on `(namespace, execution_id)` and `(namespace, grant_id)`, and an immutable claim table with no expiry/unclaim operation. A server-side mapping derives the namespace from the authenticated database login. The executor login receives only schema usage and three function execute permissions, never table writes/deletion/DDL or role-switching privileges. Security-definer functions have fixed search paths and schema-qualified tables. Grant and execution IDs must be nonempty strings, independently unique.

The adapter checks that it is connected to a primary with fsync enabled, uses synchronous commit, and returns CLAIMED only after the COMMIT acknowledgement. Every lookup opens a fresh primary connection. Claim/commit errors trigger no resend: the claim coordinator does one lookup, treats a matching existing row as spent, and otherwise returns unknown (including inconsistent results). Both decisions prohibit transport. Database acknowledgement precedes any future transport wiring; no provider response is considered evidence that the claim is durable.

Required deployment boundary, **not yet established**:

- An independent infrastructure operator runs the PostgreSQL primary and owns its volumes, snapshots, backup retention, restore procedures, and failover configuration.
- The executor operator controls only restricted client credentials, trusted configuration, code and local artifacts. The executor identity cannot reset/delete claims or restore the database.
- Executor-local restoration can restore local receipts/configuration but cannot roll back the independent database. Retired credentials/namespaces must not expose a fresh claim domain for old authorities.
- Database failover must not lose acknowledged commits. No promotion of a lagging asynchronous replica or restoration to a pre-claim snapshot may reopen authority. Primary routing, storage guarantees and administrative controls require actual deployment evidence.
- A same-machine SQLite file or another local directory has none of these demonstrated administrative boundaries. Those tests are explicitly model/same-machine integration evidence.

Ordinary JavaScript cannot defend against malicious code with the executor's own privileges: it can replace modules, patch builtins, call a raw provider client, read credentials, or import test helpers from a source checkout. WeakSet brands and frozen objects prevent ordinary API substitution/mutation, not a hostile co-resident executor. Production packaging excludes `tests/` and `experiments/`; isolated executor OS identity, credential custody, deployment-owned configuration and independent database administration are required. Direct, unwrapped provider calls are outside these entry-point guarantees.

## Acceptance evidence

All new regression work is outside `experiments/exp-001/`. The new runner is `node tests/run-freshness-boundary.mjs` / `npm run test:freshness-boundary`. Offline Stage 2/model tests preload a network-denial guard; sidecar and MCP tests use only loopback/stdio and recording callbacks.

| Acceptance case | Finding | Result/evidence |
| --- | --- | --- |
| Valid executor-bound approval, durable claim, fixed request, separately read outcome | F-001 / F-002 mechanism | PASS, SQLite/model; claim lookup, dispatch-attempt, provider-response, model-provider-effect and independent observation record |
| Same execution/different grant; same grant/different execution; altered action | Both | PASS, independent uniqueness and no extra recording-transport call |
| Missing/null/invalid identities; conflicting signed aliases | F-001 | PASS, verification refuses |
| Wrong executor, namespace, policy-only, copied marker, verified flag | F-001 | PASS, zero provider calls |
| Caller-created production backend / claimed flag / disabled-production-check flag | Both | PASS, public adapter never calls backend or transport |
| Mutation during verification; later identity mutation; A+ digest | F-001 | PASS, pre-await snapshot and deep freeze |
| Expired credential/authority; revoked grant/key | F-001 | PASS, configured current-time/list checks; global revocation freshness remains a deployment prerequisite |
| Two OS executors race | Both | PASS, one claim and one model provider attempt |
| Restart after dispatch; executor-local snapshot restored | Both | PASS, SQLite unchanged, zero additional attempts; same-machine evidence only |
| Crash before claim | Both | PASS, restart claims once and attempts once |
| Crash after claim/before transport | Both | PASS, claim spent, zero attempts/effects |
| Crash after transport starts/before response record | Both | PASS, one model effect, no response recorded, no resend |
| Outage, timeout, lost acknowledgement, inconsistent acknowledgement/lookup | Both | PASS, refusal/unknown/spent with zero provider calls |
| Missing/corrupt trusted backend config | Both | PASS, factory refuses before driver/network use |
| Stage 1 unset/missing/corrupt cache, both engines, real restarts | F-001 | PASS, disabled approval delivery, zero callbacks |
| Stage 1 authentic v2 replay across executor restarts/local restore | F-001 | PASS, verified=true, executed=false, zero requests |
| MCP server/proxy restarts and unknown-method/notification bypass | F-001 | PASS, no tools/call upstream, discovery preserved |
| Independent PostgreSQL deployment race/rollback/failure test | F-002 deployment | **NOT RUN — independent infrastructure and credential/storage boundary unavailable** |

Final selected validation: 20 new tests; 82 Stage 2 tests (now explicitly isolated model dispatch); existing execution-ID store 9/9, execution gate 15/15, executor credential 15/15, executor identity signing 12/12, policy receipt 11/11, executor enforcement 8/8, and CI script contract all pass. The gate suite also runs its existing policy-receipt and signed-policy-bundle child checks. The executor suite's former positive callback assertions were updated to the deliberate safety hold after its initial run exposed those expected incompatibilities. This is not a full repository CI pass: other historical enabled-sidecar/dispatch demos and positive-path suites may require migration to the safety hold before a general release.

Frozen baseline: no edits and no execution of `experiments/exp-001/`. The original recorded **27 PASS / 2 FAIL / 1 INCONCLUSIVE** is unchanged. Its Git tree is `62f22a828b48199b173940b498dd5e35dbd53e30`; the final diff against the starting commit for that directory is empty.

## Operator changes and remaining blockers

`/v1/decisions`, generic callbacks/wrapped tools, MCP protected calls, and the Stage 2 public adapter now refuse. `MNDE_EXEC_ID_CACHE` no longer enables sidecar execution and is not initialized by the sidecar; the retained local store helper is only local dedup/model evidence and refuses when unset. There is deliberately no feature flag to undo the hold. Health, discovery, offline verification and pure evaluators are available.

Before an enabled deployment: provision the independently administered primary and restricted login; install/pin and integration-test `pg` and the SQL/adapter; prove durable acknowledgement and primary-consistent lookup under outage/lost-ack/failover; establish immutable namespace, clock and current revocation/expiry revalidation; implement trusted executor startup that owns verification/config/backend/transport rather than accepting caller injection; and run the independent-backend rollback/race/crash suite under documented credentials/storage/backups. Re-enable only in a reviewed change after that evidence exists. This task deliberately performs none of that live infrastructure work.

**F-002 deployment proof pending.**
