import http from "node:http";
import cluster from "node:cluster";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { availableParallelism } from "node:os";
import { dirname, join, parse as parsePath, resolve } from "node:path";
import { PerformanceObserver, monitorEventLoopDelay, performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { assertReceiptSigningKeysAvailable } from "./shared/receipt-signing.ts";
import { loadAuthorityBundle } from "./shared/authority-manifest.mjs";
import { canonicalizeJson, parseStrictJson } from "./shared/json.ts";
import { canonicalPolicyPayload, policyHash, verifyPolicySignature } from "./shared/policy-trust.ts";
import {
  executeDeterministicPipeline,
  verifySignedReceipt
} from "./audit/node_runtime.ts";
import { boundaryReplayEndpointResponse } from "./shared/receipt-replay.mjs";
import { parseRuntimeProfile } from "./shared/runtime-profile.mjs";
import { resolveDecisionEngine } from "./shared/decision-engine.mjs";
import { ledgerStartupGate, isLedgerDisabled } from "./src/execution-ledger/paths.mjs";
import { resolveLedgerRuntime, recordReceiptInLedger, ledgerResponseMeta, ledgerHeadResponse, ledgerVerifyResponse, ledgerExportResponse, anchorNow, checkpointHeadResponse, proofResponse } from "./src/execution-ledger/sidecar.mjs";
import { createLocalDemoCustody } from "./src/custody/index.mjs";
import {
  DeterministicWorkerPool,
  WORKER_POOL_SATURATED,
  WORKER_TIMEOUT
} from "./sidecar/deterministic_worker_pool.mjs";
import {
  ReceiptPersistenceQueue,
  RECEIPT_QUEUE_SATURATED,
  SYSTEM_SATURATED,
  SystemSaturationController,
  validateReceiptPersistenceConfig
} from "./sidecar/receipt_persistence_queue.mjs";
import {
  ERR_L0_TRANSPORT_SHED,
  ERR_SIDECAR_SATURATED,
  createAdmissionController,
  parseHttpLimitConfig,
  parseL0LimitConfig
} from "./sidecar/http_admission.mjs";
import { buildSidecarRefusalReceipt } from "./sidecar/refusal_receipt.mjs";
import {
  ERR_UNAUTHORIZED_ORIGIN,
  corsHeadersForOrigin,
  createRuntimeInput,
  isAllowedCorsOrigin
} from "./sidecar/runtime_request.mjs";
import { SocketRegistry } from "./sidecar/socket_registry.mjs";
import { ERR_RUNTIME_DEGRADED, ERR_RUNTIME_FATAL, RuntimeWatchdog } from "./sidecar/runtime_watchdog.mjs";
import {
  buildCapabilityObject,
  clampReceiptLimit,
  createAuditBundle,
  readRecentReceipts,
  replayRecentReceipts,
  validatePolicyDocument,
  verifyReceiptContract
} from "./sidecar/production_api.mjs";
import {
  appendAuthAuditEvent,
  authorizeAuthorityAction,
  isSensitiveNamespacePath,
  nonceDirPath,
  parseAuthorityAssertion,
  refusalBody
} from "./sidecar/auth_authority.mjs";
import { replayReceiptDeterministically } from "./sidecar/replay_engine.mjs";
import { assertStartupDirectoryPermissions } from "./sidecar/startup_checks.mjs";
import {
  createGracefulShutdown,
  parseShutdownDeadlineMs,
  waitForQuiescence
} from "./sidecar/graceful_shutdown.mjs";
import { getReleaseIdentity } from "./src/release/identity.mjs";

const HOST = "127.0.0.1";
const PORT = parseBindPort(process.env.MNDE_BIND_PORT, 8787);
const REPO_ROOT = dirname(fileURLToPath(import.meta.url));
// REPO_ROOT locates runtime code and static assets (dashboard.html) — always
// wherever this file is installed. DATA_ROOT locates the writable authority
// state (manifest, keys, trust root) and defaults to REPO_ROOT unchanged for
// the existing clone-and-run flow; MNDE_HOME overrides it for the packaged
// CLI, which must never read/write authority state inside node_modules.
const DATA_ROOT = process.env.MNDE_HOME ? resolve(process.env.MNDE_HOME) : REPO_ROOT;
const verifySignedReceiptAtDataRoot = (receipt) => verifySignedReceipt(receipt, { dataRoot: DATA_ROOT });
let activePolicyPath = new URL("./sample-policies/legacy-gpu-policy.signed.json", import.meta.url);
const RECEIPT_LOG_PATH = process.env.MNDE_RECEIPT_LOG ?? join(process.cwd(), "hostile-verifier-proof-bundle", "receipts.jsonl");
const AUTH_AUDIT_LOG_PATH = process.env.MNDE_AUTH_AUDIT_LOG ?? join(process.cwd(), "auth-audit", "auth-events.jsonl");
const CLUSTER_MODE = process.env.MNDE_CLUSTER_MODE === "1";
const CLUSTER_SHARED_RECEIPT_LOG = process.env.MNDE_CLUSTER_SHARED_RECEIPT_LOG === "1";
const CLUSTER_WORKERS = Number.parseInt(process.env.MNDE_CLUSTER_WORKERS ?? String(availableParallelism()), 10);
const HTTP_LIMITS = parseHttpLimitConfig(process.env);
const L0_LIMITS = parseL0LimitConfig(process.env);
const MAX_INFLIGHT = Number.parseInt(process.env.MNDE_MAX_INFLIGHT ?? "128", 10);
const SHED_INFLIGHT = Number.parseInt(process.env.MNDE_SHED_INFLIGHT ?? "64", 10);
const MAX_EVENT_LOOP_LAG_MS = Number.parseInt(process.env.MNDE_MAX_EVENT_LOOP_LAG_MS ?? "80", 10);
const WORKER_POOL_SIZE = Number.parseInt(process.env.MNDE_WORKER_POOL_SIZE ?? String(Math.max(1, availableParallelism() - 1)), 10);
const WORKER_QUEUE_MAX_DEPTH = Number.parseInt(process.env.MNDE_WORKER_QUEUE_MAX_DEPTH ?? String(Math.max(1, WORKER_POOL_SIZE)), 10);
const WORKER_TASK_TIMEOUT_MS = Number.parseInt(process.env.MNDE_WORKER_TASK_TIMEOUT_MS ?? String(Math.max(100, HTTP_LIMITS.request_timeout_ms - 100)), 10);
const INLINE_REFUSAL_RECEIPTS = process.env.MNDE_INLINE_REFUSAL_RECEIPTS === "1";
const TEST_HARNESS_ENABLED = process.env.MNDE_TEST_HARNESS === "1";
// Single finite budget covering the ENTIRE graceful-shutdown sequence (quiesce
// in-flight work → flush receipts → stop workers → clean up sockets). Explicitly
// invalid values fail fast at startup; unset uses the documented default. See
// sidecar/graceful_shutdown.mjs and the ERR_SHUTDOWN_CONFIG contract.
const SHUTDOWN_DEADLINE_MS = parseShutdownDeadlineMs(process.env);
// Draining latch. Flipped true the instant shutdown begins (before any await) so
// readiness reports not-ready and new decision work is refused while the process
// finishes already-admitted requests. Never flips back.
let draining = false;
// Opaque nonce a spawning harness passes in so /readyz answers can be tied to
// THIS process. Without it a readiness poll cannot distinguish this sidecar
// from an unrelated process already bound to the same port.
const HARNESS_INSTANCE_ID = process.env.MNDE_HARNESS_INSTANCE_ID || null;
const RECEIPT_DURABILITY_MODE = process.env.MNDE_RECEIPT_DURABILITY_MODE ?? "throughput";
const RECEIPT_QUEUE_CONFIG = validateReceiptPersistenceConfig({
  path: receiptPathForWorker(RECEIPT_LOG_PATH),
  durability_mode: RECEIPT_DURABILITY_MODE,
  max_items: Number.parseInt(process.env.MNDE_RECEIPT_QUEUE_MAX_ITEMS ?? "50000", 10),
  max_bytes: Number.parseInt(process.env.MNDE_RECEIPT_QUEUE_MAX_BYTES ?? String(256 * 1024 * 1024), 10),
  max_batch_size: Number.parseInt(process.env.MNDE_RECEIPT_BATCH_MAX_SIZE ?? "256", 10),
  max_batch_age_ms: Number.parseInt(process.env.MNDE_RECEIPT_BATCH_MAX_AGE_MS ?? "10", 10),
  flush_timeout_ms: Number.parseInt(process.env.MNDE_RECEIPT_FLUSH_TIMEOUT_MS ?? "2000", 10)
});
let policy = JSON.parse(readFileSync(activePolicyPath, "utf8"));
let policy_hash = policyHash(policy);
try {
  assertReceiptSigningKeysAvailable();
  const authority = loadAuthorityBundle(DATA_ROOT, { kind: "local" });
  if (!authority.ok) throw new Error(`ERR_AUTHORITY_MANIFEST_INVALID: ${authority.reason}`);
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
const receiptQueue = new ReceiptPersistenceQueue(RECEIPT_QUEUE_CONFIG);
const workerPool = new DeterministicWorkerPool({
  worker_count: WORKER_POOL_SIZE,
  max_queue_depth: WORKER_QUEUE_MAX_DEPTH,
  task_timeout_ms: WORKER_TASK_TIMEOUT_MS,
  worker_url: new URL("./sidecar/deterministic_worker.mjs", import.meta.url)
});

function parseBindPort(value, fallback) {
  const port = Number.parseInt(value ?? String(fallback), 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return fallback;
  return port;
}
const saturationController = new SystemSaturationController({
  max_inflight: MAX_INFLIGHT,
  inflight_shed_threshold: Math.min(SHED_INFLIGHT, MAX_INFLIGHT),
  max_event_loop_lag_ms: MAX_EVENT_LOOP_LAG_MS,
  queue_high_watermark_items: Math.max(1, Math.floor(RECEIPT_QUEUE_CONFIG.max_items * 0.75)),
  queue_high_watermark_bytes: Math.max(1, Math.floor(RECEIPT_QUEUE_CONFIG.max_bytes * 0.75))
});
const admission = createAdmissionController(HTTP_LIMITS);
const socketRegistry = new SocketRegistry({
  idle_timeout_ms: Number.parseInt(process.env.MNDE_SOCKET_IDLE_TIMEOUT_MS ?? String(Math.max(250, serverKeepAliveTimeout() * 2)), 10),
  eviction_interval_ms: Number.parseInt(process.env.MNDE_SOCKET_EVICTION_INTERVAL_MS ?? "250", 10),
  shutdown_grace_ms: Number.parseInt(process.env.MNDE_SOCKET_SHUTDOWN_GRACE_MS ?? "500", 10)
});
const watchdog = new RuntimeWatchdog({
  interval_ms: Number.parseInt(process.env.MNDE_WATCHDOG_INTERVAL_MS ?? "250", 10),
  max_event_loop_lag_ms: Number.parseInt(process.env.MNDE_WATCHDOG_MAX_EVENT_LOOP_LAG_MS ?? String(Math.max(250, MAX_EVENT_LOOP_LAG_MS * 2)), 10),
  fatal_event_loop_lag_ms: Number.parseInt(process.env.MNDE_WATCHDOG_FATAL_EVENT_LOOP_LAG_MS ?? "2000", 10),
  max_open_sockets: Number.parseInt(process.env.MNDE_WATCHDOG_MAX_OPEN_SOCKETS ?? "256", 10),
  fatal_open_sockets: Number.parseInt(process.env.MNDE_WATCHDOG_FATAL_OPEN_SOCKETS ?? "1024", 10)
}, () => {
  const queueMetrics = receiptQueue.metrics();
  const socketMetrics = socketRegistry.metrics();
  return {
    open_sockets: socketMetrics.open,
    receipt_fail_closed: queueMetrics.fail_closed
  };
});
const eventLoopDelay = monitorEventLoopDelay({ resolution: 10 });
eventLoopDelay.enable();
let latestEventLoopLagMs = 0;
const eventLoopLagTimer = setInterval(() => {
  latestEventLoopLagMs = Math.max(0, Math.round(eventLoopDelay.percentile(99) / 1_000_000));
  eventLoopDelay.reset();
}, 500);
eventLoopLagTimer.unref();
let inflight = 0;
let l0ActiveConnections = 0;
const counters = {
  l0_shed_total: 0,
  l0_shed_destroy_total: 0,
  l0_shed_503_total: 0,
  l0_preparse_destroy_sheds: 0,
  l0_malformed_destroy_sheds: 0,
  l0_timeout_destroy_sheds: 0,
  l0_overload_503_sheds: 0,
  l0_connections_accepted_total: 0,
  l0_connections_closed_total: 0,
  completed_http_responses: 0,
  requests: 0,
  refused_overload: 0,
  flush_failures: 0,
  unsigned_allows_blocked: 0,
  refused_system_saturated: 0,
  refused_worker_pool_saturated: 0,
  refused_receipt_queue_saturated: 0,
  admission_refusals: 0,
  worker_refusals: 0,
  receipt_refusals: 0,
  saturation_inflight: 0,
  saturation_event_loop_lag: 0,
  saturation_receipt_queue_depth: 0,
  saturation_receipt_queue_bytes: 0,
  request_timeout_refusals: 0,
  browser_origin_requests: 0,
  watchdog_interventions: 0,
  malformed_receipt_lines: 0
};
const latencyTotals = {
  parse_ms: 0,
  preflight_ms: 0,
  orbit_ms: 0,
  arm_ms: 0,
  ramona_ms: 0,
  custody_ms: 0,
  canonicalize_ms: 0,
  receipt_build_ms: 0,
  signing_ms: 0,
  worker_queue_wait_ms: 0,
  worker_exec_ms: 0,
  receipt_enqueue_ms: 0,
  persistence_flush_ms: 0,
  response_serialize_ms: 0,
  response_flush_ms: 0,
  total_server_ms: 0,
  request_admission_wait_ms: 0,
  request_body_read_ms: 0,
  request_parse_ms: 0,
  event_loop_lag_ms: 0
};
const socketTimings = new WeakMap();

function serverKeepAliveTimeout() {
  return L0_LIMITS.enable ? L0_LIMITS.keepalive_timeout_ms : HTTP_LIMITS.keep_alive_timeout_ms;
}

function telemetrySafe(value) {
  if (typeof value === "number") return Number.isFinite(value) ? Math.round(value) : 0;
  if (Array.isArray(value)) return value.map((item) => telemetrySafe(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, telemetrySafe(item)]));
  }
  return value;
}

function ms(value = performance.now()) {
  return Math.max(0, Math.round(value));
}
const runtimeStats = {
  gc_count: 0,
  gc_pause_ms_total: 0,
  gc_pause_ms_max: 0,
  heap_used_bytes: 0,
  heap_total_bytes: 0,
  rss_bytes: 0
};
new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) {
    const duration = Math.max(0, Math.round(entry.duration));
    runtimeStats.gc_count += 1;
    runtimeStats.gc_pause_ms_total += duration;
    runtimeStats.gc_pause_ms_max = Math.max(runtimeStats.gc_pause_ms_max, duration);
  }
}).observe({ entryTypes: ["gc"] });
const memoryStatsTimer = setInterval(() => {
  const memory = process.memoryUsage();
  runtimeStats.heap_used_bytes = memory.heapUsed;
  runtimeStats.heap_total_bytes = memory.heapTotal;
  runtimeStats.rss_bytes = memory.rss;
}, 500);
memoryStatsTimer.unref();

function receiptPathForWorker(basePath) {
  if (!cluster.isWorker || !CLUSTER_MODE || CLUSTER_SHARED_RECEIPT_LOG) return basePath;
  const parsed = parsePath(basePath);
  return join(parsed.dir, `${parsed.name}.worker-${cluster.worker.id}${parsed.ext || ".jsonl"}`);
}

// ── Trust-root pre-flight (S-02 / P-01) ──────────────────────────────────────
// Single deterministic gate before anything serves traffic. In MNDE_PROFILE=
// production, MNDe refuses to start unless an explicit, valid production custody
// provider is configured and no demo/dev key material is in use. Runs in the
// primary BEFORE forking so a misconfiguration fails fast (no worker crash-loop).
// In MNDE_PROFILE=local (default) this is a no-op and custody is not loaded.
let ACTIVATION_ID = null;
let EXECUTOR_READINESS = { ok: true, configured: false };
let PRELOADED_SIGNING_CONFIG = null;
{
  const { assertTrustRoot } = await import("./src/authority-signing/preflight.mjs");
  const trust = await assertTrustRoot(process.env, { repoRoot: DATA_ROOT });
  if (!trust.ok) {
    process.stderr.write(`\nMNDe refused to start — trust-root pre-flight failed.\n  reason_code: ${trust.reason_code}\n  ${trust.detail}\n\n`);
    process.exit(1);
  }
  // The preflight-verified id of the active authority transition
  // (mnde.activation.v1). Receipts produced by this process are bound to it
  // through the custody attestation. Null when no activation record is
  // configured (local mode, or production before activation tooling).
  ACTIVATION_ID = typeof trust.activation_id === "string" ? trust.activation_id : null;
  if (trust.profile === "production") {
    process.stdout.write(`MNDe trust-root: production custody verified (authority '${trust.authority_id || "?"}')${ACTIVATION_ID ? `; activation ${ACTIVATION_ID.slice(0, 12)}…` : ""}\n`);
  }
}

// ── Executor-identity pre-flight (Phase 0 / Design A) ────────────────────────
// Executor identity is OPT-IN. When MNDE_EXECUTOR_* is configured, the material
// must be usable (credential verifies, unexpired, right environment, key matches)
// or MNDe refuses to start — no silent downgrade to authority-only. When absent,
// this is a no-op and authority-only signing is unchanged.
{
  const { assertExecutorIdentityReadiness } = await import("./src/custody/executor-readiness.mjs");
  const executorConfiguration = [
    process.env.MNDE_EXECUTOR_ID,
    process.env.MNDE_EXECUTOR_PRIVATE_KEY,
    process.env.MNDE_EXECUTOR_CREDENTIAL,
    process.env.MNDE_EXECUTOR_ENVIRONMENT
  ];
  const executorFullyConfigured = executorConfiguration.every((value) => typeof value === "string" && value.length > 0);
  let readinessOptions = {};
  if (executorFullyConfigured) {
    const requestedSigningMode = process.env.MNDE_RECEIPT_SIGNING_MODE;
    if (requestedSigningMode !== "custody" && requestedSigningMode !== "external-signer") {
      process.stderr.write("ERR_EXECUTOR_AUTHORITY_SIGNER_REQUIRED\n");
      process.exit(1);
    }
    const signingModule = await import("./src/authority-signing/index.mjs");
    PRELOADED_SIGNING_CONFIG = await signingModule.loadSigningConfig(process.env);
    if (!PRELOADED_SIGNING_CONFIG.ok) {
      process.stderr.write(`${PRELOADED_SIGNING_CONFIG.reason_code}\n`);
      process.exit(1);
    }
    readinessOptions = {
      authorityBundle: PRELOADED_SIGNING_CONFIG.provider.getPublicBundle(),
      trustedRootFingerprint: PRELOADED_SIGNING_CONFIG.provider.trustedRootFingerprint
    };
  }
  EXECUTOR_READINESS = await assertExecutorIdentityReadiness(process.env, readinessOptions);
  if (!EXECUTOR_READINESS.ok) {
    process.stderr.write(`\nMNDe refused to start — executor identity pre-flight failed.\n  reason_code: ${EXECUTOR_READINESS.reason_code}\n  ${EXECUTOR_READINESS.detail}\n\n`);
    process.exit(1);
  }
  if (EXECUTOR_READINESS.configured) {
    process.stdout.write(`MNDe executor identity: ${EXECUTOR_READINESS.executor_id} (key ${String(EXECUTOR_READINESS.executor_key_id).slice(0, 20)}…) ready\n`);
  }
}

// ── Startup directory permission checks ──────────────────────────────────────
// Verify security-critical directories are not world-writable before forking
// workers or serving traffic. A world-writable directory lets any local user
// pre-create or delete nonce/exec-id files, undermining replay protection and
// audit integrity.
assertStartupDirectoryPermissions([
  { name: "nonce cache", dir: nonceDirPath() },
  { name: "receipt log", dir: dirname(RECEIPT_LOG_PATH) },
  { name: "auth audit log", dir: dirname(AUTH_AUDIT_LOG_PATH) }
]);

// ── Production posture pre-flight ─────────────────────────────────────────────
// Complements the trust-root gate: in MNDE_PROFILE=production the decision
// endpoint must ALSO require caller authentication and an enforced (signed-
// bundle) policy engine. Runs in the primary before forking so a misconfiguration
// fails fast rather than deferring to per-request denial. No-op outside production.
{
  const { assertProductionPosture } = await import("./src/production-posture-preflight.mjs");
  const posture = await assertProductionPosture(process.env);
  if (!posture.ok) {
    process.stderr.write(`\nMNDe refused to start — production posture pre-flight failed.\n  reason_code: ${posture.reason_code}\n  ${posture.detail}\n\n`);
    process.exit(1);
  }
}

// ── Decision-engine selection guard ──────────────────────────────────────────
// Fail closed on an unrecognized MNDE_DECISION_ENGINE before forking, rather than
// silently choosing an engine. Unset resolves to the v1 default (policy-engine).
if (resolveDecisionEngine(process.env) === null) {
  process.stderr.write(`\nMNDe refused to start — unknown MNDE_DECISION_ENGINE '${process.env.MNDE_DECISION_ENGINE}'. Valid values: 'policy-engine' (default), 'legacy'.\n\n`);
  process.exit(1);
}

// Optional, opt-in caller authentication. Default "off" (legacy-compatible).
const {
  authSourceForRequest,
  authenticate,
  clearAuthFailures,
  isAuthThrottled,
  loadAuthConfig,
  recordAuthFailure
} = await import("./src/sidecar-auth/index.mjs");
const AUTH = loadAuthConfig(process.env);
const AUTH_MODE = AUTH.mode;
const AUTH_CONFIG_ERROR = AUTH.ok ? null : AUTH.reason;
const runtimeProfileResult = parseRuntimeProfile(process.env.MNDE_PROFILE);
if (!runtimeProfileResult.ok) {
  process.stderr.write(`\nMNDe refused to start — ${runtimeProfileResult.detail}\n`);
  process.exit(1);
}
const RUNTIME_PROFILE = runtimeProfileResult.profile;
if (RUNTIME_PROFILE === "production" && (AUTH_MODE !== "bearer" || AUTH_CONFIG_ERROR)) {
  process.stderr.write("\nMNDe refused to start — production sidecar mode requires MNDE_SIDECAR_AUTH=bearer with a valid bearer token configuration.\n");
  if (AUTH_CONFIG_ERROR) process.stderr.write(`  ${AUTH_CONFIG_ERROR}\n`);
  process.exit(1);
}
if (AUTH_MODE === "bearer") {
  process.stdout.write(`MNDe caller auth: bearer${AUTH_CONFIG_ERROR ? ` (CONFIG ERROR: ${AUTH_CONFIG_ERROR})` : ` (${AUTH.tokens.size} token(s))`}\n`);
}

if (cluster.isPrimary && CLUSTER_MODE) {
  // The primary blocks here forever (below), so the graceful-shutdown controller
  // and the SIGINT/SIGTERM handlers defined later in this file are never reached
  // in the primary — only in workers. The primary therefore needs its OWN
  // termination handling: forward the signal to each worker (so each runs its own
  // graceful drain) and, critically, STOP restarting workers once shutdown has
  // begun, or a cleanly-draining worker would be respawned.
  let clusterShuttingDown = false;
  cluster.on("exit", (worker, code) => {
    if (clusterShuttingDown) {
      if (Object.keys(cluster.workers ?? {}).length === 0) process.exit(0);
      return;
    }
    process.stderr.write(`MNDe sidecar worker ${worker.id} exited with code ${code}; restarting fail-closed worker\n`);
    cluster.fork();
  });
  const shutdownPrimary = () => {
    if (clusterShuttingDown) return;
    clusterShuttingDown = true;
    for (const worker of Object.values(cluster.workers ?? {})) {
      try { worker.process.kill("SIGTERM"); } catch { /* already gone */ }
    }
    // Bound the primary's own wait so one stuck worker cannot wedge the group.
    // Slightly beyond a worker's deadline so a worker can finish first.
    const forceExit = setTimeout(() => process.exit(1), SHUTDOWN_DEADLINE_MS + 1_000);
    forceExit.unref?.();
  };
  process.on("SIGINT", shutdownPrimary);
  process.on("SIGTERM", shutdownPrimary);
  for (let i = 0; i < CLUSTER_WORKERS; i += 1) cluster.fork();
  await new Promise(() => {});
} else {
  await receiptQueue.start();
  workerPool.start();
}

// Decision engine. v1 default is "policy-engine" (the canonical authority path);
// "legacy" is the explicit opt-in compatibility profile. The policy-engine adapter
// is dynamically imported ONLY in policy-engine mode, so legacy mode never loads it
// and its behavior is byte-for-byte unchanged.
const DECISION_ENGINE = resolveDecisionEngine(process.env);
let policyEngine = null;
let policyEngineConfigError = null;
let policyConfigurationState = null; // deployment state (e.g. NO_POLICY_CONFIGURED); never written into receipts
if (DECISION_ENGINE === "policy-engine") {
  try {
    const adapter = await import("./src/policy-engine/sidecar-adapter.mjs");
    const peConfig = await adapter.loadPolicyEngineConfig(process.env);
    if (!peConfig.ok) policyEngineConfigError = peConfig.reason;
    else {
      policyEngine = { decide: (body, opts) => adapter.decidePolicyEngine(body, peConfig, opts) };
      policyConfigurationState = peConfig.policy_configuration_state ?? null;
    }
    const stateNote = policyConfigurationState ? ` (${policyConfigurationState}: built-in default-deny policy active; every decision REFUSES until a policy is installed)` : "";
    process.stdout.write(`MNDe decision engine: policy-engine${policyEngineConfigError ? ` (CONFIG ERROR: ${policyEngineConfigError})` : stateNote}\n`);
  } catch (error) {
    policyEngineConfigError = error instanceof Error ? error.message : String(error);
    process.stderr.write(`MNDe policy-engine adapter failed to load: ${policyEngineConfigError}\n`);
  }
}

// Execution ledger (V1 integrity layer). Default-on. Appends one tamper-evident,
// hash-chained entry per finalized receipt — a SEPARATE layer that never touches
// the receipt format, signing, or standalone verification. Disabling it is a
// development-only convenience and fails closed at startup under MNDE_PROFILE=
// production. Append failure fails the request closed in production.
const ledgerGate = ledgerStartupGate(process.env);
if (!ledgerGate.ok) {
  process.stderr.write(`\nMNDe refused to start — ${ledgerGate.detail}\n  reason_code: ${ledgerGate.code}\n\n`);
  process.exit(1);
}
const LEDGER_RUNTIME = resolveLedgerRuntime(process.env, receiptQueue.config.path);
const LEDGER_ENGINE = { name: DECISION_ENGINE === "legacy" ? "mnde-legacy-pipeline" : "mnde-policy-engine", version: null };
if (LEDGER_RUNTIME.enabled) {
  process.stdout.write(`MNDe execution ledger: enabled (${LEDGER_RUNTIME.ledgerPath})\n`);
} else {
  process.stdout.write(`MNDe execution ledger: DISABLED (MNDE_EXECUTION_LEDGER=off; non-production only)\n`);
}

// Optional custody-backed live receipt signing. Default "legacy" retains the
// existing authority signer and adds only the required explicit authority_only
// mode. The custody signing adapter is imported only when custody is selected.
// Signing is applied as a separate step AFTER the receipt is built — decision
// engines never sign and never import custody.
const SIGNING_MODE = (process.env.MNDE_RECEIPT_SIGNING_MODE === "custody" || process.env.MNDE_RECEIPT_SIGNING_MODE === "external-signer") ? "custody" : "legacy";
let signingConfig = { ok: true, mode: "legacy" };
let signReceiptAdapter = async (receipt) => ({ ok: true, receipt });
let liveSigningContext = null;
let signingConfigError = null;
if (SIGNING_MODE === "custody") {
  try {
    const mod = await import("./src/authority-signing/index.mjs");
    signingConfig = PRELOADED_SIGNING_CONFIG ?? await mod.loadSigningConfig(process.env);
    signReceiptAdapter = mod.signLiveReceipt;
    if (!signingConfig.ok) signingConfigError = signingConfig.reason_code;
    // Bind receipts to the preflight-verified activation (mnde.activation.v1).
    if (signingConfig.ok && ACTIVATION_ID) signingConfig.activation_id = ACTIVATION_ID;
    process.stdout.write(`MNDe receipt signing: custody${signingConfigError ? ` (CONFIG ERROR: ${signingConfigError})` : ""}\n`);
  } catch (error) {
    signingConfigError = "ERR_CUSTODY_UNAVAILABLE";
    process.stderr.write(`MNDe custody signing failed to load: ${error instanceof Error ? error.message : String(error)}\n`);
  }
}
if (EXECUTOR_READINESS.configured && SIGNING_MODE !== "custody") {
  process.stderr.write("ERR_EXECUTOR_AUTHORITY_SIGNER_REQUIRED\n");
  process.exit(1);
}
if (SIGNING_MODE === "custody") {
  const mod = await import("./src/authority-signing/index.mjs");
  const contextResult = mod.createLiveReceiptSigningContext(signingConfig, EXECUTOR_READINESS);
  if (!contextResult.ok) {
    if (EXECUTOR_READINESS.configured) {
      process.stderr.write(`${contextResult.reason_code}\n`);
      process.exit(1);
    }
    liveSigningContext = Object.freeze({ mode: "authority_only", authorityConfig: Object.freeze({ ...signingConfig }), authoritySigner: null, executorSigner: null, executorIdentity: null });
  } else {
    liveSigningContext = contextResult.context;
  }
} else {
  liveSigningContext = Object.freeze({
    mode: "authority_only",
    authorityConfig: Object.freeze({ ...signingConfig }),
    authoritySigner: null,
    executorSigner: null,
    executorIdentity: null
  });
}
process.stdout.write(`MNDe live receipt signing_mode=${liveSigningContext.mode}\n`);
if (EXECUTOR_READINESS.signer?.destroy) {
  process.once("exit", () => EXECUTOR_READINESS.signer.destroy());
}

// Ledger signing custody. Execution-ledger entries are always signed v2. In
// custody mode reuse the already-loaded published provider (real, rotatable,
// revocable ledger key) and its bundle. Otherwise mint an ephemeral local-demo
// custody so local/legacy runs still produce a signed, self-verifying chain —
// same posture as local-demo receipt signing: in-process keys, reset on restart,
// which means entries appended before a restart won't verify against the new
// process's bundle (a known local-demo limitation, never the production path).
let LEDGER_SIGN = null;
let LEDGER_BUNDLE = null;
if (SIGNING_MODE === "custody" && signingConfig.ok && signingConfig.provider) {
  LEDGER_SIGN = signingConfig.provider.signLedger;
  LEDGER_BUNDLE = signingConfig.provider.getPublicBundle();
  process.stdout.write(`MNDe execution ledger: signed (custody ledger key)\n`);
} else {
  const demoLedgerCustody = await createLocalDemoCustody();
  LEDGER_SIGN = demoLedgerCustody.signLedger;
  LEDGER_BUNDLE = demoLedgerCustody.getPublicBundle();
  process.stdout.write(`MNDe execution ledger: signed (ephemeral local-demo ledger key; non-production)\n`);
}

// Anchoring scheduler (Phase 1): produce a signed checkpoint every N entries OR
// every T ms, whichever comes first — plus the on-demand POST /ledger/anchor
// endpoint below. This runs on a background timer, wholly OFF the request/append
// path: it takes only the checkpoint lock, NEVER the ledger append lock.
function positiveIntegerEnv(name, fallback, minimum = 1) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${name} must be a safe integer >= ${minimum}`);
  }
  return value;
}
const ANCHOR_EVERY_ENTRIES = positiveIntegerEnv("MNDE_LEDGER_ANCHOR_EVERY", 100);
const ANCHOR_INTERVAL_MS = positiveIntegerEnv("MNDE_LEDGER_ANCHOR_INTERVAL_MS", 60000, 1000);
const ANCHOR_TICK_MS = positiveIntegerEnv("MNDE_LEDGER_ANCHOR_TICK_MS", 5000, 1000);
function countLedgerEntries() {
  try {
    if (!existsSync(LEDGER_RUNTIME.ledgerPath)) return 0;
    return readFileSync(LEDGER_RUNTIME.ledgerPath, "utf8").split("\n").filter((l) => l.trim() !== "").length;
  } catch { return 0; }
}
async function anchorTick() {
  try {
    const headResponse = checkpointHeadResponse(LEDGER_RUNTIME);
    if (!headResponse.ok) throw new Error(headResponse.message);
    const head = headResponse.checkpoint;
    const count = countLedgerEntries();
    const lastSize = head?.tree_size ?? 0;
    if (count <= lastSize) return; // nothing new to anchor
    const dueByCount = (count - lastSize) >= ANCHOR_EVERY_ENTRIES;
    const dueByTime = !head || (Date.now() - Date.parse(head.issued_at) >= ANCHOR_INTERVAL_MS);
    if (dueByCount || dueByTime) await anchorNow(LEDGER_RUNTIME, { signLedger: LEDGER_SIGN, bundle: LEDGER_BUNDLE });
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ ts: new Date().toISOString(), event: "mnde.execution_ledger.anchor_tick_failed", message: error?.message ?? String(error) })}\n`);
  }
}
if (LEDGER_RUNTIME.enabled) {
  const anchorTimer = setInterval(() => { void anchorTick(); }, ANCHOR_TICK_MS);
  if (typeof anchorTimer.unref === "function") anchorTimer.unref(); // never keep the process alive
}

// Sign a built receipt for delivery. Legacy mode is a pass-through; custody mode
// returns a signed envelope or fails closed with a distinct reason code. No
// automatic downgrade to legacy when custody is selected.
async function signForDelivery(receipt) {
  if (SIGNING_MODE !== "custody") return { ok: true, receipt };
  if (signingConfigError) return { ok: false, reason_code: signingConfigError };
  return signReceiptAdapter(receipt, liveSigningContext, { now: new Date().toISOString() });
}

function testTimingHeaders(timings) {
  if (!TEST_HARNESS_ENABLED) return {};
  return {
    "x-mnde-server-ms": String(Math.max(0, timings?.total_server_ms ?? 0)),
    "x-mnde-admission-ms": String(Math.max(0, timings?.request_admission_wait_ms ?? 0)),
    "x-mnde-parse-ms": String(Math.max(0, timings?.request_parse_ms ?? timings?.parse_ms ?? 0)),
    "x-mnde-worker-wait-ms": String(Math.max(0, timings?.worker_queue_wait_ms ?? 0)),
    "x-mnde-worker-exec-ms": String(Math.max(0, timings?.worker_exec_ms ?? 0)),
    "x-mnde-response-flush-ms": String(Math.max(0, timings?.response_flush_ms ?? 0)),
    "x-mnde-process-id": String(process.pid)
  };
}

const L0_503_BYTES = Buffer.from(`${canonicalizeJson({
  schema_version: "mnde.api.response.v1",
  decision: "REFUSE",
  reason_code: ERR_L0_TRANSPORT_SHED,
  request_hash: null,
  decision_hash: null,
  receipt: null,
  l0_transport_shed: true
})}\n`, "utf8");

function l0ShedDecision(req, res) {
  counters.l0_shed_total += 1;
  try {
    if (res.destroyed || req.socket?.destroyed) {
      counters.l0_shed_destroy_total += 1;
      counters.l0_malformed_destroy_sheds += 1;
      req.socket?.destroy();
      return true;
    }
    counters.l0_shed_503_total += 1;
    counters.l0_overload_503_sheds += 1;
    res.writeHead(503, {
      "cache-control": "no-store",
      "connection": "close",
      "content-length": L0_503_BYTES.byteLength,
      "content-type": "application/json; charset=utf-8"
    });
    res.shouldKeepAlive = false;
    res.end(L0_503_BYTES, () => {
      counters.completed_http_responses += 1;
    });
  } catch {
    counters.l0_shed_destroy_total += 1;
    counters.l0_malformed_destroy_sheds += 1;
    counters.l0_shed_503_total = Math.max(0, counters.l0_shed_503_total - 1);
    counters.l0_overload_503_sheds = Math.max(0, counters.l0_overload_503_sheds - 1);
    req.socket?.destroy();
  }
  return true;
}

function response(res, status, body, timings) {
  if (res.writableEnded || res.destroyed) return;
  const serializationStarted = performance.now();
  const bytes = Buffer.from(`${canonicalizeJson(body)}\n`, "utf8");
  if (timings) timings.response_serialize_ms = Math.max(0, Math.round(performance.now() - serializationStarted));
  res.writeHead(status, {
    ...corsHeadersForOrigin(res.req?.headers?.origin),
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
    "cache-control": "no-store",
    "connection": "close",
    "content-type": "application/json; charset=utf-8",
    "content-length": bytes.byteLength,
    ...testTimingHeaders(timings)
  });
  const writeStarted = performance.now();
  res.end(bytes, () => {
    counters.completed_http_responses += 1;
    if (timings) timings.response_flush_ms = Math.max(0, Math.round(performance.now() - writeStarted));
    res.req?.socket?.destroySoon?.();
  });
}

async function persistRefusal(reason_code, extra = {}, timings = {}) {
  const builtReceipt = buildSidecarRefusalReceipt({
    raw_body: extra.raw_body ?? "",
    reason_code,
    policy_hash,
    policy_version: policy.policy_version,
    timings,
    request_id: extra.request_id ?? null,
    request_hash: extra.request_hash ?? null,
    decision_hash: extra.decision_hash ?? null
  });
  const signed = await signForDelivery(builtReceipt);
  if (!signed.ok) return { ok: false, reason_code: signed.reason_code, receipt: null };
  const receipt = signed.receipt;
  const queued = await receiptQueue.enqueue(receipt);
  if (!queued.ok) {
    counters.refused_overload += 1;
    counters.refused_receipt_queue_saturated += queued.reason_code === RECEIPT_QUEUE_SATURATED ? 1 : 0;
    counters.receipt_refusals += 1;
    return { ok: false, reason_code: queued.reason_code, receipt };
  }
  if (LEDGER_RUNTIME.enabled) {
    const ledger = await recordReceiptInLedger({ runtime: LEDGER_RUNTIME, receipt, durable: queued.durable, profile: RUNTIME_PROFILE, engine: LEDGER_ENGINE, flush: () => receiptQueue.flush(), signLedger: LEDGER_SIGN });
    if (ledger.failClosed) return { ok: false, reason_code: ledger.code, receipt };
  } else if (RECEIPT_QUEUE_CONFIG.durability_mode === "strict_audit") {
    await queued.durable;
  }
  return { ok: true, receipt };
}

async function fail(res, reason_code, status = 200, extra = {}, timings = {}) {
  const persisted = await persistRefusal(reason_code, extra, timings);
  const finalReason = persisted.ok ? reason_code : persisted.reason_code;
  const { raw_body: _rawBody, ...publicExtra } = extra;
  response(res, status, {
    schema_version: "mnde.api.response.v1",
    decision: "REFUSE",
    reason_code: finalReason,
    request_hash: persisted.receipt?.request_hash ?? extra.request_hash ?? null,
    decision_hash: persisted.receipt?.decision_output?.decision_hash ?? extra.decision_hash ?? null,
    receipt: persisted.ok ? persisted.receipt : null,
    receipt_persisted: persisted.ok,
    ...publicExtra
  }, timings);
}

function failWithoutReceipt(res, reason_code, status = 200, extra = {}, timings = {}) {
  const { raw_body: _rawBody, ...publicExtra } = extra;
  response(res, status, {
    schema_version: "mnde.api.response.v1",
    decision: "REFUSE",
    reason_code,
    request_hash: extra.request_hash ?? null,
    decision_hash: extra.decision_hash ?? null,
    receipt: null,
    receipt_persisted: false,
    ...publicExtra
  }, timings);
}

function recordAdmissionRefusal(reason_code) {
  counters.refused_overload += 1;
  counters.admission_refusals += 1;
  if (reason_code === WORKER_POOL_SATURATED) {
    counters.refused_worker_pool_saturated += 1;
    counters.worker_refusals += 1;
  }
}

function readBody(req, timings) {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const chunks = [];
    let size = 0;
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      if (timings) timings.request_body_read_ms = Math.max(0, Math.round(performance.now() - started));
      fn(value);
    };
    req.on("data", (chunk) => {
      size += chunk.byteLength;
      if (size > HTTP_LIMITS.max_request_body_bytes) {
        req.pause();
        req.resume();
        finish(reject, new Error("ERR_BODY_TOO_LARGE"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => finish(resolve, Buffer.concat(chunks).toString("utf8")));
    req.on("error", (error) => finish(reject, error));
  });
}

async function readStrictObject(req, timings) {
  const raw = await readBody(req, timings);
  const started = performance.now();
  const parsed = parseStrictJson(raw);
  timings.request_parse_ms = Math.max(0, Math.round(performance.now() - started));
  timings.parse_ms = timings.request_parse_ms;
  if (!parsed.ok || typeof parsed.value !== "object" || parsed.value === null || Array.isArray(parsed.value)) {
    const error = new Error(parsed.ok ? "ERR_REQUEST_SCHEMA_INVALID" : `ERR_${parsed.reason.toUpperCase()}`);
    error.raw_body = raw;
    throw error;
  }
  return { value: parsed.value, raw };
}

function apiResponseFromReceipt(receipt) {
  const decision = receipt.decision_output;
  const body = {
    schema_version: "mnde.api.response.v1",
    decision: decision.decision,
    reason_code: decision.reason_code,
    request_hash: decision.request_hash,
    decision_hash: decision.decision_hash,
    total_cost_usd: decision.total_cost_usd,
    allowed_cost_usd: decision.allowed_cost_usd,
    prevented_cost_usd: decision.prevented_cost_usd,
    policy_version: decision.policy_version,
    policy_hash: decision.policy_hash
  };
  if (decision.decision === "ALLOW" || INLINE_REFUSAL_RECEIPTS) {
    body.receipt = receipt;
  } else {
    body.receipt_persisted = true;
  }
  return body;
}

function receiptFromInput(input) {
  return input?.receipt && typeof input.receipt === "object" ? input.receipt : input;
}

function isDecisionRoute(pathname) {
  return pathname === "/v1/decisions" || pathname === "/decide";
}

function authorityActionName(pathname) {
  if (pathname === "/policy/activate") return "policy.activate";
  if (pathname === "/audit/bundle") return "audit.bundle";
  if (pathname === "/replay/recent") return "replay.recent";
  if (pathname === "/receipts/verify" || pathname === "/verify") return "receipt.verify";
  return pathname;
}

function auditAuthority(pathname, authz, result, target = null, decision_hash = null, reason = null) {
  try {
    appendAuthAuditEvent(AUTH_AUDIT_LOG_PATH, {
      actor: authz.actor,
      action: authorityActionName(pathname),
      target,
      result,
      decision_hash,
      reason
    });
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ ts: new Date().toISOString(), event: "mnde.auth_audit_write_failed", error: error instanceof Error ? error.message : String(error) })}\n`);
  }
}

function authorizeRequest(req, pathname, target = null) {
  const authz = authorizeAuthorityAction(pathname, parseAuthorityAssertion(req.headers));
  if (!authz.ok) auditAuthority(pathname, authz, "REFUSE", target, null, authz.reason);
  return authz;
}

function authorizeProductionRead(req, res, pathname, target) {
  if (RUNTIME_PROFILE !== "production") return true;
  const authz = authorizeRequest(req, pathname, target);
  if (!authz.ok) {
    response(res, 403, authRefusalBody(authz, target));
    return false;
  }
  auditAuthority(pathname, authz, "ALLOW", target, null, null);
  return true;
}

function externalAuthRefusalBody(target = null) {
  return refusalBody("ERR_AUTH_REFUSED", null, target);
}

// Choose the external refusal body for a failed authz result. Credential-class
// failures (missing/expired/tampered/wrong-capability) collapse to the uniform
// ERR_AUTH_REFUSED so no internal reason leaks. A capability-mapping gap
// (ERR_AUTH_CAPABILITY_UNMAPPED) is a server-config signal, not a caller-secret,
// so it is surfaced verbatim to make the fail-closed boundary observable.
function authRefusalBody(authz, target = null) {
  if (authz && authz.reason === "ERR_AUTH_CAPABILITY_UNMAPPED") {
    return refusalBody("ERR_AUTH_CAPABILITY_UNMAPPED", null, target);
  }
  return externalAuthRefusalBody(target);
}

// Production-gated authority check for privileged ledger operations (anchor,
// proof). Mirrors authorizeProductionRead's environment gating — in the local
// profile this is a dev pass-through so the localhost round-trip works without an
// authority assertion — but, unlike authorizeProductionRead, it does NOT emit the
// ALLOW audit itself so the caller can record an operation-specific audit line
// (e.g. tree_size). On refusal it writes the uniform 403 and returns {ok:false}.
// In production the mapped capability is enforced fail-closed. The pathname passed
// here is the SAME canonical value the router matched on, so guard and router can
// never diverge.
function gateLedgerOperation(req, res, pathname, target) {
  if (RUNTIME_PROFILE !== "production") return { ok: true, actor: null };
  const authz = authorizeRequest(req, pathname, target);
  if (!authz.ok) {
    response(res, 403, authRefusalBody(authz, target));
    return { ok: false };
  }
  return authz;
}

// Policy-engine decision path (opt-in). Fails closed on config errors or engine
// errors. Returns the signed policy-engine receipt for offline verification.
async function respondPolicyEngine(res, request, timings, totalStarted, caller) {
  if (policyEngineConfigError) {
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, "ERR_PE_CONFIG_INVALID", 200, { policy_engine_error: policyEngineConfigError }, timings);
    return;
  }
  let outcome;
  try {
    outcome = policyEngine.decide(request, { now: new Date().toISOString(), caller });
  } catch (error) {
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, "ERR_PE_DECISION_FAILED", 200, { policy_engine_error: error instanceof Error ? error.message : String(error) }, timings);
    return;
  }
  // Custody signing (opt-in) is applied to the built receipt before delivery and
  // fails closed: if custody is selected and signing fails, the request fails.
  const signed = await signForDelivery(outcome.receipt);
  if (!signed.ok) {
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    failWithoutReceipt(res, signed.reason_code, 200, {}, timings);
    return;
  }
  const queued = await receiptQueue.enqueue(signed.receipt);
  if (!queued.ok) {
    counters.refused_overload += 1;
    counters.receipt_refusals += 1;
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, queued.reason_code, 200, {}, timings);
    return;
  }
  let ledgerMeta = null;
  if (LEDGER_RUNTIME.enabled) {
    const ledger = await recordReceiptInLedger({ runtime: LEDGER_RUNTIME, receipt: signed.receipt, durable: queued.durable, profile: RUNTIME_PROFILE, engine: LEDGER_ENGINE, flush: () => receiptQueue.flush(), signLedger: LEDGER_SIGN });
    if (ledger.failClosed) {
      counters.receipt_refusals += 1;
      timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
      recordTimings(timings);
      await fail(res, ledger.code, 200, {}, timings);
      return;
    }
    ledgerMeta = ledgerResponseMeta(ledger);
  } else if (RECEIPT_QUEUE_CONFIG.durability_mode === "strict_audit") {
    await queued.durable;
  }
  timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
  recordTimings(timings);
  response(res, 200, {
    schema_version: "mnde.api.response.v1",
    decision_engine: "policy-engine",
    // Ledger status lives OUTSIDE the receipt (never mutates receipt bytes).
    ...(ledgerMeta ? { ledger: ledgerMeta } : {}),
    // Deployment state surfaced to operators only (API/logs); NOT in the signed receipt.
    ...(policyConfigurationState ? { policy_configuration_state: policyConfigurationState } : {}),
    decision: outcome.decision,
    reason_code: outcome.reason_code,
    policy_id: outcome.receipt.decision_output.policy_id,
    policy_hash: outcome.receipt.policy_hash,
    request_hash: outcome.receipt.request_hash,
    decision_hash: outcome.receipt.decision_output.decision_hash,
    trust_enforced: Boolean(outcome.receipt.trust_enforced),
    approval_enforced: Boolean(outcome.receipt.approval_enforced),
    ...(SIGNING_MODE === "custody" ? { receipt_signing: "custody" } : {}),
    ...(caller ? { authenticated_caller: caller.id } : {}),
    receipt: signed.receipt,
    timings
  }, timings);
}

async function handleDecide(req, res) {
  // Caller authentication runs before any decision work. Fails closed; an
  // unauthenticated caller never reaches evaluation and never gets a receipt.
  if (AUTH_MODE === "bearer") {
    if (AUTH_CONFIG_ERROR) {
      response(res, 503, { schema_version: "mnde.api.response.v1", decision: "REFUSE", reason_code: "ERR_AUTH_CONFIG_INVALID", receipt: null });
      return;
    }
    const authSource = authSourceForRequest(req);
    if (isAuthThrottled(authSource)) {
      counters.auth_failures = (counters.auth_failures ?? 0) + 1;
      response(res, 401, { schema_version: "mnde.api.response.v1", decision: "REFUSE", reason_code: "ERR_UNAUTHENTICATED", receipt: null });
      return;
    }
    const authResult = authenticate(req.headers, AUTH);
    if (!authResult.ok) {
      counters.auth_failures = (counters.auth_failures ?? 0) + 1;
      recordAuthFailure(authSource);
      response(res, 401, { schema_version: "mnde.api.response.v1", decision: "REFUSE", reason_code: "ERR_UNAUTHENTICATED", receipt: null });
      return;
    }
    clearAuthFailures(authSource);
    req._mndeCaller = authResult.caller;
  }
  const totalStarted = performance.now();
  const timings = {
    parse_ms: 0,
    preflight_ms: 0,
    orbit_ms: 0,
    arm_ms: 0,
    ramona_ms: 0,
    custody_ms: 0,
    canonicalize_ms: 0,
    receipt_build_ms: 0,
    signing_ms: 0,
    worker_queue_wait_ms: 0,
    worker_exec_ms: 0,
    receipt_enqueue_ms: 0,
    persistence_flush_ms: 0,
    response_serialize_ms: 0,
    response_flush_ms: 0,
    total_server_ms: 0,
    request_admission_wait_ms: 0,
    request_body_read_ms: 0,
    request_parse_ms: 0,
    active_requests: 0,
    active_sockets: 0,
    event_loop_lag_ms: latestEventLoopLagMs
  };
  const socketState = socketTimings.get(req.socket);
  timings.socket_accepted_ms = socketState?.accepted_at_ms ? ms(socketState.accepted_at_ms) : 0;
  timings.first_byte_ms = socketState?.first_byte_at_ms ? ms(socketState.first_byte_at_ms) : 0;
  timings.request_event_ms = ms(totalStarted);
  timings.pre_request_queue_delay_ms = socketState?.accepted_at_ms ? Math.max(0, Math.round(totalStarted - socketState.accepted_at_ms)) : 0;
  counters.requests += 1;
  if (req.headers.origin) counters.browser_origin_requests += 1;
  if (!watchdog.canAcceptDecisions()) {
    counters.watchdog_interventions += 1;
    watchdog.markIntervention();
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, watchdog.snapshot().fatal ? ERR_RUNTIME_FATAL : ERR_RUNTIME_DEGRADED, 200, { runtime_degraded: watchdog.snapshot() }, timings);
    return;
  }
  const socketLimit = admission.noteSocketRequest(req.socket);
  if (!socketLimit.ok) {
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, socketLimit.reason_code, 200, { saturation_signal: "socket_request_limit" }, timings);
    req.socket.destroySoon?.();
    return;
  }
  const admitted = admission.tryAcquireRequest();
  timings.request_admission_wait_ms = admitted.admission_wait_ms ?? 0;
  timings.slot_allocation_ms = ms();
  if (!admitted.ok) {
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, admitted.reason_code, 200, { saturation_signal: "active_requests" }, timings);
    return;
  }
  const admissionSnapshot = admission.snapshot();
  timings.active_requests = admissionSnapshot.active_requests;
  timings.active_sockets = admissionSnapshot.active_sockets;
  const queueMetricsAtStart = receiptQueue.metrics();
  const saturation = saturationController.shouldRefuse({
    inflight,
    event_loop_lag_ms: latestEventLoopLagMs,
    queue_depth: queueMetricsAtStart.queue_depth,
    queue_bytes: queueMetricsAtStart.queue_bytes
  });
  if (!saturation.ok) {
    counters.refused_overload += 1;
    counters.refused_system_saturated += 1;
    if (saturation.saturation_signal === "inflight") counters.saturation_inflight += 1;
    if (saturation.saturation_signal === "event_loop_lag") counters.saturation_event_loop_lag += 1;
    if (saturation.saturation_signal === "receipt_queue_depth") counters.saturation_receipt_queue_depth += 1;
    if (saturation.saturation_signal === "receipt_queue_bytes") counters.saturation_receipt_queue_bytes += 1;
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, SYSTEM_SATURATED, 200, { saturation_signal: saturation.saturation_signal }, timings);
    admitted.release();
    return;
  }
  inflight += 1;
  try {
    if (TEST_HARNESS_ENABLED && req.headers["x-mnde-custody-mode"] === "timeout") {
      const custodyStarted = performance.now();
      timings.custody_ms = Math.max(0, Math.round(performance.now() - custodyStarted));
      timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
      recordTimings(timings);
      await fail(res, "ERR_CUSTODY_SIGNER_TIMEOUT", 200, { timings }, timings);
      return;
    }
    if (TEST_HARNESS_ENABLED && req.headers["x-mnde-shutdown-test"] === "hang") {
      // Never resolves: pins this request in-flight (inflight stays > 0) so a
      // test can exercise the shutdown DEADLINE path. The process is expected to
      // exit via the deadline, never via this handler returning.
      await new Promise(() => {});
      return;
    }
    await readStrictObject(req, timings);
    timings.body_read_complete_ms = ms();
    if (TEST_HARNESS_ENABLED && req.headers["x-mnde-shutdown-test"] === "slow") {
      // Bounded delay AFTER the body is captured, so real application work
      // (decision + receipt persistence) is still running when a test begins
      // shutdown mid-request — including after the client has disconnected.
      const slowMs = Number.parseInt(req.headers["x-mnde-shutdown-slow-ms"] ?? "300", 10);
      await new Promise((resolve) => setTimeout(resolve, Number.isSafeInteger(slowMs) && slowMs > 0 ? slowMs : 300));
    }

    // Approval delivery is disabled: executor-local replay files cannot establish
    // the independent rollback boundary. Do not fall back to memory or local files.
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, "ERR_FRESHNESS_DEPLOYMENT_DISABLED", 200, { timings }, timings);
  } catch (error) {
    if (error?.message?.startsWith("ERR_RECEIPT_FLUSH_FAILED")) counters.flush_failures += 1;
    if (error?.message === WORKER_TIMEOUT) counters.request_timeout_refusals += 1;
    timings.total_server_ms = Math.max(0, Math.round(performance.now() - totalStarted));
    recordTimings(timings);
    await fail(res, error.message?.startsWith("ERR_") ? error.message : "ERR_RUNTIME_ERROR", 400, { raw_body: error.raw_body ?? "" }, timings);
  } finally {
    inflight -= 1;
    admitted.release();
  }
}

async function handleVerify(req, res) {
  const authz = authorizeRequest(req, new URL(req.url, `http://${HOST}:${PORT}`).pathname);
  if (!authz.ok) {
    response(res, 403, externalAuthRefusalBody("receipt.verify"));
    return;
  }
  try {
    const input = await readStrictObject(req, {});
    const result = verifyReceiptContract(input.value, verifySignedReceiptAtDataRoot);
    auditAuthority(new URL(req.url, `http://${HOST}:${PORT}`).pathname, authz, result.status === "VALID" ? "ALLOW" : "REFUSE", result.receipt_id, result.decision_hash, result.reason);
    response(res, 200, result);
  } catch (error) {
    auditAuthority(new URL(req.url, `http://${HOST}:${PORT}`).pathname, authz, "REFUSE", "receipt.verify", null, "ERR_RECEIPT_VERIFY_FAILED");
    response(res, 200, {
      status: "INVALID",
      receipt_id: null,
      request_hash: null,
      decision_hash: null,
      policy_hash: null,
      reason: error.message?.startsWith("ERR_") ? error.message : "ERR_RECEIPT_VERIFY_FAILED"
    });
  }
}

// Local operational dashboard (no login, no account, no cloud). It is a static
// page that reads only the unauthenticated local status endpoints, so a fresh
// user reaches "is execution protected right now?" immediately on launch.
const DASHBOARD_PATH = join(REPO_ROOT, "desktop", "dashboard.html");
function serveDashboard(req, res) {
  let html;
  try {
    html = readFileSync(DASHBOARD_PATH);
  } catch {
    response(res, 404, { schema_version: "mnde.api.response.v1", reason_code: "ERR_DASHBOARD_UNAVAILABLE" });
    return;
  }
  res.writeHead(200, {
    ...corsHeadersForOrigin(req.headers.origin),
    "cache-control": "no-store",
    "connection": "close",
    "content-security-policy": "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; img-src 'self' data:; connect-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'",
    "content-length": html.byteLength,
    "content-type": "text/html; charset=utf-8",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff"
  });
  res.end(html);
}

function currentPolicyResponse() {
  return {
    status: "ACTIVE",
    policy: policy.policy_version,
    policy_hash,
    reason: null
  };
}

function verifyPolicyTrust(publicKeyHex, policyDocument, signatureHex) {
  return verifyPolicySignature(publicKeyHex, canonicalPolicyPayload(policyDocument), signatureHex);
}

async function handlePolicyActivate(req, res) {
  const authz = authorizeRequest(req, "/policy/activate");
  if (!authz.ok) {
    response(res, 403, externalAuthRefusalBody("policy.activate"));
    return;
  }
  try {
    const input = await readStrictObject(req, {});
    const policyPath = input.value?.policy_path;
    if (typeof policyPath !== "string" || !policyPath.trim()) {
      auditAuthority("/policy/activate", authz, "REFUSE", "missing policy path", null, "policy_path is required");
      response(res, 200, { status: "REFUSED", policy: policy.policy_version, policy_hash, reason: "policy_path is required" });
      return;
    }
    if (!existsSync(policyPath)) {
      auditAuthority("/policy/activate", authz, "REFUSE", policyPath, null, "policy file does not exist");
      response(res, 200, { status: "REFUSED", policy: policy.policy_version, policy_hash, reason: "policy file does not exist" });
      return;
    }
    const candidate = JSON.parse(readFileSync(policyPath, "utf8"));
    const validation = validatePolicyDocument(candidate, verifyPolicyTrust);
    if (!validation.ok) {
      auditAuthority("/policy/activate", authz, "REFUSE", policyPath, null, validation.reason);
      response(res, 200, { status: "REFUSED", policy: policy.policy_version, policy_hash, reason: validation.reason });
      return;
    }
    policy = candidate;
    policy_hash = policyHash(policy);
    activePolicyPath = policyPath;
    auditAuthority("/policy/activate", authz, "ALLOW", policyPath, policy_hash, null);
    response(res, 200, currentPolicyResponse());
  } catch (error) {
    auditAuthority("/policy/activate", authz, "REFUSE", "policy.activate", null, error instanceof Error ? error.message : "policy activation failed");
    response(res, 200, { status: "REFUSED", policy: policy.policy_version, policy_hash, reason: error instanceof Error ? error.message : "policy activation failed" });
  }
}

function recentReceiptsForApi(url) {
  const limit = clampReceiptLimit(url.searchParams.get("limit"));
  return readRecentReceipts(RECEIPT_LOG_PATH, limit, (warning) => {
    counters.malformed_receipt_lines += 1;
    process.stderr.write(`${JSON.stringify({ ts: new Date().toISOString(), event: "mnde.receipt_history_malformed", ...warning })}\n`);
  });
}

function replayRecentForApi(limit) {
  return replayRecentReceipts(RECEIPT_LOG_PATH, limit, verifySignedReceiptAtDataRoot, replayReceiptDeterministically);
}

function readinessSnapshot() {
  const queueMetrics = receiptQueue.metrics();
  const workerMetrics = workerPool.metrics();
  const watchdogState = watchdog.snapshot();
  return {
    // Draining reports NOT ready while still reachable: a load balancer or the
    // spawning harness sees ok:false the instant shutdown begins and stops
    // routing new work here, even though the process keeps serving already-
    // admitted requests until they settle.
    ok: !draining && !queueMetrics.fail_closed && !watchdogState.fatal,
    ...(HARNESS_INSTANCE_ID ? { harness_instance_id: HARNESS_INSTANCE_ID } : {}),
    draining,
    degraded: draining || queueMetrics.fail_closed || watchdogState.degraded,
    degraded_reason: draining ? "ERR_SIDECAR_DRAINING" : (queueMetrics.fail_closed_reason ?? watchdogState.degraded_reason),
    active_policy_version: policy.policy_version,
    policy_hash,
    worker_id: cluster.worker?.id ?? 0,
    inflight,
    event_loop_lag_ms: latestEventLoopLagMs,
    receipt_queue: telemetrySafe(queueMetrics),
    worker_pool: telemetrySafe(workerMetrics),
    watchdog: telemetrySafe(watchdogState),
    durability_mode: RECEIPT_QUEUE_CONFIG.durability_mode
  };
}

function auditBundleForApi() {
  const queueMetrics = receiptQueue.metrics();
  const workerMetrics = workerPool.metrics();
  return createAuditBundle({
    outputRoot: join(DATA_ROOT, "audit-bundles"),
    recentReceipts: readRecentReceipts(RECEIPT_LOG_PATH, 100, () => {
      counters.malformed_receipt_lines += 1;
    }),
    replaySummary: replayRecentForApi(100),
    metricsText: metricsText(queueMetrics, workerMetrics),
    readySnapshot: readinessSnapshot(),
    policySummary: currentPolicyResponse()
  });
}

async function handleReplay(req, res) {
  try {
    const input = await readStrictObject(req, {});
    const receipt = receiptFromInput(input.value);
    if (!verifySignedReceiptAtDataRoot(receipt)) {
      response(res, 200, {
        schema_version: "mnde.receipt_replay.v1",
        request_hash: receipt?.request_hash ?? null,
        original: receipt?.decision_output ?? null,
        replayed: null,
        drift: true,
        mismatches: [{ field: "signature", original: "valid", replayed: "invalid" }]
      });
      return;
    }
    const boundaryReplay = boundaryReplayEndpointResponse(receipt);
    if (boundaryReplay) {
      response(res, 200, boundaryReplay);
      return;
    }
    const replay = executeDeterministicPipeline(receipt.canonical_request, { enforceExecutionId: false });
    if ("parse_boundary" in replay) {
      const original = receipt.decision_output;
      const mismatches = [
        ["request_hash", receipt.request_hash, replay.request_hash],
        ["decision", original.decision, replay.decision],
        ["reason_code", original.reason_code, replay.reason_code],
        ["decision_hash", original.decision_hash, replay.decision_hash]
      ]
        .filter(([, left, right]) => left !== right)
        .map(([field, originalValue, replayedValue]) => ({ field, original: originalValue, replayed: replayedValue }));
      response(res, 200, {
        schema_version: "mnde.receipt_replay.v1",
        request_hash: receipt.request_hash,
        original,
        replayed: replay,
        drift: mismatches.length > 0,
        mismatches
      });
      return;
    }
    const original = receipt.decision_output;
    const replayed = replay.receipt.decision_output;
    const mismatches = Object.keys(original)
      .filter((key) => original[key] !== replayed[key])
      .map((key) => ({ field: key, original: original[key], replayed: replayed[key] }));
    response(res, 200, {
      schema_version: "mnde.receipt_replay.v1",
      request_hash: receipt.request_hash,
      original,
      replayed,
      drift: mismatches.length > 0,
      mismatches
    });
  } catch (error) {
    response(res, 400, {
      schema_version: "mnde.receipt_replay.v1",
      drift: true,
      reason_code: error.message?.startsWith("ERR_") ? error.message : "ERR_REPLAY_FAILED",
      mismatches: []
    });
  }
}

const server = http.createServer(async (req, res) => {
  watchdog.heartbeat("request");
  socketRegistry.markRequest(req.socket);
  const pathname = new URL(req.url, `http://${HOST}:${PORT}`).pathname;
  if (!isAllowedCorsOrigin(req.headers.origin)) {
    response(res, 403, {
      schema_version: "mnde.api.response.v1",
      decision: "REFUSE",
      reason_code: ERR_UNAUTHORIZED_ORIGIN,
      request_hash: null,
      decision_hash: null,
      receipt: null
    });
    return;
  }
  if (req.method === "OPTIONS") {
    response(res, 204, {});
    return;
  }
  if (req.method === "GET" && pathname === "/healthz") {
    watchdog.heartbeat("healthz");
    response(res, 200, {
      ok: true,
      degraded: watchdog.snapshot().degraded,
      fatal: watchdog.snapshot().fatal,
      event_loop_lag_ms: latestEventLoopLagMs,
      worker_id: cluster.worker?.id ?? 0
    });
    return;
  }
  if (req.method === "GET" && pathname === "/identity") {
    if (!authorizeProductionRead(req, res, pathname, "identity")) return;
    response(res, 200, {
      schema_version: "mnde.sidecar_identity.v1",
      // Immutable release identity of the running artifact, from embedded build
      // metadata (never Git). Lets a caller confirm the running sidecar and the
      // installed CLI belong to the same MNDe release.
      release: getReleaseIdentity(),
      repo_root: REPO_ROOT,
      process_id: process.pid,
      policy_hash,
      policy_version: policy.policy_version,
      started_at_ms: Math.round(performance.timeOrigin)
    });
    return;
  }
  if (req.method === "GET" && pathname === "/readyz") {
    const socketMetrics = socketRegistry.metrics();
    response(res, 200, {
      ...readinessSnapshot(),
      max_inflight: MAX_INFLIGHT,
      shed_inflight: Math.min(SHED_INFLIGHT, MAX_INFLIGHT),
      sockets: telemetrySafe(socketMetrics),
    });
    return;
  }
  if (req.method === "GET" && pathname === "/metrics") {
    if (!authorizeProductionRead(req, res, pathname, "metrics")) return;
    const queueMetrics = receiptQueue.metrics();
    const workerMetrics = workerPool.metrics();
    const body = Buffer.from(metricsText(queueMetrics, workerMetrics), "utf8");
    res.writeHead(200, {
      ...corsHeadersForOrigin(req.headers.origin),
      "cache-control": "no-store",
      "connection": "close",
      "content-length": body.byteLength,
      "content-type": "text/plain; version=0.0.4; charset=utf-8"
    });
    res.end(body);
    return;
  }
  if (req.method === "POST" && isDecisionRoute(pathname)) {
    // Drain gate. Once shutdown has begun we admit NO new decision work — not
    // even on a connection that was already open before draining started (the
    // socket outlives server.close()). This is a liveness refusal, not a policy
    // decision, so it carries no receipt and enqueues nothing into the queue we
    // are about to flush; it still returns the standard REFUSE envelope with
    // connection:close so the caller retries elsewhere.
    if (draining) {
      failWithoutReceipt(res, "ERR_SIDECAR_DRAINING", 503);
      return;
    }
    if (L0_LIMITS.enable && l0ActiveConnections > L0_LIMITS.max_connections) {
      l0ShedDecision(req, res);
      return;
    }
    await handleDecide(req, res);
    return;
  }
  if (req.method === "GET" && pathname === "/receipts/recent") {
    if (!authorizeProductionRead(req, res, pathname, "receipts.recent")) return;
    response(res, 200, recentReceiptsForApi(new URL(req.url, `http://${HOST}:${PORT}`)));
    return;
  }
  if (req.method === "POST" && (pathname === "/verify" || pathname === "/receipts/verify")) {
    await handleVerify(req, res);
    return;
  }
  if (req.method === "POST" && pathname === "/replay/recent") {
    const authz = authorizeRequest(req, pathname);
    if (!authz.ok) {
      response(res, 403, externalAuthRefusalBody("replay.recent"));
      return;
    }
    try {
      const input = await readStrictObject(req, {});
      const result = replayRecentForApi(input.value?.limit);
      auditAuthority(pathname, authz, result.status === "PASS" ? "ALLOW" : "REFUSE", `limit:${input.value?.limit ?? 100}`, result.policy_hash, result.status);
      response(res, 200, result);
    } catch {
      const result = replayRecentForApi(100);
      auditAuthority(pathname, authz, result.status === "PASS" ? "ALLOW" : "REFUSE", "limit:100", result.policy_hash, result.status);
      response(res, 200, result);
    }
    return;
  }
  if (req.method === "POST" && pathname === "/replay") {
    await handleReplay(req, res);
    return;
  }
  if (req.method === "GET" && pathname === "/policy/current") {
    if (!authorizeProductionRead(req, res, pathname, "policy.current")) return;
    response(res, 200, currentPolicyResponse());
    return;
  }
  if (req.method === "POST" && pathname === "/policy/activate") {
    await handlePolicyActivate(req, res);
    return;
  }
  if (req.method === "POST" && pathname === "/audit/bundle") {
    const authz = authorizeRequest(req, pathname);
    if (!authz.ok) {
      response(res, 403, externalAuthRefusalBody("audit.bundle"));
      return;
    }
    try {
      const result = auditBundleForApi();
      auditAuthority(pathname, authz, result.status === "PASS" ? "ALLOW" : "REFUSE", result.bundle_path, null, result.reason);
      response(res, 200, result);
    } catch (error) {
      auditAuthority(pathname, authz, "REFUSE", "audit.bundle", null, error instanceof Error ? error.message : "audit bundle failed");
      response(res, 200, { status: "FAIL", bundle_path: null, created_at: new Date().toISOString(), files: [], reason: error instanceof Error ? error.message : "audit bundle failed" });
    }
    return;
  }
  if (req.method === "GET" && (pathname === "/" || pathname === "/dashboard")) {
    if (!authorizeProductionRead(req, res, pathname, "dashboard")) return;
    serveDashboard(req, res);
    return;
  }
  if (req.method === "GET" && pathname === "/capabilities") {
    if (!authorizeProductionRead(req, res, pathname, "capabilities")) return;
    response(res, 200, buildCapabilityObject({
      health: true,
      ready: true,
      metrics: true,
      receipts_recent: true,
      receipt_verify: true,
      replay_recent: true,
      policy_activation: true,
      audit_bundle: true
    }));
    return;
  }
  // Execution-ledger read endpoints. Gated the same way as the receipt
  // endpoints: head ~ inspect_receipts (production-read), verify ~ verify_receipts,
  // export ~ export_audit. Export is never exposed without authority gating.
  if (req.method === "GET" && pathname === "/ledger/head") {
    if (!authorizeProductionRead(req, res, pathname, "ledger.head")) return;
    response(res, 200, await ledgerHeadResponse(LEDGER_RUNTIME, LEDGER_BUNDLE));
    return;
  }
  if (req.method === "GET" && pathname === "/ledger/verify") {
    const authz = authorizeRequest(req, pathname);
    if (!authz.ok) {
      response(res, 403, refusalBody(authz.reason, authz.actor, "ledger.verify"));
      return;
    }
    const result = await ledgerVerifyResponse(LEDGER_RUNTIME, LEDGER_BUNDLE);
    auditAuthority(pathname, authz, result.ok ? "ALLOW" : "REFUSE", `entries:${result.entries_checked}`, null, result.ok ? null : result.errors[0]?.code);
    response(res, 200, result);
    return;
  }
  if (req.method === "GET" && pathname === "/ledger/export") {
    const authz = authorizeRequest(req, pathname);
    if (!authz.ok) {
      response(res, 403, refusalBody(authz.reason, authz.actor, "ledger.export"));
      return;
    }
    const result = ledgerExportResponse(LEDGER_RUNTIME);
    auditAuthority(pathname, authz, "ALLOW", `entries:${result.entry_count}`, null, null);
    response(res, 200, result);
    return;
  }
  // Anchoring: checkpoint head (read), on-demand anchor (authority-gated), and a
  // single-receipt inclusion proof (authority-gated). Anchoring never touches the
  // append lock — the on-demand path just triggers the same off-lock anchor step.
  if (req.method === "GET" && pathname === "/ledger/checkpoint") {
    if (!authorizeProductionRead(req, res, pathname, "ledger.checkpoint")) return;
    response(res, 200, checkpointHeadResponse(LEDGER_RUNTIME));
    return;
  }
  if (req.method === "POST" && pathname === "/ledger/anchor") {
    // Authorization runs BEFORE anchorNow(), so an unauthorized caller triggers
    // no Merkle work and no checkpoint mutation.
    const authz = gateLedgerOperation(req, res, pathname, "ledger.anchor");
    if (!authz.ok) return;
    try {
      const out = await anchorNow(LEDGER_RUNTIME, { signLedger: LEDGER_SIGN, bundle: LEDGER_BUNDLE });
      auditAuthority(pathname, authz, "ALLOW", out.checkpoint ? `tree_size:${out.checkpoint.tree_size}` : "disabled", null, null);
      response(res, 200, out);
    } catch (error) {
      auditAuthority(pathname, authz, "REFUSE", "anchor", null, error?.code ?? "ERR_LEDGER_ANCHOR_FAILED");
      response(res, 200, { enabled: true, anchored: false, code: error?.code ?? "ERR_LEDGER_ANCHOR_FAILED", message: error?.message ?? String(error) });
    }
    return;
  }
  if (req.method === "GET" && pathname === "/ledger/proof") {
    // Authorization runs BEFORE any selector parsing or proof-bundle load, so an
    // unauthorized caller never causes a receipt/proof read.
    const authz = gateLedgerOperation(req, res, pathname, "ledger.proof");
    if (!authz.ok) return;
    const params = new URL(req.url, "http://127.0.0.1").searchParams;
    const rid = params.get("receipt_id");
    const rh = params.get("receipt_hash");
    const selector = rid ? { receipt_id: rid } : (rh ? { receipt_hash: rh } : null);
    if (!selector) { response(res, 400, { ok: false, code: "ERR_LEDGER_PROOF_SELECTOR", message: "receipt_id or receipt_hash query param required" }); return; }
    const out = await proofResponse(LEDGER_RUNTIME, selector, {
      trustedBundle: LEDGER_BUNDLE,
      executorEnvironmentId: EXECUTOR_READINESS.configured ? EXECUTOR_READINESS.environment_id : undefined,
      expectedExecutorId: EXECUTOR_READINESS.configured ? EXECUTOR_READINESS.executor_id : undefined
    });
    auditAuthority(pathname, authz, out.ok ? "ALLOW" : "REFUSE", out.ok ? `seq:${out.proof.entry.sequence}` : "proof", null, out.ok ? null : out.code);
    response(res, out.ok ? 200 : 404, out);
    return;
  }
  // Test-only seam (inert unless MNDE_TEST_UNMAPPED_LEDGER_PROBE is set): a
  // REGISTERED /ledger/* handler that is deliberately absent from SENSITIVE_PATHS
  // and sits BEFORE the post-dispatch namespace guard below. It exists so the
  // regression suite can prove the authorization BOUNDARY — not route ordering —
  // rejects an unmapped sensitive route. It calls the normal gate helper; the
  // observable mutation (a file append) is reached ONLY on an allow result, which
  // must never happen in production. Requires an explicit opt-in env flag so it is
  // never registered in a real deployment.
  if (process.env.MNDE_TEST_UNMAPPED_LEDGER_PROBE === "1" && req.method === "POST" && pathname === "/ledger/__authz_probe") {
    const authz = gateLedgerOperation(req, res, pathname, "ledger.__authz_probe");
    if (!authz.ok) return;
    const probeFile = process.env.MNDE_TEST_UNMAPPED_LEDGER_PROBE_FILE;
    if (probeFile) appendFileSync(probeFile, "MUTATED\n");
    response(res, 200, { ok: true, mutated: true });
    return;
  }
  // Fail-closed for sensitive namespaces: every KNOWN route above returns before
  // reaching here. Anything left under a sensitive namespace (e.g. /ledger/*) is
  // an unmapped route — in production it must be DENIED, never allowed to fall
  // through to a bare 404 and thereby become implicitly reachable because a
  // capability mapping was forgotten. Outside production the router's normal
  // behavior is preserved. Non-sensitive unknown routes keep their existing 404.
  if (RUNTIME_PROFILE === "production" && isSensitiveNamespacePath(pathname)) {
    response(res, 403, externalAuthRefusalBody(null));
    return;
  }
  await fail(res, "ERR_NOT_FOUND", 404);
});
server.on("connection", (socket) => {
  socket.on("error", () => {});
  const socketAdmission = admission.tryAcquireSocket(socket);
  if (!socketAdmission.ok) {
    counters.admission_refusals += 1;
    counters.refused_overload += 1;
    socket.destroy();
    return;
  }
  const socketState = socketRegistry.track(socket);
  l0ActiveConnections += 1;
  let l0Closed = false;
  const recordL0Close = () => {
    if (l0Closed) return;
    l0Closed = true;
    l0ActiveConnections = Math.max(0, l0ActiveConnections - 1);
    counters.l0_connections_closed_total += 1;
    socketAdmission.release();
    const state = socketTimings.get(socket);
    if (state) state.close_at_ms = performance.now();
  };
  socket.on("close", recordL0Close);
  socketTimings.set(socket, {
    accepted_at_ms: socketState.opened_at_ms,
    first_byte_at_ms: 0,
    close_at_ms: 0
  });
  counters.l0_connections_accepted_total += 1;
  socket.prependOnceListener("data", () => {
    const state = socketTimings.get(socket);
    if (state && state.first_byte_at_ms === 0) state.first_byte_at_ms = performance.now();
  });
});
server.on("clientError", (_error, socket) => {
  counters.l0_shed_total += 1;
  counters.l0_shed_destroy_total += 1;
  counters.l0_malformed_destroy_sheds += 1;
  socket.destroy();
});
server.on("timeout", (socket) => {
  counters.l0_shed_total += 1;
  counters.l0_shed_destroy_total += 1;
  counters.l0_timeout_destroy_sheds += 1;
  socket.destroy();
});
server.maxRequestsPerSocket = HTTP_LIMITS.max_requests_per_socket;
server.maxHeadersCount = 64;
server.maxConnections = L0_LIMITS.enable ? L0_LIMITS.hybrid_503_connections : Number.MAX_SAFE_INTEGER;
server.keepAliveTimeout = L0_LIMITS.enable ? L0_LIMITS.keepalive_timeout_ms : HTTP_LIMITS.keep_alive_timeout_ms;
server.headersTimeout = L0_LIMITS.enable ? L0_LIMITS.headers_timeout_ms : HTTP_LIMITS.headers_timeout_ms;
server.requestTimeout = HTTP_LIMITS.request_timeout_ms;
server.timeout = HTTP_LIMITS.request_timeout_ms;

server.on("error", (error) => {
  // Bind/listen failures (EADDRINUSE et al) must exit with a readable reason,
  // not an uncaught stack trace: harnesses surface this stderr verbatim.
  process.stderr.write(`ERR_BIND_FAILED: ${error?.code ?? "unknown"} on http://${HOST}:${PORT} — ${error?.message ?? error}\n`);
  process.exit(1);
});

server.listen(PORT, HOST, L0_LIMITS.enable ? L0_LIMITS.backlog : Number.parseInt(process.env.MNDE_LISTEN_BACKLOG ?? "4096", 10), () => {
  socketRegistry.start();
  watchdog.start();
  process.stdout.write(`MNDe local sidecar listening on http://${HOST}:${PORT} worker=${cluster.worker?.id ?? 0} durability=${RECEIPT_QUEUE_CONFIG.durability_mode}\n`);
});

function recordTimings(timings) {
  for (const key of Object.keys(latencyTotals)) {
    latencyTotals[key] += timings[key] ?? 0;
  }
}

function metricLine(name, value) {
  return `${name} ${Number.isFinite(value) ? value : 0}\n`;
}

function metricsText(queueMetrics, workerMetrics) {
  const completed = Math.max(1, counters.requests);
  let out = "# TYPE mnde_local_demo_info gauge\nmnde_local_demo_info 1\n";
  out += metricLine("mnde_sidecar_inflight", inflight);
  out += metricLine("mnde_l0_enabled", L0_LIMITS.enable ? 1 : 0);
  out += metricLine("mnde_l0_max_connections", L0_LIMITS.max_connections);
  out += metricLine("mnde_l0_hybrid_503_connections", L0_LIMITS.hybrid_503_connections);
  out += metricLine("mnde_l0_active_connections", l0ActiveConnections);
  out += metricLine("mnde_l0_backlog", L0_LIMITS.backlog);
  out += metricLine("mnde_l0_shed_total", counters.l0_shed_total);
  out += metricLine("mnde_l0_shed_destroy_total", counters.l0_shed_destroy_total);
  out += metricLine("mnde_l0_shed_503_total", counters.l0_shed_503_total);
  out += metricLine("mnde_l0_preparse_destroy_sheds", counters.l0_preparse_destroy_sheds);
  out += metricLine("mnde_l0_malformed_destroy_sheds", counters.l0_malformed_destroy_sheds);
  out += metricLine("mnde_l0_timeout_destroy_sheds", counters.l0_timeout_destroy_sheds);
  out += metricLine("mnde_l0_overload_503_sheds", counters.l0_overload_503_sheds);
  out += metricLine("mnde_l0_connections_accepted_total", counters.l0_connections_accepted_total);
  out += metricLine("mnde_l0_connections_closed_total", counters.l0_connections_closed_total);
  out += metricLine("mnde_sidecar_accepted_requests", counters.requests);
  out += metricLine("mnde_sidecar_completed_http_responses", counters.completed_http_responses);
  const admissionSnapshot = admission.snapshot();
  out += metricLine("mnde_sidecar_active_requests", admissionSnapshot.active_requests);
  out += metricLine("mnde_sidecar_active_sockets", admissionSnapshot.active_sockets);
  out += metricLine("mnde_sidecar_max_inflight", MAX_INFLIGHT);
  out += metricLine("mnde_sidecar_shed_inflight", Math.min(SHED_INFLIGHT, MAX_INFLIGHT));
  out += metricLine("mnde_event_loop_lag_p99_ms", latestEventLoopLagMs);
  out += metricLine("mnde_sidecar_requests_total", counters.requests);
  out += metricLine("mnde_sidecar_refused_overload_total", counters.refused_overload);
  out += metricLine("mnde_sidecar_refused_by_admission_total", admissionSnapshot.refused_by_admission_total);
  out += metricLine("mnde_sidecar_refused_by_worker_pool_total", counters.refused_worker_pool_saturated);
  out += metricLine("mnde_sidecar_refused_by_receipt_queue_total", counters.refused_receipt_queue_saturated);
  out += metricLine("mnde_sidecar_admission_refusals_total", counters.admission_refusals);
  out += metricLine("mnde_sidecar_worker_refusals_total", counters.worker_refusals);
  out += metricLine("mnde_sidecar_refused_worker_pool_saturated_total", counters.refused_worker_pool_saturated);
  out += metricLine("mnde_sidecar_refused_system_saturated_total", counters.refused_system_saturated);
  out += metricLine("mnde_sidecar_saturation_inflight_total", counters.saturation_inflight);
  out += metricLine("mnde_sidecar_saturation_event_loop_lag_total", counters.saturation_event_loop_lag);
  out += metricLine("mnde_sidecar_saturation_receipt_queue_depth_total", counters.saturation_receipt_queue_depth);
  out += metricLine("mnde_sidecar_saturation_receipt_queue_bytes_total", counters.saturation_receipt_queue_bytes);
  out += metricLine("mnde_sidecar_unsigned_allows_blocked_total", counters.unsigned_allows_blocked);
  out += metricLine("mnde_sidecar_request_timeout_refusals_total", counters.request_timeout_refusals);
  out += metricLine("mnde_sidecar_browser_origin_requests_total", counters.browser_origin_requests);
  out += metricLine("mnde_watchdog_interventions_total", counters.watchdog_interventions);
  out += metricLine("mnde_receipt_history_malformed_lines_total", counters.malformed_receipt_lines);
  const socketMetrics = socketRegistry.metrics();
  out += metricLine("mnde_open_sockets", socketMetrics.open);
  out += metricLine("mnde_idle_sockets", socketMetrics.idle);
  out += metricLine("mnde_idle_sockets_destroyed_total", socketMetrics.idle_destroyed);
  const watchdogState = watchdog.snapshot();
  out += metricLine("mnde_runtime_degraded", watchdogState.degraded ? 1 : 0);
  out += metricLine("mnde_runtime_fatal", watchdogState.fatal ? 1 : 0);
  out += metricLine("mnde_watchdog_event_loop_lag_ms", watchdogState.event_loop_lag_ms);
  out += metricLine("mnde_worker_timeouts_total", workerMetrics.timeout_count ?? 0);
  out += metricLine("mnde_worker_restarts_total", workerMetrics.restart_count ?? 0);
  out += metricLine("mnde_receipt_queue_depth", queueMetrics.queue_depth);
  out += metricLine("mnde_receipt_queue_bytes", queueMetrics.queue_bytes);
  out += metricLine("mnde_receipt_queue_saturated_total", queueMetrics.saturated);
  out += metricLine("mnde_receipt_flush_failures_total", queueMetrics.flush_failures);
  out += metricLine("mnde_receipt_flush_timeouts_total", queueMetrics.flush_timeouts ?? 0);
  out += metricLine("mnde_receipt_flush_last_ms", queueMetrics.last_flush_ms);
  out += metricLine("mnde_receipt_flush_count", queueMetrics.flush_count);
  out += metricLine("mnde_receipt_flushed_receipts_total", queueMetrics.flushed_receipts);
  out += metricLine("mnde_receipt_flush_avg_batch_size", queueMetrics.flush_count === 0 ? 0 : Math.round(queueMetrics.flushed_receipts / queueMetrics.flush_count));
  out += metricLine("mnde_worker_queue_depth", workerMetrics.queue_depth);
  out += metricLine("mnde_worker_queue_wait_ms", workerMetrics.queue_wait_ms_avg);
  out += metricLine("mnde_worker_queue_wait_ms_max", workerMetrics.queue_wait_ms_max);
  out += metricLine("mnde_worker_exec_ms", workerMetrics.exec_ms_avg);
  out += metricLine("mnde_worker_exec_ms_max", workerMetrics.exec_ms_max);
  out += metricLine("mnde_worker_busy_ratio", workerMetrics.busy_ratio);
  out += metricLine("mnde_worker_refusals_total", workerMetrics.refused);
  for (const worker of workerMetrics.workers) {
    out += metricLine(`mnde_worker_${worker.worker_id}_throughput_total`, worker.throughput);
  }
  out += metricLine("mnde_gc_count_total", runtimeStats.gc_count);
  out += metricLine("mnde_gc_pause_ms_total", runtimeStats.gc_pause_ms_total);
  out += metricLine("mnde_gc_pause_ms_max", runtimeStats.gc_pause_ms_max);
  out += metricLine("mnde_heap_used_bytes", runtimeStats.heap_used_bytes);
  out += metricLine("mnde_heap_total_bytes", runtimeStats.heap_total_bytes);
  out += metricLine("mnde_rss_bytes", runtimeStats.rss_bytes);
  for (const [key, total] of Object.entries(latencyTotals)) {
    out += metricLine(`mnde_latency_avg_${key}`, total / completed);
  }
  return out;
}

// ── Graceful shutdown ────────────────────────────────────────────────────────
// Ordered so no dependency is torn down while work still needs it:
//   1. begin-drain (sync): latch `draining` (readiness → not-ready, new decisions
//      refused) and stop accepting NEW connections. Existing connections — idle
//      or mid-request — are left intact here; idle ones are torn down in the
//      final socket-cleanup phase and never affect quiescence.
//   2. await-quiescence: wait for `inflight` to reach 0. This tracks APPLICATION
//      work, not sockets — a request whose client has disconnected is still
//      counted until its worker reply and receipt persistence complete, so we
//      never cut a decision off mid-flight.
//   3. drain-receipts: flush queued receipts. The queue's shutdown() resolves
//      even when it finished fail-closed, so success is confirmed via metrics,
//      not by the promise resolving.
//   4. stop-workers, then 5. cleanup-sockets, then 6. stop-runtime timers.
// One deadline (SHUTDOWN_DEADLINE_MS) bounds the whole sequence; on expiry or a
// persistence failure we force best-effort teardown and exit non-zero.
function beginDrain() {
  if (draining) return;
  draining = true;
  // Stop accepting NEW connections. Existing connections are deliberately left
  // intact: a request arriving on one is refused at the application layer by the
  // drain gate (ERR_SIDECAR_DRAINING), and idle keep-alives are torn down in the
  // final socket-cleanup phase — NOT here — so they never affect quiescence
  // (which waits on `inflight`, i.e. application work, not sockets). We do not
  // await server.close()'s callback, so an idle keep-alive cannot block exit.
  server.close();
  // Observable drain marker: informative in normal operation and a deterministic
  // synchronization point for tests (once printed, the drain latch is set and new
  // decision work is refused). Emitted after the latch so it never races it.
  process.stdout.write("mnde.sidecar.shutdown draining\n");
}

function forcedShutdownCleanup() {
  // Best-effort, synchronous, NO awaits — we are already over budget. Fire the
  // async teardowns without waiting on them (swallowing any sync throw AND async
  // rejection so the deadline path never raises an unhandled rejection) and stop
  // the runtime timers so the process can exit promptly after exit() is called.
  try { Promise.resolve(workerPool.shutdown()).catch(() => {}); } catch { /* fire-and-forget */ }
  try { Promise.resolve(socketRegistry.shutdown()).catch(() => {}); } catch { /* fire-and-forget */ }
  stopRuntimeTimers();
}

function stopRuntimeTimers() {
  watchdog.stop();
  clearInterval(eventLoopLagTimer);
  clearInterval(memoryStatsTimer);
  try { eventLoopDelay.disable(); } catch { /* already disabled */ }
}

const gracefulShutdown = createGracefulShutdown({
  deadlineMs: SHUTDOWN_DEADLINE_MS,
  onBegin: beginDrain,
  onForcedCleanup: forcedShutdownCleanup,
  phases: [
    { name: "await-quiescence", run: (signal) => waitForQuiescence(() => inflight, signal) },
    {
      name: "drain-receipts",
      run: async () => {
        await receiptQueue.shutdown();
        const metrics = receiptQueue.metrics();
        // A resolved shutdown() does NOT mean persistence succeeded: the queue
        // can finish fail-closed after a flush failure/timeout. Confirm here.
        return metrics.fail_closed ? { ok: false, reason: metrics.fail_closed_reason } : { ok: true };
      }
    },
    { name: "stop-workers", run: () => workerPool.shutdown() },
    { name: "cleanup-sockets", run: () => socketRegistry.shutdown() },
    { name: "stop-runtime", run: () => stopRuntimeTimers() }
  ]
});

function shutdown() {
  return gracefulShutdown.shutdown();
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

// Cross-platform test seam (never active in production): when the sidecar is
// spawned by a test harness with a piped stdin, a `stop` line triggers the exact
// same graceful shutdown that SIGINT/SIGTERM do — the same path Ctrl+C drives —
// without depending on POSIX signal delivery (unreliable for a child on Windows).
// Gated behind MNDE_TEST_HARNESS so it adds zero surface to real deployments,
// where the launcher spawns this process with stdin ignored.
if (TEST_HARNESS_ENABLED) {
  try {
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      if (/(^|\n)\s*(stop|shutdown|quit|exit)\s*(\n|$)/i.test(String(chunk))) shutdown();
    });
    process.stdin.on("error", () => {});
  } catch {
    /* stdin may be unavailable */
  }
}
