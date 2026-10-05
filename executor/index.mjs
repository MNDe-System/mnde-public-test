// @mnde/executor — the enforcement point. Authorize a call through MNDe, then
// decide whether MNDe may actually perform it.
//
// ─────────────────────────────────────────────────────────────────────────────
// ALLOW MEANS "POLICY APPROVED THIS REQUEST."
// ALLOW DOES NOT MEAN "EXECUTION HAPPENED" OR "EXECUTION IS PERMITTED NOW."
//
// The sidecar evaluates policy, signs a receipt, and appends it to the execution
// ledger. That receipt is real, verifiable evidence of a decision. It is not an
// execution grant, and a consumer that reads ALLOW from /v1/decisions and acts on
// it has not been authorized by MNDe — it has bypassed the enforcement point,
// which is this file.
//
// Protected execution is currently DISABLED. execute() and wrapTool() never
// invoke the supplied callback, even after an authentic, request-bound ALLOW that
// clears the strict gate. Offline verification remains fully available. No caller
// flag, backend, or environment variable enables dispatch.
//
// Why: a verified receipt is a signature, and a signature can be presented twice.
// After a crash, a restart, or a restore of executor-local files, the same
// authentic ALLOW authorizes the same effect again (finding F-001). Closing that
// needs durable single-use redemption in a store the executor operator cannot roll
// back. See src/execution-availability/index.mjs and docs/FRESHNESS-BOUNDARY-AUDIT.md.
//
// The strict gate below is still enforced and still meaningful: it is what makes
// a receipt binding evidence rather than a decoration, and it is what a future
// typed effect will sit behind.
// ─────────────────────────────────────────────────────────────────────────────

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { reviewerRequest } from "../scripts/reviewer-request.mjs";
import { verifyReceiptFile, verificationPassed } from "../tools/verify-receipt.mjs";
import { verifyAnyReceiptFile } from "../tools/verify.mjs";
import { isSignedReceiptEnvelope, SIGNED_RECEIPT_SCHEMA } from "../src/authority-signing/index.mjs";
import { ERR_EXECUTION_DISABLED } from "../src/execution-availability/index.mjs";
import { canonicalizeJson, parseStrictJson } from "../shared/json.ts";
import { assertExecutorPosture } from "../src/executor-posture-preflight.mjs";
import { REPO_LOCAL_TRUST_SOURCE } from "../shared/authority-manifest.mjs";
import { resolveBearerToken, bearerAuthHeader } from "./bearer.mjs";

// The directory the receipt verifier searches for a repo-local authority bundle.
// Same rule as src/policy-engine/receipt.mjs, so the posture gate judges the very
// path that verification would fall back to.
const VERIFIER_ROOT = process.env.MNDE_HOME
  ? resolve(process.env.MNDE_HOME)
  : resolve(dirname(fileURLToPath(import.meta.url)), "..");

const DEFAULT_SIDECAR_URL = "http://127.0.0.1:8787";
const DEFAULT_RECEIPTS_DIR = "./mnde-receipts";
const DEFAULT_TIMEOUT_MS = 5000;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function deepMerge(base, override) {
  if (!isPlainObject(base) || !isPlainObject(override)) return override;
  const out = { ...base };
  for (const [key, value] of Object.entries(override)) {
    out[key] = isPlainObject(value) && isPlainObject(base[key]) ? deepMerge(base[key], value) : value;
  }
  return out;
}

function loadVerifyBundle(pathOrUndefined) {
  if (!pathOrUndefined) return undefined;
  try {
    return JSON.parse(readFileSync(pathOrUndefined, "utf8"));
  } catch {
    return undefined;
  }
}

let sequence = 0;
function nextExecutionId(action) {
  sequence += 1;
  return `${action || "action"}-${Date.now()}-${process.pid}-${sequence}`;
}

// Pull an action name out of the several shapes it takes across engines: a bare
// string (legacy tool_calls[].tool), or an object { tool_name } / { tool }
// (policy-engine canonical_request.tool).
function extractActionName(value) {
  if (typeof value === "string") return value;
  if (isPlainObject(value)) {
    if (typeof value.tool_name === "string") return value.tool_name;
    if (typeof value.tool === "string") return value.tool;
  }
  return null;
}

// Exact, order-insensitive JSON comparison (both sides canonicalized the same
// way). Returns false rather than throwing on any non-canonicalizable value, so
// an unexpected shape fails closed.
function jsonEqual(a, b) {
  try { return canonicalizeJson(a) === canonicalizeJson(b); } catch { return false; }
}

// Normalize the request-binding identity out of a receipt, tolerant of BOTH
// supported engines — the legacy pipeline (nested `execution_request` with
// `tool_calls`) and the policy engine (flat `canonical_request` with `tool` +
// `parameters`). Once a receipt has verified offline, its `canonical_request` is
// authenticated (its hash is the signed request_hash), so comparing this to the
// exact action/input we sent is a trustworthy binding across both paths.
// For a custody-signed envelope (`mnde.signed-receipt.v1/v2`) the signed decision
// and canonical request live in the inner `receipt`; the envelope as a whole is
// what verifies, but request bindings must be read from that verified inner
// receipt. Everything else binds against itself.
export function receiptForBinding(receipt) {
  if (isPlainObject(receipt) && isSignedReceiptEnvelope(receipt) && isPlainObject(receipt.receipt)) {
    return receipt.receipt;
  }
  return receipt;
}

export function receiptBinding(receipt) {
  if (!isPlainObject(receipt)) return { decision: null, requestIds: [], action: null, params: null, subjectId: null, policyHash: null, policyVersion: null };
  // Defense in depth: bindings always come from the (verified) inner receipt, so
  // even a caller that hands us a raw custody envelope binds the inner receipt
  // rather than the binding-less outer wrapper.
  receipt = receiptForBinding(receipt);
  const dout = isPlainObject(receipt.decision_output) ? receipt.decision_output : {};
  let cr = null;
  if (typeof receipt.canonical_request === "string") {
    // parseStrictJson returns a wrapped { ok, value } result — unwrap it.
    try {
      const parsed = parseStrictJson(receipt.canonical_request);
      cr = parsed && parsed.ok ? parsed.value : null;
    } catch { cr = null; }
  }
  cr = isPlainObject(cr) ? cr : {};
  const er = isPlainObject(cr.execution_request) ? cr.execution_request : null;

  // Every execution-id-like field present in the receipt. All must equal the id
  // we generated for this call (anti-replay); at least one must be present.
  const requestIds = [];
  const pushId = (v) => { if (typeof v === "string" && v.length > 0) requestIds.push(v); };
  if (er) {
    pushId(er.request_id);
    if (isPlainObject(er.release_request)) pushId(er.release_request.execution_id);
  } else {
    pushId(cr.request_id);
  }
  pushId(dout.execution_id);

  // The decided action + parameters, per shape. The executor always submits
  // exactly one tool call, so a legacy receipt with anything other than one is
  // treated as unbindable (action stays null -> fail closed).
  let action = null;
  let params = null;
  if (er && Array.isArray(er.tool_calls)) {
    if (er.tool_calls.length === 1) {
      action = extractActionName(er.tool_calls[0] ? er.tool_calls[0].tool : null);
      params = isPlainObject(er.tool_calls[0].parameters) ? er.tool_calls[0].parameters : {};
    }
  } else if (!er) {
    action = extractActionName(cr.tool);
    params = isPlainObject(cr.parameters) ? cr.parameters : {};
  }

  return {
    decision: typeof dout.decision === "string" ? dout.decision : null,
    requestIds,
    action,
    params,
    subjectId: er
      ? (typeof er?.actor?.user_id === "string" ? er.actor.user_id : null)
      : (typeof cr?.principal?.id === "string" ? cr.principal.id : null),
    policyHash: dout.policy_hash ?? receipt.policy_hash ?? null,
    policyVersion: dout.policy_version ?? receipt.policy_version ?? null
  };
}

function buildResult(parts) {
  return {
    decision: parts.decision,
    allowed: parts.decision === "ALLOW",
    refused: parts.decision === "REFUSE",
    executed: Boolean(parts.executed),
    reason: parts.reason ?? null,
    result: parts.result,
    error: parts.error,
    receipt: parts.receipt ?? null,
    receiptPath: parts.receiptPath ?? null,
    verified: parts.verified ?? null,
    failClosed: Boolean(parts.failClosed)
  };
}

export function createMndeExecutor(config = {}) {
  const sidecarUrl = String(config.sidecarUrl ?? DEFAULT_SIDECAR_URL).replace(/\/+$/, "");
  const receiptsDir = resolve(config.receiptsDir ?? DEFAULT_RECEIPTS_DIR);
  const testerId = config.testerId ?? process.env.MNDE_TESTER_ID ?? "TESTER-UNASSIGNED";
  const installationId = config.installationId ?? process.env.MNDE_INSTALLATION_ID ?? "INSTALLATION-UNASSIGNED";
  const timeoutMs = Number.isFinite(config.timeoutMs) ? config.timeoutMs : DEFAULT_TIMEOUT_MS;
  // Offline verification is MANDATORY for execution and can no longer be disabled
  // — an unverified receipt never executes. (The old `verify:false` bypass was
  // exactly the fail-open hole this gate closes.)
  // Optional expected-policy binding: when the caller declares the policy it
  // expects to be enforced, a receipt decided under any other policy is refused.
  const expectedPolicyHash = config.expectedPolicyHash ?? process.env.MNDE_EXECUTOR_EXPECTED_POLICY_HASH ?? null;
  const expectedPolicyVersion = config.expectedPolicyVersion ?? process.env.MNDE_EXECUTOR_EXPECTED_POLICY_VERSION ?? null;
  const expectedSubjectId = config.expectedSubjectId ?? process.env.MNDE_EXECUTOR_EXPECTED_SUBJECT_ID ?? null;
  // Sent only when configured (env MNDE_SIDECAR_BEARER_TOKEN or config.bearerToken).
  const bearerToken = resolveBearerToken(config.bearerToken);
  // Optional published authority bundle for offline verification of custody-signed
  // receipts. Unset by default; legacy/PE receipts verify without it.
  const verifyAuthorityBundle = loadVerifyBundle(config.verifyAuthorityBundle ?? process.env.MNDE_VERIFY_AUTHORITY_BUNDLE);
  // Custody-signed (`mnde.signed-receipt.v1/v2`) receipts additionally need the
  // published root fingerprint, and v2 executor-bound receipts need the expected
  // environment id, to verify offline. Without them a production custody ALLOW
  // could never verify and would (correctly but uselessly) always fail closed.
  const verifyTrustedRootFingerprint = config.verifyTrustedRootFingerprint ?? process.env.MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT ?? undefined;
  const verifyEnvironmentId = config.verifyEnvironmentId ?? process.env.MNDE_VERIFY_ENVIRONMENT_ID ?? undefined;
  const verifyExpectedExecutorId = config.verifyExpectedExecutorId ?? process.env.MNDE_VERIFY_EXPECTED_EXECUTOR_ID ?? undefined;
  const verifyRequireExecutor = config.verifyRequireExecutor === true || (typeof verifyExpectedExecutorId === "string" && verifyExpectedExecutorId.length > 0);

  // Production posture. Inert unless MNDE_PROFILE=production, and then refuses
  // to hand back an executor whose verification inputs were never configured.
  // Thrown rather than returned: an executor that exists is an executor
  // something will call, and a caller that ignores a return value would be
  // running the fallback it was warned about.
  const verifyAuthorityBundlePath = config.verifyAuthorityBundle ?? process.env.MNDE_VERIFY_AUTHORITY_BUNDLE ?? null;
  const posture = assertExecutorPosture({
    verifyAuthorityBundlePath,
    verifyAuthorityBundleLoaded: verifyAuthorityBundle !== undefined,
    verifyTrustedRootFingerprint,
    verifyEnvironmentId,
    verifyExpectedExecutorId,
    verifyRequireExecutor,
    repoRoot: VERIFIER_ROOT
  });
  if (!posture.ok) {
    const error = new Error(`${posture.reason_code}: ${posture.detail}`);
    error.code = posture.reason_code;
    error.violations = posture.violations;
    throw error;
  }
  const productionPosture = posture.enforced === true;

  mkdirSync(receiptsDir, { recursive: true });

  function persist(name, value) {
    const filePath = join(receiptsDir, name);
    writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    return filePath;
  }

  // True when ANY layer of a verification result rests on the authority bundle
  // that ships in the package rather than one the operator configured.
  function repoLocalTrust(result) {
    return result?.trust_source === REPO_LOCAL_TRUST_SOURCE
      || result?.inner?.trust_source === REPO_LOCAL_TRUST_SOURCE;
  }

  async function offlineVerify(receiptPath) {
    try {
      // Unified verifier handles legacy pipeline, policy-engine, and custody-signed
      // receipts; legacy/PE receipts verify identically to before. A custody
      // envelope additionally needs the published authority bundle, the trusted
      // root fingerprint, and (for v2 executor-bound receipts) the environment id.
      const result = await verifyAnyReceiptFile(receiptPath, {
        authorityBundle: verifyAuthorityBundle,
        trustedRootFingerprint: verifyTrustedRootFingerprint,
        environmentId: verifyEnvironmentId,
        expectedExecutorId: verifyExpectedExecutorId,
        requireExecutor: verifyRequireExecutor
      });
      if (result.verified !== true) return false;
      // The construction gate demands a configured trust root, but the trust
      // source is chosen per receipt inside the verifier, not per deployment —
      // and a custody envelope chooses it TWICE. verifySignedEnvelope checks the
      // attestation against the configured bundle, then drops that bundle for the
      // inner receipt whenever the inner authority_id is not the configured one
      // (innerEnvelopeOptions in tools/verify.mjs). The inner decision therefore
      // falls back to the authority shipped in the package and the envelope still
      // reports verified:true with an outer trust source of
      // ROOT_PINNED_AUTHORITY_BUNDLE. That is a production executor vouching for a
      // decision signed by demo key material. In production posture neither layer
      // may rest on the fallback.
      if (productionPosture && repoLocalTrust(result)) return false;
      return true;
    } catch {
      return false;
    }
  }

  // The strict execution gate. Runs ONLY when the sidecar's HTTP decision was
  // ALLOW; returns { ok, reason } and never has a side effect. `ok:true` is the
  // historical authorization check; dispatch is separately disabled below.
  function authorizeExecution({ receipt, action, input, executionId, verified }) {
    if (!isPlainObject(receipt)) return { ok: false, reason: "ERR_NO_RECEIPT" };
    if (verified !== true) return { ok: false, reason: "ERR_RECEIPT_UNVERIFIED" };
    // When an executor identity is required, raw legacy/PE receipts and
    // authority-only custody v1 envelopes are not an acceptable downgrade. A
    // verified executor layer exists only on mnde.signed-receipt.v2.
    if (verifyRequireExecutor && receipt.schema_version !== SIGNED_RECEIPT_SCHEMA) {
      return { ok: false, reason: "ERR_EXECUTOR_MISMATCH" };
    }
    const b = receiptBinding(receipt);
    // The receipt's OWN signed decision must be ALLOW (not just the HTTP body).
    if (b.decision !== "ALLOW") return { ok: false, reason: "ERR_RECEIPT_DECISION_MISMATCH" };
    // Request-instance binding (anti-replay): the signed receipt must name the
    // exact execution id we generated for THIS call — every id it carries, and at
    // least one.
    if (b.requestIds.length === 0 || !b.requestIds.every((rid) => rid === executionId)) {
      return { ok: false, reason: "ERR_RECEIPT_REQUEST_MISMATCH" };
    }
    // Action + parameter binding: the receipt must have decided the exact action
    // and parameters we submitted.
    if (b.action == null || b.action !== action) return { ok: false, reason: "ERR_RECEIPT_ACTION_MISMATCH" };
    if (!jsonEqual(b.params ?? {}, isPlainObject(input) ? input : {})) return { ok: false, reason: "ERR_RECEIPT_ACTION_MISMATCH" };
    // Optional subject binding. Bearer-authenticated deployments should set the
    // expected mapped caller id explicitly; unauthenticated/local deployments
    // may bind the configured tester identity the same way.
    if (expectedSubjectId && b.subjectId !== expectedSubjectId) return { ok: false, reason: "ERR_SUBJECT_MISMATCH" };
    // Expected-policy binding (only when the caller declares one).
    if (expectedPolicyHash && b.policyHash !== expectedPolicyHash) return { ok: false, reason: "ERR_POLICY_MISMATCH" };
    if (expectedPolicyVersion && b.policyVersion !== expectedPolicyVersion) return { ok: false, reason: "ERR_POLICY_MISMATCH" };
    return { ok: true, reason: null };
  }

  function buildRequest({ action, input, executionId, requestOverrides }) {
    const base = reviewerRequest({
      requestId: executionId,
      tool: action,
      testerId,
      installationId,
      parameters: isPlainObject(input) ? input : {}
    });
    return isPlainObject(requestOverrides) ? deepMerge(base, requestOverrides) : base;
  }

  // Ask MNDe. Fails closed: any transport/parse/shape problem returns { error }.
  async function askMnde({ action, input, executionId, requestOverrides }) {
    const request = buildRequest({ action, input, executionId, requestOverrides });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    try {
      response = await fetch(`${sidecarUrl}/v1/decisions`, {
        method: "POST",
        headers: { "content-type": "application/json", ...bearerAuthHeader(bearerToken) },
        body: JSON.stringify(request),
        signal: controller.signal
      });
    } catch (error) {
      return { error: "ERR_SIDECAR_UNREACHABLE", detail: String(error?.message ?? error) };
    } finally {
      clearTimeout(timer);
    }

    let body;
    try {
      body = await response.json();
    } catch {
      return { error: "ERR_MALFORMED_DECISION", detail: "decision response was not JSON" };
    }
    if (!isPlainObject(body) || (body.decision !== "ALLOW" && body.decision !== "REFUSE")) {
      return { error: "ERR_MALFORMED_DECISION", detail: `decision field was ${JSON.stringify(body?.decision)}` };
    }
    return {
      decision: body.decision,
      reason: typeof body.reason_code === "string" ? body.reason_code : null,
      receipt: isPlainObject(body.receipt) ? body.receipt : null,
      request
    };
  }

  async function execute({ action, input, run, executionId, requestOverrides } = {}) {
    if (typeof run !== "function") {
      throw new TypeError("mnde.execute({ run }) requires run to be a function");
    }
    const id = executionId ?? nextExecutionId(action);
    const decision = await askMnde({ action, input, executionId: id, requestOverrides });

    // FAIL CLOSED — the sidecar gave us nothing we can trust. run() is unreachable here.
    if (decision.error) {
      const receiptPath = persist(`failclosed-${id}.json`, {
        mnde_failclosed: true,
        decision: "REFUSE",
        action: action ?? null,
        execution_id: id,
        reason: decision.error,
        detail: decision.detail ?? null,
        note: "Client-side fail-closed record. This is NOT a signed receipt — MNDe returned no usable decision, so the action was refused locally.",
        recorded_at: new Date().toISOString()
      });
      return buildResult({ decision: "REFUSE", executed: false, reason: decision.error, receipt: null, receiptPath, verified: false, failClosed: true });
    }

    // Persist the receipt BEFORE running, so a throwing run() can never erase it.
    let receiptPath = null;
    let verified = null;
    if (decision.receipt) {
      receiptPath = persist(`receipt-${id}.json`, decision.receipt);
      verified = await offlineVerify(receiptPath);
    }

    // Sidecar authorization was REFUSE (or anything not ALLOW). Normal denial —
    // not a client fault. run() is unreachable here.
    if (decision.decision !== "ALLOW") {
      return buildResult({ decision: "REFUSE", executed: false, reason: decision.reason, receipt: decision.receipt, receiptPath, verified, failClosed: false });
    }

    // STRICT GATE — an ALLOW string is not enough. Execution requires a present,
    // offline-verified receipt whose OWN signed decision is ALLOW and which is
    // bound to this exact request (and expected policy, when declared). Fail closed
    // on any gap. This is the execution-firewall claim.
    const authz = authorizeExecution({ receipt: decision.receipt, action, input, executionId: id, verified });
    if (!authz.ok) {
      // Always persist a DISTINCT refusal record — even when the sidecar's ALLOW
      // receipt was also stored — so an audit can tell the executor refused it
      // rather than mistaking the stored ALLOW for an execution.
      const failPath = persist(`failclosed-${id}.json`, {
        mnde_failclosed: true,
        decision: "REFUSE",
        action: action ?? null,
        execution_id: id,
        reason: authz.reason,
        supplied_receipt_path: receiptPath ?? null,
        note: "Client-side fail-closed record: MNDe returned ALLOW but the receipt did not satisfy the strict execution gate (missing, unverifiable, or not bound to this request/policy), so the action was refused locally.",
        recorded_at: new Date().toISOString()
      });
      return buildResult({ decision: "REFUSE", executed: false, reason: authz.reason, receipt: decision.receipt ?? null, receiptPath: failPath, verified: verified ?? false, failClosed: true });
    }

    // THE ENFORCEMENT POINT. Control reaches here only with an authentic,
    // request-bound ALLOW that cleared the strict gate above — and it still does
    // not execute. A verified receipt is a signature, and a signature can be
    // presented twice; nothing in it makes it single-use. Until durable single-use
    // redemption is wired and proven, every protected effect is refused.
    //
    // This is what separates the two facts: the receipt above is genuine evidence
    // that policy approved the request. It is not, and never was, permission to
    // act. No caller flag, backend, or environment variable reaches this branch.
    // There is deliberately no generic run() call site below, and flipping the
    // flag in src/execution-availability/index.mjs would not create one. Arbitrary
    // JavaScript cannot be shown to be idempotent, single-effect, or free of a
    // second egress path, so enabling dispatch means building a narrow typed
    // effect that derives its request from signed fields — not restoring a
    // callback. Deleting this return does not give you an executor; it gives you
    // an undefined result and a failing freshness suite.
    return buildResult({ decision: "REFUSE", executed: false,
      reason: ERR_EXECUTION_DISABLED, receipt: decision.receipt,
      receiptPath, verified, failClosed: true });
  }

  // Turn a raw function into an MNDe-guarded tool. Callers must not retain or
  // invoke separate raw-function references for actions they intend MNDe to protect.
  function wrapTool(toolName, fn, defaults = {}) {
    if (typeof fn !== "function") throw new TypeError("mnde.wrapTool(name, fn) requires fn to be a function");
    const wrapped = (input, options = {}) =>
      execute({ action: toolName, input, run: () => fn(input), ...defaults, ...options });
    wrapped.mndeProtected = true;
    wrapped.toolName = toolName;
    return wrapped;
  }

  function verifyReceipt(receiptPath) {
    const report = verifyReceiptFile(receiptPath);
    return { verified: verificationPassed(report), report };
  }

  return {
    execute,
    wrapTool,
    verifyReceipt,
    config: {
      sidecarUrl,
      receiptsDir,
      testerId,
      installationId,
      timeoutMs,
      expectedPolicyHash,
      expectedPolicyVersion,
      expectedSubjectId,
      verifyTrustedRootFingerprint,
      verifyEnvironmentId,
      verifyExpectedExecutorId,
      verifyRequireExecutor
    }
  };
}

export default createMndeExecutor;
