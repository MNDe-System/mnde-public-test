import http from "node:http";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseStrictJson } from "../../shared/json.ts";
import { authenticate, loadAuthConfig, isAuthThrottled, recordAuthFailure, clearAuthFailures } from "../sidecar-auth/index.mjs";
import { createGitPushExecutor } from "../effects/git-push/index.mjs";
import { loadGitPushStartup } from "../effects/git-push/startup.mjs";
import { validateGitPushParameters } from "../effects/git-push/validate.mjs";
import { inspectSecretFile } from "../effects/git-push/secret-files.mjs";
import { openHubState, randomId } from "./state.mjs";
import { openHubAuthorization } from "./authorization.mjs";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const fields = ["action", "expectedOldSha", "id", "remote", "remoteUrl", "repository", "sourceCommit", "targetRef"];
const object = v => v !== null && typeof v === "object" && !Array.isArray(v);
const exact = (v, keys) => object(v) && JSON.stringify(Object.keys(v).sort()) === JSON.stringify([...keys].sort());
const fail = code => ({ decision: "REFUSE", reason_code: code });

async function body(req) {
  if (req.headers["content-type"]?.split(";")[0] !== "application/json") throw new Error("input");
  let length = 0;
  const chunks = [];
  for await (const chunk of req) {
    length += chunk.length;
    if (length > 64 * 1024) throw new Error("input");
    chunks.push(chunk);
  }
  const parsed = parseStrictJson(Buffer.concat(chunks).toString("utf8"));
  if (!parsed.ok || !object(parsed.value)) throw new Error("input");
  return parsed.value;
}

function view(record) {
  return {
    id: record.id, decision: record.decision, phase: record.phase === "EXECUTING" ? "INDETERMINATE" : record.phase,
    execution: record.result ?? null, receiptId: record.receipt ? record.id : null,
    retryPermitted: false
  };
}

// No injected executor, authorization provider, credential provider or claim
// backend. Tests substitute the existing claim adapter only through ESM hooks.
export async function startHub(env = process.env) {
  let state = "STARTING", storage, loaded, authorization, executor, broken = false, stopping = false;
  let active = null, busy = false;
  const events = [];
  function event(type, id) {
    const value = { type, at: new Date().toISOString(), ...(id ? { id } : {}) };
    events.push(value);
    if (events.length > 100) events.shift();
    // Fixed event vocabulary only. Never log requests, errors, keys or stderr.
    process.stdout.write(`${JSON.stringify(value)}\n`);
  }
  const auth = loadAuthConfig(env);
  const operatorIds = JSON.parse(env.MNDE_HUB_OPERATORS ?? "[]");
  if (!Array.isArray(operatorIds) || operatorIds.some(id => typeof id !== "string" || !id)) throw new Error("ERR_HUB_AUTH_CONFIG");
  const operators = new Set(operatorIds);
  if (!auth.ok || auth.mode !== "bearer" || !operators.size) throw new Error("ERR_HUB_AUTH_CONFIG");
  const port = Number(env.MNDE_HUB_PORT ?? 8790);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("ERR_HUB_PORT");
  try {
    storage = openHubState(env.MNDE_HUB_DATA_DIR);
    for (const key of ["MNDE_PE_POLICY_BUNDLE", "MNDE_PE_AUTHORITY_BUNDLE", "MNDE_PE_APPROVAL_TRUST_ANCHORS", "MNDE_AUTHORITY_BUNDLE", "MNDE_RECEIPT_SIGNING_KEY", "MNDE_SIDECAR_AUTH_TOKENS_FILE"]) {
      if (!env[key] || !inspectSecretFile(env[key], { secret: key.includes("SIGNING_KEY") || key.includes("TOKENS"), forbiddenRoots: [env.MNDE_GIT_PUSH_REPO_PATH, PACKAGE_ROOT] }).ok) throw new Error("ERR_HUB_CONFIG");
    }
    loaded = await loadGitPushStartup(env);
    if (!loaded.ok) throw new Error("ERR_HUB_EXECUTOR");
    authorization = await openHubAuthorization(env, loaded.startup);
    executor = createGitPushExecutor({ ...loaded.startup, verificationContext: authorization.verificationContext });
  } catch { broken = true; state = "DEGRADED"; }

  async function status() {
    let disk = false, claims = false, signing = false;
    try { disk = storage?.probe() === true; }
    catch { broken = true; try { storage.lock(true); } catch {} event("storage.degraded"); }
    try { claims = (await executor?.readiness())?.ready === true; } catch { /* fail closed */ }
    try { signing = (await authorization?.readiness()) === true; } catch { /* fail closed */ }
    let locked = true;
    try { locked = storage?.locked() !== false; } catch { broken = true; }
    state = broken || !disk || !claims || !signing || stopping ? "DEGRADED" : locked ? "LOCKED" : "ACTIVE";
    return { state, executor: executor && claims ? "ready" : "unavailable", storage: disk && claims ? "ready" : "unavailable", receiptSigning: signing && !broken ? "ready" : "unavailable", powerLossProtection: "not_installed" };
  }
  function reply(res, code, value) {
    res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store", "connection": "close", "x-content-type-options": "nosniff" });
    res.end(JSON.stringify(value));
  }
  function save(record) {
    try { storage.save(record); }
    catch { broken = true; try { storage.lock(true); } catch {} event("storage.degraded"); throw new Error("storage"); }
  }
  async function run(record, approvals) {
    try {
      const decision = await authorization.decide(record.request, approvals);
      record.decision = decision.decision;
      if (record.receipt) record.previousReceipts = [...(record.previousReceipts ?? []), record.receipt];
      record.receipt = decision.receipt;
      record.phase = decision.decision === "REVIEW" ? "REVIEW" : "DECIDED";
      save(record);
      event("receipt.signed", record.id);
      event(decision.decision === "REVIEW" ? "action.review_required" : decision.decision === "ALLOW" ? "action.allowed" : "action.refused", record.id);
      if (decision.decision !== "ALLOW") return view(record);
      if ((await status()).state !== "ACTIVE") {
        record.phase = "REFUSED"; record.result = { outcome: "REFUSED", executed: false };
        save(record); return view(record);
      }
      // Persist before invocation. A crash here is never auto-resumed or retried.
      record.phase = "EXECUTING"; save(record); event("execution.started", record.id);
      const p = record.request.parameters;
      const result = await executor.executeGitPush({ authorization: decision.receipt,
        repository: p.repository, remote: p.remote, remoteUrl: p.remote_url,
        sourceCommit: p.source_commit, targetRef: p.target_ref, expectedOldSha: p.expected_old_sha });
      record.phase = "COMPLETED";
      record.result = { outcome: result.outcome, executed: result.executed, ok: result.ok === true };
      record.evidencePath = result.signedEvidencePath ?? null;
      save(record);
      event(result.ok ? "execution.completed" : "execution.failed", record.id);
      if (record.evidencePath) event("receipt.signed", record.id);
      return view(record);
    } catch {
      broken = true;
      try { storage.lock(true); } catch {}
      event("execution.failed", record.id);
      // Preserve the durable pre-invocation state. Never turn uncertainty into
      // a retryable refusal and never serialize the exception.
      return { id: record.id, decision: "REFUSE", phase: "INDETERMINATE", retryPermitted: false };
    }
  }
  const server = http.createServer(async (req, res) => {
    try {
      const path = new URL(req.url, "http://127.0.0.1").pathname;
      if (req.headers.origin) return reply(res, 403, fail("ERR_HUB_ORIGIN"));
      if (req.method === "GET" && path === "/healthz") return reply(res, 200, { ok: true });
      if (req.method === "GET" && path === "/readyz") {
        const current = await status();
        return reply(res, current.state === "ACTIVE" ? 200 : 503, current);
      }
      const source = req.socket.remoteAddress;
      const identity = isAuthThrottled(source) ? { ok: false } : authenticate(req.headers, auth);
      if (!identity.ok) { recordAuthFailure(source); return reply(res, 401, fail("ERR_UNAUTHENTICATED")); }
      clearAuthFailures(source);
      const operator = operators.has(identity.caller.id);
      if (req.method === "GET" && path === "/v1/status") return reply(res, 200, await status());
      if (req.method === "GET" && path === "/v1/events") return reply(res, operator ? 200 : 403, operator ? { events } : fail("ERR_FORBIDDEN"));
      if (req.method === "GET" && path === "/v1/receipts") {
        const records = storage.list().map(id => storage.read(id)).filter(r => operator || r.owner === identity.caller.id);
        return reply(res, 200, { actions: records.map(view) });
      }
      const receiptMatch = /^\/v1\/receipts\/([0-9a-f-]{36})$/.exec(path);
      if (req.method === "GET" && receiptMatch) {
        const record = storage.read(receiptMatch[1]);
        if (!operator && record.owner !== identity.caller.id) return reply(res, 404, fail("ERR_NOT_FOUND"));
        return reply(res, 200, { ...view(record), authorization: record.receipt ?? null,
          previousAuthorizations: record.previousReceipts ?? [],
          executionEvidence: record.evidencePath ? JSON.parse(readFileSync(record.evidencePath, "utf8")) : null });
      }
      if (req.method !== "POST" || stopping) return reply(res, 404, fail("ERR_NOT_FOUND"));
      const input = await body(req);
      if (path === "/v1/lock" || path === "/v1/unlock") {
        if (!operator) return reply(res, 403, fail("ERR_FORBIDDEN"));
        if (!exact(input, [])) return reply(res, 400, fail("ERR_HUB_INPUT"));
        const locked = path === "/v1/lock";
        if (!locked && (busy || (await status()).state === "DEGRADED")) return reply(res, 503, fail("ERR_HUB_NOT_READY"));
        try { storage.lock(locked); }
        catch { broken = true; event("storage.degraded"); return reply(res, 503, fail("ERR_HUB_STORAGE")); }
        event(locked ? "hub.locked" : "hub.unlocked");
        // Acknowledge a lock only after admitted work has released credentials.
        if (locked && active) await active;
        return reply(res, 200, await status());
      }
      if (busy) return reply(res, 409, fail("ERR_HUB_BUSY"));
      const control = /^\/v1\/actions\/([0-9a-f-]{36})\/(approve|refuse)$/.exec(path);
      if (path !== "/v1/actions" && !control) return reply(res, 404, fail("ERR_NOT_FOUND"));
      // Reserve before an await. One operation at a time on a 1 GB appliance.
      busy = true;
      try {
        let record, approvals = [];
        if (control) {
          if (!operator) return reply(res, 403, fail("ERR_FORBIDDEN"));
          record = storage.read(control[1]);
          if (record.phase !== "REVIEW") return reply(res, 409, fail("ERR_HUB_FINAL"));
          if (control[2] === "refuse") {
            if (!exact(input, [])) return reply(res, 400, fail("ERR_HUB_INPUT"));
            record.phase = "REFUSED"; record.decision = "REFUSE"; save(record); event("action.refused", record.id);
            return reply(res, 200, view(record));
          }
          if (!exact(input, ["approvals"]) || !Array.isArray(input.approvals) || !input.approvals.length || input.approvals.length > 8) return reply(res, 400, fail("ERR_HUB_INPUT"));
          approvals = input.approvals;
          if (approvals.some(a => a?.scope?.request_id !== record.id)
            || new Set(approvals.map(a => a?.signature?.key_id)).size !== approvals.length) return reply(res, 400, fail("ERR_HUB_APPROVAL_SCOPE"));
        } else {
          if (!exact(input, fields) || input.action !== "git.push" || !UUID.test(input.id)) return reply(res, 400, fail("ERR_HUB_INPUT"));
          const parameters = { repository: input.repository, remote: input.remote, remote_url: input.remoteUrl,
            source_commit: input.sourceCommit, target_ref: input.targetRef, expected_old_sha: input.expectedOldSha };
          if (!validateGitPushParameters(parameters, { allowedSchemes: loaded?.startup?.allowedSchemes }).ok) return reply(res, 400, fail("ERR_HUB_INPUT"));
          try { storage.read(input.id); return reply(res, 409, fail("ERR_HUB_DUPLICATE")); }
          catch (error) { if (error.code !== "ENOENT") throw error; }
          const now = new Date().toISOString();
          record = { id: input.id, owner: identity.caller.id, phase: "REQUESTED", decision: null,
            request: { schema_version: "1.0", request_id: input.id, grant_id: randomId(), timestamp: now,
              expires_at: new Date(Date.now() + 5 * 60_000).toISOString(), principal: { id: identity.caller.id },
              agent: { id: "mnde-hub" }, tool: { tool_name: "git.push" }, parameters, environment: {}, context: {} } };
        }
        if ((await status()).state !== "ACTIVE") return reply(res, 503, fail("ERR_HUB_NOT_READY"));
        save(record); event("action.requested", record.id);
        active = run(record, approvals);
        return reply(res, 200, await active);
      } finally { busy = false; active = null; }
    } catch {
      reply(res, 400, fail("ERR_HUB_REQUEST_FAILED"));
    }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  server.maxConnections = 16;
  server.maxHeadersCount = 32;
  server.on("clientError", (_error, socket) => socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"));
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, "127.0.0.1", resolve); });
  event("hub.started");
  if ((await status()).state === "LOCKED") event("hub.ready");
  return Object.freeze({
    address: server.address(),
    async close() {
      stopping = true;
      try { storage?.lock(true); } catch { broken = true; }
      const closed = new Promise(resolve => server.close(resolve));
      server.closeIdleConnections();
      if (active) await active;
      await closed;
      loaded?.signer?.destroy?.();
    }
  });
}
