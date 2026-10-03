import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, readdirSync, renameSync, rmdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { startHub } from "../src/hub/service.mjs";
import { createGitPushExecutor } from "../src/effects/git-push/index.mjs";
import { loadGitPushStartup } from "../src/effects/git-push/startup.mjs";
import { canonicalRepositoryIdentity } from "../src/effects/git-push/validate.mjs";
import { openHubAuthorization } from "../src/hub/authorization.mjs";
import { openHubState, readInterlock } from "../src/hub/state.mjs";
import { verifyAnyReceiptObject } from "../tools/verify.mjs";
import { verifyExecutionEvidence } from "../src/effects/git-push/evidence.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { signPolicyBundle } from "../src/policy-bundles/index.mjs";
import { signApproval } from "../src/policy-engine/authenticated-approvals.mjs";
import { productionTrust, makeRepositories, inMemoryClaimBackend, EXECUTOR_ID, ENVIRONMENT_ID } from "./support/git_push_fixtures.mjs";
import { installClaimBackend } from "./support/claim_backend_double.mjs";

// Real policy, signatures, executor and local file:// Git effect. ONLY the
// PostgreSQL adapter is replaced by the existing test-only ESM preload.
// Always exercise URL encoding, even when the developer's temp directory lacks
// a Windows short name such as RUNNER~1 (serialized by pathToFileURL as %7E).
const dir = mkdtempSync(join(tmpdir(), "mnde-hub-test~encoded-"));
const trust = await productionTrust(dir);
const policyKey = { keyId: "hub-policy", ...generateAuthorityKeyPair() };
const approvalKey = { keyId: "hub-approval", ...generateAuthorityKeyPair() };
const key = k => ({ keyId: k.keyId, publicPem: k.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" });
trust.bundle = await buildAuthorityBundle({ authorityId: trust.authorityId, issuedAt: "2026-01-01T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z",
  root: trust.root, receiptKeys: [key(trust.receipt)], policyKeys: [key(policyKey)], approvalKeys: [key(approvalKey)], ledgerKeys: [], revocation: [] });
function file(name, value) { const path = join(dir, name); writeFileSync(path, typeof value === "string" ? value : JSON.stringify(value), { mode: 0o600 }); return path; }
file(trust.bundlePath.slice(dir.length + 1), trust.bundle);
const token = `fixture-api-secret-${randomUUID()}`;
const policy = { schema_version: "1.0", policy_id: "hub-policy", version: "1", state: "ACTIVE", rules: [
  { rule_id: "allow", effect: "ALLOW", match: { field: "parameters.target_ref", op: "eq", value: "refs/heads/main" } },
  { rule_id: "review", effect: "ALLOW", approval_required: true, match: { field: "parameters.target_ref", op: "eq", value: "refs/heads/review" } }
] };
const policyBundle = await signPolicyBundle({ bundle_id: "hub-policy-1", policy_id: policy.policy_id, serial: 1, issued_at: "2026-01-01T00:00:00.000Z", policy_document: policy }, { keyId: policyKey.keyId, privateKeyPem: policyKey.privatePem });
const approvalAnchors = { approval_keys: [{ key_id: approvalKey.keyId, public_key: approvalKey.publicPem }] };
const common = {
  MNDE_PROFILE: "production", MNDE_HUB_PORT: "0", MNDE_HUB_OPERATORS: '["operator"]',
  MNDE_SIDECAR_AUTH: "bearer", MNDE_SIDECAR_AUTH_TOKENS_FILE: file("api.json", { [token]: "operator", "test-agent-token": "agent" }),
  MNDE_CLAIM_CONFIG: file("claim.json", { testOnly: true }), MNDE_GIT_PUSH_NAMESPACE: "hub-test",
  MNDE_GIT_PUSH_ALLOWED_SCHEMES: "file", MNDE_VERIFY_AUTHORITY_BUNDLE: trust.bundlePath,
  MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT: trust.fingerprint, MNDE_VERIFY_ENVIRONMENT_ID: ENVIRONMENT_ID,
  MNDE_VERIFY_EXPECTED_EXECUTOR_ID: EXECUTOR_ID, MNDE_EXECUTOR_ID: EXECUTOR_ID,
  MNDE_EXECUTOR_PRIVATE_KEY: file("executor.pem", trust.executor.keys.privatePem),
  MNDE_EXECUTOR_CREDENTIAL: file("executor.json", trust.executor.credential), MNDE_EXECUTOR_ENVIRONMENT: ENVIRONMENT_ID,
  MNDE_AUTHORITY_BUNDLE: trust.bundlePath, MNDE_RECEIPT_SIGNING_KEY: file("receipt.pem", trust.receipt.privatePem),
  MNDE_RECEIPT_KEY_ID: trust.receipt.keyId,
  MNDE_PE_POLICY_BUNDLE: file("policy.json", policyBundle), MNDE_PE_AUTHORITY_BUNDLE: trust.bundlePath,
  MNDE_PE_TRUSTED_ROOT_FINGERPRINT: trust.fingerprint, MNDE_PE_APPROVAL_TRUST_ANCHORS: file("approvals.json", approvalAnchors)
};
let passed = 0, failed = 0;
const output = [];
const stdout = process.stdout.write.bind(process.stdout);
process.stdout.write = (chunk, ...args) => { output.push(String(chunk)); return stdout(chunk, ...args); };
async function test(name, fn) { try { await fn(); passed++; console.log(`PASS ${name}`); } catch (error) { failed++; console.error(`FAIL ${name}: ${error.stack}`); } }

async function waitForAcquisition(acquired, action, timeoutMs = 5000) {
  let timer;
  try {
    await Promise.race([
      acquired,
      action.then(response => assert.fail(`action completed before credential acquisition: HTTP ${response.status} ${JSON.stringify(response.body)}`)),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new assert.AssertionError({ message: `credential acquisition was not reached within ${timeoutMs} ms` })), timeoutMs);
      })
    ]);
  } finally { clearTimeout(timer); }
}

function actionRequest(repos, branch = "main") {
  return { id: randomUUID(), action: "git.push", repository: canonicalRepositoryIdentity(repos.remoteUrl),
    remote: "origin", remoteUrl: repos.remoteUrl, expectedOldSha: repos.commits[0], sourceCommit: repos.commits[1], targetRef: `refs/heads/${branch}` };
}

let count = 0;
async function fixture(extra = {}) {
  globalThis.__hubObservation = { executions: 0, acquisitions: 0 };
  const base = join(dir, `case-${++count}`); mkdirSync(base);
  const repos = makeRepositories(base);
  const data = join(base, "data"); mkdirSync(data, { mode: 0o700 });
  const env = { ...common, MNDE_HUB_DATA_DIR: data, MNDE_GIT_PUSH_REPO_PATH: repos.localPath,
    MNDE_GIT_CREDENTIAL_CONFIG: repos.credentialConfigPath, MNDE_GIT_PUSH_EVIDENCE_DIR: join(base, "evidence"),
    MNDE_PE_POLICY_BUNDLE_STATE: join(data, "policy-state.json"), ...extra };
  const backend = inMemoryClaimBackend({ namespace: "hub-test" }); installClaimBackend(backend);
  const hub = await startHub(env);
  const replies = [];
  async function api(path, input, bearer = token) {
    const response = await fetch(`http://127.0.0.1:${hub.address.port}${path}`, { method: input === undefined ? "GET" : "POST",
      headers: { authorization: `Bearer ${bearer}`, "content-type": "application/json" }, ...(input === undefined ? {} : { body: JSON.stringify(input) }) });
    const text = await response.text(); replies.push(text); return { status: response.status, body: JSON.parse(text) };
  }
  const request = branch => actionRequest(repos, branch);
  return { env, backend, hub, api, request, repos, data, replies };
}

await test("startup, health, readiness, authenticated controls, unlock and relock", async () => {
  // Literal expectations cover Windows and POSIX on every host, including
  // decoding exactly once. The fixture must not reimplement URL normalization.
  for (const [remoteUrl, repository] of [
    ["file:///C:/Users/RUNNER%7E1/Temp/remote.git", "file:/C:/Users/RUNNER~1/Temp/remote"],
    ["file:///C:/Users/Runner%20Admin/Temp/remote.git", "file:/C:/Users/Runner Admin/Temp/remote"],
    ["file:///tmp/mnde%7Etest/remote.git", "file:/tmp/mnde~test/remote"],
    ["file:///tmp/mnde%2520test/remote.git/", "file:/tmp/mnde%20test/remote"]
  ]) {
    assert.equal(actionRequest({ remoteUrl, commits: ["a".repeat(40), "b".repeat(40)] }).repository, repository);
  }
  const f = await fixture();
  try {
    assert.equal((await f.api("/healthz")).status, 200);
    assert.equal((await f.api("/readyz")).body.state, "LOCKED");
    assert.equal((await f.api("/v1/status", undefined, "wrong")).status, 401);
    assert.equal((await f.api("/v1/unlock", {}, "test-agent-token")).status, 403);
    assert.equal((await f.api("/v1/actions", f.request())).status, 503);
    assert.equal((await f.api("/v1/unlock", {})).body.state, "ACTIVE");
    assert.equal((await f.api("/readyz")).status, 200);
    assert.equal((await f.api("/v1/lock", {})).body.state, "LOCKED");
    assert.equal(f.backend.claimed().length, 0);
    assert.equal(globalThis.__hubObservation.executions, 0);
  } finally { await f.hub.close(); }
});

await test("malformed, unknown actions, duplicate JSON keys and injected backend fail closed", async () => {
  const f = await fixture();
  try {
    await f.api("/v1/unlock", {});
    for (const request of [null, {}, { ...f.request(), action: "shell" }, { ...f.request(), claimBackend: {} }, { ...f.request(), sourceCommit: "bad" }]) {
      assert.equal((await f.api("/v1/actions", request)).status, 400);
    }
    const duplicate = await fetch(`http://127.0.0.1:${f.hub.address.port}/v1/actions`, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: '{"action":"git.push","action":"shell"}' });
    assert.equal(duplicate.status, 400);
    assert.equal(f.backend.claimed().length, 0);
  } finally { await f.hub.close(); }
});

await test("policy REFUSE and REVIEW never invoke the effect; operator refusal persists", async () => {
  const f = await fixture();
  try {
    await f.api("/v1/unlock", {});
    const refused = await f.api("/v1/actions", f.request("denied")); assert.equal(refused.body.decision, "REFUSE");
    const request = f.request("review");
    assert.equal((await f.api("/v1/actions", request)).body.decision, "REVIEW");
    assert.equal((await f.api(`/v1/actions/${request.id}/approve`, {})).status, 400);
    assert.equal((await f.api(`/v1/actions/${request.id}/refuse`, {})).body.decision, "REFUSE");
    assert.equal((await f.api(`/v1/actions/${request.id}/approve`, { approvals: [] })).status, 409);
    assert.equal(f.backend.claimed().length, 0);
    assert.equal(readdirSync(f.data).filter(n => n.startsWith("action-")).length, 2);
    assert.equal(globalThis.__hubObservation.executions, 0);
  } finally { await f.hub.close(); }
});

await test("ALLOW performs real typed push, receipt/evidence verify, duplicate id and authority replay refuse", async () => {
  const f = await fixture();
  try {
    await f.api("/v1/unlock", {});
    const request = f.request();
    const result = await f.api("/v1/actions", request);
    assert.equal(result.body.decision, "ALLOW", JSON.stringify(result.body));
    assert.equal(result.body.execution.outcome, "EXECUTED", JSON.stringify(result.body));
    assert.equal(f.backend.claimed().length, 1);
    const receipt = (await f.api(`/v1/receipts/${request.id}`)).body;
    const loaded = await loadGitPushStartup(f.env); assert.equal(loaded.ok, true, loaded.detail);
    const auth = await openHubAuthorization(f.env, loaded.startup);
    const verification = { ...auth.verificationContext, authorityBundle: trust.bundle, trustedRootFingerprint: trust.fingerprint, environmentId: ENVIRONMENT_ID, expectedExecutorId: EXECUTOR_ID };
    assert.equal((await verifyAnyReceiptObject(receipt.authorization, verification)).verified, true);
    assert.equal((await verifyExecutionEvidence(receipt.executionEvidence, verification)).ok, true);
    assert.equal((await f.api("/v1/actions", request)).status, 409);
    f.repos.setRemoteTo(f.repos.commits[0]);
    const executor = createGitPushExecutor({ ...loaded.startup, verificationContext: auth.verificationContext });
    const { id, action, ...typed } = request;
    const replay = await executor.executeGitPush({ ...typed, authorization: receipt.authorization });
    assert.equal(replay.reason_code, "ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT");
    loaded.signer.destroy?.();
    assert.ok(f.replies.every(text => !text.includes(token) && !text.includes("PRIVATE KEY")));
  } finally { await f.hub.close(); }
});

await test("signed approval re-enters existing policy and reaches executor only after verification", async () => {
  const f = await fixture();
  try {
    await f.api("/v1/unlock", {});
    execFileSync("git", ["--git-dir", f.repos.barePath, "update-ref", "refs/heads/review", f.repos.commits[0]], { stdio: "pipe" });
    const request = f.request("review");
    assert.equal((await f.api("/v1/actions", request)).body.decision, "REVIEW");
    const approval = signApproval({ approval_id: randomUUID(), approver: "operator", issuer: "operator",
      issued_at: new Date(Date.now() - 1000).toISOString(), expires_at: new Date(Date.now() + 60_000).toISOString(),
      scope: { tool_name: "git.push", request_id: request.id } }, { keyId: approvalKey.keyId, privateKeyPem: approvalKey.privatePem });
    const result = await f.api(`/v1/actions/${request.id}/approve`, { approvals: [approval] });
    assert.equal(result.body.decision, "ALLOW", JSON.stringify(result.body));
    assert.equal(result.body.execution.outcome, "EXECUTED");
    const response = (await f.api(`/v1/receipts/${request.id}`)).body;
    const receipt = response.authorization;
    assert.equal(receipt.receipt.approval_enforced, true);
    assert.equal(receipt.receipt.approvals.length, 1);
    assert.equal(response.previousAuthorizations[0].receipt.decision_output.reason_code, "APPROVAL_REQUIRED");
  } finally { await f.hub.close(); }
});

await test("missing data directory degrades; health stays up and unlock fails", async () => {
  const f = await fixture({ MNDE_HUB_DATA_DIR: join(dir, "missing") });
  try {
    assert.equal((await f.api("/healthz")).status, 200);
    assert.equal((await f.api("/readyz")).body.state, "DEGRADED");
    assert.equal((await f.api("/v1/unlock", {})).status, 503);
  } finally { await f.hub.close(); }
});

await test("lost storage fails closed and never uses SD fallback", async () => {
  const f = await fixture();
  try {
    await f.api("/v1/unlock", {});
    renameSync(f.data, `${f.data}-removed`);
    assert.equal((await f.api("/readyz")).body.state, "DEGRADED");
    assert.notEqual((await f.api("/v1/actions", f.request())).status, 200);
    assert.equal(f.backend.claimed().length, 0);
  } finally { await f.hub.close(); }
});

await test("executor itself checks lock before authorization or credential use; reboot relocks", async () => {
  const f = await fixture();
  try {
    const loaded = await loadGitPushStartup(f.env); assert.equal(loaded.ok, true, loaded.detail);
    const executor = createGitPushExecutor(loaded.startup);
    assert.throws(() => createGitPushExecutor({ ...loaded.startup, verificationContext: { now: "2020-01-01T00:00:00Z" } }), /ERR_GIT_PUSH_STARTUP_CONFIG/);
    const auth = await openHubAuthorization(f.env, loaded.startup);
    const input = f.request();
    const decision = await auth.decide({ schema_version: "1.0", request_id: input.id, grant_id: randomUUID(), timestamp: new Date().toISOString(),
      expires_at: new Date(Date.now() + 60_000).toISOString(), principal: { id: "operator" }, agent: { id: "test" }, tool: { tool_name: "git.push" },
      parameters: { repository: input.repository, remote: input.remote, remote_url: input.remoteUrl, source_commit: input.sourceCommit, target_ref: input.targetRef, expected_old_sha: input.expectedOldSha }, environment: {}, context: {} });
    assert.equal(decision.decision, "ALLOW");
    const { id, action, ...typed } = input;
    assert.equal((await executor.executeGitPush({ ...typed, authorization: decision.receipt })).reason_code, "ERR_HUB_LOCKED");
    assert.equal(globalThis.__hubObservation.acquisitions, 0);
    await f.api("/v1/unlock", {});
    assert.notEqual((await executor.executeGitPush({})).reason_code, "ERR_HUB_LOCKED");
    openHubState(f.data);
    assert.equal((await executor.executeGitPush({})).reason_code, "ERR_HUB_LOCKED");
    loaded.signer.destroy?.();
  } finally { await f.hub.close(); }
});

await test("claim dependency loss changes readiness and prevents executor invocation", async () => {
  const f = await fixture();
  try {
    await f.api("/v1/unlock", {});
    f.backend.health = async () => ({ ok: false });
    assert.equal((await f.api("/readyz")).body.state, "DEGRADED");
    assert.equal((await f.api("/v1/actions", f.request())).status, 503);
    assert.equal(globalThis.__hubObservation.executions, 0);
    f.backend.health = async () => ({ ok: true });
    assert.equal((await f.api("/readyz")).status, 200);
  } finally { await f.hub.close(); }
});

await test("unsigned and wrong-scope approval cannot execute; duplicate issuer cannot meet threshold", async () => {
  const f = await fixture();
  try {
    await f.api("/v1/unlock", {});
    const request = f.request("review"); await f.api("/v1/actions", request);
    const approval = { approval_id: randomUUID(), approver: "operator", issuer: "operator",
      issued_at: new Date().toISOString(), expires_at: new Date(Date.now() + 60_000).toISOString(), scope: { tool_name: "git.push", request_id: randomUUID() } };
    assert.equal((await f.api(`/v1/actions/${request.id}/approve`, { approvals: [approval] })).status, 400);
    approval.scope.request_id = request.id;
    const signed = signApproval(approval, { keyId: approvalKey.keyId, privateKeyPem: approvalKey.privatePem });
    assert.equal((await f.api(`/v1/actions/${request.id}/approve`, { approvals: [signed, signed] })).status, 400);
    assert.equal((await f.api(`/v1/actions/${request.id}/approve`, { approvals: [approval] })).body.decision, "REFUSE");
    assert.equal(globalThis.__hubObservation.executions, 0);
  } finally { await f.hub.close(); }
});

await test("credential-provider exception cannot leak through API, signed evidence, or normal logs", async () => {
  const f = await fixture();
  const sentinel = `test-only-push-secret-${randomUUID()}`;
  try {
    await f.api("/v1/unlock", {});
    globalThis.__hubObservation.beforeAcquire = () => { throw new Error(sentinel); };
    const request = f.request();
    assert.equal((await f.api("/v1/actions", request)).body.execution.outcome, "REFUSED");
    const receipt = await f.api(`/v1/receipts/${request.id}`);
    assert.equal(JSON.stringify(receipt).includes(sentinel), false);
    assert.ok(f.replies.every(text => !text.includes(sentinel)));
    assert.ok(output.every(text => !text.includes(sentinel)));
    assert.equal(f.backend.claimed().length, 0);
  } finally { globalThis.__hubObservation.beforeAcquire = undefined; await f.hub.close(); }
});

await test("lock during credential acquisition prevents dispatch and drains before acknowledgment", async () => {
  // Guard the guard: a rejected prerequisite reports its HTTP result, and a
  // request that never settles cannot leave this test waiting indefinitely.
  await assert.rejects(waitForAcquisition(new Promise(() => {}), Promise.resolve({ status: 400, body: { reason_code: "ERR_HUB_INPUT" } })), /HTTP 400.*ERR_HUB_INPUT/);
  await assert.rejects(waitForAcquisition(new Promise(() => {}), new Promise(() => {}), 25), /credential acquisition was not reached within 25 ms/);
  const f = await fixture();
  let release, action, lock;
  try {
    const unlocked = await f.api("/v1/unlock", {});
    assert.equal(unlocked.body.state, "ACTIVE", JSON.stringify(unlocked));
    let entered;
    const acquired = new Promise(r => { entered = r; });
    const paused = new Promise(r => { release = r; });
    globalThis.__hubObservation.beforeAcquire = async () => { entered(); await paused; };
    action = f.api("/v1/actions", f.request());
    await waitForAcquisition(acquired, action);
    let acknowledged = false;
    lock = f.api("/v1/lock", {}).then(value => { acknowledged = true; return value; });
    for (let i = 0; i < 100 && JSON.parse(readFileSync(join(f.data, "lock.json"))).locked !== true; i++) await new Promise(r => setTimeout(r, 10));
    assert.equal(JSON.parse(readFileSync(join(f.data, "lock.json"))).locked, true);
    assert.equal(acknowledged, false);
    release();
    assert.equal((await action).body.execution.outcome, "REFUSED");
    assert.equal((await lock).body.state, "LOCKED");
    assert.equal(f.backend.claimed().length, 0);
    globalThis.__hubObservation.beforeAcquire = undefined;
    await f.api("/v1/unlock", {});
    assert.equal((await f.api("/v1/actions", f.request())).body.execution.outcome, "EXECUTED");
  } finally {
    // Always unblock the real executor, including when the lock assertions or
    // prerequisite deadline fail, before draining the server and pending HTTP.
    release?.();
    globalThis.__hubObservation.beforeAcquire = undefined;
    await f.hub.close();
    await Promise.allSettled([action, lock].filter(Boolean));
  }
});

await test("lock/unlock epoch invalidates an in-flight execution after its one-use claim", async () => {
  const f = await fixture();
  try {
    await f.api("/v1/unlock", {});
    const original = f.backend.claim;
    f.backend.claim = async record => {
      const result = await original.call(f.backend, record);
      const state = openHubState(f.data); state.lock(false);
      return result;
    };
    const result = await f.api("/v1/actions", f.request());
    assert.equal(result.body.execution.outcome, "REFUSED");
    assert.equal(f.backend.claimed().length, 1);
  } finally { await f.hub.close(); }
});

await test("restart keeps duplicate IDs and exposes interrupted execution without replay", async () => {
  const f = await fixture();
  const request = f.request("review");
  try {
    await f.api("/v1/unlock", {});
    await f.api("/v1/actions", request);
    await f.hub.close();
    const path = join(f.data, `action-${request.id}.json`);
    const record = JSON.parse(readFileSync(path)); record.phase = "EXECUTING";
    writeFileSync(path, JSON.stringify(record));
    const rebooted = await startHub(f.env);
    try {
      const url = `http://127.0.0.1:${rebooted.address.port}`;
      const headers = { authorization: `Bearer ${token}`, "content-type": "application/json" };
      const recovery = await (await fetch(`${url}/v1/receipts/${request.id}`, { headers })).json();
      assert.equal(recovery.phase, "INDETERMINATE");
      await fetch(`${url}/v1/unlock`, { method: "POST", headers, body: "{}" });
      assert.equal((await fetch(`${url}/v1/actions`, { method: "POST", headers, body: JSON.stringify(request) })).status, 409);
      assert.equal(globalThis.__hubObservation.executions, 0);
    } finally { await rebooted.close(); }
  } finally { await f.hub.close(); }
});

await test("missing receipt signer changes readiness without printing key material", async () => {
  const f = await fixture();
  const path = f.env.MNDE_RECEIPT_SIGNING_KEY;
  try {
    renameSync(path, `${path}.away`);
    const result = await f.api("/readyz");
    assert.equal(result.body.receiptSigning, "unavailable");
    assert.equal(result.body.state, "DEGRADED");
  } finally { renameSync(`${path}.away`, path); await f.hub.close(); }
});

await test("failed durable lock write latches refusal even if old unlocked bytes remain", async () => {
  const f = await fixture();
  const path = join(f.data, "lock.json");
  try {
    await f.api("/v1/unlock", {});
    renameSync(path, `${path}.old`); mkdirSync(path);
    assert.equal((await f.api("/v1/lock", {})).status, 503);
    rmdirSync(path); renameSync(`${path}.old`, path);
    assert.equal(JSON.parse(readFileSync(path)).locked, false);
    assert.equal(readInterlock(f.data), false);
    assert.equal((await f.api("/readyz")).body.state, "DEGRADED");
    assert.equal((await f.api("/v1/unlock", {})).status, 503);
  } finally { await f.hub.close(); }
});

await test("normal logs contain no API credential or private key", async () => {
  assert.ok(output.every(text => !text.includes(token) && !text.includes("PRIVATE KEY")));
});
process.stdout.write = stdout;
console.log(`Hub tests: ${passed} passed, ${failed} failed. PostgreSQL replaced by test adapter; Git and cryptography real.`);
process.exitCode = failed ? 1 : 0;
