// Sidecar caller authentication tests (opt-in bearer mode).
//
//   npm run test:auth
//
// Default (auth off) is unchanged. In bearer mode, /v1/decisions rejects missing,
// malformed, and wrong tokens, accepts a valid token, maps the authenticated
// caller into the PE principal, never creates an ALLOW receipt for a rejected
// caller, and the MCP proxy does not forward an unauthenticated call.

import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { createStdioClient } from "../mcp/stdio-client.mjs";
import { reviewerRequest } from "../scripts/reviewer-request.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { signPolicyBundle } from "../src/policy-bundles/index.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const samplePolicy = join(repoRoot, "examples", "policy-engine", "sample-policy-no-approval.json");
const TOKEN = "good-token-123";
const TOKENS_JSON = JSON.stringify({ [TOKEN]: "svc-caller" });

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}
async function post(url, body, headers = {}) {
  const r = await fetch(`${url}/v1/decisions`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
}
function peReq(tool, extra = {}) {
  return { schema_version: "1.0", request_id: `req-${tool}`, timestamp: new Date().toISOString(), principal: { id: "from-body" }, agent: { id: "a" }, tool: { tool_name: tool }, parameters: {}, environment: {}, context: {}, ...extra };
}

async function writeProductionCustody(dir) {
  const root = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "prod-receipt-1", ...generateAuthorityKeyPair() };
  const ledger = { keyId: "prod-ledger-1", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "acme-prod-auth",
    issuedAt: "2026-06-14T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    ledgerKeys: [{ keyId: ledger.keyId, publicPem: ledger.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const bundlePath = join(dir, "authority.bundle.json");
  const keyPath = join(dir, "receipt.key.pem");
  const ledgerKeyPath = join(dir, "ledger.key.pem");
  writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(keyPath, receipt.privatePem, "utf8");
  writeFileSync(ledgerKeyPath, ledger.privatePem, "utf8");
  return {
    MNDE_PROFILE: "production",
    MNDE_RECEIPT_SIGNING_MODE: "custody",
    MNDE_KEY_CUSTODY: "file-backed-production",
    MNDE_AUTHORITY_BUNDLE: bundlePath,
    MNDE_RECEIPT_SIGNING_KEY: keyPath,
    MNDE_RECEIPT_KEY_ID: receipt.keyId,
    MNDE_LEDGER_SIGNING_KEY: ledgerKeyPath,
    MNDE_LEDGER_KEY_ID: ledger.keyId
  };
}

// Production ALSO requires an enforced signed-bundle policy engine (production
// posture pre-flight). These extras let production sidecars in this test boot
// under the stricter posture; caller auth stays under each test's own control.
async function policyEnforcementExtras(dir) {
  const root = { keyId: "pe-root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const authorityBundle = await buildAuthorityBundle({
    authorityId: "mnde-auth-pe", issuedAt: "2026-01-01T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z", root,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const bundle = await signPolicyBundle({
    bundle_id: "ops-policy-10-10.0.0", policy_id: "ops-policy", serial: 10, issued_at: "2026-06-23T12:00:00.000Z",
    policy_document: { schema_version: "1.0", policy_id: "ops-policy", version: "10.0.0", state: "ACTIVE", rules: [{ rule_id: "allow-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }] }
  }, { keyId: policyKey.keyId, privateKeyPem: policyKey.privatePem });
  const policyBundlePath = join(dir, "policy-bundle.json");
  const authorityBundlePath = join(dir, "pe-authority-bundle.json");
  writeFileSync(policyBundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(authorityBundlePath, JSON.stringify(authorityBundle), "utf8");
  return {
    MNDE_DECISION_ENGINE: "policy-engine",
    MNDE_PE_POLICY_BUNDLE: policyBundlePath,
    MNDE_PE_AUTHORITY_BUNDLE: authorityBundlePath,
    MNDE_PE_POLICY_BUNDLE_STATE: join(dir, "pe-bundle-state.json"),
    MNDE_PE_TRUSTED_ROOT_FINGERPRINT: authorityBundle.root_key.fingerprint,
    MNDE_PE_BUNDLE_NOW: "2026-06-23T12:00:00.000Z"
  };
}

async function expectSidecarStartFailure(options, pattern) {
  let started = null;
  let caught = null;
  try {
    started = await startMndeSidecar(options);
  } catch (error) {
    caught = error;
  } finally {
    if (started) await started.stop();
  }
  assert.equal(started, null, "sidecar should not have started");
  assert.ok(caught, "startup should fail");
  assert.match(String(caught.message), pattern);
}

async function main() {
  console.log("MNDe sidecar — caller authentication\n");

  // ── auth off (default): existing behavior ──────────────────────────────────
  // Dedicated port: 8787 is the sidecar's real default, so a developer's live
  // sidecar may legitimately own it. Auth semantics under test are unchanged.
  const off = await startMndeSidecar({ url: "http://127.0.0.1:8803", env: {} });
  try {
    await test("default auth off: request without Authorization works", async () => {
      const { body } = await post(off.url, reviewerRequest({ requestId: "r1", tool: "read_status" }));
      assert.notEqual(body.reason_code, "ERR_UNAUTHENTICATED");
      assert.equal(body.decision, "ALLOW");
    });
  } finally {
    await off.stop();
  }

  // ── bearer + legacy ────────────────────────────────────────────────────────
  const legacy = await startMndeSidecar({ url: "http://127.0.0.1:8797", env: { MNDE_SIDECAR_AUTH: "bearer", MNDE_SIDECAR_AUTH_TOKENS: TOKENS_JSON, MNDE_BIND_PORT: "8797" } });
  try {
    await test("bearer: missing token rejected (no ALLOW receipt)", async () => {
      const { status, body } = await post(legacy.url, reviewerRequest({ requestId: "r", tool: "read_status" }));
      assert.equal(status, 401);
      assert.equal(body.decision, "REFUSE");
      assert.equal(body.reason_code, "ERR_UNAUTHENTICATED");
      assert.equal(body.receipt ?? null, null);
    });
    await test("bearer: malformed Authorization header rejected", async () => {
      const { body } = await post(legacy.url, reviewerRequest({ requestId: "r", tool: "read_status" }), { authorization: "Token abc" });
      assert.equal(body.reason_code, "ERR_UNAUTHENTICATED");
    });
    await test("bearer: wrong token rejected", async () => {
      const { body } = await post(legacy.url, reviewerRequest({ requestId: "r", tool: "read_status" }), { authorization: "Bearer nope" });
      assert.equal(body.reason_code, "ERR_UNAUTHENTICATED");
    });
    await test("bearer: valid token accepted (legacy mode still works)", async () => {
      const { body } = await post(legacy.url, reviewerRequest({ requestId: "r", tool: "read_status" }), { authorization: `Bearer ${TOKEN}` });
      assert.equal(body.decision, "ALLOW");
      assert.equal(body.authenticated_caller, "svc-caller");
    });
  } finally {
    await legacy.stop();
  }

  // ── bearer + policy-engine ─────────────────────────────────────────────────
  const pe = await startMndeSidecar({ url: "http://127.0.0.1:8798", env: { MNDE_SIDECAR_AUTH: "bearer", MNDE_SIDECAR_AUTH_TOKENS: TOKENS_JSON, MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: samplePolicy, MNDE_BIND_PORT: "8798" } });
  try {
    await test("bearer + PE: valid token accepted and caller maps into principal", async () => {
      const { body } = await post(pe.url, peReq("read_status"), { authorization: `Bearer ${TOKEN}` });
      assert.equal(body.decision, "ALLOW");
      assert.equal(body.authenticated_caller, "svc-caller");
      // body principal "from-body" must be overridden by the token identity
      const principal = JSON.parse(body.receipt.canonical_request).principal.id;
      assert.equal(principal, "svc-caller");
    });
    await test("bearer + PE: missing token rejected with no receipt", async () => {
      const { status, body } = await post(pe.url, peReq("read_status"));
      assert.equal(status, 401);
      assert.equal(body.reason_code, "ERR_UNAUTHENTICATED");
      assert.equal(body.receipt ?? null, null);
    });
    await test("bearer + PE: unauthenticated call is not forwarded through the MCP proxy", async () => {
      const marker = join(repoRoot, "mnde-receipts", "auth-proxy-marker.txt");
      rmSync(marker, { force: true });
      // The proxy/executor send no Authorization header -> sidecar rejects -> REFUSE.
      const client = createStdioClient(process.execPath, ["mcp/mnde-mcp-proxy.mjs"], {
        MNDE_SIDECAR_URL: pe.url,
        MNDE_MCP_MARKER: marker,
        MNDE_MCP_RECEIPTS_DIR: "./mnde-receipts/auth-proxy",
        MNDE_PROXY_UPSTREAM_ARGS: JSON.stringify(["mcp/example-upstream-server.mjs"])
      });
      try {
        await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
        client.notify("notifications/initialized", {});
        const call = await client.request("tools/call", { name: "read_status", arguments: {} });
        const env = JSON.parse(call.content.find((c) => { try { return JSON.parse(c.text).mnde; } catch { return false; } }).text).mnde;
        assert.equal(env.decision, "REFUSE");
        assert.equal(env.forwarded, false);
        assert.equal(existsSync(marker), false, "an unauthenticated call must not be forwarded");
      } finally {
        await client.stop();
      }
    });
  } finally {
    await pe.stop();
  }

  await test("bearer: repeated bad tokens throttle the source with uniform failure", async () => {
    const throttled = await startMndeSidecar({ url: "http://127.0.0.1:8800", env: { MNDE_SIDECAR_AUTH: "bearer", MNDE_SIDECAR_AUTH_TOKENS: TOKENS_JSON, MNDE_BIND_PORT: "8800" } });
    try {
      for (let i = 0; i < 5; i += 1) {
        const { status, body } = await post(throttled.url, reviewerRequest({ requestId: `bad-${i}`, tool: "read_status" }), { authorization: "Bearer wrong-token" });
        assert.equal(status, 401);
        assert.equal(body.reason_code, "ERR_UNAUTHENTICATED");
        assert.equal(body.receipt ?? null, null);
      }
      const { status, body } = await post(throttled.url, reviewerRequest({ requestId: "valid-after-throttle", tool: "read_status" }), { authorization: `Bearer ${TOKEN}` });
      assert.equal(status, 401);
      assert.equal(body.reason_code, "ERR_UNAUTHENTICATED");
      assert.equal(body.receipt ?? null, null);
    } finally {
      await throttled.stop();
    }
  });

  const prodNoAuthDir = mkdtempSync(join(tmpdir(), "mnde-auth-prod-noauth-"));
  try {
    await test("production with auth off refuses startup", async () => {
      await expectSidecarStartFailure({
        url: "http://127.0.0.1:8801",
        env: { ...(await writeProductionCustody(prodNoAuthDir)), MNDE_BIND_PORT: "8801" }
      }, /MNDE_SIDECAR_AUTH=bearer/);
    });
  } finally {
    rmSync(prodNoAuthDir, { recursive: true, force: true });
  }

  const prodBearerDir = mkdtempSync(join(tmpdir(), "mnde-auth-prod-bearer-"));
  let prodBearer = null;
  try {
    await test("production with bearer auth and token config starts", async () => {
      prodBearer = await startMndeSidecar({
        url: "http://127.0.0.1:8802",
        env: { ...(await writeProductionCustody(prodBearerDir)), ...(await policyEnforcementExtras(prodBearerDir)), MNDE_SIDECAR_AUTH: "bearer", MNDE_SIDECAR_AUTH_TOKENS: TOKENS_JSON, MNDE_BIND_PORT: "8802" }
      });
      const res = await fetch(`${prodBearer.url}/readyz`);
      assert.equal(res.status, 200);
    });

    await test("production /v1/decisions refuses requests without Authorization", async () => {
      const { status, body } = await post(prodBearer.url, reviewerRequest({ requestId: "prod-missing-auth", tool: "read_status" }));
      assert.equal(status, 401);
      assert.equal(body.reason_code, "ERR_UNAUTHENTICATED");
      assert.equal(body.receipt ?? null, null);
    });
  } finally {
    if (prodBearer) await prodBearer.stop();
    rmSync(prodBearerDir, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL sidecar auth tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS sidecar auth tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
