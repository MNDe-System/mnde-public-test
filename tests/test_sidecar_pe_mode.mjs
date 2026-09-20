// Sidecar policy-engine mode tests (opt-in decision path).
//
//   npm run test:sidecar-pe
//
// Verifies that with MNDE_DECISION_ENGINE=policy-engine the live /v1/decisions
// path routes through the policy engine, returns a signed policy-engine receipt
// that verifies offline, fails closed on bad config/approvals, and that the MCP
// proxy emits a policy-engine receipt and never forwards a REFUSE. Legacy mode is
// covered by the existing suites and is unaffected.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { createStdioClient } from "../mcp/stdio-client.mjs";
import { signApproval } from "../src/policy-engine/authenticated-approvals.mjs";
import { verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { verifyAnyReceiptFile } from "../tools/verify.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const samplePolicy = join(repoRoot, "examples", "policy-engine", "sample-policy.json");

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

async function decide(url, body) {
  const r = await fetch(`${url}/v1/decisions`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return r.json();
}
function peReq(tool, extra = {}) {
  return {
    schema_version: "1.0", request_id: `req-${tool}`, timestamp: new Date().toISOString(),
    principal: { id: "alice" }, agent: { id: "a1" }, tool: { tool_name: tool },
    parameters: {}, environment: {}, context: {}, ...extra
  };
}

async function main() {
  console.log("MNDe sidecar — policy-engine mode\n");

  // ── Phase 1: PE mode, policy only (receipts non-enforced) ──────────────────
  // Dedicated port: 8787 is the sidecar's real default, so a developer's live
  // sidecar may legitimately own it while tests run.
  const a = await startMndeSidecar({ url: "http://127.0.0.1:8809", env: { MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: samplePolicy } });
  try {
    await test("PE mode ALLOW returns a policy-engine receipt that verifies offline", async () => {
      const res = await decide(a.url, peReq("read_status"));
      assert.equal(res.decision_engine, "policy-engine");
      assert.equal(res.decision, "ALLOW");
      assert.equal(res.receipt.schema_version, "mnde.pe.receipt.v1");
      assert.equal((await verifyPolicyReceipt(res.receipt)).verified, true);
      // unified verifier via file
      const f = join(mkdtempSync(join(tmpdir(), "mnde-pe-")), "r.json");
      writeFileSync(f, JSON.stringify(res.receipt));
      assert.equal((await verifyAnyReceiptFile(f)).verified, true);
    });

    await test("PE mode REFUSE (no matching rule)", async () => {
      const res = await decide(a.url, peReq("recursive_delete"));
      assert.equal(res.decision, "REFUSE");
      assert.equal(res.reason_code, "NO_MATCHING_RULE");
    });

    await test("MCP proxy emits a policy-engine receipt and never forwards a REFUSE", async () => {
      const marker = join(repoRoot, "mnde-receipts", "pe-proxy-marker.txt");
      rmSync(marker, { force: true });
      const client = createStdioClient(process.execPath, ["mcp/mnde-mcp-proxy.mjs"], {
        MNDE_SIDECAR_URL: a.url,
        MNDE_MCP_MARKER: marker,
        MNDE_MCP_RECEIPTS_DIR: "./mnde-receipts/pe-proxy",
        MNDE_PROXY_UPSTREAM_ARGS: JSON.stringify(["mcp/example-upstream-server.mjs"])
      });
      try {
        await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } });
        client.notify("notifications/initialized", {});
        // The shipped proxy refuses locally and starts no upstream. It holds no
        // executor and produces no receipt, by design: the shipped-surface guard
        // (tests/test_shipped_surface_bypass.mjs) forbids an executor callback or
        // any spawn path in the distributed artifact.
        //
        // KNOWN EVIDENCE GAP: because the proxy never reaches the sidecar, a
        // blocked MCP tool call produces no signed decision and no ledger entry.
        // Closing that means letting the shipped proxy hold an executor, which is
        // a deliberate trade against that guard and is not made here.
        const allow = await client.request("tools/call", { name: "read_status", arguments: {} });
        const allowEnv = JSON.parse(allow.content.find((c) => { try { return JSON.parse(c.text).mnde; } catch { return false; } }).text).mnde;
        assert.equal(allowEnv.decision, "REFUSE", "a policy-ALLOW tool name must not become an execution");
        assert.equal(allowEnv.executed, false);
        assert.equal(allowEnv.forwarded, false);
        assert.equal(existsSync(marker), false, "nothing may reach upstream while execution is disabled");

        const refuse = await client.request("tools/call", { name: "delete_backups", arguments: { path: "backups/", script: "rm -rf backups/" } });
        const refuseEnv = JSON.parse(refuse.content.find((c) => { try { return JSON.parse(c.text).mnde; } catch { return false; } }).text).mnde;
        assert.equal(refuseEnv.decision, "REFUSE");
        assert.equal(refuseEnv.forwarded, false);
        assert.equal(existsSync(marker), false, "REFUSE must not forward to upstream");
      } finally {
        await client.stop();
      }
    });
  } finally {
    await a.stop();
  }

  // ── Phase 2: PE mode + approval enforcement ────────────────────────────────
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const anchorsDir = mkdtempSync(join(tmpdir(), "mnde-pe-anchors-"));
  const anchorsPath = join(anchorsDir, "approval-anchors.json");
  writeFileSync(anchorsPath, JSON.stringify({ approval_keys: [{ key_id: "ak1", public_key: publicKey.export({ type: "spki", format: "pem" }) }] }));
  const approvalAnchors = JSON.parse(readFileSync(anchorsPath, "utf8"));
  const priv = privateKey.export({ type: "pkcs8", format: "pem" });
  const nowMs = Date.now();
  const iso = (ms) => new Date(ms).toISOString();
  const validApproval = signApproval({ approval_id: "ap1", approver: { id: "carol" }, issuer: { id: "svc" }, issued_at: iso(nowMs - 3_600_000), expires_at: iso(nowMs + 3_600_000), scope: { tool_name: "deploy" } }, { keyId: "ak1", privateKeyPem: priv });
  const expiredApproval = signApproval({ approval_id: "ap2", approver: { id: "carol" }, issuer: { id: "svc" }, issued_at: iso(nowMs - 7_200_000), expires_at: iso(nowMs - 60_000), scope: { tool_name: "deploy" } }, { keyId: "ak1", privateKeyPem: priv });
  const forgedApproval = { ...validApproval, signature: { ...validApproval.signature, value: validApproval.signature.value.replace(/.$/, validApproval.signature.value.endsWith("0") ? "1" : "0") } };

  const b = await startMndeSidecar({ url: "http://127.0.0.1:8798", env: { MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: samplePolicy, MNDE_PE_APPROVAL_TRUST_ANCHORS: anchorsPath, MNDE_BIND_PORT: "8798", MNDE_RECEIPT_LOG: join(anchorsDir, "receipts.jsonl") } });
  try {
    await test("PE mode + valid approval -> ALLOW (receipt verifies with approval anchors)", async () => {
      const res = await decide(b.url, peReq("deploy", { mnde_approvals: [validApproval] }));
      assert.equal(res.decision, "ALLOW");
      assert.equal(res.approval_enforced, true);
      assert.equal((await verifyPolicyReceipt(res.receipt, { approvalTrustAnchors: approvalAnchors })).verified, true);
    });
    await test("PE mode + missing approval -> REFUSE APPROVAL_REQUIRED", async () => {
      assert.equal((await decide(b.url, peReq("deploy"))).reason_code, "APPROVAL_REQUIRED");
    });
    await test("PE mode + forged approval -> fails closed", async () => {
      assert.equal((await decide(b.url, peReq("deploy", { mnde_approvals: [forgedApproval] }))).reason_code, "APPROVAL_SIGNATURE_INVALID");
    });
    await test("PE mode + expired approval -> fails closed", async () => {
      assert.equal((await decide(b.url, peReq("deploy", { mnde_approvals: [expiredApproval] }))).reason_code, "APPROVAL_EXPIRED");
    });
  } finally {
    await b.stop();
    rmSync(anchorsDir, { recursive: true, force: true });
  }

  // ── Phase 3: malformed config fails closed ─────────────────────────────────
  const c = await startMndeSidecar({ url: "http://127.0.0.1:8799", env: { MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: samplePolicy, MNDE_PE_TRUST_ANCHORS: join(repoRoot, "does-not-exist.json"), MNDE_BIND_PORT: "8799", MNDE_RECEIPT_LOG: join(mkdtempSync(join(tmpdir(), "mnde-pe-c-")), "r.jsonl") } });
  try {
    await test("PE mode with missing/invalid trust anchor config fails closed", async () => {
      const res = await decide(c.url, peReq("read_status"));
      assert.equal(res.decision, "REFUSE");
      assert.equal(res.reason_code, "ERR_PE_CONFIG_INVALID");
    });
  } finally {
    await c.stop();
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL sidecar PE-mode tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS sidecar PE-mode tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
