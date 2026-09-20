// MNDe MCP Server — protocol conformance + enforcement over a real stdio transport.
//
//   npm run test:mcp
//
// Checks that a tool exposed over MCP and gated by MNDe has no code path where a
// REFUSE decision executes — verified across process boundaries via a marker file.

import assert from "node:assert/strict";
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { createStdioClient } from "../mcp/stdio-client.mjs";
import { verificationPassed, verifyReceiptFile } from "../tools/verify-receipt.mjs";

// Dedicated port: 8787 is the sidecar's real default, so a developer's live
// sidecar may legitimately own it while tests run.
const SIDECAR_URL = "http://127.0.0.1:8806";
const RECEIPTS_DIR = "./mnde-receipts/mcp-tests";
const MARKER = join(process.cwd(), "mnde-receipts", "mcp-test-destruction-marker.txt");

rmSync(RECEIPTS_DIR, { recursive: true, force: true });
rmSync(MARKER, { force: true });

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

function envelopeOf(call) {
  const block = call.content.find((part) => {
    try {
      return Boolean(JSON.parse(part.text).mnde);
    } catch {
      return false;
    }
  });
  assert.ok(block, "tool result must include an mnde envelope block");
  return JSON.parse(block.text).mnde;
}

async function main() {
  console.log("MNDe MCP Server — conformance + enforcement\n");

  const sidecar = await startMndeSidecar({ url: SIDECAR_URL });
  const client = createStdioClient(process.execPath, ["mcp/mnde-mcp-server.mjs"], {
    MNDE_SIDECAR_URL: SIDECAR_URL,
    MNDE_MCP_MARKER: MARKER,
    MNDE_MCP_RECEIPTS_DIR: RECEIPTS_DIR
  });

  try {
    await test("initialize handshake returns serverInfo + protocolVersion", async () => {
      const init = await client.request("initialize", {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "test-client", version: "0.1.0" }
      });
      client.notify("notifications/initialized", {});
      assert.equal(typeof init.protocolVersion, "string");
      assert.equal(init.serverInfo.name, "mnde-mcp");
    });

    await test("tools/list exposes guarded tools with input schemas", async () => {
      const list = await client.request("tools/list", {});
      const names = list.tools.map((tool) => tool.name);
      assert.ok(names.includes("read_status"), "read_status must be listed");
      assert.ok(names.includes("delete_backups"), "delete_backups must be listed");
      for (const tool of list.tools) assert.equal(tool.inputSchema.type, "object");
    });

    // Live dispatch is disabled at the frozen source (commit 7de0163). A
    // policy-allowable tool is therefore refused fail-closed, is never executed,
    // and still produces a verifiable refusal receipt. This replaces the earlier
    // "ALLOW executes" assertion, which encoded a contract that stopped being
    // true when dispatch was disabled.
    await test("a policy-allowable tool is refused under disabled dispatch, never executes, and its receipt verifies", async () => {
      const call = await client.request("tools/call", { name: "read_status", arguments: { service: "billing" } });
      assert.equal(call.isError, true);
      const env = envelopeOf(call);
      assert.equal(env.decision, "REFUSE");
      assert.equal(env.reason, "ERR_FRESHNESS_DEPLOYMENT_DISABLED");
      assert.equal(env.executed, false, "no tool may execute while dispatch is disabled");
      assert.equal(existsSync(MARKER), false);
      assert.equal(verificationPassed(verifyReceiptFile(env.receiptPath)), true);
    });

    await test("REFUSE tool call does NOT run the tool (marker absent across the wire)", async () => {
      const call = await client.request("tools/call", {
        name: "delete_backups",
        arguments: { path: "backups/", script: "rm -rf backups/" }
      });
      assert.equal(call.isError, true);
      const env = envelopeOf(call);
      assert.equal(env.decision, "REFUSE");
      assert.equal(env.executed, false);
      assert.equal(existsSync(MARKER), false, "the destructive tool must not have run");
      assert.equal(verificationPassed(verifyReceiptFile(env.receiptPath)), true);
    });

    await test("non-object tool arguments are rejected before the protected tool can run", async () => {
      await assert.rejects(
        () => client.request("tools/call", { name: "delete_backups", arguments: ["backups/"] }),
        /arguments must be an object/
      );
      assert.equal(existsSync(MARKER), false, "invalid arguments must never reach the destructive tool");
    });

    await test("unknown tool returns a JSON-RPC error", async () => {
      await assert.rejects(() => client.request("tools/call", { name: "no_such_tool", arguments: {} }));
    });
  } finally {
    await client.stop();
    await sidecar.stop();
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL MCP server tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS MCP server tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
