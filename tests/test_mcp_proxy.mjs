// MNDe MCP Proxy — proves the deployment-hold proxy exposes no upstream and
// forwards nothing.
//
//   npm run test:mcp-proxy
//
// Contract under test (Production Proof 001, Phase 2 / F-001 holding action):
// the proxy MUST NOT start an upstream, MUST NOT forward, and MUST refuse every
// protected tool fail-closed. Discovery reveals only the local status tool.
// Live dispatch is disabled at the frozen source (commit 7de0163, "disable
// unproven dispatch"); the earlier "ALLOW forwards to upstream" assertions
// encoded a contract that has been false since that commit and are replaced here
// by the stronger "there is no upstream to reach" assertions.

import assert from "node:assert/strict";
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";

import { createStdioClient } from "../mcp/stdio-client.mjs";

const RECEIPTS_DIR = "./mnde-receipts/mcp-proxy-tests";
const MARKER = join(process.cwd(), "mnde-receipts", "mcp-proxy-test-marker.txt");

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

function blocks(call) {
  return (call.content ?? [])
    .map((part) => {
      try {
        return JSON.parse(part.text);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}
const mndeOf = (call) => blocks(call).find((block) => block.mnde)?.mnde;
const upstreamRan = (call) => blocks(call).some((block) => block.source === "upstream");

// `mode` and the upstream args are deliberately hostile: a real upstream command
// is configured and a crash/malformed mode is requested. The deployment-hold
// proxy must ignore all of it and never start a child, so these settings must
// have no observable effect.
function makeProxy(mode) {
  return createStdioClient(process.execPath, ["mcp/mnde-mcp-proxy.mjs"], {
    MNDE_MCP_MARKER: MARKER,
    MNDE_MCP_RECEIPTS_DIR: RECEIPTS_DIR,
    MNDE_UPSTREAM_MODE: mode,
    MNDE_PROXY_UPSTREAM_TIMEOUT_MS: "4000",
    MNDE_PROXY_UPSTREAM_ARGS: JSON.stringify(["mcp/example-upstream-server.mjs"])
  });
}
async function handshake(client) {
  const init = await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } });
  client.notify("notifications/initialized", {});
  return init;
}

async function main() {
  console.log("MNDe MCP Proxy — deployment hold: no upstream, nothing forwarded\n");

  const proxy = makeProxy("normal");
  try {
    const init = await handshake(proxy);

    await test("1-2. discovery reveals only the local status tool, no upstream tools", async () => {
      assert.equal(init.serverInfo?.name, "mnde-proxy");
      const list = await proxy.request("tools/list", {});
      const names = list.tools.map((tool) => tool.name);
      assert.deepEqual(names, ["mnde_proxy_status"], "only the local status tool must be visible");
      for (const upstreamTool of ["delete_backups", "read_status", "restart_service"]) {
        assert.equal(names.includes(upstreamTool), false, `upstream tool ${upstreamTool} must not be discoverable`);
      }
    });

    await test("3. a protected tool call is refused fail-closed and never forwarded", async () => {
      const call = await proxy.request("tools/call", { name: "read_status", arguments: { service: "billing" } });
      const env = mndeOf(call);
      assert.equal(call.isError, true, "a protected call must be an error under deployment hold");
      assert.equal(env.decision, "REFUSE");
      assert.equal(env.reason, "ERR_FRESHNESS_DEPLOYMENT_DISABLED");
      assert.equal(env.forwarded, false, "nothing may be forwarded");
      assert.equal(env.executed, false);
      assert.equal(env.failClosed, true);
      assert.equal(upstreamRan(call), false, "no upstream may run");
      assert.equal(existsSync(MARKER), false);
    });

    await test("3a. extra top-level control fields cannot cause any forwarding", async () => {
      const call = await proxy.request("tools/call", {
        name: "read_status",
        arguments: { service: "billing" },
        unbound_execution_control: { target: "production" }
      });
      assert.equal(call.isError, true);
      assert.equal(mndeOf(call).forwarded, false);
      assert.equal(upstreamRan(call), false, "no crafted control field may reach an upstream");
    });

    await test("3b. non-object arguments are rejected before anything runs", async () => {
      await assert.rejects(
        () => proxy.request("tools/call", { name: "delete_backups", arguments: ["backups/"] }),
        /arguments must be an object/
      );
      assert.equal(existsSync(MARKER), false, "invalid arguments must never reach any tool");
    });

    await test("4-5. a destructive tool is refused; the upstream marker stays absent", async () => {
      const call = await proxy.request("tools/call", { name: "delete_backups", arguments: { path: "backups/", script: "rm -rf backups/" } });
      const env = mndeOf(call);
      assert.equal(call.isError, true);
      assert.equal(env.decision, "REFUSE");
      assert.equal(env.forwarded, false, "a refused call must NOT be forwarded upstream");
      assert.equal(upstreamRan(call), false);
      assert.equal(existsSync(MARKER), false, "the destructive tool must not have run");
    });

    await test("6. the local status tool reports execution and upstream disabled", async () => {
      const call = await proxy.request("tools/call", { name: "mnde_proxy_status", arguments: {} });
      assert.equal(call.isError, false);
      const state = JSON.parse(call.content[0].text);
      assert.equal(state.executionEnabled, false);
      assert.equal(state.upstreamStarted, false);
      assert.equal(state.reason, "ERR_FRESHNESS_DEPLOYMENT_DISABLED");
      await assert.rejects(
        () => proxy.request("tools/call", { name: "mnde_proxy_status", arguments: { any: "thing" } }),
        /takes no arguments/
      );
    });
  } finally {
    await proxy.stop();
  }

  // The proxy must not start an upstream even when a crashing or malformed
  // upstream is configured: there is no upstream to crash, so the outcome is an
  // ordinary fail-closed refusal, and the process reports it never started one.
  for (const mode of ["crash-on-call", "malformed-on-call"]) {
    const proxy = makeProxy(mode);
    try {
      await handshake(proxy);
      await test(`7-8. configured upstream mode "${mode}" starts no upstream and still refuses`, async () => {
        const call = await proxy.request("tools/call", { name: "read_status", arguments: {} });
        const env = mndeOf(call);
        assert.equal(call.isError, true);
        assert.equal(env.reason, "ERR_FRESHNESS_DEPLOYMENT_DISABLED");
        assert.equal(env.forwarded, false);
        assert.equal(upstreamRan(call), false);
        assert.equal(existsSync(MARKER), false);
        assert.match(proxy.getStderr(), /upstream not started/i, "the proxy must report it started no upstream");
      });
    } finally {
      await proxy.stop();
    }
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL MCP proxy tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS MCP proxy tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
