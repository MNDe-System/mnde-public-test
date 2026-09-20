#!/usr/bin/env node
// MNDe MCP Proxy — put MNDe in front of any MCP server.
//
//   Agent (MCP client)
//     -> MNDe MCP proxy   (this process)
//        -> upstream MCP server (spawned child)
//
// Protected tools/call uses the disabled executor and cannot reach upstream.
// Only allowlisted protocol discovery/inspection and lifecycle notifications
// pass through while independent freshness deployment proof is pending.
//
// Config (env):
//   MNDE_SIDECAR_URL                MNDe sidecar (default http://127.0.0.1:8787)
//   MNDE_PROXY_UPSTREAM_COMMAND     upstream command (default: this node binary)
//   MNDE_PROXY_UPSTREAM_ARGS        JSON array of args (default: example upstream)
//   MNDE_PROXY_UPSTREAM_TIMEOUT_MS  per-forward timeout (default 8000)
//   MNDE_MCP_RECEIPTS_DIR           where receipts are written

import { createMndeExecutor } from "../executor/index.mjs";
import { createStdioClient } from "./stdio-client.mjs";

const sidecarUrl = process.env.MNDE_SIDECAR_URL ?? "http://127.0.0.1:8787";
const receiptsDir = process.env.MNDE_MCP_RECEIPTS_DIR ?? "./mnde-receipts/mcp-proxy";
const upstreamCommand = process.env.MNDE_PROXY_UPSTREAM_COMMAND ?? process.execPath;
const upstreamArgs = parseJsonArray(process.env.MNDE_PROXY_UPSTREAM_ARGS, ["mcp/example-upstream-server.mjs"]);
const upstreamTimeoutMs = Number.parseInt(process.env.MNDE_PROXY_UPSTREAM_TIMEOUT_MS ?? "8000", 10);

function parseJsonArray(raw, fallback) {
  if (!raw) return fallback;
  try {
    const value = JSON.parse(raw);
    return Array.isArray(value) ? value : fallback;
  } catch {
    return fallback;
  }
}
function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function log(...parts) {
  process.stderr.write(`[mnde-proxy] ${parts.join(" ")}\n`);
}

const mnde = createMndeExecutor({ sidecarUrl, receiptsDir });

// Connection to the upstream MCP server. Any upstream-initiated message (server
// notifications/requests) is relayed straight to the agent, keeping the proxy
// transparent.
const upstream = createStdioClient(upstreamCommand, upstreamArgs, {}, {
  onUnmatched: (message) => process.stdout.write(`${JSON.stringify(message)}\n`)
});

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}
function sendResult(id, result) {
  send({ jsonrpc: "2.0", id, result });
}
function sendError(id, code, message) {
  send({ jsonrpc: "2.0", id, error: { code, message } });
}

function mndeBlock(outcome, extra = {}) {
  return {
    type: "text",
    text: JSON.stringify({
      mnde: {
        decision: outcome.decision,
        reason: outcome.reason,
        executed: outcome.executed,
        forwarded: Boolean(extra.forwarded),
        receiptPath: outcome.receiptPath,
        verified: outcome.verified,
        failClosed: outcome.failClosed,
        ...(extra.upstreamError ? { upstreamError: extra.upstreamError } : {})
      }
    })
  };
}
function refusalResult(name, outcome) {
  return {
    content: [
      { type: "text", text: `${outcome.failClosed ? "FAIL-CLOSED" : "REFUSE"} — MNDe blocked ${name} (${outcome.reason}). Not forwarded to upstream.` },
      mndeBlock(outcome, { forwarded: false })
    ],
    isError: true
  };
}
function failClosedForward(name, outcome, code) {
  return {
    content: [
      { type: "text", text: `FAIL-CLOSED — MNDe authorized ${name} but the upstream call failed (${code}).` },
      mndeBlock(outcome, { forwarded: true, upstreamError: code })
    ],
    isError: true
  };
}

async function gateToolCall(id, params) {
  const name = params?.name;
  if (!isPlainObject(params) || typeof name !== "string" || name.length === 0) {
    sendError(id, -32602, "tools/call requires a non-empty string name");
    return;
  }
  if (params.arguments !== undefined && !isPlainObject(params.arguments)) {
    sendError(id, -32602, "tools/call arguments must be an object");
    return;
  }
  const args = params.arguments ?? {};
  // Forward only the exact tool name and argument object that the receipt binds.
  // Unrecognized top-level fields are not authorization inputs and therefore
  // must never reach an upstream implementation as hidden execution controls.
  const boundParams = { name, arguments: args };

  // The gate. run() forwards to upstream and is reached ONLY on ALLOW.
  const outcome = await mnde.execute({
    action: name,
    input: args,
    run: () => upstream.request("tools/call", boundParams, upstreamTimeoutMs)
  });

  if (!outcome.allowed) {
    sendResult(id, refusalResult(name, outcome)); // REFUSE / fail-closed -> never forwarded
    return;
  }
  if (outcome.error) {
    sendResult(id, failClosedForward(name, outcome, "ERR_UPSTREAM_UNAVAILABLE")); // forward threw (crash/timeout)
    return;
  }
  const upstreamResult = outcome.result;
  if (!isPlainObject(upstreamResult) || !Array.isArray(upstreamResult.content)) {
    sendResult(id, failClosedForward(name, outcome, "ERR_UPSTREAM_BAD_RESPONSE")); // malformed upstream
    return;
  }
  // Success: return upstream's real result, annotated with the MNDe receipt.
  sendResult(id, {
    content: [...upstreamResult.content, mndeBlock(outcome, { forwarded: true })],
    isError: Boolean(upstreamResult.isError)
  });
}

async function handle(message) {
  const { id, method, params } = message;
  const isRequest = id !== undefined && id !== null;

  if (!isRequest) {
    if (method === "notifications/initialized" || method === "notifications/cancelled") upstream.notify(method, params);
    return;
  }
  if (method === "tools/call") {
    await gateToolCall(id, params);
    return;
  }
  // Only protocol discovery/inspection passes while dispatch is disabled.
  if (!["initialize", "ping", "tools/list", "resources/list", "resources/templates/list", "resources/read", "prompts/list", "prompts/get"].includes(method)) {
    sendError(id, -32601, "ERR_FRESHNESS_DEPLOYMENT_DISABLED");
    return;
  }
  try {
    const result = await upstream.request(method, params, upstreamTimeoutMs);
    sendResult(id, result);
  } catch (error) {
    sendError(id, -32603, `upstream unavailable: ${error?.message ?? String(error)}`);
  }
}

let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let newline;
  while ((newline = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, newline).trim();
    buffer = buffer.slice(newline + 1);
    if (!line) continue;
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      sendError(null, -32700, "parse error");
      continue;
    }
    Promise.resolve(handle(message)).catch((error) => log("handler error:", error?.message ?? String(error)));
  }
});
process.stdin.on("end", async () => {
  await upstream.stop();
  process.exit(0);
});

log(`ready; upstream=${upstreamCommand} ${upstreamArgs.join(" ")}; sidecar=${sidecarUrl}`);
