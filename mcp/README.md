# MNDe MCP Server

> Current Phase 2 safety hold (2026-09-18): the proxy does **not** start its
> configured upstream or forward any messages. Discovery exposes only the local
> `mnde_proxy_status` tool. Protected tool calls refuse locally without a signed
> receipt; resource/prompt inspection is disabled. The earlier enabled-proxy
> examples below are historical, not the current execution contract. See the
> [F-001 audit and evidence](../experiments/production-proof-001/f001/AUDIT.md).
> F-001 remains open pending a mandatory production authority boundary.

An [MCP](https://modelcontextprotocol.io) server that puts MNDe between an agent and its tools.

Every `tools/call` is routed through MNDe first: ALLOW runs the tool, REFUSE does not, and the response carries a signed receipt that can be verified offline. It speaks newline-delimited JSON-RPC over stdio with no third-party dependencies, so it works with MCP clients such as Claude Desktop, Cursor, and MCP Inspector.

## What it is for

Point an MCP client at this server instead of (or in front of) a tool server, and each `tools/call` is authorized before execution and produces a receipt that can be verified without a running MNDe process. It does not require an SDK or changes to the agent.

```
Agent (MCP client)
  -> tools/call delete_backups
     -> MNDe MCP server -> POST /v1/decisions
        -> ALLOW: tool runs, receipt returned
        -> REFUSE: tool never runs, refusal receipt returned
```

## Try it

```bash
npm run mcp-demo     # drives the server over real stdio: ALLOW runs, REFUSE doesn't, receipts verify
npm run test:mcp     # protocol conformance + enforcement (REFUSE proven via a cross-process marker)
```

## Register with an MCP client

The MNDe sidecar must be reachable at `MNDE_SIDECAR_URL`. Example `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mnde": {
      "command": "node",
      "args": ["/absolute/path/to/mnde-public-test/mcp/mnde-mcp-server.mjs"],
      "env": { "MNDE_SIDECAR_URL": "http://127.0.0.1:8787" }
    }
  }
}
```

`stdout` is protocol traffic only; logs go to `stderr`.

## Tool result shape

Each `tools/call` returns two content blocks: a human-readable line, and a JSON
block with the MNDe envelope so an agent can branch on it programmatically.

```json
{ "mnde": { "decision": "REFUSE", "reason": "ERR_FORBIDDEN_ACTION_IN_PARAMETERS",
            "executed": false, "receiptPath": "...", "verified": true, "failClosed": false } }
```

`isError` is `true` on REFUSE / fail-closed so MCP clients surface the block.

## Adding your own tools

Edit [`guarded-tools.mjs`](./guarded-tools.mjs): each entry is `{ name, description, inputSchema, run }`.
The server wraps every `run` through the executor, so the safety invariant holds
for any tool you add — there is no code path where REFUSE executes it.

## Proxy mode — protect a server you did not write

The hosted server above guards tools you define. **Proxy mode** ([mnde-mcp-proxy.mjs](./mnde-mcp-proxy.mjs)) puts MNDe in front of an existing MCP server: it relays methods to the upstream unchanged except `tools/call`, which it gates through MNDe. On REFUSE the call is not forwarded through the proxy.

```
Agent (MCP client) -> MNDe MCP proxy -> upstream MCP server
                                         (gated only on tools/call)
```

```bash
npm run mcp-proxy-demo    # ALLOW forwarded + runs upstream; REFUSE never forwarded; receipts verify
npm run test:mcp-proxy    # 9 acceptance criteria incl. upstream crash + malformed response fail closed
```

Register it like the hosted server, but point it at your upstream:

```json
{
  "mcpServers": {
    "mnde-proxy": {
      "command": "node",
      "args": ["/abs/path/to/mnde-public-test/mcp/mnde-mcp-proxy.mjs"],
      "env": {
        "MNDE_SIDECAR_URL": "http://127.0.0.1:8787",
        "MNDE_PROXY_UPSTREAM_COMMAND": "node",
        "MNDE_PROXY_UPSTREAM_ARGS": "[\"/abs/path/to/your-mcp-server.js\"]"
      }
    }
  }
}
```

Pass-through methods (`initialize`, `tools/list`, `resources/*`, `prompts/*`, `ping`, …) are relayed verbatim; only `tools/call` is gated.

## Limitations

- The decision comes from the MNDe sidecar's bundled policy, which is small and illustrative (see [docs/production-readiness.md](../docs/production-readiness.md)).
- The sidecar must be reachable at `MNDE_SIDECAR_URL`. If it is not, calls fail closed (REFUSE), they do not run.
- Enforcement applies only to calls that pass through this server or proxy. A client that talks to the upstream directly is not gated.
- Receipts verify against the locally generated test authority in this repository; there is no published authority bundle yet.
