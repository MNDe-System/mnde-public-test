// Discovery layer.
//
// Deterministic detection of the environment and the MCP tool surface. Relies
// only on filesystem inspection, known paths, and known config schemas. No AI,
// no network, no telemetry, no cloud. Reads only; changes nothing.

import { existsSync, readFileSync } from "node:fs";
import path, { join } from "node:path";

function platformPath(ctx) {
  if (ctx.platform === "win32") return path.win32;
  if (ctx.platform === "darwin" || ctx.platform === "linux") return path.posix;
  return path;
}

// Known MCP client config locations, resolved from the context (so tests can
// point homedir/env/platform anywhere). serversKey is the object in the config
// that holds MCP server definitions.
export const KNOWN_CLIENTS = [
  {
    id: "claude-desktop",
    name: "Claude Desktop",
    serversKey: "mcpServers",
    resolvePath(ctx) {
      const p = platformPath(ctx);
      if (ctx.platform === "win32") {
        const appData = ctx.env.APPDATA ?? p.join(ctx.homedir, "AppData", "Roaming");
        return p.join(appData, "Claude", "claude_desktop_config.json");
      }
      if (ctx.platform === "darwin") {
        return p.join(ctx.homedir, "Library", "Application Support", "Claude", "claude_desktop_config.json");
      }
      return p.join(ctx.homedir, ".config", "Claude", "claude_desktop_config.json");
    }
  },
  {
    id: "cursor",
    name: "Cursor",
    serversKey: "mcpServers",
    resolvePath(ctx) {
      return platformPath(ctx).join(ctx.homedir, ".cursor", "mcp.json");
    }
  },
  {
    id: "project-mcp",
    name: "Project (.mcp.json)",
    serversKey: "mcpServers",
    resolvePath(ctx) {
      return platformPath(ctx).join(ctx.cwd, ".mcp.json");
    }
  }
];

function fileExists(ctx, file) {
  return existsSync(join(ctx.cwd, file));
}

export function detectEnvironment(ctx) {
  const packageManager =
    fileExists(ctx, "pnpm-lock.yaml") ? "pnpm" :
    fileExists(ctx, "yarn.lock") ? "yarn" :
    fileExists(ctx, "bun.lockb") ? "bun" :
    fileExists(ctx, "package-lock.json") ? "npm" :
    fileExists(ctx, "package.json") ? "npm" : null;

  const projectTypes = [];
  if (fileExists(ctx, "package.json")) projectTypes.push("node");
  if (fileExists(ctx, "pyproject.toml") || fileExists(ctx, "requirements.txt") || fileExists(ctx, "setup.py")) projectTypes.push("python");
  if (fileExists(ctx, "Cargo.toml")) projectTypes.push("rust");
  if (fileExists(ctx, "go.mod")) projectTypes.push("go");

  return {
    os: ctx.platform,
    runtime: { node: process.version },
    packageManager,
    projectTypes: projectTypes.length ? projectTypes : ["unknown"],
    cwd: ctx.cwd
  };
}

function serverIsWrapped(entry) {
  return Boolean(entry && typeof entry === "object" && entry.env && entry.env._mnde_wrapped === "1");
}

export function discoverClients(ctx) {
  return KNOWN_CLIENTS.map((client) => {
    const configPath = client.resolvePath(ctx);
    const exists = existsSync(configPath);
    const result = { id: client.id, name: client.name, serversKey: client.serversKey, configPath, exists, error: null, servers: [] };
    if (!exists) return result;

    let config;
    try {
      config = JSON.parse(readFileSync(configPath, "utf8"));
    } catch (error) {
      result.error = `unreadable config: ${error?.message ?? String(error)}`;
      return result;
    }
    const servers = config?.[client.serversKey];
    if (servers && typeof servers === "object" && !Array.isArray(servers)) {
      result.servers = Object.entries(servers).map(([name, raw]) => ({
        name,
        command: raw?.command ?? null,
        args: Array.isArray(raw?.args) ? raw.args : [],
        env: raw?.env && typeof raw.env === "object" ? raw.env : {},
        wrapped: serverIsWrapped(raw),
        raw
      }));
    }
    return result;
  });
}

export function runDiscovery(ctx) {
  const clients = discoverClients(ctx);
  return {
    environment: detectEnvironment(ctx),
    clients,
    summary: {
      clientsFound: clients.filter((c) => c.exists && !c.error).length,
      clientsUnreadable: clients.filter((c) => c.error).length,
      serversFound: clients.reduce((n, c) => n + c.servers.length, 0),
      serversUnwrapped: clients.reduce((n, c) => n + c.servers.filter((s) => !s.wrapped).length, 0),
      serversAlreadyWrapped: clients.reduce((n, c) => n + c.servers.filter((s) => s.wrapped).length, 0)
    }
  };
}
