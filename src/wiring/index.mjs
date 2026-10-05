// Wiring layer.
//
// Generates configuration changes (deterministic) and applies approved ones.
// Every modification: backs up the original file first, is recorded in a
// manifest, is written to an onboarding log, and appears in dry-run output.
// Reversible via uninstall(). This layer changes config files only — it never
// touches authority, decisions, receipts, replay, or verification.

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { sha256 as hashHex } from "../crypto/provider.mjs";

function sha256(value) {
  return hashHex(value);
}
function backupsDir(ctx) {
  return join(ctx.stateDir, "backups");
}
function manifestPath(ctx) {
  return join(ctx.stateDir, "onboarding-manifest.json");
}
function logPath(ctx) {
  return join(ctx.stateDir, "onboarding.log");
}
function ensureStateDirs(ctx) {
  mkdirSync(ctx.stateDir, { recursive: true });
  mkdirSync(backupsDir(ctx), { recursive: true });
}
function backupPathFor(ctx, configPath) {
  return join(backupsDir(ctx), `${sha256(configPath).slice(0, 16)}.bak`);
}
function backupMetadataPathFor(ctx, configPath) {
  return `${backupPathFor(ctx, configPath)}.metadata.json`;
}
function log(ctx, line) {
  ensureStateDirs(ctx);
  appendFileSync(logPath(ctx), `${ctx.now()} ${line}\n`, "utf8");
}

export function readManifest(ctx) {
  const path = manifestPath(ctx);
  if (!existsSync(path)) return { version: 1, entries: [] };
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    return parsed && Array.isArray(parsed.entries) ? parsed : { version: 1, entries: [] };
  } catch {
    return { version: 1, entries: [] };
  }
}
function writeManifest(ctx, manifest) {
  ensureStateDirs(ctx);
  writeFileSync(manifestPath(ctx), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

// Replace a server definition with the MNDe proxy in front of the original.
// The original command/args are preserved as the proxy's upstream, and the
// original env is kept so the upstream still receives it.
export function wrapServer(raw, proxyPath, sidecarUrl) {
  return {
    command: "node",
    args: [proxyPath],
    env: {
      ...(raw?.env && typeof raw.env === "object" ? raw.env : {}),
      MNDE_SIDECAR_URL: sidecarUrl,
      MNDE_PROXY_UPSTREAM_COMMAND: raw?.command ?? "node",
      MNDE_PROXY_UPSTREAM_ARGS: JSON.stringify(Array.isArray(raw?.args) ? raw.args : []),
      _mnde_wrapped: "1"
    }
  };
}
function isWrapped(entry) {
  return Boolean(entry && entry.env && entry.env._mnde_wrapped === "1");
}

// Deterministic: identical discovery + context always produce an identical plan.
export function buildWiringPlan(discovery, ctx) {
  const proxyPath = join(ctx.repoRoot, "mcp", "mnde-mcp-proxy.mjs");
  const modifications = [];
  for (const client of discovery.clients) {
    if (!client.exists || client.error) continue;
    const servers = [];
    for (const server of client.servers) {
      if (server.wrapped) continue; // idempotent: never double-wrap
      servers.push({ server: server.name, before: server.raw, after: wrapServer(server.raw, proxyPath, ctx.sidecarUrl) });
    }
    if (servers.length > 0) {
      modifications.push({
        clientId: client.id,
        clientName: client.name,
        configPath: client.configPath,
        backupPath: backupPathFor(ctx, client.configPath),
        backupMetadataPath: backupMetadataPathFor(ctx, client.configPath),
        restoreCommand: "mnde uninstall",
        serversKey: client.serversKey,
        servers
      });
    }
  }
  return {
    sidecarUrl: ctx.sidecarUrl,
    proxyPath,
    modifications,
    changeCount: modifications.reduce((n, m) => n + m.servers.length, 0)
  };
}

function verifyWrappedConfig(config, key, serverNames) {
  return serverNames.every((serverName) => isWrapped(config?.[key]?.[serverName]));
}

export function applyPlan(plan, ctx) {
  ensureStateDirs(ctx);
  const manifest = readManifest(ctx);
  const applied = [];
  for (const mod of plan.modifications) {
    if (!existsSync(mod.configPath)) continue;
    const original = readFileSync(mod.configPath, "utf8");
    let config;
    try {
      config = JSON.parse(original);
    } catch {
      log(ctx, `skip ${mod.configPath} (unreadable at apply time)`);
      continue;
    }
    const key = mod.serversKey ?? "mcpServers";
    let changed = 0;
    for (const sm of mod.servers) {
      const current = config?.[key]?.[sm.server];
      if (!current || isWrapped(current)) continue;
      config[key][sm.server] = wrapServer(current, plan.proxyPath, plan.sidecarUrl);
      changed += 1;
    }
    if (changed === 0) continue;

    const backupPath = mod.backupPath ?? backupPathFor(ctx, mod.configPath);
    const backupMetadataPath = mod.backupMetadataPath ?? backupMetadataPathFor(ctx, mod.configPath);
    const appliedAt = ctx.now();
    const serverNames = mod.servers.map((s) => s.server);
    writeFileSync(backupPath, original, "utf8"); // BACKUP first
    writeFileSync(backupMetadataPath, `${JSON.stringify({
      schema_version: "mnde.onboarding.backup.v1",
      config_path: mod.configPath,
      backup_path: backupPath,
      client_id: mod.clientId,
      client_name: mod.clientName,
      servers: serverNames,
      sha256_before: sha256(original),
      created_at: appliedAt,
      restore_command: "mnde uninstall"
    }, null, 2)}\n`, "utf8");
    const entry = {
      configPath: mod.configPath,
      backupPath,
      backupMetadataPath,
      clientId: mod.clientId,
      clientName: mod.clientName,
      servers: serverNames,
      sha256Before: sha256(original),
      appliedAt,
      restoreCommand: "mnde uninstall"
    };
    const existingIndex = manifest.entries.findIndex((e) => e.configPath === entry.configPath);
    if (existingIndex >= 0) manifest.entries[existingIndex] = entry;
    else manifest.entries.push(entry);
    writeManifest(ctx, manifest);
    log(ctx, `apply client=${mod.clientId} file=${mod.configPath} servers=${entry.servers.join(",")} backup=${backupPath}`);
    writeFileSync(mod.configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
    const written = JSON.parse(readFileSync(mod.configPath, "utf8"));
    if (!verifyWrappedConfig(written, key, serverNames)) {
      writeFileSync(mod.configPath, original, "utf8");
      log(ctx, `rollback client=${mod.clientId} file=${mod.configPath} reason=verification_failed`);
      throw new Error(`wiring verification failed for ${mod.configPath}; original file restored`);
    }
    applied.push(entry);
  }
  writeManifest(ctx, manifest);
  return { applied };
}

export function uninstall(ctx) {
  const manifest = readManifest(ctx);
  const restored = [];
  const missing = [];
  for (const entry of manifest.entries) {
    if (!existsSync(entry.backupPath)) {
      missing.push(entry);
      continue;
    }
    writeFileSync(entry.configPath, readFileSync(entry.backupPath, "utf8"), "utf8");
    log(ctx, `restore client=${entry.clientId} file=${entry.configPath} from=${entry.backupPath}`);
    restored.push(entry);
  }
  writeManifest(ctx, { version: 1, entries: [] });
  return { restored, missing };
}
