#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function resolveNpmCli() {
  const nodeDir = dirname(process.execPath);
  const candidates = [
    join(nodeDir, "node_modules", "npm", "bin", "npm-cli.js"),
    join(nodeDir, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js")
  ];
  return candidates.find((candidate) => existsSync(candidate)) ?? null;
}

const npmCli = resolveNpmCli();
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.error) throw result.error;
  return result;
}
function runNpm(args, options = {}) {
  return npmCli
    ? run(process.execPath, [npmCli, ...args], options)
    : run(process.platform === "win32" ? "npm.cmd" : "npm", args, { shell: process.platform === "win32", ...options });
}
function assertOk(label, result) {
  assert.equal(result.status, 0, `${label} failed:\n${result.stdout}\n${result.stderr}`);
  return result;
}

function initializeProxy(proxyPath, packageRoot) {
  return new Promise((resolveProxy, reject) => {
    const child = spawn(process.execPath, [proxyPath], {
      cwd: packageRoot,
      env: {
        ...process.env,
        // Deliberately unreachable: the proxy must initialize and refuse without
        // a sidecar, and must not start an upstream either way.
        MNDE_SIDECAR_URL: "http://127.0.0.1:1"
      },
      stdio: ["pipe", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`installed proxy did not initialize in time:\n${stdout}\n${stderr}`));
    }, 10000);
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      for (const line of stdout.split(/\r?\n/)) {
        if (!line.trim()) continue;
        try {
          const message = JSON.parse(line);
          if (message.id === 1 && message.result?.serverInfo) {
            clearTimeout(timer);
            child.kill();
            resolveProxy(message);
            return;
          }
        } catch {
          // Wait for a complete JSON line.
        }
      }
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.stdin.write(`${JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "packaging-test", version: "1" } }
    })}\n`);
  });
}

let packDir;
let projectDir;
try {
  packDir = mkdtempSync(join(tmpdir(), "mnde-onboarding-pack-"));
  const packed = assertOk("npm pack", runNpm(["pack", "--json", "--pack-destination", packDir], { cwd: repoRoot }));
  const jsonStart = packed.stdout.indexOf("[");
  assert.ok(jsonStart >= 0, `npm pack produced no JSON:\n${packed.stdout}`);
  const packInfo = JSON.parse(packed.stdout.slice(jsonStart))[0];
  assert.ok(packInfo.files.some((file) => file.path.replace(/\\/g, "/") === "dist/mcp/mnde-mcp-proxy.mjs"));
  const tarballPath = join(packDir, packInfo.filename);

  projectDir = mkdtempSync(join(tmpdir(), "mnde-onboarding-install-"));
  assertOk("npm init", runNpm(["init", "-y"], { cwd: projectDir }));
  assertOk("npm install", runNpm(["install", tarballPath], { cwd: projectDir }));

  const packageRoot = join(projectDir, "node_modules", "mnde-public-test", "dist");
  const onboardingCli = join(packageRoot, "bin", "mnde.mjs");
  const proxyPath = join(packageRoot, "mcp", "mnde-mcp-proxy.mjs");
  assert.ok(existsSync(proxyPath), "packed artifact must contain the MCP proxy");

  // The shipped artifact deliberately carries NO demo upstream and no raw stdio
  // client. stdio-client.mjs spawns an arbitrary command with the parent's
  // environment inherited; the demo servers exist only to exercise it. Nothing in
  // the shipped product imports any of them, so they are excluded from the tarball
  // (build/build-package.mjs) and remain in the source checkout for local demos.
  // Asserting their ABSENCE keeps that capability from quietly returning.
  for (const excluded of [
    ["mcp", "example-upstream-server.mjs"],
    ["mcp", "stdio-client.mjs"],
    ["mcp", "shell-mcp-server.mjs"],
    ["scripts", "mcp-demo.mjs"],
    ["scripts", "mcp-proxy-demo.mjs"],
    ["scripts", "shell-demo.mjs"]
  ]) {
    assert.equal(existsSync(join(packageRoot, ...excluded)), false,
      `packed artifact must NOT contain ${excluded.join("/")}`);
  }

  const configPath = join(projectDir, ".mcp.json");
  writeFileSync(configPath, `${JSON.stringify({
    mcpServers: {
      example: { command: process.execPath, args: ["--version"] }
    }
  }, null, 2)}\n`);

  const applyResult = assertOk("installed mnde init --apply", run(process.execPath, [onboardingCli, "init", "--apply"], {
    cwd: projectDir,
    env: { ...process.env, MNDE_STATE_DIR: join(projectDir, ".mnde-onboarding") }
  }));
  assert.match(applyResult.stdout, /Done\. MNDe now sits in front/);

  const applied = JSON.parse(readFileSync(configPath, "utf8"));
  for (const server of Object.values(applied.mcpServers)) {
    assert.equal(server.command, "node");
    assert.equal(server.env?._mnde_wrapped, "1");
    const referencedProxy = server.args?.[0];
    assert.equal(typeof referencedProxy, "string");
    assert.equal(isAbsolute(referencedProxy), true);
    assert.ok(existsSync(referencedProxy), `init --apply referenced a missing file: ${referencedProxy}`);
    assert.ok(!relative(packageRoot, referencedProxy).startsWith(".."), "proxy reference must stay inside the installed package");
  }

  // The installed proxy starts and identifies as ITSELF, not as an upstream it
  // proxied through to. It spawns no child: protected execution is disabled, so
  // there is nothing to forward to and no upstream process to start.
  const initialized = await initializeProxy(proxyPath, packageRoot);
  assert.equal(initialized.result.serverInfo.name, "mnde-proxy");
  assert.match(initialized.result.instructions ?? "", /execution is disabled/i);

  console.log("PASS packaged onboarding references and starts the installed MCP proxy");
} finally {
  if (projectDir) rmSync(projectDir, { recursive: true, force: true });
  if (packDir) rmSync(packDir, { recursive: true, force: true });
}
