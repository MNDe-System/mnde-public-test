// Shipped-surface bypass guard (Production Proof 001, Phase 2 / F-001).
//
//   npm run test:shipped-surface-bypass
//
// Builds the package exactly as `prepack` does and asserts that the distributed
// artifact carries no raw MCP upstream-spawn capability and no path that forwards
// to an operator-configured upstream. Concretely:
//   * the raw stdio *client* (spawns an arbitrary command, audit path E07),
//   * the ungated demo upstream and simulated shell server (audit path E14), and
//   * the demo drivers that exist only to exercise them,
// must not be present in dist/. The only shipped MCP proxy is the deployment-hold
// stub, which must contain no child-process spawn, no MCP stdio client, and no
// executor callback. The genuine product surface (gated MCP server, proxy stub,
// CLI bins) must still ship. This does not by itself close F-001 (direct-import
// and deployment-level paths remain — see experiments/production-proof-001/f001/
// AUDIT.md); it locks the one bounded property that IS established: the legacy
// upstream-forwarding bypass is absent from the published package.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(repoRoot, "dist");

const REMOVED = [
  "mcp/stdio-client.mjs",
  "mcp/example-upstream-server.mjs",
  "mcp/shell-mcp-server.mjs",
  "scripts/mcp-demo.mjs",
  "scripts/mcp-proxy-demo.mjs",
  "scripts/shell-demo.mjs"
];
const REQUIRED = [
  "mcp/mnde-mcp-proxy.mjs",
  "mcp/mnde-mcp-server.mjs",
  "mcp/guarded-tools.mjs",
  "bin/mnde.mjs",
  "bin/mnde-sidecar.mjs"
];

const results = [];
function test(name, fn) {
  try {
    fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

function walk(dir, onFile) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, onFile);
    else onFile(full);
  }
}

function main() {
  console.log("Shipped-surface bypass guard — building package and inspecting dist/\n");

  // Build exactly as prepack does. A fresh build every run is intentional: the
  // guard must reflect the current build configuration, not a stale artifact.
  execFileSync(process.execPath, [join(repoRoot, "build", "build-package.mjs")], { cwd: repoRoot, stdio: "pipe" });

  test("the package built", () => {
    assert.ok(existsSync(dist), "dist/ must exist after the build");
  });

  test("raw upstream-spawn client and demo surface are absent from the package", () => {
    for (const rel of REMOVED) {
      assert.equal(existsSync(join(dist, rel)), false, `${rel} must NOT ship in the package`);
    }
  });

  test("the genuine product surface still ships", () => {
    for (const rel of REQUIRED) {
      assert.equal(existsSync(join(dist, rel)), true, `${rel} must ship`);
    }
  });

  test("the shipped proxy has no spawn, no MCP stdio client, no executor callback", () => {
    const proxy = readFileSync(join(dist, "mcp/mnde-mcp-proxy.mjs"), "utf8");
    for (const forbidden of ["createStdioClient", "child_process", "spawn(", "createMndeExecutor"]) {
      assert.equal(proxy.includes(forbidden), false, `shipped proxy must not contain "${forbidden}"`);
    }
  });

  test("no shipped file imports the raw stdio client", () => {
    const offenders = [];
    walk(dist, (file) => {
      if (!/\.(mjs|js)$/.test(file)) return;
      if (readFileSync(file, "utf8").includes("stdio-client")) offenders.push(file.slice(dist.length + 1));
    });
    assert.deepEqual(offenders, [], `no shipped module may import the raw stdio client; found: ${offenders.join(", ")}`);
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL shipped-surface bypass guard (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS shipped-surface bypass guard (${results.length}/${results.length})`);
}

main();
