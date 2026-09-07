#!/usr/bin/env node
// Authoritative package-boundary secret check.
//
// Verifies the actual npm-pack boundary — not the build script's own idea of
// what it copied, but the literal file list npm reports and the literal bytes
// inside the resulting tarball once extracted. It runs the SAME generalized
// scanner the build step uses (build/lib/package-secret-scan.mjs), so a leak
// that only manifested between "what the build wrote" and "what npm actually
// packed" is still caught here. The scanned set is the full supported secret
// set (PEM/DER/JWK/PuTTY private keys, selected provider tokens, and
// conservatively detected credential assignments), not PEM alone.
//
// The test name is unchanged for compatibility with the package script wiring.
//
// Never logs secret contents: findings carry only detector id, path, line, and
// a truncated fingerprint.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { scanForPackageSecrets, applyAllowlist } from "../build/lib/package-secret-scan.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const allowlistPath = join(repoRoot, "build", "secret-scan-allowlist.json");

function resolveNpmCli() {
  const nodeDir = dirname(process.execPath);
  const candidates = [
    join(nodeDir, "node_modules", "npm", "bin", "npm-cli.js"),
    join(nodeDir, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js")
  ];
  return candidates.find((c) => existsSync(c)) ?? null;
}
const npmCliJs = resolveNpmCli();
const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";

function run(cmd, args, opts = {}) {
  const result = spawnSync(cmd, args, { encoding: "utf8", ...opts });
  if (result.error) throw result.error;
  return result;
}
function runNpm(args, opts = {}) {
  return npmCliJs ? run(process.execPath, [npmCliJs, ...args], opts) : run(npmCmd, args, { shell: true, ...opts });
}
function assertOk(label, result) {
  assert.equal(result.status, 0, `${label} failed (exit ${result.status}):\n${result.stdout}\n${result.stderr}`);
  return result;
}

let packDir;
let extractDir;
try {
  packDir = mkdtempSync(join(tmpdir(), "mnde-pack-security-"));
  const packResult = assertOk("npm pack", runNpm(["pack", "--json", "--pack-destination", packDir], { cwd: repoRoot }));
  const jsonStart = packResult.stdout.indexOf("[");
  assert.ok(jsonStart >= 0, `npm pack --json produced no JSON array:\n${packResult.stdout}`);
  const packInfo = JSON.parse(packResult.stdout.slice(jsonStart))[0];
  const tarballPath = join(packDir, packInfo.filename);
  assert.ok(existsSync(tarballPath), `packed tarball missing: ${tarballPath}`);

  // Path-based sanity check against npm's own reported file list — cheap,
  // catches the obvious case even before touching the actual tarball bytes.
  // Forbidden shipped paths: receipt keys, root authority private key, the
  // .mnde-test scratch dir, and the build/ tooling (which holds this scanner and
  // its allowlist and must never ship).
  const shippedPaths = packInfo.files.map((f) => f.path.replace(/\\/g, "/"));
  for (const forbidden of ["shared/receipt_keys/", "authority/root_authority_private.pem", ".mnde-test/", "build/"]) {
    assert.ok(
      !shippedPaths.some((p) => p.includes(forbidden)),
      `npm pack must never report ${forbidden} in its file list, found in: ${shippedPaths.join(", ")}`
    );
  }

  // Authoritative check: extract the REAL tarball and content-scan what's
  // actually inside it — not the pre-pack dist/ directory, not npm's file
  // list, the literal packed bytes — with the full generalized secret scanner.
  extractDir = mkdtempSync(join(tmpdir(), "mnde-pack-extract-"));
  // Keep the archive argument relative: GNU tar otherwise parses a Windows
  // drive letter as "host:path", while bsdtar does not support --force-local.
  const relativeTarballPath = relative(extractDir, tarballPath).replace(/\\/g, "/");
  assertOk("tar extract", run("tar", ["-xzf", relativeTarballPath], { cwd: extractDir }));

  // npm wraps tarball contents in a top-level `package/` directory. Scan THAT
  // directory as the root so findings use the same package-relative paths as the
  // pre-pack `dist/` build scan (e.g. `bin/mnde.mjs`, not `package/bin/mnde.mjs`),
  // which is what makes a single exact allowlist entry valid at both boundaries.
  // We resolve the wrapper explicitly rather than stripping a leading segment.
  const packageContentDir = join(extractDir, "package");
  assert.ok(
    existsSync(packageContentDir) && statSync(packageContentDir).isDirectory(),
    `expected npm package-content directory at ${packageContentDir}`
  );

  const findings = applyAllowlist(scanForPackageSecrets(packageContentDir), {
    rootDir: packageContentDir,
    allowlistPath
  });
  const redacted = findings.map((f) => `[${f.detectorId}] ${f.relativePath}:${f.line} (${f.fingerprint})`);
  assert.deepEqual(
    findings,
    [],
    `suspected secret material inside the packed tarball (no values shown):\n${redacted.join("\n")}`
  );

  console.log(
    `PASS pack boundary contains no supported secret material — PEM/DER/JWK/PuTTY keys, provider tokens, credential assignments ` +
      `(${packInfo.entryCount} files scanned)`
  );
} finally {
  if (extractDir) rmSync(extractDir, { recursive: true, force: true });
  if (packDir) rmSync(packDir, { recursive: true, force: true });
}
