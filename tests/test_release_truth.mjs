#!/usr/bin/env node
// Heavy release-truth proof (run via `npm run release:verify`, NOT in the default
// suite — it packs, installs, boots, and uninstalls, so it is deliberately kept
// out of ordinary CI cost and run as a dedicated release-contract job).
//
// It behaves like a skeptical enterprise engineer who received the MNDe tarball
// with NO access to the developer repository, and tries to prove the package is
// lying: wrong version, needs Git, needs the repo, writes into node_modules,
// ships secrets or developer paths, fails open without security prerequisites,
// or leaves contradictory identities behind.
//
// REL-01..REL-18 map to the PR B hostile-test contract.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PKG_NAME = "mnde-public-test";
const nodeCmd = process.execPath;

function resolveNpmCli() {
  const nodeDir = dirname(process.execPath);
  const candidates = [
    join(nodeDir, "node_modules", "npm", "bin", "npm-cli.js"),
    join(nodeDir, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js")
  ];
  return candidates.find((c) => existsSync(c)) ?? null;
}
const npmCliJs = resolveNpmCli();

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", ...opts });
  if (r.error) throw r.error;
  return r;
}
function runNpm(args, opts = {}) {
  return npmCliJs ? run(nodeCmd, [npmCliJs, ...args], opts) : run(process.platform === "win32" ? "npm.cmd" : "npm", args, { shell: true, ...opts });
}
function hardOk(label, r) {
  if (r.status !== 0) throw new Error(`${label} failed (exit ${r.status}):\n${r.stdout}\n${r.stderr}`);
  return r;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function health(port) {
  try {
    return (await fetch(`http://127.0.0.1:${port}/healthz`, { signal: AbortSignal.timeout(1200) })).ok;
  } catch { return false; }
}
async function stopTree(child) {
  if (!child) return;
  if (child.exitCode === null) {
    try {
      if (process.platform === "win32") {
        spawnSync("taskkill", ["/F", "/T", "/PID", String(child.pid)], { stdio: "ignore" });
      } else {
        // The packaged CLI launches the runtime as a child. On POSIX, killing
        // only the CLI can leave that runtime holding the inherited stderr pipe,
        // which keeps this test process alive after every assertion has passed.
        // The test spawns CLIs in their own process group so teardown can signal
        // the complete tree without touching unrelated runner processes.
        process.kill(-child.pid, "SIGTERM");
      }
    } catch { /* already gone */ }
  }

  if (child.exitCode === null) {
    await new Promise((resolveStop) => {
      const timer = setTimeout(() => {
        try {
          if (process.platform !== "win32") process.kill(-child.pid, "SIGKILL");
        } catch { /* already gone */ }
        resolveStop();
      }, 5000);
      timer.unref();
      child.once("close", () => {
        clearTimeout(timer);
        resolveStop();
      });
    });
  }

  child.stdout?.destroy();
  child.stderr?.destroy();
  child.stdin?.destroy();
}

const results = [];
async function check(id, desc, fn) {
  try {
    await fn();
    results.push({ id, desc, pass: true });
    console.log(`[PASS] ${id} ${desc}`);
  } catch (error) {
    results.push({ id, desc, pass: false, error: error?.message ?? String(error) });
    console.error(`[FAIL] ${id} ${desc}: ${error?.message ?? error}`);
  }
}

// List the entries inside a tarball (posix paths, `package/` prefix stripped).
// Runs `tar` with cwd = the tarball's directory and passes only the basename, so
// GNU tar (Git Bash) does not misread a Windows `C:\` drive-colon as a remote
// host; Windows bsdtar (CI) handles it identically.
function tarListing(tarballPath) {
  const dir = dirname(tarballPath);
  const base = tarballPath.split(/[\\/]/).pop();
  const r = spawnSync("tar", ["-tzf", base], { cwd: dir, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`tar -tzf failed for ${base}:\n${r.stderr}`);
  return r.stdout
    .split(/\r?\n/)
    .filter(Boolean)
    .map((p) => p.replace(/\\/g, "/").replace(/^(\.\/)?package\//, ""));
}

// Recursively list files under a dir (relative posix paths).
function listFiles(root, base = root, out = []) {
  for (const entry of readdirSync(root)) {
    const full = join(root, entry);
    const st = statSync(full);
    if (st.isDirectory()) listFiles(full, base, out);
    else out.push(resolve(full).slice(resolve(base).length + 1).replace(/\\/g, "/"));
  }
  return out;
}

let packDir;
let projectDir;
let child;
try {
  // ---- Setup: obtain the artifact under test --------------------------------
  // Prefer the ACTUAL artifact `npm run release` emitted (release/*.tgz + its
  // published SHA256SUMS.txt + release-manifest.json) so CI validates exactly
  // what ships — digest, manifest, and all. Only when no release/ output exists
  // (a standalone dev run of this test) do we pack a throwaway tarball, purely to
  // exercise install/runtime behavior.
  const releaseDir = join(repoRoot, "release");
  const releaseTgz = existsSync(releaseDir)
    ? readdirSync(releaseDir).find((f) => /^mnde-public-test-.*\.tgz$/.test(f))
    : null;
  let tarballPath;
  let publishedManifest = null;
  let publishedSums = null;
  if (releaseTgz && existsSync(join(releaseDir, "release-manifest.json")) && existsSync(join(releaseDir, "SHA256SUMS.txt"))) {
    tarballPath = join(releaseDir, releaseTgz);
    publishedManifest = JSON.parse(readFileSync(join(releaseDir, "release-manifest.json"), "utf8"));
    publishedSums = readFileSync(join(releaseDir, "SHA256SUMS.txt"), "utf8");
    console.log(`[info] verifying the released artifact: release/${releaseTgz}`);
  } else {
    packDir = mkdtempSync(join(tmpdir(), "mnde-reltruth-pack-"));
    const packResult = hardOk("npm pack", runNpm(["pack", "--json", "--pack-destination", packDir], { cwd: repoRoot }));
    const jsonStart = packResult.stdout.indexOf("[");
    assert.ok(jsonStart >= 0, `npm pack --json produced no JSON array:\n${packResult.stdout}`);
    const packInfo = JSON.parse(packResult.stdout.slice(jsonStart))[0];
    tarballPath = join(packDir, packInfo.filename);
    console.log("[info] no release/ artifact present; verifying a freshly packed tarball");
  }
  assert.ok(existsSync(tarballPath), `tarball missing: ${tarballPath}`);
  const shipped = tarListing(tarballPath);

  // ---- REL-04: required production files exist ------------------------------
  await check("REL-04", "required production files are present in the tarball", () => {
    const required = [
      "package.json",
      "README.md",
      "dist/bin/mnde.mjs",
      "dist/bin/mnde-sidecar.mjs",
      "dist/mnde-local-sidecar.mjs",
      "dist/src/release/identity.mjs",
      "dist/src/release/build-info.json",
      "dist/scripts/start-sidecar.mjs",
      "dist/scripts/bootstrap_dev_receipt_keys.mjs",
      "dist/templates/starter-policy.json",
      "dist/shared/receipt-signing.js",
      "dist/tools/verify.mjs"
    ];
    const missing = required.filter((r) => !shipped.includes(r));
    assert.deepEqual(missing, [], `required files absent from tarball: ${missing.join(", ")}`);
  });

  // ---- REL-05: forbidden development-only files are excluded -----------------
  await check("REL-05", "development-only files are excluded from the tarball", () => {
    const forbiddenPrefixes = ["tests/", "dist/tests/", "reviewer-kit/", "docs/", "build/", "dist/build/", "examples/", "dist/examples/", ".mnde-test/", "shared/receipt_keys/", "dist/shared/receipt_keys/", "node_modules/"];
    const offenders = shipped.filter((p) => forbiddenPrefixes.some((f) => p.startsWith(f)));
    assert.deepEqual(offenders, [], `forbidden files shipped: ${offenders.join(", ")}`);
    // Private keys must never ship; a PUBLIC key (e.g. the committed demo
    // authority's root_authority_public.pem, needed to verify example receipts)
    // legitimately may.
    const privatePems = shipped.filter((p) => /private.*\.pem$/i.test(p) || p.endsWith("_private.pem"));
    assert.deepEqual(privatePems, [], `private key files shipped: ${privatePems.join(", ")}`);
    // The build/release tooling and dev proof harness must never ship.
    const devTooling = shipped.filter((p) => /build-package\.mjs|(^|\/)release\.mjs$|tools\/reviewer-kit\.mjs/.test(p));
    assert.deepEqual(devTooling, [], `dev tooling shipped: ${devTooling.join(", ")}`);
  });

  // ---- REL-12 / REL-13: checksum verification succeeds and tamper fails ------
  const tarballBytes = readFileSync(tarballPath);
  const trueDigest = createHash("sha256").update(tarballBytes).digest("hex");
  const artifactBase = tarballPath.split(/[\\/]/).pop();
  await check("REL-12", "release checksum verification succeeds for the real artifact", () => {
    const recomputed = createHash("sha256").update(readFileSync(tarballPath)).digest("hex");
    assert.equal(recomputed, trueDigest, "recomputed digest must match");
    // When validating the actual `npm run release` output, the digest MUST equal
    // the one published in SHA256SUMS.txt — proving the checksum binds the shipped
    // bytes, not a repack.
    if (publishedSums) {
      const line = publishedSums.split(/\r?\n/).find((l) => l.trim().endsWith(artifactBase));
      assert.ok(line, `SHA256SUMS.txt has no entry for ${artifactBase}`);
      assert.equal(line.trim().split(/\s+/)[0], trueDigest, "published SHA256SUMS digest must match the real artifact bytes");
    }
  });
  await check("REL-13", "a modified artifact fails checksum verification", () => {
    const tampered = Buffer.from(tarballBytes);
    tampered[Math.floor(tampered.length / 2)] ^= 0xff; // flip one byte
    const tamperedDigest = createHash("sha256").update(tampered).digest("hex");
    assert.notEqual(tamperedDigest, trueDigest, "tampered artifact must not match the published digest");
  });

  // ---- Install into a clean, repo-independent project ------------------------
  projectDir = mkdtempSync(join(tmpdir(), "mnde-reltruth-install-"));
  hardOk("npm init", runNpm(["init", "-y"], { cwd: projectDir }));

  // ---- REL-16: production dependency installation works from the package ----
  await check("REL-16", "the package installs from the tarball alone (no external runtime deps)", () => {
    const r = runNpm(["install", tarballPath], { cwd: projectDir });
    assert.equal(r.status, 0, `install failed:\n${r.stdout}\n${r.stderr}`);
  });

  const pkgDir = join(projectDir, "node_modules", PKG_NAME);
  const binDir = join(projectDir, "node_modules", ".bin");
  const mndeCli = join(pkgDir, "dist", "bin", "mnde.mjs");
  const sidecarCli = join(pkgDir, "dist", "bin", "mnde-sidecar.mjs");
  const runtime = join(pkgDir, "dist", "mnde-local-sidecar.mjs");
  const installedPkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
  const buildInfo = JSON.parse(readFileSync(join(pkgDir, "dist", "src", "release", "build-info.json"), "utf8"));
  assert.ok(!existsSync(join(pkgDir, ".git")), "install must not carry a .git directory");

  // ---- REL-02 / REL-03: CLI runs without .git and outside the repository -----
  const versionJson = (cli) => JSON.parse(run(nodeCmd, [cli, "version", "--json"], { cwd: projectDir }).stdout);
  await check("REL-02", "packaged CLI works without .git", () => {
    assert.ok(!existsSync(join(projectDir, ".git")), "test project must have no .git");
    const id = versionJson(mndeCli);
    assert.equal(id.version, installedPkg.version);
  });
  await check("REL-03", "packaged CLI works from outside the repository", () => {
    // cwd is the throwaway project, which is not under repoRoot.
    assert.ok(!resolve(projectDir).startsWith(resolve(repoRoot)), "project dir must be outside the repo");
    const r = run(nodeCmd, [sidecarCli, "version"], { cwd: projectDir });
    assert.equal(r.status, 0, `sidecar version failed outside repo:\n${r.stderr}`);
    assert.match(r.stdout, /MNDe/);
  });

  // ---- REL-01: all exposed version sources agree ----------------------------
  await check("REL-01", "all exposed version sources agree", () => {
    const a = versionJson(mndeCli);
    const b = versionJson(sidecarCli);
    assert.equal(a.version, installedPkg.version, "mnde version vs package.json");
    assert.equal(b.version, installedPkg.version, "mnde-sidecar version vs package.json");
    assert.equal(a.commit, buildInfo.commit, "mnde commit vs build-info");
    assert.equal(b.commit, buildInfo.commit, "mnde-sidecar commit vs build-info");
    assert.equal(a.commit, b.commit, "the two CLIs must report the same commit");
  });

  // ---- REL-08: installed runtime reports the embedded identity (no Git) ------
  await check("REL-08", "installed CLI reports the embedded release commit", () => {
    const id = versionJson(sidecarCli);
    assert.equal(id.commit, buildInfo.commit, "embedded commit must surface via the CLI");
    assert.equal(id.source, "packaged");
    assert.equal(id.artifact_format, "npm-tarball");
  });

  // ---- REL-19: the release manifest binds the real artifact -----------------
  // Only meaningful when validating an actual `npm run release` output: the
  // manifest's recorded digest/size/version/commit must match the shipped
  // artifact and the identity embedded inside it.
  if (publishedManifest) {
    await check("REL-19", "release manifest binds the real artifact digest, size, version, and source commit", () => {
      const entry = (publishedManifest.artifacts || []).find((a) => a.name === artifactBase);
      assert.ok(entry, `manifest has no artifact entry for ${artifactBase}`);
      assert.equal(entry.sha256, trueDigest, "manifest artifact digest must match the real artifact bytes");
      assert.equal(entry.bytes, tarballBytes.length, "manifest artifact size must match the real artifact");
      assert.equal(publishedManifest.version, installedPkg.version, "manifest version vs installed package version");
      assert.ok(publishedManifest.commit, "manifest must carry a non-null source commit");
      assert.equal(publishedManifest.commit, buildInfo.commit, "manifest commit vs the commit embedded in the shipped artifact");
    });
  }

  // ---- REL-14: no developer-machine absolute paths embedded -----------------
  await check("REL-14", "no developer-machine absolute paths are embedded in shipped files", () => {
    const files = listFiles(pkgDir);
    const home = resolve(homedir());
    const repoAbs = resolve(repoRoot);
    const offenders = [];
    for (const rel of files) {
      // Only scan text-like files.
      if (!/\.(mjs|js|ts|json|md|txt)$/.test(rel)) continue;
      const content = readFileSync(join(pkgDir, rel), "utf8");
      if (content.includes(repoAbs) || content.includes(home) || /[/\\]INsol[/\\]mnde-/.test(content)) {
        offenders.push(rel);
      }
    }
    assert.deepEqual(offenders, [], `developer paths embedded in: ${offenders.join(", ")}`);
  });

  // ---- REL-15: no private keys ship; the demo signing default never leaks
  // into the trust core.
  //
  // The legacy demo HMAC constant is an intentional, documented LOCAL/DEMO
  // signing default (env-overridable) that production rejects outright — REL-06
  // proves a production sidecar refuses to start with legacy signing. So it is
  // not a private key and not a production credential. What MUST hold is (a) no
  // real private-key material ships, and (b) the demo constant never contaminates
  // the decision/signing/verification trust core — it may appear ONLY in files
  // whose job is local/demo bootstrap.
  await check("REL-15", "no private keys ship and the demo signing default stays out of the trust core", () => {
    const DEMO_HMAC = "demo-legacy-signature-key-000000000001";
    // Files that are legitimately allowed to carry the local/demo signing default.
    const demoAllowlist = new Set([
      "dist/scripts/start-sidecar.mjs",
      "dist/executor/sidecar-harness.mjs"
    ]);
    const files = listFiles(pkgDir);
    const privateKeyHits = [];
    const demoLeaks = [];
    for (const rel of files) {
      const text = readFileSync(join(pkgDir, rel)).toString("latin1");
      if (/-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/.test(text)) privateKeyHits.push(rel);
      if (text.includes(DEMO_HMAC) && !demoAllowlist.has(rel)) demoLeaks.push(rel);
    }
    assert.deepEqual(privateKeyHits, [], `private key material shipped: ${privateKeyHits.join(", ")}`);
    assert.deepEqual(demoLeaks, [], `demo signing default leaked outside local/demo bootstrap files: ${demoLeaks.join(", ")}`);
  });

  // ---- REL-20: every relative import resolves with EXACT case (Linux-safe) ---
  // CI runs only on case-insensitive Windows, so a mis-cased import (Foo.mjs
  // imported as foo.mjs) would ship broken to Linux while CI stays green. This
  // compares each shipped module's relative import specifiers against the actual
  // on-disk filenames case-sensitively, catching that class of defect on any OS.
  await check("REL-20", "shipped modules' relative imports resolve with exact case (Linux-safe)", () => {
    const distDir = join(pkgDir, "dist");
    const specRe = /(?:from\s+|import\s*\(\s*|export\s+[^;]*?from\s+)["'](\.[^"'\n]+)["']/g;
    const dirCache = new Map();
    const listing = (dir) => {
      if (!dirCache.has(dir)) {
        try { dirCache.set(dir, new Set(readdirSync(dir))); } catch { dirCache.set(dir, new Set()); }
      }
      return dirCache.get(dir);
    };
    const offenders = [];
    let scanned = 0;
    for (const rel of listFiles(distDir)) {
      if (!/\.(mjs|js)$/.test(rel)) continue;
      const abs = join(distDir, rel);
      const src = readFileSync(abs, "utf8");
      let m;
      while ((m = specRe.exec(src))) {
        const target = resolve(dirname(abs), m[1]);
        const base = target.split(/[\\/]/).pop();
        const names = listing(dirname(target));
        scanned += 1;
        if (names.has(base)) continue; // exact-case match
        const clash = [...names].find((n) => n.toLowerCase() === base.toLowerCase());
        if (clash) offenders.push(`${rel} imports "${m[1]}" but on disk it is "${clash}"`);
        else if (!existsSync(target)) offenders.push(`${rel} imports "${m[1]}" -> missing target`);
      }
    }
    assert.ok(scanned > 0, "expected to scan at least one relative import");
    assert.deepEqual(offenders, [], `case-mismatched or missing imports:\n  ${offenders.join("\n  ")}`);
  });

  // ---- init under MNDE_HOME, then data-location assertions -------------------
  const home = join(projectDir, "customer-data");
  const cliEnv = { ...process.env, MNDE_HOME: home };
  const preInstallFiles = new Set(listFiles(pkgDir));
  hardOk("mnde-sidecar init", run(nodeCmd, [sidecarCli, "init"], { cwd: projectDir, env: cliEnv }));

  // ---- REL-07: state is written under MNDE_HOME, not repo-relative fallback --
  await check("REL-07", "runtime state is written under MNDE_HOME (no repo-relative fallback)", () => {
    assert.ok(existsSync(join(home, "shared", "receipt_keys", "receipt_signing_private.pem")), "signing key must be under MNDE_HOME");
    assert.ok(existsSync(join(home, "starter-policy.json")), "starter policy must be under MNDE_HOME");
  });

  // ---- REL-09: no mutable state leaked into the installed package tree -------
  await check("REL-09", "init writes no mutable state into the installed package tree", () => {
    const postInstallFiles = listFiles(pkgDir);
    const added = postInstallFiles.filter((f) => !preInstallFiles.has(f));
    assert.deepEqual(added, [], `init wrote into the package install dir: ${added.join(", ")}`);
  });

  // ---- REL-17: a missing runtime prerequisite fails clearly (start w/o init) -
  await check("REL-17", "start with an uninitialized MNDE_HOME fails closed with a clear message", () => {
    const freshHome = join(projectDir, "uninit-home");
    const r = run(nodeCmd, [sidecarCli, "start"], { cwd: projectDir, env: { ...process.env, MNDE_HOME: freshHome, MNDE_BIND_PORT: "8849" } });
    assert.notEqual(r.status, 0, "start without init must exit non-zero");
    assert.match(`${r.stdout}\n${r.stderr}`, /Not initialized|Run: npx mnde-sidecar init/, "must give a clear, actionable message");
  });

  // ---- REL-06: production profile without custody fails closed --------------
  await check("REL-06", "production profile without custody fails closed at startup", async () => {
    const prodHome = join(projectDir, "prod-home");
    const proc = spawn(nodeCmd, [runtime], {
      cwd: pkgDir,
      env: { ...process.env, MNDE_PROFILE: "production", MNDE_HOME: prodHome, MNDE_BIND_PORT: "8851" },
      stdio: ["ignore", "ignore", "pipe"],
      detached: process.platform !== "win32"
    });
    let stderr = "";
    proc.stderr.on("data", (d) => { stderr += d.toString(); });
    const exitCode = await new Promise((res) => {
      const timer = setTimeout(async () => { await stopTree(proc); res("timeout"); }, 10000);
      proc.once("exit", (code) => { clearTimeout(timer); res(code); });
    });
    assert.notEqual(exitCode, 0, `production sidecar must not start without custody (exit=${exitCode})`);
    assert.notEqual(exitCode, "timeout", "production sidecar must fail fast, not hang");
    assert.ok(!(await health(8851)), "no sidecar may be listening after a fail-closed startup");
    assert.match(stderr, /ERR_|refused to start|custody/i, `fail-closed reason expected in stderr:\n${stderr}`);
  });

  // ---- REL-18: a running sidecar and the CLI report the same identity -------
  await check("REL-18", "running sidecar and CLI report the same release identity", async () => {
    const startPort = 8847;
    child = spawn(nodeCmd, [sidecarCli, "start"], {
      cwd: projectDir,
      env: { ...cliEnv, MNDE_BIND_PORT: String(startPort) },
      stdio: ["ignore", "ignore", "pipe"],
      detached: process.platform !== "win32"
    });
    let up = false;
    for (let i = 0; i < 40 && !up; i += 1) {
      if (child.exitCode !== null) break;
      up = await health(startPort);
      if (!up) await sleep(400);
    }
    assert.ok(up, "sidecar did not become ready for the identity check");
    const identityResp = await (await fetch(`http://127.0.0.1:${startPort}/identity`, { signal: AbortSignal.timeout(2000) })).json();
    const cliId = versionJson(sidecarCli);
    assert.ok(identityResp.release, "/identity must expose a release block");
    assert.equal(identityResp.release.version, cliId.version, "sidecar vs CLI version must agree");
    assert.equal(identityResp.release.commit, cliId.commit, "sidecar vs CLI commit must agree");
    assert.equal(identityResp.release.product, "MNDe");
    await stopTree(child);
    child = null;
  });

  // ---- REL-10: reinstalling the same version is deterministic ---------------
  await check("REL-10", "reinstalling the same version over itself is deterministic", () => {
    const r = runNpm(["install", tarballPath], { cwd: projectDir });
    assert.equal(r.status, 0, `reinstall failed:\n${r.stdout}\n${r.stderr}`);
    assert.ok(existsSync(sidecarCli), "CLI entry must remain after reinstall");
    const id = versionJson(sidecarCli);
    assert.equal(id.version, installedPkg.version, "version must be unchanged after reinstall");
    // Customer data under MNDE_HOME must survive a reinstall.
    assert.ok(existsSync(join(home, "shared", "receipt_keys", "receipt_signing_private.pem")), "customer keys must survive reinstall");
  });

  // ---- REL-11: uninstall removes app files, preserves customer data ---------
  await check("REL-11", "uninstall removes application files and preserves customer data", () => {
    const r = runNpm(["uninstall", PKG_NAME], { cwd: projectDir });
    assert.equal(r.status, 0, `uninstall failed:\n${r.stdout}\n${r.stderr}`);
    assert.ok(!existsSync(pkgDir), "package directory must be removed on uninstall");
    for (const bin of ["mnde", "mnde-sidecar", "sidecar"]) {
      const p = process.platform === "win32" ? join(binDir, `${bin}.cmd`) : join(binDir, bin);
      assert.ok(!existsSync(p), `bin must be removed on uninstall: ${p}`);
    }
    // Customer security/audit data lives under MNDE_HOME and must NOT be touched.
    assert.ok(existsSync(join(home, "shared", "receipt_keys", "receipt_signing_private.pem")), "uninstall must preserve customer keys under MNDE_HOME");
  });

  // ---- Summary --------------------------------------------------------------
  const failed = results.filter((r) => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} REL checks passed`);
  if (failed.length > 0) {
    console.error(`FAIL: ${failed.map((f) => f.id).join(", ")}`);
    process.exit(1);
  }
  console.log("PASS release truth (all REL-* checks)");
} finally {
  await stopTree(child);
  if (projectDir) rmSync(projectDir, { recursive: true, force: true });
  if (packDir) rmSync(packDir, { recursive: true, force: true });
}
