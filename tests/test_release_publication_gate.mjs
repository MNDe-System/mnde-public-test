#!/usr/bin/env node
// The release gate is what gives the human approval click its meaning: the
// bytes published after the click must be the bytes that were verified before
// it. If this check can be fooled, the approval is theatre, so it is tested
// hostilely here rather than trusted because it is short.
//
// Everything below runs against a synthetic release directory. It never packs,
// publishes, tags, or talks to the network.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(repoRoot, "build", "release-publication.mjs");
const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));

const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const TARBALL_BYTES = Buffer.from("not a real tarball, only bytes to hash\n", "utf8");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const workspace = mkdtempSync(join(tmpdir(), "mnde-release-gate-"));
let caseId = 0;

// Build a release directory that a correct `npm run release` would have
// produced, then let each case corrupt exactly one thing about it.
function makeRelease({ mutateManifest, mutateSums, tarballBytes = TARBALL_BYTES, extraFile = null } = {}) {
  caseId += 1;
  const dir = join(workspace, `case-${caseId}`);
  mkdirSync(dir, { recursive: true });
  const name = `${pkg.name}-${pkg.version}.tgz`;
  writeFileSync(join(dir, name), tarballBytes);

  const manifest = {
    schema: "mnde.release-manifest.v1",
    product: "MNDe",
    package: pkg.name,
    version: pkg.version,
    commit: COMMIT,
    commit_short: COMMIT.slice(0, 7),
    dirty: false,
    build_id: COMMIT.slice(0, 7),
    build_time: "2026-09-20T00:00:00.000Z",
    runtime: { node: "24.14.1", npm: "11.11.0", os: "win32-x64" },
    engines: pkg.engines ?? null,
    artifacts: [{ name, bytes: TARBALL_BYTES.length, sha256: sha256(TARBALL_BYTES) }],
    generated_at: "2026-09-20T00:00:00.000Z"
  };
  if (mutateManifest) mutateManifest(manifest);
  writeFileSync(join(dir, "release-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  let sums = `${sha256(TARBALL_BYTES)}  ${name}\n`;
  if (mutateSums) sums = mutateSums(sums, name);
  writeFileSync(join(dir, "SHA256SUMS.txt"), sums, "utf8");

  if (extraFile) writeFileSync(join(dir, extraFile), "stowaway\n", "utf8");
  return { dir, name, manifest };
}

function runGate(dir, extraArgs = [], env = {}) {
  return spawnSync(process.execPath, [
    script, "gate",
    "--release-dir", dir,
    "--expect-version", pkg.version,
    "--expect-commit", COMMIT,
    ...extraArgs
  ], { encoding: "utf8", env: { ...process.env, ...env } });
}

const results = [];
function check(description, fn) {
  try {
    fn();
    results.push({ description, pass: true });
    console.log(`  [PASS] ${description}`);
  } catch (error) {
    results.push({ description, pass: false, error: error?.message ?? String(error) });
    console.error(`  [FAIL] ${description}: ${error?.message ?? error}`);
  }
}

console.log("Release publication gate — hostile tests\n");

check("a correct release directory passes", () => {
  const { dir } = makeRelease();
  const result = runGate(dir);
  assert.equal(result.status, 0, `expected pass, got ${result.status}:\n${result.stdout}${result.stderr}`);
  assert.match(result.stdout, /PASS release gate/);
});

check("a tarball swapped after the approval is refused", () => {
  // The digest the approver saw, against a directory that now holds other bytes.
  const { dir } = makeRelease({ tarballBytes: Buffer.from("substituted payload\n", "utf8") });
  const result = runGate(dir, ["--expect-tarball-sha256", sha256(TARBALL_BYTES)]);
  assert.notEqual(result.status, 0, "gate accepted a substituted tarball");
  assert.match(result.stdout, /byte-identical to the approved build/);
});

check("a SHA256SUMS.txt swapped after the approval is refused", () => {
  const { dir } = makeRelease();
  const result = runGate(dir, ["--expect-sums-sha256", sha256(Buffer.from("different sums file\n", "utf8"))]);
  assert.notEqual(result.status, 0, "gate accepted a substituted SHA256SUMS.txt");
});

check("a release-manifest.json swapped after the approval is refused", () => {
  const { dir } = makeRelease();
  const result = runGate(dir, ["--expect-manifest-sha256", sha256(Buffer.from("different manifest\n", "utf8"))]);
  assert.notEqual(result.status, 0, "gate accepted a substituted manifest");
});

check("matching approved digests still pass", () => {
  const { dir } = makeRelease();
  const sums = readFileSync(join(dir, "SHA256SUMS.txt"));
  const manifest = readFileSync(join(dir, "release-manifest.json"));
  const result = runGate(dir, [
    "--expect-tarball-sha256", sha256(TARBALL_BYTES),
    "--expect-sums-sha256", sha256(sums),
    "--expect-manifest-sha256", sha256(manifest)
  ]);
  assert.equal(result.status, 0, `expected pass, got ${result.status}:\n${result.stdout}${result.stderr}`);
});

check("a tarball that disagrees with its own manifest digest is refused", () => {
  const { dir } = makeRelease({ tarballBytes: Buffer.from("tampered\n", "utf8") });
  const result = runGate(dir);
  assert.notEqual(result.status, 0, "gate accepted a tarball that does not match the manifest");
  assert.match(result.stdout, /digest matches the manifest/);
});

check("a dirty build is refused", () => {
  const { dir } = makeRelease({ mutateManifest: (m) => { m.dirty = true; } });
  const result = runGate(dir);
  assert.notEqual(result.status, 0, "gate accepted a dirty build");
  assert.match(result.stdout, /dirty working tree/);
});

check("a manifest with no source commit is refused", () => {
  const { dir } = makeRelease({ mutateManifest: (m) => { m.commit = null; m.commit_short = null; } });
  const result = runGate(dir);
  assert.notEqual(result.status, 0, "gate accepted a commit-less manifest");
});

check("a build of a different commit than the one dispatched is refused", () => {
  const { dir } = makeRelease({ mutateManifest: (m) => { m.commit = "f".repeat(40); } });
  const result = runGate(dir);
  assert.notEqual(result.status, 0, "gate accepted the wrong source commit");
  assert.match(result.stdout, /commit is the commit being released/);
});

check("a version other than the one the dispatcher typed is refused", () => {
  const { dir } = makeRelease();
  const result = spawnSync(process.execPath, [
    script, "gate", "--release-dir", dir, "--expect-version", "99.99.99", "--expect-commit", COMMIT
  ], { encoding: "utf8" });
  assert.notEqual(result.status, 0, "gate accepted a version the dispatcher did not request");
  assert.match(result.stdout, /requested version matches package\.json/);
});

check("a manifest version that drifts from package.json is refused", () => {
  const { dir } = makeRelease({ mutateManifest: (m) => { m.version = "0.0.0-drift"; } });
  const result = runGate(dir);
  assert.notEqual(result.status, 0, "gate accepted a manifest version that drifts from package.json");
});

check("an unexpected extra file in the release directory is refused", () => {
  const { dir } = makeRelease({ extraFile: "stowaway.txt" });
  const result = runGate(dir);
  assert.notEqual(result.status, 0, "gate accepted an unaccounted-for file");
  assert.match(result.stdout, /exactly the tarball plus metadata/);
});

check("a SHA256SUMS.txt that omits the tarball is refused", () => {
  const { dir } = makeRelease({ mutateSums: () => "\n" });
  const result = runGate(dir);
  assert.notEqual(result.status, 0, "gate accepted checksums that cover nothing");
  assert.match(result.stdout, /SHA256SUMS\.txt lists exactly the artifacts/);
});

check("a SHA256SUMS.txt digest that disagrees with the bytes is refused", () => {
  const { dir } = makeRelease({ mutateSums: (_sums, name) => `${"a".repeat(64)}  ${name}\n` });
  const result = runGate(dir);
  assert.notEqual(result.status, 0, "gate accepted checksums that disagree with the artifact");
});

check("a passing gate publishes its digests as workflow outputs", () => {
  const { dir, name } = makeRelease();
  const outputFile = join(workspace, "outputs-pass.txt");
  writeFileSync(outputFile, "", "utf8");
  const result = runGate(dir, [], { GITHUB_OUTPUT: outputFile });
  assert.equal(result.status, 0, `expected pass:\n${result.stdout}${result.stderr}`);
  const outputs = readFileSync(outputFile, "utf8");
  assert.match(outputs, new RegExp(`^tarball_sha256=${sha256(TARBALL_BYTES)}$`, "m"));
  assert.match(outputs, new RegExp(`^commit=${COMMIT}$`, "m"));
  assert.match(outputs, new RegExp(`^tag=v${pkg.version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"));
  assert.match(outputs, new RegExp(`^tarball=${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"));
});

check("a failing gate publishes no workflow outputs", () => {
  // A failed gate that still emitted digests would let a later job carry on
  // with numbers nobody vouched for.
  const { dir } = makeRelease({ mutateManifest: (m) => { m.dirty = true; } });
  const outputFile = join(workspace, "outputs-fail.txt");
  writeFileSync(outputFile, "", "utf8");
  const result = runGate(dir, [], { GITHUB_OUTPUT: outputFile });
  assert.notEqual(result.status, 0);
  assert.equal(readFileSync(outputFile, "utf8"), "", "a failed gate wrote workflow outputs");
});

check("release notes restate the manifest, not a recollection of it", () => {
  const { dir, name } = makeRelease();
  const notesPath = join(workspace, "notes.md");
  const result = spawnSync(process.execPath, [
    script, "notes", "--release-dir", dir, "--tag", `v${pkg.version}`, "--out", notesPath
  ], { encoding: "utf8" });
  assert.equal(result.status, 0, `notes failed:\n${result.stdout}${result.stderr}`);
  const notes = readFileSync(notesPath, "utf8");
  assert.ok(notes.includes(COMMIT), "notes omit the source commit");
  assert.ok(notes.includes(sha256(TARBALL_BYTES)), "notes omit the artifact digest");
  assert.ok(notes.includes(name), "notes omit the artifact filename");
  assert.ok(notes.includes(`v${pkg.version}`), "notes omit the tag");
  // The documentation-truth rules apply to what a release page says too.
  assert.match(notes, /No desktop installer exists/);
  assert.match(notes, /not published to the public npm registry/);
  assert.match(notes, /gh attestation verify/);
  for (const command of ["npm init -y", "npx mnde-sidecar doctor", "npx mnde-sidecar smoke"]) {
    assert.ok(notes.includes(command), `notes omit the packaged install command: ${command}`);
  }
});

check("an unreadable release directory is a hard error, not a pass", () => {
  const result = spawnSync(process.execPath, [
    script, "gate", "--release-dir", join(workspace, "does-not-exist")
  ], { encoding: "utf8" });
  assert.notEqual(result.status, 0, "gate passed on a missing release directory");
});

// --- approval-gate precheck ---------------------------------------------------
// `environment: release` in a workflow is not a gate unless that environment
// actually requires a reviewer. These cases drive the precheck against a stub
// GitHub API on an ephemeral port, so nothing here depends on a fixed port or
// on the network.
async function withStubApi(handler, fn) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

// Spawned asynchronously on purpose: the stub API lives in this process, and
// spawnSync would block the event loop that has to answer the child's request.
function runApprovalGate(apiUrl) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      script, "verify-approval-gate", "--repo", "example/repo", "--environment", "release"
    ], { env: { ...process.env, GITHUB_API_URL: apiUrl, GITHUB_TOKEN: "stub-token" } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

function jsonResponder(status, body) {
  return (_request, response) => {
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify(body));
  };
}

async function checkAsync(description, fn) {
  try {
    await fn();
    results.push({ description, pass: true });
    console.log(`  [PASS] ${description}`);
  } catch (error) {
    results.push({ description, pass: false, error: error?.message ?? String(error) });
    console.error(`  [FAIL] ${description}: ${error?.message ?? error}`);
  }
}

await checkAsync("an environment with a required reviewer passes", async () => {
  await withStubApi(jsonResponder(200, {
    name: "release",
    protection_rules: [{ id: 1, type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { login: "owner" } }] }],
    deployment_branch_policy: null
  }), async (apiUrl) => {
    const result = await runApprovalGate(apiUrl);
    assert.equal(result.status, 0, `expected pass:\n${result.stdout}${result.stderr}`);
    assert.match(result.stdout, /requires approval from: owner/);
    assert.match(result.stdout, /self-review is permitted/);
  });
});

await checkAsync("a missing environment is refused", async () => {
  await withStubApi(jsonResponder(404, { message: "Not Found" }), async (apiUrl) => {
    const result = await runApprovalGate(apiUrl);
    assert.notEqual(result.status, 0, "precheck accepted a missing environment");
    assert.match(result.stderr, /does not exist/);
  });
});

await checkAsync("an environment with no protection rules is refused", async () => {
  await withStubApi(jsonResponder(200, { name: "release", protection_rules: [] }), async (apiUrl) => {
    const result = await runApprovalGate(apiUrl);
    assert.notEqual(result.status, 0, "precheck accepted an unprotected environment");
    assert.match(result.stderr, /no required-reviewer rule/);
  });
});

await checkAsync("an environment that requires review by nobody is refused", async () => {
  await withStubApi(jsonResponder(200, {
    name: "release",
    protection_rules: [{ id: 1, type: "wait_timer", wait_timer: 5 }, { id: 2, type: "required_reviewers", reviewers: [] }]
  }), async (apiUrl) => {
    const result = await runApprovalGate(apiUrl);
    assert.notEqual(result.status, 0, "precheck accepted an empty reviewer list");
    assert.match(result.stderr, /requires review by nobody/);
  });
});

await checkAsync("an unreadable environment is refused, not assumed safe", async () => {
  await withStubApi(jsonResponder(403, { message: "Forbidden" }), async (apiUrl) => {
    const result = await runApprovalGate(apiUrl);
    assert.notEqual(result.status, 0, "precheck passed when it could not read the environment");
    assert.match(result.stderr, /cannot read the 'release' environment/);
  });
});

rmSync(workspace, { recursive: true, force: true });

const failed = results.filter((entry) => !entry.pass);
if (failed.length > 0) {
  console.error(`\nFAIL release publication gate (${results.length - failed.length}/${results.length})`);
  process.exit(1);
}
console.log(`\nPASS release publication gate (${results.length}/${results.length})`);
