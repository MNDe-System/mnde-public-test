#!/usr/bin/env node
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
const workflowPath = join(repoRoot, ".github", "workflows", "ci.yml");
const expectedTestScriptsPath = join(repoRoot, "tests", "expected-test-scripts.json");

assert.equal(packageJson.scripts.test, "node ./scripts/run-all-tests.mjs");
assert.equal(packageJson.scripts.ci, "node ./scripts/run-ci.mjs");
assert.equal(packageJson.scripts["check:whitespace"], "node ./scripts/check-whitespace.mjs");
assert.equal(packageJson.scripts["test:replay"], "node ./scripts/test-replay-verification.mjs");
assert.equal(packageJson.scripts["test:conformance"], "node ./tests/test_conformance_vectors.mjs");

for (const file of [
  workflowPath,
  join(repoRoot, "scripts", "run-all-tests.mjs"),
  join(repoRoot, "scripts", "run-ci.mjs"),
  join(repoRoot, "scripts", "check-whitespace.mjs"),
  join(repoRoot, "scripts", "test-replay-verification.mjs"),
  expectedTestScriptsPath
]) {
  assert.equal(existsSync(file), true, `${file} is missing`);
}

const expectedTestScripts = JSON.parse(readFileSync(expectedTestScriptsPath, "utf8"));
assert.ok(Array.isArray(expectedTestScripts), "expected test script list must be an array");
assert.deepEqual([...expectedTestScripts].sort(), expectedTestScripts, "expected test script list must be sorted");
assert.equal(new Set(expectedTestScripts).size, expectedTestScripts.length, "expected test script list must not contain duplicates");
assert.deepEqual(
  Object.keys(packageJson.scripts).filter((name) => name.startsWith("test:")).sort(),
  expectedTestScripts,
  "package.json test:* scripts must match tests/expected-test-scripts.json"
);

const workflow = readFileSync(workflowPath, "utf8");
assert.match(workflow, /uses:\s+actions\/checkout@[a-f0-9]{40}/);
assert.match(workflow, /uses:\s+actions\/setup-node@[a-f0-9]{40}/);
assert.doesNotMatch(workflow, /uses:\s+actions\/checkout@v\d/);
assert.doesNotMatch(workflow, /uses:\s+actions\/setup-node@v\d/);
for (const snippet of [
  "npm ci",
  "npm test",
  "npm run reviewer-kit",
  "npm run check:whitespace",
  "npm run test:replay",
  "npm run test:conformance"
]) {
  assert.match(workflow, new RegExp(snippet.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
}

// --- Release workflow contract ------------------------------------------------
// The release workflow can tag, publish, and attest. Those powers are only safe
// because they sit behind a GitHub Environment approval gate, so the shape that
// makes them safe is asserted here rather than left to review memory. See
// docs/release-automation.md for the environment configuration this assumes.
const releaseWorkflowPath = join(repoRoot, ".github", "workflows", "release.yml");
assert.equal(existsSync(releaseWorkflowPath), true, `${releaseWorkflowPath} is missing`);
const releaseWorkflow = readFileSync(releaseWorkflowPath, "utf8");

for (const scriptName of ["release:gate", "release:notes", "release:verify-published", "release:verify-approval-gate"]) {
  assert.equal(
    typeof packageJson.scripts[scriptName],
    "string",
    `package.json must define the ${scriptName} script the release workflow calls`
  );
}
assert.equal(existsSync(join(repoRoot, "build", "release-publication.mjs")), true, "build/release-publication.mjs is missing");

// Every action in every workflow is pinned to a full commit SHA. A floating tag
// is a supply-chain hole in the one workflow that holds write credentials.
for (const [path, text] of [["ci.yml", workflow], ["release.yml", releaseWorkflow]]) {
  for (const match of text.matchAll(/^\s*uses:\s*(\S+)\s*$/gm)) {
    assert.match(match[1], /^[\w.-]+\/[\w.-]+@[a-f0-9]{40}$/, `${path} uses an unpinned action: ${match[1]}`);
  }
}

// Manual dispatch only: a release never starts because something was pushed.
assert.match(releaseWorkflow, /^on:\n  workflow_dispatch:/m, "release.yml must trigger only on workflow_dispatch");
for (const forbidden of ["push", "pull_request", "schedule", "release"]) {
  assert.doesNotMatch(
    releaseWorkflow,
    new RegExp(`^  ${forbidden}:`, "m"),
    `release.yml must not add the ${forbidden} trigger`
  );
}
assert.match(releaseWorkflow, /^permissions:\n  contents: read$/m, "release.yml must default to read-only permissions");

// Both workflows run the one verified runtime; a release built on a different
// Node than CI proves nothing CI proved.
const ciNode = /node-version:\s*"([^"]+)"/.exec(workflow)?.[1];
assert.ok(ciNode, "ci.yml must pin node-version");
for (const match of releaseWorkflow.matchAll(/node-version:\s*"([^"]+)"/g)) {
  assert.equal(match[1], ciNode, "release.yml must pin the same Node version as ci.yml");
}

// Split the workflow into its jobs so the assertions below can talk about which
// job holds which power, not merely whether a string appears somewhere.
function splitJobs(text) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((line) => line === "jobs:");
  assert.ok(start >= 0, "workflow has no jobs: block");
  const jobs = new Map();
  let current = null;
  for (const line of lines.slice(start + 1)) {
    const header = /^ {2}([A-Za-z][\w-]*):\s*$/.exec(line);
    if (header) {
      current = header[1];
      jobs.set(current, []);
      continue;
    }
    if (current) jobs.get(current).push(line);
  }
  return new Map([...jobs].map(([name, body]) => [name, body.join("\n")]));
}

const releaseJobs = splitJobs(releaseWorkflow);
assert.ok(releaseJobs.has("build"), "release.yml must have a build job");
assert.ok(releaseJobs.has("publish"), "release.yml must have a publish job");

const gatedJobs = [...releaseJobs].filter(([, body]) => /^\s{4}environment:/m.test(body)).map(([name]) => name);
assert.deepEqual(gatedJobs, ["publish"], "exactly one job — publish — may sit behind the approval environment");
assert.match(releaseJobs.get("publish"), /^\s{6}name: release$/m, "the publish job must use the `release` environment");

// No write permission anywhere except behind the gate.
const writeJobs = [...releaseJobs]
  .filter(([, body]) => /^\s{6}(contents|packages|id-token|attestations|actions|deployments|issues|pull-requests|security-events):\s*write/m.test(body))
  .map(([name]) => name);
assert.deepEqual(writeJobs, ["publish"], "only the approval-gated publish job may hold write permissions");
assert.match(releaseJobs.get("build"), /^\s{6}contents: read$/m, "the build job must be read-only");

// The outward-facing effects live in the gated job and nowhere else.
for (const [effect, pattern] of [
  ["tag/release creation", /gh release create/],
  ["provenance attestation", /attest-build-provenance@[a-f0-9]{40}/]
]) {
  const jobsWithEffect = [...releaseJobs].filter(([, body]) => pattern.test(body)).map(([name]) => name);
  assert.deepEqual(jobsWithEffect, ["publish"], `${effect} must happen only in the approval-gated job`);
}
assert.match(releaseJobs.get("publish"), /id-token: write/, "provenance attestation needs id-token: write");
assert.match(releaseJobs.get("publish"), /attestations: write/, "provenance attestation needs attestations: write");

// The approval is only meaningful if the post-approval job re-proves that every
// artifact still hashes to what the approver was shown. Losing any one of these
// re-opens artifact substitution while the run waits for a human.
const publishJob = releaseJobs.get("publish");
for (const flag of ["--expect-tarball-sha256", "--expect-sums-sha256", "--expect-manifest-sha256", "--expect-commit"]) {
  assert.ok(publishJob.includes(flag), `the post-approval gate must re-check ${flag}`);
}
assert.match(publishJob, /needs\.build\.outputs\.tarball_sha256/, "the post-approval gate must consume the pre-approval digest");
assert.match(publishJob, /ref: \$\{\{ needs\.build\.outputs\.commit \}\}/, "the publish job must check out the exact commit that was built");

// Publication is verified from the outside, by a job that cannot write.
assert.ok(releaseJobs.has("verify-published"), "release.yml must verify what it published");
assert.match(releaseJobs.get("verify-published"), /release:verify-published/, "the verify job must run the published-digest check");
assert.match(releaseJobs.get("verify-published"), /^\s{6}contents: read$/m, "the verify job must be read-only");

// The runbook's validate-and-build block runs before anything is proposed for
// approval; a release that skipped the suite would be approved on no evidence.
const buildJob = releaseJobs.get("build");
for (const snippet of [
  "npm ci",
  "npm test",
  "npm run reviewer-kit",
  "npm run check:whitespace",
  "npm run test:replay",
  "npm run test:conformance",
  "npm run test:release-identity",
  "npm run release",
  "npm run release:verify"
]) {
  assert.ok(buildJob.includes(snippet), `the release build job must run ${snippet}`);
}

// The gate is only a gate if somebody has to approve it. The build job proves
// that before it builds anything, so a release cannot be prepared against an
// environment that would wave the publish job straight through.
assert.match(buildJob, /release:verify-approval-gate/, "the build job must confirm the approval gate is configured");

function walkFiles(entry) {
  const full = join(repoRoot, entry);
  if (!existsSync(full)) return [];
  if (statSync(full).isFile()) return /\.(?:mjs|ts)$/.test(full) ? [full] : [];
  const out = [];
  for (const child of readdirSync(full)) {
    if (child === "node_modules" || child === ".git") continue;
    out.push(...walkFiles(join(entry, child)));
  }
  return out;
}

const allowedCryptoImports = new Map([
  ["scripts/bootstrap_dev_receipt_keys.mjs", "key authoring"],
  ["scripts/refresh-demo-receipts.mjs", "demo key/HMAC receipt authoring"],
  ["shared/authority-manifest.mjs", "A.2b shared crypto layer"],
  ["shared/hash.ts", "A.2b shared crypto layer"],
  ["shared/policy-trust.ts", "A.2b shared crypto layer"],
  ["shared/receipt-signing.ts", "A.2b shared crypto layer"],
  ["shared/receipt-replay.mjs", "A.2b shared crypto layer"],
  ["sidecar/auth_authority.mjs", "deferred raw Ed25519 authority verifier"],
  ["sidecar/refusal_receipt.mjs", "deferred legacy HMAC refusal receipts"],
  ["src/crypto/node-provider.mjs", "crypto provider implementation"],
  ["src/custody/lifecycle.mjs", "Node-only lifecycle root-key validation"],
  ["src/identity/adapters/github-actions.mjs", "deferred RS256 OIDC adapter support"],
  ["src/policy-engine/authenticated-approvals.mjs", "deferred raw Ed25519 approval helper"],
  ["src/policy-engine/authority-grants.mjs", "deferred raw Ed25519 grant helper"],
  ["src/policy-engine/trust.mjs", "deferred raw Ed25519 policy helper"]
]);

const productionFiles = [
  ...walkFiles("bin"),
  ...walkFiles("executor"),
  ...walkFiles("mcp"),
  ...walkFiles("scripts"),
  ...walkFiles("sidecar"),
  ...walkFiles("src"),
  ...walkFiles("tools"),
  ...walkFiles("shared"),
  ...walkFiles("mnde-local-sidecar.mjs")
];

const directCryptoImport = /\b(?:from\s+["'](?:node:)?crypto["']|import\s*\(["'](?:node:)?crypto["']\)|require\s*\(\s*["'](?:node:)?crypto["']\s*\))/;
const cryptoImportViolations = productionFiles
  .filter((file) => directCryptoImport.test(readFileSync(file, "utf8")))
  .map((file) => file.slice(repoRoot.length + 1).replace(/\\/g, "/"))
  .filter((file) => !allowedCryptoImports.has(file));

assert.deepEqual(cryptoImportViolations, [], "direct crypto imports must stay inside src/crypto or documented deferred/key-authoring files");

const asyncCustodyExports = new Set([
  "buildAuthorityBundle",
  "verifyAuthorityBundle",
  "verifyAgainstBundle",
  "signCanonical",
  "verifyCanonical",
  "createCustody",
  "createLocalDemoCustody",
  "rotateSigningKey",
  "revokeKey",
  "buildSignedExecutionReceipt",
  "verifySignedExecutionReceipt",
  "verifyExecutionResult",
  "buildSignedExecutionResult",
  "verifySignedExecutionResult",
  "loadSigningConfig",
  "signReceiptForDelivery",
  "verifyCustodyAttestation",
  "verifyAnyReceiptFile",
  "verifyAnyReceiptObject",
  "verifyPolicyReceipt",
  "verifyHistoricalPolicyBundleProvenance",
  "signPolicyBundle",
  "signRollbackAuthorization",
  "activateSignedPolicyBundle",
  "loadSignedPolicyBundleConfig"
]);

const callPattern = new RegExp(`\\b(${[...asyncCustodyExports].join("|")})\\s*\\(`);
const missedAwaitViolations = [];
for (const file of productionFiles) {
  const rel = file.slice(repoRoot.length + 1).replace(/\\/g, "/");
  const lines = readFileSync(file, "utf8").split(/\r?\n/);
  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!callPattern.test(line)) return;
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) return;
    if (/^(export\s+)?async\s+function\s+/.test(trimmed)) return;
    if (/^(export\s+)?function\s+/.test(trimmed)) return;
    if (trimmed.includes("await ") || trimmed.startsWith("return ") || trimmed.includes("=>")) return;
    if (/^\w+:\s/.test(trimmed)) return;
    missedAwaitViolations.push(`${rel}:${index + 1}: ${trimmed}`);
  });
}

assert.deepEqual(missedAwaitViolations, [], "async custody/provider callers must await or return the Promise explicitly");

console.log("PASS CI contract");
