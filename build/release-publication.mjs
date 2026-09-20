#!/usr/bin/env node
// Release publication tooling: the steps of
// docs/release-publication-runbook.md that must not be done by eye.
//
//   gate              Re-prove an already-built release directory. Run once
//                     before the approval gate and again after it, so the
//                     approver's click covers the exact bytes that get
//                     published and nothing can be substituted in between.
//   notes             Render the release body from release-manifest.json, so
//                     published metadata restates the manifest instead of a
//                     human's recollection of it.
//   verify-published  Re-download every published asset through its public URL
//                     and re-derive its digest from the wire. The published
//                     copy is trusted only once it matches the local one byte
//                     for byte.
//   verify-approval-gate
//                     Prove the approval gate is real before the release run
//                     spends an hour building something it would then publish
//                     unattended. `environment: release` in the workflow buys
//                     nothing on its own: without a required-reviewer rule on
//                     that environment, the gated job simply runs.
//
// Like build/release.mjs this is release tooling: never shipped inside the
// tarball, never on the packaged runtime path. It has no dependencies, it never
// creates or deletes a release, and `gate` / `verify-published` are read-only.

import { createHash } from "node:crypto";
import { appendFileSync, existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const META_FILES = ["SHA256SUMS.txt", "release-manifest.json"];
const MANIFEST_SCHEMA = "mnde.release-manifest.v1";

function fail(message) {
  process.stderr.write(`release-publication: ${message}\n`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) fail(`unexpected argument: ${token}`);
    const equals = token.indexOf("=");
    if (equals > 0) {
      args.set(token.slice(2, equals), token.slice(equals + 1));
      continue;
    }
    const next = argv[index + 1];
    if (next === undefined || next.startsWith("--")) {
      args.set(token.slice(2), "true");
      continue;
    }
    args.set(token.slice(2), next);
    index += 1;
  }
  return args;
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function sha256Bytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// Read the built release directory without judging it yet. Anything structurally
// unreadable is a hard error here; everything else is reported as a named check
// so a failure says which guarantee broke, not just "release is bad".
function loadRelease(dirArg) {
  const releaseDir = resolve(dirArg ?? join(repoRoot, "release"));
  if (!existsSync(releaseDir) || !statSync(releaseDir).isDirectory()) {
    fail(`release directory not found: ${releaseDir}`);
  }
  const entries = readdirSync(releaseDir).filter((name) => statSync(join(releaseDir, name)).isFile()).sort();
  for (const required of META_FILES) {
    if (!entries.includes(required)) fail(`${releaseDir} is missing ${required}`);
  }
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(join(releaseDir, "release-manifest.json"), "utf8"));
  } catch (error) {
    fail(`release-manifest.json is not readable JSON: ${error?.message ?? error}`);
  }
  const sumsText = readFileSync(join(releaseDir, "SHA256SUMS.txt"), "utf8");
  const sums = [];
  for (const line of sumsText.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    const match = /^([0-9a-f]{64}) {2}(.+)$/.exec(line);
    if (!match) fail(`SHA256SUMS.txt has an unparseable line: ${line}`);
    sums.push({ sha256: match[1], name: match[2] });
  }
  const artifactNames = entries.filter((name) => !META_FILES.includes(name));
  return { releaseDir, entries, artifactNames, manifest, sums, sumsText };
}

function readPackageJson() {
  return JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
}

function expectedTarballName(manifest) {
  return `${manifest.package}-${manifest.version}.tgz`;
}

// ---------------------------------------------------------------------------
// gate
// ---------------------------------------------------------------------------

function commandGate(args) {
  const release = loadRelease(args.get("release-dir"));
  const { releaseDir, artifactNames, manifest, sums } = release;
  const pkg = readPackageJson();

  const failures = [];
  const check = (label, ok, detail) => {
    if (ok) {
      process.stdout.write(`  [OK]   ${label}\n`);
      return true;
    }
    const line = detail ? `${label}: ${detail}` : label;
    failures.push(line);
    process.stdout.write(`  [FAIL] ${line}\n`);
    return false;
  };

  process.stdout.write(`release gate: ${releaseDir}\n`);

  check("manifest schema is " + MANIFEST_SCHEMA, manifest.schema === MANIFEST_SCHEMA, `saw ${manifest.schema}`);
  check("manifest package matches package.json", manifest.package === pkg.name, `manifest ${manifest.package} vs package.json ${pkg.name}`);
  check("manifest version matches package.json", manifest.version === pkg.version, `manifest ${manifest.version} vs package.json ${pkg.version}`);

  // The dispatcher types the version they believe they are releasing. It is a
  // human cross-check against releasing the wrong commit's version, not a
  // second source of truth: package.json stays authoritative.
  const expectVersion = args.get("expect-version");
  if (expectVersion) {
    check("requested version matches package.json", expectVersion === pkg.version, `requested ${expectVersion} vs package.json ${pkg.version}`);
  }

  const tarball = expectedTarballName(manifest);
  check("release directory holds exactly the tarball plus metadata", artifactNames.length === 1 && artifactNames[0] === tarball,
    `saw [${artifactNames.join(", ")}], expected [${tarball}]`);

  // A dirty build cannot be reproduced from the commit it names, so its manifest
  // is a false statement about provenance no matter how good the digest is.
  check("build was not made from a dirty working tree", manifest.dirty === false, `manifest dirty=${JSON.stringify(manifest.dirty)}`);

  const commit = typeof manifest.commit === "string" ? manifest.commit.toLowerCase() : "";
  check("manifest names a full source commit", /^[0-9a-f]{40}$/.test(commit), `saw ${JSON.stringify(manifest.commit)}`);
  const expectCommit = args.get("expect-commit");
  if (expectCommit) {
    check("manifest commit is the commit being released", commit === expectCommit.toLowerCase(), `manifest ${commit} vs expected ${expectCommit.toLowerCase()}`);
  }

  // Every byte on disk is re-hashed here. The manifest is treated as a claim to
  // be checked, never as the answer.
  const onDisk = new Map();
  for (const name of artifactNames) {
    const full = join(releaseDir, name);
    onDisk.set(name, { name, bytes: statSync(full).size, sha256: sha256File(full) });
  }
  const declared = Array.isArray(manifest.artifacts) ? manifest.artifacts : [];
  check("manifest declares every artifact present", declared.length === onDisk.size,
    `manifest declares ${declared.length}, directory holds ${onDisk.size}`);
  for (const artifact of declared) {
    const actual = onDisk.get(artifact.name);
    if (!actual) {
      check(`manifest artifact ${artifact.name} exists on disk`, false, "missing");
      continue;
    }
    check(`${artifact.name} size matches the manifest`, actual.bytes === artifact.bytes, `disk ${actual.bytes} vs manifest ${artifact.bytes}`);
    check(`${artifact.name} digest matches the manifest`, actual.sha256 === artifact.sha256, `disk ${actual.sha256} vs manifest ${artifact.sha256}`);
  }

  // SHA256SUMS.txt is what a downloader actually runs `sha256sum -c` against, so
  // it has to agree with both the bytes and the manifest, not just one of them.
  const sumsByName = new Map(sums.map((entry) => [entry.name, entry.sha256]));
  check("SHA256SUMS.txt lists exactly the artifacts on disk",
    sums.length === onDisk.size && [...onDisk.keys()].every((name) => sumsByName.has(name)),
    `SHA256SUMS.txt lists [${[...sumsByName.keys()].join(", ")}], directory holds [${[...onDisk.keys()].join(", ")}]`);
  for (const [name, actual] of onDisk) {
    if (!sumsByName.has(name)) continue;
    check(`${name} digest matches SHA256SUMS.txt`, sumsByName.get(name) === actual.sha256,
      `SHA256SUMS.txt ${sumsByName.get(name)} vs disk ${actual.sha256}`);
  }

  // The whole point of running this twice. Before the approval gate the digests
  // are recorded; after it they are supplied back as --expect-* and must still
  // hold. If an artifact were swapped while the run waited for a human, these
  // are the checks that catch it.
  const tarballDigest = onDisk.get(tarball)?.sha256 ?? null;
  const sumsDigest = sha256File(join(releaseDir, "SHA256SUMS.txt"));
  const manifestDigest = sha256File(join(releaseDir, "release-manifest.json"));
  const crossings = [
    ["tarball", args.get("expect-tarball-sha256"), tarballDigest],
    ["SHA256SUMS.txt", args.get("expect-sums-sha256"), sumsDigest],
    ["release-manifest.json", args.get("expect-manifest-sha256"), manifestDigest]
  ];
  for (const [label, expected, actual] of crossings) {
    if (!expected) continue;
    check(`${label} is byte-identical to the approved build`, expected.toLowerCase() === actual, `approved ${expected.toLowerCase()} vs now ${actual}`);
  }

  process.stdout.write("\n");
  process.stdout.write(`  version         ${manifest.version}\n`);
  process.stdout.write(`  commit          ${commit}\n`);
  process.stdout.write(`  tarball         ${tarball}\n`);
  process.stdout.write(`  tarball sha256  ${tarballDigest}\n`);
  process.stdout.write(`  sums sha256     ${sumsDigest}\n`);
  process.stdout.write(`  manifest sha256 ${manifestDigest}\n`);

  if (failures.length > 0) {
    process.stderr.write(`\nFAIL release gate (${failures.length} check(s) failed)\n`);
    process.exit(1);
  }

  // Hand the verified digests to the workflow so the post-approval run can
  // demand them back. Written only on success: a failed gate publishes nothing,
  // including its own outputs.
  const outputFile = process.env.GITHUB_OUTPUT;
  if (outputFile) {
    appendFileSync(outputFile, [
      `version=${manifest.version}`,
      `commit=${commit}`,
      `commit_short=${manifest.commit_short ?? commit.slice(0, 7)}`,
      `tag=v${manifest.version}`,
      `tarball=${tarball}`,
      `tarball_sha256=${tarballDigest}`,
      `sums_sha256=${sumsDigest}`,
      `manifest_sha256=${manifestDigest}`,
      ""
    ].join("\n"), "utf8");
  }

  process.stdout.write(`\nPASS release gate (${manifest.version} @ ${commit.slice(0, 7)})\n`);
}

// ---------------------------------------------------------------------------
// notes
// ---------------------------------------------------------------------------

function commandNotes(args) {
  const { releaseDir, manifest } = loadRelease(args.get("release-dir"));
  const tag = args.get("tag") ?? `v${manifest.version}`;
  const tarball = expectedTarballName(manifest);
  const runtime = manifest.runtime ?? {};
  const engines = manifest.engines?.node ?? readPackageJson().engines?.node ?? "unknown";

  const lines = [
    `# MNDe ${manifest.version}`,
    "",
    "Evaluation release of the MNDe pre-execution authorization layer.",
    "",
    "## Release identity",
    "",
    `- Tag: \`${tag}\``,
    `- Version: \`${manifest.version}\` (from \`package.json\`, the one authoritative source)`,
    `- Source commit: \`${manifest.commit}\``,
    `- Build id: \`${manifest.build_id ?? "unknown"}\``,
    `- Build time: \`${manifest.build_time ?? "unknown"}\``,
    `- Built with: Node.js \`${runtime.node ?? "unknown"}\`, npm \`${runtime.npm ?? "unknown"}\`, \`${runtime.os ?? "unknown"}\``,
    `- Runtime requirement: Node.js \`${engines}\``,
    "",
    "## Artifacts",
    "",
    "| file | bytes | sha256 |",
    "| --- | --- | --- |",
    ...(manifest.artifacts ?? []).map((artifact) => `| \`${artifact.name}\` | ${artifact.bytes} | \`${artifact.sha256}\` |`),
    `| \`SHA256SUMS.txt\` | ${statSync(join(releaseDir, "SHA256SUMS.txt")).size} | \`${sha256File(join(releaseDir, "SHA256SUMS.txt"))}\` |`,
    `| \`release-manifest.json\` | ${statSync(join(releaseDir, "release-manifest.json")).size} | \`${sha256File(join(releaseDir, "release-manifest.json"))}\` |`,
    "",
    "Verify a downloaded artifact before installing it:",
    "",
    "```bash",
    "sha256sum -c SHA256SUMS.txt",
    "```",
    "",
    "```powershell",
    `(Get-FileHash ${tarball} -Algorithm SHA256).Hash.ToLower()`,
    "```",
    "",
    `\`release-manifest.json\` binds the digest above to source commit \`${manifest.commit_short ?? manifest.commit}\`.`,
    "",
    "## Install and smoke test",
    "",
    "```bash",
    "npm init -y",
    `npm install ./${tarball}`,
    "npx mnde-sidecar version",
    "npx mnde-sidecar init",
    "npx mnde-sidecar doctor",
    "npx mnde-sidecar smoke",
    "```",
    "",
    "## Build provenance",
    "",
    "Build provenance for the tarball is attested by GitHub from the workflow run",
    "that produced it. Verify it against this repository:",
    "",
    "```bash",
    `gh attestation verify ${tarball} --repo ${process.env.GITHUB_REPOSITORY ?? "mndesystems-ship-it/mnde-public-test"}`,
    "```",
    "",
    "## What this release does not include",
    "",
    "- No desktop installer exists. No MSI, NSIS, EXE, DMG, PKG, or AppImage is available.",
    "- The tarball carries no detached signature; provenance attestation is the only signed statement about it.",
    "- The package is not published to the public npm registry; install from this tarball.",
    "- Windows 11 x64 is the only CI-verified platform.",
    "- Reproducible-build proof is not claimed.",
    ""
  ];

  const body = lines.join("\n");
  const outPath = args.get("out");
  if (outPath) {
    writeFileSync(resolve(outPath), body, "utf8");
    process.stdout.write(`release notes written: ${resolve(outPath)}\n`);
  } else {
    process.stdout.write(body);
  }
}

// ---------------------------------------------------------------------------
// verify-published
// ---------------------------------------------------------------------------

function apiBase() {
  return (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/+$/, "");
}

function authHeaders(token, accept) {
  const headers = { accept, "user-agent": "mnde-release-publication", "x-github-api-version": "2022-11-28" };
  if (token) headers.authorization = `Bearer ${token}`;
  return headers;
}

async function apiJson(url, token) {
  const response = await fetch(url, { headers: authHeaders(token, "application/vnd.github+json") });
  if (!response.ok) fail(`GET ${url} returned ${response.status} ${response.statusText}`);
  return response.json();
}

// Download an asset the way a customer would and hash what actually arrives.
// The redirect is followed by hand: GitHub redirects release assets to a storage
// host that rejects a forwarded Authorization header, so credentials are dropped
// at the hop.
async function downloadAsset(url, token) {
  let current = url;
  let carryToken = true;
  for (let hop = 0; hop < 6; hop += 1) {
    const response = await fetch(current, {
      redirect: "manual",
      headers: authHeaders(carryToken ? token : null, "application/octet-stream")
    });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) fail(`redirect from ${current} carried no Location header`);
      current = new URL(location, current).toString();
      carryToken = false;
      continue;
    }
    if (!response.ok) fail(`GET ${current} returned ${response.status} ${response.statusText}`);
    return Buffer.from(await response.arrayBuffer());
  }
  fail(`too many redirects downloading ${url}`);
  return Buffer.alloc(0);
}

async function commandVerifyPublished(args) {
  const { releaseDir, entries, manifest } = loadRelease(args.get("release-dir"));
  const repo = args.get("repo") ?? process.env.GITHUB_REPOSITORY;
  if (!repo || !/^[^/]+\/[^/]+$/.test(repo)) fail("--repo owner/name is required");
  const tag = args.get("tag") ?? `v${manifest.version}`;
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || null;

  const failures = [];
  const check = (label, ok, detail) => {
    if (ok) {
      process.stdout.write(`  [OK]   ${label}\n`);
      return true;
    }
    const line = detail ? `${label}: ${detail}` : label;
    failures.push(line);
    process.stdout.write(`  [FAIL] ${line}\n`);
    return false;
  };

  process.stdout.write(`verify published: ${repo} ${tag}\n`);

  const release = await apiJson(`${apiBase()}/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`, token);
  check("release resolves by tag", release.tag_name === tag, `API returned tag_name ${release.tag_name}`);
  check("release is published, not a draft", release.draft === false, `draft=${release.draft}`);

  // The tag has to name the commit the manifest claims, or the digests are
  // correct about bytes and wrong about provenance.
  const tagged = await apiJson(`${apiBase()}/repos/${repo}/commits/${encodeURIComponent(tag)}`, token);
  check("tag points at the manifest source commit",
    typeof tagged.sha === "string" && tagged.sha.toLowerCase() === String(manifest.commit).toLowerCase(),
    `tag resolves to ${tagged.sha} vs manifest ${manifest.commit}`);

  const assets = Array.isArray(release.assets) ? release.assets : [];
  const assetNames = assets.map((asset) => asset.name).sort();
  check("published asset set matches the local release directory",
    JSON.stringify(assetNames) === JSON.stringify([...entries].sort()),
    `published [${assetNames.join(", ")}], local [${[...entries].sort().join(", ")}]`);

  for (const name of entries) {
    const asset = assets.find((candidate) => candidate.name === name);
    if (!asset) {
      check(`${name} is published`, false, "no asset with that name");
      continue;
    }
    const localDigest = sha256File(join(releaseDir, name));
    const downloaded = await downloadAsset(asset.url, token);
    const publishedDigest = sha256Bytes(downloaded);
    check(`${name} downloads and matches the built artifact`, publishedDigest === localDigest,
      `published ${publishedDigest} vs built ${localDigest}`);
    check(`${name} reported size matches the download`, asset.size === downloaded.length,
      `API says ${asset.size}, downloaded ${downloaded.length}`);
  }

  if (release.html_url) {
    const page = await fetch(release.html_url, { headers: authHeaders(token, "text/html") });
    check("release page resolves", page.ok, `${release.html_url} returned ${page.status}`);
  }

  if (failures.length > 0) {
    process.stderr.write(`\nFAIL published release verification (${failures.length} check(s) failed)\n`);
    process.exit(1);
  }
  process.stdout.write(`\nPASS published release verification (${repo} ${tag})\n`);
}

// ---------------------------------------------------------------------------
// verify-approval-gate
// ---------------------------------------------------------------------------

// A workflow that names an environment looks gated in the YAML whether or not
// anyone has to approve it. Checked here, in the read-only build job, so a
// misconfigured environment stops the release before anything is built rather
// than after everything is published.
async function commandVerifyApprovalGate(args) {
  const repo = args.get("repo") ?? process.env.GITHUB_REPOSITORY;
  if (!repo || !/^[^/]+\/[^/]+$/.test(repo)) fail("--repo owner/name is required");
  const environment = args.get("environment") ?? "release";
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || null;
  const remedy = `Configure it under Settings -> Environments -> ${environment} -> Required reviewers. See docs/release-automation.md.`;

  const url = `${apiBase()}/repos/${repo}/environments/${encodeURIComponent(environment)}`;
  const response = await fetch(url, { headers: authHeaders(token, "application/vnd.github+json") });
  if (response.status === 404) {
    fail(`the '${environment}' environment does not exist on ${repo}, so the publish job would run unapproved. ${remedy}`);
  }
  if (!response.ok) {
    fail(
      `cannot read the '${environment}' environment on ${repo} (HTTP ${response.status} ${response.statusText}). ` +
      "Refusing to build a release whose approval gate cannot be confirmed. " + remedy
    );
  }
  const environmentConfig = await response.json();
  const rules = Array.isArray(environmentConfig.protection_rules) ? environmentConfig.protection_rules : [];
  const reviewerRule = rules.find((rule) => rule.type === "required_reviewers");
  if (!reviewerRule) {
    fail(`the '${environment}' environment has no required-reviewer rule, so the publish job would run unapproved. ${remedy}`);
  }
  const reviewers = Array.isArray(reviewerRule.reviewers) ? reviewerRule.reviewers : [];
  if (reviewers.length === 0) {
    fail(`the '${environment}' environment requires review by nobody, so the publish job would run unapproved. ${remedy}`);
  }

  const names = reviewers
    .map((reviewer) => reviewer?.reviewer?.login ?? reviewer?.reviewer?.slug ?? reviewer?.reviewer?.name ?? "unnamed")
    .sort();
  process.stdout.write(`  [OK]   '${environment}' requires approval from: ${names.join(", ")}\n`);
  if (reviewerRule.prevent_self_review === false) {
    // Not fatal: a single-maintainer repository has no one else to approve. It
    // is stated so nobody mistakes this gate for four-eyes review.
    process.stdout.write("  [NOTE] self-review is permitted: the dispatcher may approve their own release run\n");
  }
  const branchPolicy = environmentConfig.deployment_branch_policy;
  process.stdout.write(`  [INFO] deployment branch policy: ${branchPolicy ? JSON.stringify(branchPolicy) : "any branch"}\n`);
  process.stdout.write(`\nPASS approval gate present (${repo} / ${environment})\n`);
}

// ---------------------------------------------------------------------------

const [command, ...rest] = process.argv.slice(2);
const args = parseArgs(rest);

switch (command) {
  case "gate":
    commandGate(args);
    break;
  case "notes":
    commandNotes(args);
    break;
  case "verify-published":
    await commandVerifyPublished(args);
    break;
  case "verify-approval-gate":
    await commandVerifyApprovalGate(args);
    break;
  default:
    process.stderr.write("usage: release-publication.mjs <gate|notes|verify-published|verify-approval-gate> [--flag value ...]\n");
    process.exit(2);
}
