#!/usr/bin/env node
// SBOM tooling: SBOM.md is derived from the tree, never typed.
//
//   generate  Rewrite SBOM.md from the working tree.
//   check     Re-derive the document and compare it to the committed SBOM.md.
//             Exits non-zero on any difference, naming the first line that
//             disagrees. This is what makes the file a contract instead of a
//             claim: a hash that no longer matches its file, a version bump, a
//             new brand asset or a new lockfile entry all fail the build.
//
// Why generated at all: the hand-maintained SBOM.md drifted. It recorded
// version 0.1.0 against a 0.1.1 tree, carried stale hashes for five of the
// seven files it covered, and asserted that the root lockfile had no
// third-party packages after `typescript` was added to it. Every one of those
// is a fact about the tree, so the tree should state them.
//
// Two rules keep the document stable enough to be a contract:
//
//   No timestamp. A generation date is not a fact about the tree; embedding one
//   makes every regeneration a diff and turns `check` into noise.
//
//   No hand-curated inclusion lists. The old document enumerated four brand
//   SVGs by name, which is the same maintenance burden one level up: a fifth
//   asset would never have appeared. Membership is derived instead - every
//   tracked package.json, every tracked file under brand/, every non-root entry
//   in the root lockfile.
//
// Enumeration goes through `git ls-files`, the same source of truth
// scripts/check-whitespace.mjs uses, so a file that is not tracked is not in
// the SBOM. Hashes are taken over raw bytes; .gitattributes pins `eol=lf` for
// the whole tree, so the same commit hashes identically on Windows and Linux.
//
// Like build/release.mjs this is repository tooling: never shipped inside the
// tarball, never on the packaged runtime path, no dependencies. `check` is
// read-only.

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const SBOM_PATH = "SBOM.md";
export const ASSET_DIR = "brand";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function fail(message) {
  process.stderr.write(`sbom: ${message}\n`);
  process.exit(1);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// Tracked files, as forward-slash paths, so the inventory reads the same on
// every platform. Untracked files are deliberately invisible here: an SBOM
// describes what the repository ships, not what happens to be on a disk.
export function listTrackedFiles(root) {
  const git = spawnSync("git", ["ls-files", "-z"], { cwd: root, encoding: "buffer" });
  if (git.error) fail(`could not run git: ${git.error.message}`);
  if (git.status !== 0) fail(`git ls-files failed: ${git.stderr.toString("utf8").trim()}`);
  return git.stdout.toString("utf8").split("\0").filter(Boolean).sort();
}

// A package's license as the package itself declares it. When the field is
// absent the document says so rather than inferring one from the LICENSE file:
// an SBOM that silently supplies a missing license is the kind of tidy answer
// that a procurement reviewer cannot check.
function declaredLicense(manifest) {
  if (typeof manifest.license === "string" && manifest.license.trim() !== "") {
    return { license: manifest.license, declared: true };
  }
  return { license: "Not declared in package.json", declared: false };
}

export function collectInventory(root) {
  const tracked = listTrackedFiles(root);
  const read = (path) => readFileSync(join(root, path));

  const packages = tracked
    .filter((path) => path === "package.json" || path.endsWith("/package.json"))
    .map((path) => {
      const bytes = read(path);
      const manifest = JSON.parse(bytes.toString("utf8"));
      const { license, declared } = declaredLicense(manifest);
      return {
        path,
        name: typeof manifest.name === "string" ? manifest.name : "(unnamed)",
        version: typeof manifest.version === "string" ? manifest.version : "(no version)",
        license,
        licenseDeclared: declared,
        sha256: sha256(bytes)
      };
    });

  const lockPath = "package-lock.json";
  if (!tracked.includes(lockPath)) fail(`${lockPath} is not tracked; cannot derive a dependency inventory`);
  const lockBytes = read(lockPath);
  const lock = JSON.parse(lockBytes.toString("utf8"));
  const lockfile = {
    path: lockPath,
    lockfileVersion: lock.lockfileVersion,
    sha256: sha256(lockBytes)
  };

  // Everything the lockfile resolves except the root package itself. `dev: true`
  // means the entry is a build-time dependency: it is installed by `npm ci` in
  // this repository and is not installed for anyone who consumes the package.
  const dependencies = Object.entries(lock.packages ?? {})
    .filter(([key]) => key !== "")
    .map(([key, entry]) => ({
      path: key,
      name: entry.name ?? key.replace(/^(?:.*\/)?node_modules\//, ""),
      version: entry.version ?? "(no version)",
      license: entry.license ?? "Not recorded in lockfile",
      scope: entry.dev === true ? "dev" : "runtime",
      integrity: entry.integrity ?? "Not recorded in lockfile"
    }))
    .sort((a, b) => a.path.localeCompare(b.path));

  const assets = tracked
    .filter((path) => path === ASSET_DIR || path.startsWith(`${ASSET_DIR}/`))
    .map((path) => ({ path, sha256: sha256(read(path)) }));

  return { packages, lockfile, dependencies, assets };
}

function row(cells) {
  return `| ${cells.join(" | ")} |`;
}

export function renderSbom(inventory) {
  const { packages, lockfile, dependencies, assets } = inventory;
  const runtimeDependencies = dependencies.filter((dependency) => dependency.scope === "runtime");
  const devDependencies = dependencies.filter((dependency) => dependency.scope === "dev");
  const undeclared = packages.filter((entry) => !entry.licenseDeclared);

  const lines = [];
  const push = (...text) => lines.push(...text);

  push(
    "# Software Bill of Materials",
    "",
    "Generated from the working tree by `npm run sbom`. Do not edit this file by hand:",
    "`npm run test:sbom` re-derives it and fails the build on any difference.",
    "",
    "No third-party package registry lookup is performed. Versions and licenses are",
    "read from the repository's own manifests and lockfile; hashes are SHA-256 over",
    "the tracked bytes. This is not a signed release SBOM.",
    "",
    "## Packages",
    "",
    "Every `package.json` tracked in this repository.",
    "",
    row(["Package", "Version", "License", "Manifest", "Manifest hash"]),
    row(["---", "---", "---", "---", "---"])
  );
  for (const entry of packages) {
    push(row([
      `\`${entry.name}\``,
      `\`${entry.version}\``,
      entry.licenseDeclared ? `\`${entry.license}\`` : entry.license,
      `\`${entry.path}\``,
      `\`sha256:${entry.sha256}\``
    ]));
  }
  push(
    "",
    row(["Lockfile", "Lockfile version", "Hash"]),
    row(["---", "---", "---"]),
    row([`\`${lockfile.path}\``, `\`${lockfile.lockfileVersion}\``, `\`sha256:${lockfile.sha256}\``]),
    ""
  );

  if (undeclared.length > 0) {
    push(
      "Packages above that declare no `license` field carry no license statement of",
      "their own. The repository [LICENSE](LICENSE) governs the repository, but this",
      "document does not assert it on a manifest's behalf:",
      ""
    );
    for (const entry of undeclared) push(`- \`${entry.path}\` (\`${entry.name}\`)`);
    push("");
  }

  push(
    "## Third-Party Dependencies",
    "",
    "Every non-root entry resolved by the root `package-lock.json`. `dev` scope means",
    "the package is installed by `npm ci` in this repository and is not installed for",
    "anyone who consumes the published package.",
    ""
  );
  if (dependencies.length === 0) {
    push("The root lockfile resolves no third-party packages.", "");
  } else {
    push(
      row(["Package", "Version", "Scope", "License", "Integrity"]),
      row(["---", "---", "---", "---", "---"])
    );
    for (const dependency of dependencies) {
      push(row([
        `\`${dependency.name}\``,
        `\`${dependency.version}\``,
        dependency.scope,
        dependency.license,
        `\`${dependency.integrity}\``
      ]));
    }
    push(
      "",
      `Runtime third-party packages: ${runtimeDependencies.length}. Build-time only: ${devDependencies.length}.`,
      ""
    );
  }

  push(
    "## Assets",
    "",
    `Every file tracked under \`${ASSET_DIR}/\`. Membership is the directory, not a`,
    "curated list, so a new asset appears here the moment it is committed.",
    "",
    row(["Asset", "Supplier", "License", "Hash"]),
    row(["---", "---", "---", "---"])
  );
  for (const asset of assets) {
    push(row([
      `\`${asset.path}\``,
      "MNDe project",
      "Repository license unless separately licensed",
      `\`sha256:${asset.sha256}\``
    ]));
  }

  push(
    "",
    "## Missing Information",
    "",
    "- No signed release artifact hashes are included.",
    "- No build provenance or SLSA attestation is recorded in this document.",
    "- No reproducible build proof is included.",
    "- No dependency vulnerability scan is included."
  );
  if (dependencies.length > 0) {
    push(
      `- Dependency licenses are copied from the lockfile's own \`license\` fields; no`,
      "  registry or license-text verification is performed."
    );
  }
  push(
    "",
    "## Regeneration",
    "",
    "```bash",
    "npm run sbom        # rewrite this file from the tree",
    "npm run test:sbom   # fail if the committed file disagrees with the tree",
    "```",
    ""
  );

  return `${lines.join("\n").replace(/[ \t]+$/gm, "")}`;
}

export function buildSbom(root = repoRoot) {
  return renderSbom(collectInventory(root));
}

// Compare line by line rather than reporting "files differ": the failure that
// matters is usually one hash or one version, and a reviewer should not have to
// diff the file by eye to find it.
export function diffLines(expected, actual) {
  const expectedLines = expected.split("\n");
  const actualLines = actual.split("\n");
  const limit = Math.max(expectedLines.length, actualLines.length);
  for (let index = 0; index < limit; index += 1) {
    if (expectedLines[index] !== actualLines[index]) {
      return {
        line: index + 1,
        expected: expectedLines[index] ?? "(end of file)",
        actual: actualLines[index] ?? "(end of file)"
      };
    }
  }
  return null;
}

function commandGenerate() {
  const document = buildSbom();
  writeFileSync(join(repoRoot, SBOM_PATH), document, "utf8");
  process.stdout.write(`sbom: wrote ${SBOM_PATH}\n`);
}

function commandCheck() {
  const expected = buildSbom();
  let committed;
  try {
    committed = readFileSync(join(repoRoot, SBOM_PATH), "utf8");
  } catch (error) {
    fail(`could not read ${SBOM_PATH}: ${error instanceof Error ? error.message : String(error)}`);
  }
  const difference = diffLines(expected, committed);
  if (difference) {
    process.stderr.write(
      `sbom: ${SBOM_PATH} does not match the working tree.\n` +
      `  ${SBOM_PATH}:${difference.line}\n` +
      `    committed: ${difference.actual}\n` +
      `    from tree: ${difference.expected}\n` +
      "  Run `npm run sbom` and commit the result.\n"
    );
    process.exit(1);
  }
  process.stdout.write(`sbom: ${SBOM_PATH} matches the working tree\n`);
}

const isEntryPoint = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isEntryPoint) {
  switch (process.argv[2]) {
    case "generate":
      commandGenerate();
      break;
    case "check":
      commandCheck();
      break;
    default:
      fail("usage: node build/sbom.mjs <generate|check>");
  }
}
