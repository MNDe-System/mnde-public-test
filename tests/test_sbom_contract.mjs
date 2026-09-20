#!/usr/bin/env node
// SBOM contract: SBOM.md is a statement about the tree, and the tree enforces it.
//
// The document this replaced was hand-maintained and had drifted in three ways
// at once - a stale version, stale hashes for five of the seven files it
// covered, and an assertion that the root lockfile carried no third-party
// packages after `typescript` was added to it. Nothing caught any of it, which
// is the actual defect: an unenforced SBOM is a claim, not evidence.
//
// So this suite proves two things, and the second is the one that matters:
//
//   1. The committed SBOM.md matches what the tree produces right now.
//   2. The comparison has teeth - each class of drift that went unnoticed
//      before is re-created against a mutated inventory and must be rejected.
//
// A check that only ever runs against a clean tree proves nothing about what it
// would do against a dirty one.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ASSET_DIR,
  SBOM_PATH,
  buildSbom,
  collectInventory,
  diffLines,
  listTrackedFiles,
  renderSbom
} from "../build/sbom.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(repoRoot, path), "utf8");

let failures = 0;
function test(name, fn) {
  try {
    fn();
    console.log(`[PASS] ${name}`);
  } catch (error) {
    failures += 1;
    console.error(`[FAIL] ${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

const tracked = listTrackedFiles(repoRoot);
const inventory = collectInventory(repoRoot);
const generated = buildSbom(repoRoot);

// --- 1. The committed document is the generated document ------------------

test("committed SBOM.md matches the working tree", () => {
  const committed = read(SBOM_PATH);
  const difference = diffLines(generated, committed);
  assert.equal(
    difference,
    null,
    difference
      ? `${SBOM_PATH}:${difference.line} committed ${JSON.stringify(difference.actual)} ` +
        `but the tree produces ${JSON.stringify(difference.expected)}. Run \`npm run sbom\`.`
      : ""
  );
});

// The generator writes a file that must survive the repository's own whitespace
// contract, or `npm run sbom` would hand the next contributor a failing build.
test("generated SBOM.md satisfies the whitespace contract", () => {
  assert.ok(generated.endsWith("\n"), "generated SBOM.md must end with a newline");
  const offenders = generated.split("\n")
    .map((line, index) => ({ line, number: index + 1 }))
    .filter(({ line }) => /[ \t]+$/.test(line));
  assert.deepEqual(offenders, [], "generated SBOM.md must have no trailing whitespace");
});

// A generation timestamp is not a fact about the tree: it would make the
// document differ from itself on every run and turn this suite into noise.
test("generated SBOM.md embeds no timestamp", () => {
  assert.doesNotMatch(generated, /\b20\d{2}-\d{2}-\d{2}\b/, "SBOM.md must not embed a generation date");
});

// --- 2. The inventory is derived, not enumerated ---------------------------

test("every tracked package.json appears in the inventory", () => {
  const expected = tracked.filter((path) => path === "package.json" || path.endsWith("/package.json")).sort();
  assert.deepEqual(inventory.packages.map((entry) => entry.path).sort(), expected);
  assert.ok(expected.length > 0, "the repository must have at least one tracked package.json");
});

test("package versions come from the manifests themselves", () => {
  for (const entry of inventory.packages) {
    const manifest = JSON.parse(read(entry.path));
    assert.equal(entry.version, manifest.version, `${entry.path} version must be read from the manifest`);
    assert.equal(entry.name, manifest.name, `${entry.path} name must be read from the manifest`);
  }
});

test(`every tracked file under ${ASSET_DIR}/ appears in the inventory`, () => {
  const expected = tracked.filter((path) => path.startsWith(`${ASSET_DIR}/`)).sort();
  assert.deepEqual(inventory.assets.map((asset) => asset.path).sort(), expected);
  assert.ok(expected.length > 0, `the repository must track at least one file under ${ASSET_DIR}/`);
});

test("every non-root lockfile entry appears in the inventory", () => {
  const lock = JSON.parse(read("package-lock.json"));
  const expected = Object.keys(lock.packages ?? {}).filter((key) => key !== "").sort();
  assert.deepEqual(inventory.dependencies.map((dependency) => dependency.path).sort(), expected);
  assert.equal(inventory.lockfile.lockfileVersion, lock.lockfileVersion);
});

// The specific claim that went stale: the old document said the root lockfile
// held no third-party packages. Whatever the lockfile holds, the document says
// so - including the count, so "none" can never be silently wrong again.
test("the document reports the real third-party dependency set", () => {
  for (const dependency of inventory.dependencies) {
    assert.match(
      generated,
      new RegExp(`\\|\\s*\`${dependency.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\`\\s*\\|`),
      `SBOM.md must list the dependency ${dependency.name}`
    );
  }
  if (inventory.dependencies.length === 0) {
    assert.match(generated, /resolves no third-party packages/);
  } else {
    assert.doesNotMatch(generated, /resolves no third-party packages/);
    const runtime = inventory.dependencies.filter((dependency) => dependency.scope === "runtime").length;
    const dev = inventory.dependencies.filter((dependency) => dependency.scope === "dev").length;
    assert.match(generated, new RegExp(`Runtime third-party packages: ${runtime}\\. Build-time only: ${dev}\\.`));
  }
});

// --- 3. Mutation: prove the check rejects each drift that went unnoticed ----

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function rejects(label, mutate) {
  const mutated = clone(inventory);
  mutate(mutated);
  const difference = diffLines(renderSbom(mutated), generated);
  assert.notEqual(difference, null, `${label} must be rejected by the SBOM check`);
  return difference;
}

test("a stale package version is rejected", () => {
  const difference = rejects("a package version that no longer matches its manifest", (mutated) => {
    mutated.packages[0].version = "0.0.0-stale";
  });
  assert.match(difference.expected, /0\.0\.0-stale/);
});

test("a stale manifest hash is rejected", () => {
  rejects("a manifest hash that no longer matches its file", (mutated) => {
    mutated.packages[0].sha256 = "0".repeat(64);
  });
});

test("a stale lockfile hash is rejected", () => {
  rejects("a lockfile hash that no longer matches its file", (mutated) => {
    mutated.lockfile.sha256 = "0".repeat(64);
  });
});

test("a stale asset hash is rejected", () => {
  rejects("an asset hash that no longer matches its file", (mutated) => {
    mutated.assets[0].sha256 = "0".repeat(64);
  });
});

test("a newly committed asset that the document omits is rejected", () => {
  rejects("an asset present in the tree but missing from the document", (mutated) => {
    mutated.assets.push({ path: `${ASSET_DIR}/new-asset.svg`, sha256: "1".repeat(64) });
  });
});

test("an asset removed from the tree but left in the document is rejected", () => {
  rejects("an asset listed in the document but no longer tracked", (mutated) => {
    mutated.assets.pop();
  });
});

test("a newly added dependency that the document omits is rejected", () => {
  rejects("a lockfile entry missing from the document", (mutated) => {
    mutated.dependencies.push({
      path: "node_modules/left-pad",
      name: "left-pad",
      version: "1.3.0",
      license: "WTFPL",
      scope: "runtime",
      integrity: "sha512-not-a-real-integrity"
    });
  });
});

// The exact shape of the original defect: the document asserted an empty
// dependency set while the lockfile had an entry.
test("claiming an empty dependency set while the lockfile has entries is rejected", () => {
  const difference = rejects("an emptied dependency table", (mutated) => {
    mutated.dependencies = [];
  });
  assert.ok(difference, "emptying the dependency table must produce a difference");
  assert.match(renderSbom({ ...clone(inventory), dependencies: [] }), /resolves no third-party packages/);
});

test("a dependency whose scope flipped is rejected", () => {
  const withDependencies = inventory.dependencies.length > 0;
  if (!withDependencies) {
    // Nothing to flip: the guard above already covers the empty case.
    return;
  }
  rejects("a dependency recorded under the wrong scope", (mutated) => {
    mutated.dependencies[0].scope = mutated.dependencies[0].scope === "dev" ? "runtime" : "dev";
  });
});

test("diffLines reports the first disagreeing line, not merely that files differ", () => {
  const difference = diffLines("a\nb\nc\n", "a\nX\nc\n");
  assert.deepEqual(difference, { line: 2, expected: "b", actual: "X" });
  assert.equal(diffLines("a\nb\n", "a\nb\n"), null);
  assert.deepEqual(diffLines("a\nb\n", "a\n"), { line: 2, expected: "b", actual: "" });
  assert.deepEqual(diffLines("a\nb\n", "a"), { line: 2, expected: "b", actual: "(end of file)" });
});

// --- 4. LICENSES.md carries the same derived facts -------------------------
//
// LICENSES.md is not generated: its attribution and NOTICE columns are
// judgments, not facts about the tree. But it restates versions, hashes and the
// dependency set, and it had drifted on all three in exactly the same way. This
// does not take the document over; it refuses to let its derived facts rot.

const licenses = read("LICENSES.md");
const currentHashes = new Set([
  ...inventory.packages.map((entry) => entry.sha256),
  inventory.lockfile.sha256,
  ...inventory.assets.map((asset) => asset.sha256)
]);

test("LICENSES.md quotes no hash that is not a current tracked-file hash", () => {
  const quoted = [...licenses.matchAll(/sha256:([0-9a-f]{64})/g)].map((match) => match[1]);
  const stale = quoted.filter((hash) => !currentHashes.has(hash));
  assert.deepEqual(stale, [], `LICENSES.md carries hashes that match no tracked file: ${stale.join(", ")}`);
});

test("LICENSES.md records the current version for every package it names", () => {
  for (const entry of inventory.packages) {
    const escapedName = entry.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const rowPattern = new RegExp(`\\|\\s*\`${escapedName}\`\\s*\\|\\s*\`([^\`]+)\`\\s*\\|`);
    const match = rowPattern.exec(licenses);
    if (!match) continue; // LICENSES.md need not name every package; if it does, it must be current.
    assert.equal(match[1], entry.version, `LICENSES.md records ${entry.name} at ${match[1]}, tree is ${entry.version}`);
  }
});

test("LICENSES.md names every third-party package the lockfile resolves", () => {
  for (const dependency of inventory.dependencies) {
    assert.match(
      licenses,
      new RegExp(`\`${dependency.name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\``),
      `LICENSES.md must name the third-party package ${dependency.name}`
    );
  }
  if (inventory.dependencies.length > 0) {
    assert.doesNotMatch(
      licenses,
      /lists no third-party npm packages/,
      "LICENSES.md must not claim an empty dependency set while the lockfile has entries"
    );
  }
});

test("LICENSES.md lists every tracked asset", () => {
  for (const asset of inventory.assets.filter((entry) => entry.path.endsWith(".svg"))) {
    assert.match(licenses, new RegExp(`\`${asset.path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\``),
      `LICENSES.md must list the asset ${asset.path}`);
  }
});

if (failures > 0) {
  console.error(`\nFAIL SBOM contract (${failures} failing)`);
  process.exit(1);
}
console.log("\nPASS SBOM contract");
