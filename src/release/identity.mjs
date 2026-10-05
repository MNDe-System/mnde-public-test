// Release identity — the single authoritative product/version/build identity for
// a packaged MNDe artifact.
//
// One authoritative version source: package.json "version". Build/commit
// metadata: build-info.json, written into THIS directory by
// build/build-package.mjs at pack time (when Git is available). A packaged
// install has no .git and must never need it, so this module NEVER shells out to
// Git at runtime — it reads only immutable, embedded metadata. In a source
// checkout build-info.json is absent, and the commit/build fields report
// "source-checkout" truthfully rather than fabricating an identity.
//
// Both CLIs (bin/mnde.mjs, bin/mnde-sidecar.mjs) and the sidecar runtime read
// their identity from here, so there is exactly one identity for a given install.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const PRODUCT_NAME = "MNDe";
export const RELEASE_IDENTITY_SCHEMA = "mnde.release-identity.v1";

const moduleDir = dirname(fileURLToPath(import.meta.url));

// Walk up from this module to the nearest package.json that carries a version.
// Works identically whether this file runs from a source checkout
// (<repo>/src/release/identity.mjs -> <repo>/package.json) or an installed
// package (node_modules/<pkg>/dist/src/release/identity.mjs ->
// node_modules/<pkg>/package.json). npm always includes package.json in a
// tarball regardless of the "files" allowlist, so it is guaranteed present.
function findPackageJson(startDir) {
  let dir = startDir;
  for (let i = 0; i < 8; i += 1) {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
      if (pkg && typeof pkg.version === "string") return pkg;
    } catch {
      /* not here — keep walking up */
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function readBuildInfo() {
  try {
    return JSON.parse(readFileSync(join(moduleDir, "build-info.json"), "utf8"));
  } catch {
    return null;
  }
}

// The authoritative, machine-readable identity of the installed artifact.
export function getReleaseIdentity() {
  const pkg = findPackageJson(moduleDir) ?? {};
  const build = readBuildInfo();
  const packaged = Boolean(build && build.commit);
  const commit = build?.commit ?? null;
  return {
    schema: RELEASE_IDENTITY_SCHEMA,
    product: PRODUCT_NAME,
    package: pkg.name ?? null,
    version: typeof pkg.version === "string" ? pkg.version : null,
    commit,
    commit_short: build?.commit_short ?? (commit ? commit.slice(0, 12) : null),
    build_id: build?.build_id ?? null,
    build_time: build?.build_time ?? null,
    dirty_build: typeof build?.dirty === "boolean" ? build.dirty : null,
    artifact_format: build?.artifact_format ?? (packaged ? "npm-tarball" : "source-checkout"),
    source: packaged ? "packaged" : "source-checkout",
    node: process.versions.node
  };
}

// Human-readable rendering for `mnde version` / `mnde-sidecar version`.
export function formatReleaseIdentity(identity = getReleaseIdentity()) {
  const commitLine = identity.commit
    ? `${identity.commit_short}${identity.dirty_build ? " (dirty build)" : ""}`
    : "(source checkout — no embedded commit)";
  return [
    `${identity.product} ${identity.version ?? "unknown"}  [${identity.package ?? "unknown"}]`,
    `  commit:   ${commitLine}`,
    `  build:    ${identity.build_id ?? "-"}${identity.build_time ? `  ${identity.build_time}` : ""}`,
    `  artifact: ${identity.artifact_format}`,
    `  node:     ${identity.node}`
  ].join("\n");
}
