#!/usr/bin/env node
// Prepack build step: makes the package runnable once installed via `npm install`.
//
// This repo runs .ts files directly via Node's native TypeScript type-stripping,
// which works from a source checkout but is UNSUPPORTED for any file located
// under node_modules (Node throws ERR_UNSUPPORTED_NODE_MODULES_TYPE_STRIPPING).
// That made every previous packaging attempt fail the moment a real `npm install`
// placed this package inside a consumer's node_modules/ — confirmed independently
// twice by packing and installing prior branches into a fresh directory.
//
// Fix: compile every .ts file to plain .js (type-stripped, not type-checked —
// this project has no build step today, so we do not turn on a check that could
// newly fail a slice of the tree; erasing type annotations is exactly what Node's
// own runtime stripping already assumes is safe), and rewrite every relative
// import specifier that names a sibling by its .ts extension to .js instead —
// both in the compiled .ts output and in the many plain .mjs files that import
// .ts siblings with an explicit extension (Node's own convention throughout this
// codebase). Output mirrors the source tree 1:1 under dist/, so relative import
// depth never changes — only the file extension does.
//
// This does not introduce a new trust path: it recompiles the exact same source
// the repo already runs from a checkout, unmodified in logic, into a form Node
// will load from node_modules. No signing, verification, or policy logic changes.
//
// Lives under build/ (not scripts/) deliberately: scripts/ is one of the
// directories mirrored into dist/ (the packaged runtime needs the rest of it —
// start-sidecar.mjs, bootstrap_dev_receipt_keys.mjs, etc.), and this file's own
// `import ts from "typescript"` is a devDependency-only import that would ship
// broken and unusable inside the published tarball if it lived there — an
// independent review caught exactly that. build/ is never in INCLUDE_DIRS, so
// this file and its lib/ helper are never shipped.

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync, rmSync, existsSync, copyFileSync } from "node:fs";
import { join, dirname, relative, extname } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { scanForPackageSecrets, applyAllowlist } from "./lib/package-secret-scan.mjs";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const OUT_DIR = join(repoRoot, "dist");

// Directories mirrored into dist/ (everything the packaged runtime needs).
// Deliberately excludes: tests/, docs/, examples/, reviewer-kit/, desktop/
// (except dashboard.html, copied explicitly), build/ (this build tooling
// itself), and dev-only tooling not reachable from the packaged CLI's runtime
// paths.
const INCLUDE_DIRS = [
  "shared", "preflight", "orbit", "arm", "ram0na", "audit",
  "src", "sidecar", "shell", "tools", "scripts", "bin", "mcp", "executor", "policy", "authority",
  "templates", "sample-policies"
];
const INCLUDE_FILES = ["mnde-local-sidecar.mjs"];
const EXTRA_COPY_FILES = [["desktop/dashboard.html", "desktop/dashboard.html"]];

const TS_COMPILER_OPTIONS = {
  module: ts.ModuleKind.NodeNext,
  target: ts.ScriptTarget.ES2022,
  moduleResolution: ts.ModuleResolutionKind.NodeNext,
  esModuleInterop: true,
  isolatedModules: true,
  verbatimModuleSyntax: false,
  sourceMap: false
};

// Rewrite relative import/export specifiers ending in .ts (and .mts) to .js
// (and .mjs) respectively. Only touches specifiers that start with "." (relative
// imports) — package/bare specifiers are never touched, so node: and third-party
// imports are untouched. This is a narrow, predictable text transform, applied
// identically whether the source was .ts (after type-stripping) or already .mjs.
function rewriteRelativeTsExtensions(code) {
  return code.replace(
    /((?:from\s+|import\s*\(\s*)["'])(\.[^"']*?)(\.m?ts)(["'])/g,
    (_m, pre, spec, ext, post) => `${pre}${spec}${ext === ".mts" ? ".mjs" : ".js"}${post}`
  );
}

function isTsFile(p) { return extname(p) === ".ts"; }
function isJsLikeFile(p) { return [".mjs", ".js"].includes(extname(p)); }

// Absolute paths that must NEVER be copied into the package, regardless of
// whether they happen to exist in this working tree at build time (e.g. a
// prior local test run generated real key material here). Checked by exact
// path match, not by name alone, so a differently-located file named
// "receipt_keys" elsewhere is not accidentally excluded. This is a first-line
// defense (avoids ever reading/copying the known real key locations at all);
// assertNoPrivateKeyMaterial() below is the authoritative, content-based
// backstop that does not depend on this list being complete.
const NEVER_COPY = new Set([
  join(repoRoot, "shared", "receipt_keys"),
  join(repoRoot, "authority", "root_authority_private.pem"),
  join(repoRoot, ".mnde-test")
].map((p) => p.toLowerCase()));

// Dev-only files that physically live inside an otherwise-shipped directory but
// are never on the packaged CLI/runtime path — no bin/*, the sidecar runtime, or
// start-sidecar imports them. Excluded by exact path so the production surface
// stays minimal and dev proof tooling never ships. `npm run reviewer-kit` still
// runs it from the source checkout; it is simply absent from the tarball.
const EXCLUDE_FILES = new Set([
  join(repoRoot, "tools", "reviewer-kit.mjs")
].map((p) => p.toLowerCase()));

function isExcluded(absPath) {
  const lower = absPath.toLowerCase();
  if (EXCLUDE_FILES.has(lower)) return true;
  for (const blocked of NEVER_COPY) {
    if (lower === blocked || lower.startsWith(blocked + "\\") || lower.startsWith(blocked + "/")) return true;
  }
  return false;
}

function walk(dir, onFile) {
  if (isExcluded(dir)) return;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (isExcluded(full)) continue;
    const st = statSync(full);
    if (st.isDirectory()) {
      if (entry === "node_modules" || entry === "__pycache__") continue;
      walk(full, onFile);
    } else {
      onFile(full);
    }
  }
}

function outPathFor(srcAbs) {
  const rel = relative(repoRoot, srcAbs);
  const relJs = isTsFile(srcAbs) ? rel.replace(/\.ts$/, ".js") : rel;
  return join(OUT_DIR, relJs);
}

function ensureDirFor(fileAbs) {
  mkdirSync(dirname(fileAbs), { recursive: true });
}

function build() {
  rmSync(OUT_DIR, { recursive: true, force: true });
  mkdirSync(OUT_DIR, { recursive: true });

  let tsCount = 0, jsCount = 0, otherCount = 0;

  for (const dir of INCLUDE_DIRS) {
    const abs = join(repoRoot, dir);
    if (!existsSync(abs)) continue;
    walk(abs, (fileAbs) => {
      const out = outPathFor(fileAbs);
      ensureDirFor(out);
      if (isTsFile(fileAbs)) {
        const source = readFileSync(fileAbs, "utf8");
        // transpileModule has no real filesystem context to look up a package.json
        // "type" field, so a plain .ts fileName hint leaves module format
        // ambiguous and it silently emits CommonJS. Force ESM emission
        // unambiguously by hinting a .mts filename (Node's own extension-based
        // disambiguation: .mts is always ESM), independent of the .js output path.
        const transpiled = ts.transpileModule(source, {
          compilerOptions: TS_COMPILER_OPTIONS,
          fileName: fileAbs.replace(/\.ts$/, ".mts")
        }).outputText;
        writeFileSync(out, rewriteRelativeTsExtensions(transpiled), "utf8");
        tsCount++;
      } else if (isJsLikeFile(fileAbs)) {
        const source = readFileSync(fileAbs, "utf8");
        writeFileSync(out, rewriteRelativeTsExtensions(source), "utf8");
        jsCount++;
      } else {
        copyFileSync(fileAbs, out);
        otherCount++;
      }
    });
  }

  for (const file of INCLUDE_FILES) {
    const fileAbs = join(repoRoot, file);
    if (!existsSync(fileAbs)) continue;
    const out = outPathFor(fileAbs);
    ensureDirFor(out);
    const source = readFileSync(fileAbs, "utf8");
    writeFileSync(out, rewriteRelativeTsExtensions(source), "utf8");
    jsCount++;
  }

  for (const [src, dest] of EXTRA_COPY_FILES) {
    const srcAbs = join(repoRoot, src);
    if (!existsSync(srcAbs)) continue;
    const out = join(OUT_DIR, dest);
    ensureDirFor(out);
    copyFileSync(srcAbs, out);
    otherCount++;
  }

  process.stdout.write(`build-package: ${tsCount} .ts compiled, ${jsCount} .mjs/.js rewritten+copied, ${otherCount} other files copied -> ${relative(repoRoot, OUT_DIR)}/\n`);

  writeReleaseBuildInfo();
  assertNoSecretMaterial();
}

// Capture immutable release metadata (source commit, build id, build time) at
// PACK time, when Git is available, and embed it beside the release-identity
// module in the output tree. The runtime never shells out to Git — a packaged
// install has no .git — so this is the only place commit identity is bound to
// the artifact. Written into dist/ only: it never touches the source tree, so a
// source checkout has no build-info.json and truthfully reports "source".
function gitOutput(args) {
  try {
    return execFileSync("git", args, { cwd: repoRoot, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "";
  }
}

function writeReleaseBuildInfo() {
  const releaseDir = join(OUT_DIR, "src", "release");
  if (!existsSync(releaseDir)) {
    // src/release/identity.mjs must have been mirrored for identity to work.
    process.stderr.write("FATAL: dist/src/release missing — release identity module was not packaged\n");
    process.exit(1);
  }
  const commit = gitOutput(["rev-parse", "HEAD"]) || null;
  // A real release MUST embed a source commit — that is the central promise of
  // the release contract (an artifact identifies the source that produced it).
  // `npm run release` sets MNDE_REQUIRE_COMMIT=1, so a release built from a
  // source archive with no .git fails closed here instead of silently shipping a
  // commit-less "source-checkout" artifact. Ordinary `npm pack` (used by tests
  // from a git checkout) is unaffected.
  if (process.env.MNDE_REQUIRE_COMMIT === "1" && !commit) {
    process.stderr.write(
      "FATAL: release build requires an embedded source commit, but `git rev-parse HEAD` " +
        "returned nothing (no .git?). Refusing to emit a commit-less release artifact.\n"
    );
    process.exit(1);
  }
  const commitShort = commit ? commit.slice(0, 12) : null;
  const dirty = commit ? gitOutput(["status", "--porcelain"]).length > 0 : null;
  // build_time is the one intentionally-mutable field: it makes the tarball not
  // byte-for-byte reproducible, but never changes the release IDENTITY
  // (product/version/commit), which is what integrity checks bind to. Overridable
  // via MNDE_BUILD_TIME for reproducible-release experiments.
  const buildTime = process.env.MNDE_BUILD_TIME || new Date().toISOString();
  const buildId =
    process.env.MNDE_BUILD_ID || (commitShort ? `${commitShort}${dirty ? "-dirty" : ""}` : "source");
  const info = {
    schema: "mnde.release-identity.v1",
    commit,
    commit_short: commitShort,
    dirty,
    build_id: buildId,
    build_time: buildTime,
    artifact_format: "npm-tarball"
  };
  writeFileSync(join(releaseDir, "build-info.json"), `${JSON.stringify(info, null, 2)}\n`, "utf8");
  process.stdout.write(`build-package: embedded release identity ${buildId} (commit ${commitShort ?? "unknown"})\n`);
}

// Fast, content-based backstop: fail the build outright if any recognized
// secret material made it into dist/, regardless of filename, extension,
// directory depth, or whether it's embedded inside JSON/text/config. See
// build/lib/package-secret-scan.mjs for exactly what this detects (PEM/DER/JWK/
// PuTTY private keys, selected provider tokens, and conservatively detected
// credential assignments) and, just as importantly, what it does not.
//
// This is a fast pre-pack backstop; tests/test_pack_no_private_keys.mjs runs the
// SAME scanner over the literal extracted npm tarball as the authoritative
// package-boundary check. The allowlist lives under build/ (never shipped), is
// exact + hash-bound, and can never suppress a private-key-class finding.
//
// Diagnostics report only detector id, normalized path, and line/fingerprint —
// never the secret itself.
const SECRET_SCAN_ALLOWLIST = fileURLToPath(new URL("secret-scan-allowlist.json", import.meta.url));

function assertNoSecretMaterial() {
  const findings = applyAllowlist(scanForPackageSecrets(OUT_DIR), {
    rootDir: OUT_DIR,
    allowlistPath: SECRET_SCAN_ALLOWLIST
  });
  if (findings.length > 0) {
    for (const f of findings) {
      process.stderr.write(
        `FATAL: suspected secret material in build output: [${f.detectorId}] ${f.relativePath}:${f.line} (${f.fingerprint})\n`
      );
    }
    process.exit(1);
  }
}

build();
