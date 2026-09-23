// git.push — static effect-reachability guard (F-001 regression defense).
//
//   npm run test:git-push-reachability
//
// The architecture is what keeps a second route to the protected effect from
// existing; this test keeps it from being re-introduced by accident. Layers:
//
//   1. ownership — the lowest-level effect module (src/effects/git-push/
//      transport.mjs) may be imported by exactly one non-test module, the typed
//      executor src/effects/git-push/index.mjs;
//   2. spawn allowlist — every shipped file that can start a process or thread is
//      listed here with its reason; a new one fails until someone reviews it;
//   3. mutation vocabulary — no shipped spawner other than the effect module
//      carries a git mutation subcommand or flag literal;
//   4. no provider write clients — no git library, GitHub SDK, GitHub API write
//      endpoint, or runtime dependency that could supply one;
//   5. no shipped import of tests/ or experiments/;
//   6. surfaces — the generic run() executor never invokes a callback, and the
//      effect module exports no generic runner (performPush refuses any argv
//      that is not the typed push).
//
// The shipped set is parsed out of build/build-package.mjs itself, so this test
// and the package cannot silently disagree about what ships.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, normalize, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const posix = (p) => p.split(sep).join("/");
const EFFECT = "src/effects/git-push/transport.mjs";
const EXECUTOR = "src/effects/git-push/index.mjs";

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  [PASS] ${name}`); }
  catch (error) { failed += 1; console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.message : String(error)}`); }
}

const ALL = execFileSync("git", ["ls-files", "-co", "--exclude-standard", "-z"], { cwd: ROOT, encoding: "utf8" })
  .split("\0").filter((f) => /\.(mjs|js|cjs|ts)$/.test(f) && !f.startsWith("node_modules/") && !f.startsWith("dist/"));
const read = (f) => readFileSync(join(ROOT, f), "utf8");

const buildSrc = read("build/build-package.mjs");
const INCLUDE_DIRS = JSON.parse(`[${/const INCLUDE_DIRS = \[([\s\S]*?)\];/.exec(buildSrc)[1]}]`);
const INCLUDE_FILES = JSON.parse(`[${/const INCLUDE_FILES = \[([\s\S]*?)\];/.exec(buildSrc)[1]}]`);
const excludeBlock = /const EXCLUDE_FILES = new Set\(\[([\s\S]*?)\]\.map/.exec(buildSrc)[1];
const EXCLUDED = new Set([...excludeBlock.matchAll(/join\(repoRoot,\s*((?:"[^"]+"\s*,?\s*)+)\)/g)]
  .map((m) => [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]).join("/")));
const SHIPPED = ALL.filter((f) => (INCLUDE_DIRS.some((d) => f.startsWith(`${d}/`)) || INCLUDE_FILES.includes(f)) && !EXCLUDED.has(f));
const NON_TEST = ALL.filter((f) => !f.startsWith("tests/"));

function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");
}
function specifiers(src) {
  const re = /(?:import|export)\s[^'"`;]*?from\s*["']([^"']+)["']|import\s*\(\s*["']([^"']+)["']\s*\)|require\s*\(\s*["']([^"']+)["']\s*\)|import\s+["']([^"']+)["']/g;
  return [...stripComments(src).matchAll(re)].map((m) => m[1] ?? m[2] ?? m[3] ?? m[4]);
}
const resolveSpec = (file, spec) => (spec.startsWith(".") ? posix(relative(ROOT, normalize(join(ROOT, dirname(file), spec)))) : spec);

const SPAWN_ALLOWLIST = new Map([
  [EFFECT, "THE git.push effect: fixed executable, typed argv, environment built from empty, staging repository"],
  ["bin/mnde-sidecar.mjs", "launches MNDe's own sidecar (process.execPath) / taskkill of that child"],
  ["scripts/start-sidecar.mjs", "launches MNDe's own sidecar (process.execPath)"],
  ["executor/sidecar-harness.mjs", "launches MNDe's own sidecar (process.execPath) for the local harness"],
  ["mnde-local-sidecar.mjs", "node:cluster self-fork of the sidecar"],
  ["sidecar/deterministic_worker_pool.mjs", "worker_threads for the in-repo deterministic evaluator (fixed module URL)"],
  ["sidecar/deterministic_worker.mjs", "worker_threads entry of the deterministic evaluator"],
  ["src/custody/external-signer.mjs", "operator-configured signer executable (administrative trust; no git capability)"],
  ["src/custody/root-signer.mjs", "operator-configured root signer executable (administrative trust)"],
  ["scripts/check-whitespace.mjs", "dev tooling: read-only `git ls-files`"],
  ["scripts/run-all-tests.mjs", "dev tooling: runs npm test scripts"],
  ["scripts/run-ci.mjs", "dev tooling: runs npm"],
  ["scripts/desktop-smoke.mjs", "dev tooling: launches the packaged desktop binary"]
]);
const SPAWNERS = SHIPPED.filter((f) => /child_process|node:cluster|worker_threads/.test(stripComments(read(f))));
const MUTATION = new Set([
  "push", "update-ref", "receive-pack", "send-pack", "symbolic-ref", "commit", "merge", "rebase", "reset",
  "cherry-pick", "revert", "am", "apply", "filter-branch", "replace", "update-index",
  "--force", "--force-with-lease", "--mirror", "--all", "--delete", "--receive-pack", "--exec"
]);

async function main() {
  console.log(`git.push static reachability (${ALL.length} source files, ${SHIPPED.length} shipped, ${EXCLUDED.size} dev-only excluded)\n`);

  await test("1a: only the typed executor imports the git.push effect module", () => {
    const importers = NON_TEST.filter((f) => specifiers(read(f)).some((s) => resolveSpec(f, s) === EFFECT));
    assert.deepEqual(importers, [EXECUTOR], `effect-module importers: ${importers.join(", ")}`);
  });
  await test("1b: no other non-test file even names the effect module", () => {
    const offenders = NON_TEST.filter((f) => f !== EXECUTOR && f !== EFFECT && /git-push\/transport/.test(stripComments(read(f))));
    assert.deepEqual(offenders, []);
  });
  await test("1c: the typed executor spawns nothing itself; the process boundary is only in the effect module", () => {
    assert.doesNotMatch(stripComments(read(EXECUTOR)), /child_process|node:cluster|worker_threads/);
  });

  await test("2a: every shipped file that can spawn a process or thread is on the reviewed allowlist", () => {
    const unreviewed = SPAWNERS.filter((f) => !SPAWN_ALLOWLIST.has(f));
    assert.deepEqual(unreviewed, [], `new spawn-capable shipped file(s) need an F-001 review: ${unreviewed.join(", ")}`);
  });
  await test("2b: the dev-only raw stdio client and demo servers stay out of the package", () => {
    for (const f of ["mcp/stdio-client.mjs", "mcp/example-upstream-server.mjs", "mcp/shell-mcp-server.mjs"]) {
      assert.ok(EXCLUDED.has(f) && !SHIPPED.includes(f), `${f} must not ship`);
    }
    const importers = SHIPPED.filter((f) => specifiers(read(f)).some((s) => resolveSpec(f, s) === "mcp/stdio-client.mjs"));
    assert.deepEqual(importers, []);
  });

  await test("3: no shipped spawner other than the effect module carries a git mutation literal", () => {
    const offenders = [];
    for (const f of SPAWNERS.filter((x) => x !== EFFECT)) {
      for (const m of stripComments(read(f)).matchAll(/"([^"\n]*)"|'([^'\n]*)'|`([^`$\n]*)`/g)) {
        const lit = m[1] ?? m[2] ?? m[3];
        if (MUTATION.has(lit)) offenders.push(`${f}: "${lit}"`);
      }
    }
    assert.deepEqual(offenders, []);
  });

  await test("4a: no shipped file uses a git library, GitHub SDK or GitHub API write endpoint", () => {
    const re = /isomorphic-git|simple-git|nodegit|@octokit|\boctokit\b|api\.github\.com|\/git\/refs|\/pulls\/[^"'`]*\/merge/;
    assert.deepEqual(SHIPPED.filter((f) => re.test(stripComments(read(f)))), []);
  });
  await test("4b: no runtime dependency could supply a provider write client", () => {
    const pkg = JSON.parse(read("package.json"));
    for (const k of ["dependencies", "optionalDependencies", "peerDependencies"]) {
      assert.deepEqual(Object.keys(pkg[k] ?? {}).filter((d) => /git|octokit|github/i.test(d)), [], k);
    }
  });

  await test("5: no shipped file imports tests/ or experiments/", () => {
    const offenders = [];
    for (const f of SHIPPED) for (const s of specifiers(read(f))) {
      const r = resolveSpec(f, s);
      if (r.startsWith("tests/") || r.startsWith("experiments/")) offenders.push(`${f} -> ${r}`);
    }
    assert.deepEqual(offenders, []);
  });

  await test("6a: the generic run() executor never invokes a caller-supplied callback", () => {
    assert.doesNotMatch(stripComments(read("executor/index.mjs")), /\brun\s*\(/);
  });
  await test("6b: the effect module exports no generic runner, and performPush refuses any untyped argv", async () => {
    const t = await import(pathToFileURL(join(ROOT, EFFECT)).href);
    assert.ok(!Object.keys(t).some((k) => /^(run|exec|spawn|git)(Git)?$/i.test(k) || /^runGit$/.test(k)), `exports: ${Object.keys(t)}`);
    const ctx = { cwd: ROOT, env: {}, timeoutMs: 1000 };
    const sha = "a".repeat(40);
    for (const argv of [
      ["push", "--force", "origin", `${sha}:refs/heads/main`],
      ["config", "--global", "x", "y"],
      ["push", "--no-verify", `--force-with-lease=refs/heads/main:${sha}`, "--", "origin", `${sha}:refs/heads/main`, "--mirror"],
      ["push", "--no-verify", `--force-with-lease=refs/heads/main:${sha}`, "--", "--receive-pack=sh", `${sha}:refs/heads/main`],
      ["push", "--no-verify", `--force-with-lease=refs/heads/main:${sha}`, "--", "origin", `${sha}:refs/heads/other`],
      ["push", "--no-verify", `--force-with-lease=refs/tags/v1:${sha}`, "--", "origin", `${sha}:refs/tags/v1`]
    ]) {
      const r = await t.performPush(argv, ctx);
      assert.equal(r.reason, t.ERR_PUSH_ARGV_NOT_TYPED, `untyped argv reached git: ${argv.join(" ")}`);
    }
  });

  const total = passed + failed;
  if (failed === 0) console.log(`\nPASS git.push reachability (${passed}/${total})`);
  else { console.error(`\nFAIL git.push reachability (${passed}/${total})`); process.exitCode = 1; }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
