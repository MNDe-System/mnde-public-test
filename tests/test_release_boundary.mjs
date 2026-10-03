import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { publicKeyFingerprint } from "../shared/authority-manifest.mjs";
import { loadGitPushStartup, ERR_DEMO_TRUST_MATERIAL, KNOWN_NON_PRODUCTION_ROOT_FINGERPRINTS, REQUIRED_STARTUP_ENV } from "../src/effects/git-push/startup.mjs";
import { openExecutorClaimBackend } from "../src/freshness/postgres_claim.mjs";
import { createGitPushExecutor, ERR_BACKEND_SUBSTITUTION } from "../src/effects/git-push/index.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
let passed = 0;
async function test(name, fn) {
  await fn();
  passed += 1;
  process.stdout.write(`PASS ${name}\n`);
}
function sourceFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? sourceFiles(path) : /\.(?:mjs|js|ts)$/.test(path) ? [path] : [];
  });
}

await test("production source cannot import test-only modules", () => {
  for (const dir of ["bin", "src", "shared", "arm", "orbit", "preflight", "ram0na", "tools"]) {
    for (const file of sourceFiles(join(root, dir))) {
      const text = readFileSync(file, "utf8");
      assert.doesNotMatch(text, /(?:from\s*|import\s*\()\s*["'][^"']*(?:tests|experiments)\//, relative(root, file));
    }
  }
});

await test("production package has only the two protected entrypoints", () => {
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  assert.deepEqual(Object.keys(pkg.bin).sort(), ["mnde-git-push", "mnde-hub"]);
  assert.equal(pkg.dependencies.pg, "8.23.1");
  for (const omitted of ["executor", "sidecar", "mcp", "shell", "experiments", "desktop"]) {
    assert.ok(!pkg.files.includes(omitted));
  }
  assert.ok(pkg.files.includes("scripts/trust-enroll-executor.mjs"), "trust setup's child process must ship");
});

await test("the executor refuses caller-provided claim and credential providers", () => {
  assert.throws(() => createGitPushExecutor({ claimBackend: {} }), { code: ERR_BACKEND_SUBSTITUTION });
  assert.throws(() => createGitPushExecutor({ credentialProvider: {} }), { code: "ERR_GIT_CREDENTIAL_SUBSTITUTION" });
});

await test("the shipped demo public key is explicitly rejected as production trust", async () => {
  const fingerprint = publicKeyFingerprint(readFileSync(join(root, "authority", "root_authority_public.pem"), "utf8"));
  assert.ok(KNOWN_NON_PRODUCTION_ROOT_FINGERPRINTS.includes(fingerprint));
  const temp = mkdtempSync(join(tmpdir(), "mnde-release-demo-root-"));
  try {
    const config = join(temp, "config.json");
    const bundle = join(temp, "bundle.json");
    writeFileSync(config, "{}\n", { mode: 0o600 });
    writeFileSync(bundle, JSON.stringify({ authority_id: "mnde-demo", root_key: { key_id: "demo-root", fingerprint } }), { mode: 0o600 });
    const env = Object.fromEntries(REQUIRED_STARTUP_ENV.map(key => [key, key.includes("PATH") || key.includes("DIR") || key.includes("CONFIG") || key.includes("BUNDLE") || key.includes("KEY") || key.includes("CREDENTIAL") ? config : "prod"]));
    Object.assign(env, {
      MNDE_PROFILE: "production", MNDE_CLAIM_CONFIG: config, MNDE_GIT_CREDENTIAL_CONFIG: config,
      MNDE_GIT_PUSH_REPO_PATH: join(temp, "repository"), MNDE_GIT_PUSH_EVIDENCE_DIR: join(temp, "evidence"),
      MNDE_VERIFY_AUTHORITY_BUNDLE: bundle, MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT: fingerprint,
      MNDE_EXECUTOR_PRIVATE_KEY: config, MNDE_EXECUTOR_CREDENTIAL: config
    });
    const result = await loadGitPushStartup(env);
    assert.equal(result.ok, false);
    assert.equal(result.reason_code, ERR_DEMO_TRUST_MATERIAL);
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

await test("missing production configuration cannot open the claim backend", async () => {
  assert.equal((await loadGitPushStartup({})).ok, false);
  const before = process.env.MNDE_CLAIM_CONFIG;
  delete process.env.MNDE_CLAIM_CONFIG;
  try { await assert.rejects(openExecutorClaimBackend(), /ERR_CLAIM_CONFIG/); }
  finally { if (before === undefined) delete process.env.MNDE_CLAIM_CONFIG; else process.env.MNDE_CLAIM_CONFIG = before; }
});

process.stdout.write(`PASS release boundary (${passed}/${passed})\n`);
