// Executor-identity runtime readiness gate.
//
// Absent config => no-op (authority-only unchanged). Configured-but-unusable =>
// fails closed with a stable reason_code.

import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { issueExecutorCredential } from "../src/custody/executor-credential.mjs";
import { assertExecutorIdentityReadiness } from "../src/custody/executor-readiness.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ok - ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`  FAIL - ${name}`);
    console.error(`        ${error instanceof Error ? error.message : String(error)}`);
  }
}

const CODEX_ID = "mnde:local:prod:executor:codex:01";
const ENV_ID = "prod";
const NOW = "2026-06-15T10:00:00.000Z";

async function makeAuthority() {
  const root = { keyId: "authority-root-v1", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "mnde:local:prod",
    issuedAt: "2026-06-01T00:00:00.000Z",
    notAfter: "2028-01-01T00:00:00.000Z",
    root,
    receiptKeys: [],
    policyKeys: [],
    approvalKeys: [],
    revocation: []
  });
  return { root, bundle, trustedRootFingerprint: bundle.root_key.fingerprint };
}

const work = mkdtempSync(join(tmpdir(), "mnde-readiness-"));
const authority = await makeAuthority();
const codexKeys = generateAuthorityKeyPair();
const codexCred = await issueExecutorCredential({
  authorityBundle: authority.bundle,
  rootPrivatePem: authority.root.privatePem,
  executorId: CODEX_ID,
  publicPem: codexKeys.publicPem,
  environmentId: ENV_ID,
  capabilities: ["sign_execution_receipt"],
  issuedAt: "2026-06-01T00:00:00.000Z",
  notBefore: "2026-06-01T00:00:00.000Z",
  expiresAt: "2026-07-01T00:00:00.000Z"
});
const keyPath = join(work, "codex.key");
const credPath = join(work, "codex.credential.json");
writeFileSync(keyPath, codexKeys.privatePem, { mode: 0o600 });
writeFileSync(credPath, JSON.stringify(codexCred));

function fullEnv(overrides = {}) {
  return {
    MNDE_EXECUTOR_ID: CODEX_ID,
    MNDE_EXECUTOR_PRIVATE_KEY: keyPath,
    MNDE_EXECUTOR_CREDENTIAL: credPath,
    MNDE_EXECUTOR_ENVIRONMENT: ENV_ID,
    ...overrides
  };
}
function opts(extra = {}) {
  return { authorityBundle: authority.bundle, trustedRootFingerprint: authority.trustedRootFingerprint, now: NOW, ...extra };
}

console.log("Executor-identity readiness\n");

await test("absent config is a no-op (authority-only unchanged)", async () => {
  const r = await assertExecutorIdentityReadiness({}, opts());
  assert.equal(r.ok, true);
  assert.equal(r.configured, false);
});

await test("partial config fails closed (INCOMPLETE)", async () => {
  const r = await assertExecutorIdentityReadiness({ MNDE_EXECUTOR_ID: CODEX_ID }, opts());
  assert.equal(r.ok, false);
  assert.equal(r.reason_code, "ERR_EXECUTOR_IDENTITY_INCOMPLETE");
});

await test("valid config is ready", async () => {
  const r = await assertExecutorIdentityReadiness(fullEnv(), opts());
  assert.equal(r.ok, true, r.detail ?? r.reason_code);
  assert.equal(r.configured, true);
  assert.equal(r.executor_id, CODEX_ID);
  assert.equal(r.executor_key_id, codexCred.key_id);
});

await test("expired credential fails closed", async () => {
  const r = await assertExecutorIdentityReadiness(fullEnv(), opts({ now: "2026-08-01T00:00:00.000Z" }));
  assert.equal(r.ok, false);
  assert.equal(r.reason_code, "ERR_EXECUTOR_CREDENTIAL_EXPIRED");
});

await test("wrong environment fails closed", async () => {
  const r = await assertExecutorIdentityReadiness(fullEnv({ MNDE_EXECUTOR_ENVIRONMENT: "staging" }), opts());
  assert.equal(r.ok, false);
  assert.equal(r.reason_code, "ERR_EXECUTOR_ENVIRONMENT_MISMATCH");
});

await test("in-repository private-key path fails closed", async () => {
  const inRepo = join(repoRoot, "package.json");
  const r = await assertExecutorIdentityReadiness(fullEnv({ MNDE_EXECUTOR_PRIVATE_KEY: inRepo }), opts());
  assert.equal(r.ok, false);
  assert.equal(r.reason_code, "ERR_EXECUTOR_KEY_REPOSITORY_CONTAINED");
});

await test("unreadable credential fails closed", async () => {
  const r = await assertExecutorIdentityReadiness(fullEnv({ MNDE_EXECUTOR_CREDENTIAL: join(work, "nope.json") }), opts());
  assert.equal(r.ok, false);
  assert.equal(r.reason_code, "ERR_EXECUTOR_CREDENTIAL_INVALID");
});

await test("missing key file fails closed", async () => {
  const r = await assertExecutorIdentityReadiness(fullEnv({ MNDE_EXECUTOR_PRIVATE_KEY: join(work, "gone.key") }), opts());
  assert.equal(r.ok, false);
  assert.equal(r.reason_code, "ERR_EXECUTOR_KEY_MISSING");
});

console.log(`\n${failed === 0 ? "PASS" : "FAIL"} executor readiness (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
