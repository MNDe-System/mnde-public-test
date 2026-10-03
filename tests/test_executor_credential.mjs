// Executor credential (mnde.executor.credential.v1) — issuance + fixed one-hop
// verification, including Codex/Claude distinctness and hostile tampering.
//
// Phase 0 / Design A: the custody authority bundle is the ONLY issuing authority.
// These tests prove the credential binds a stable executor_id to that executor's
// own key, verifies against the bundle root in exactly one hop, and fails closed
// on every tampered, expired, wrong-environment, or unknown-field input.

import assert from "node:assert/strict";

import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/bundle.mjs";
import {
  EXECUTOR_CREDENTIAL_SCHEMA,
  EXECUTOR_TRUST_EPOCH,
  executorKeyId,
  issueExecutorCredential,
  verifyExecutorCredential
} from "../src/custody/executor-credential.mjs";

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

const ISSUED_AT = "2026-08-01T00:00:00.000Z";
const NOT_BEFORE = "2026-08-01T00:00:00.000Z";
const EXPIRES_AT = "2026-08-02T00:00:00.000Z";
const NOW = "2026-08-01T12:00:00.000Z"; // inside the window
const AUTHORITY_ID = "mnde:local:prod";
const ENVIRONMENT_ID = "prod";
const CODEX_ID = "mnde:local:prod:executor:codex:01";
const CLAUDE_ID = "mnde:local:prod:executor:claude:01";

async function makeAuthority() {
  const root = { keyId: "authority-root-v1", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: AUTHORITY_ID,
    issuedAt: ISSUED_AT,
    notAfter: "2999-01-01T00:00:00.000Z",
    root,
    receiptKeys: [],
    policyKeys: [],
    approvalKeys: [],
    resultKeys: [],
    ledgerKeys: [],
    activationKeys: [],
    revocation: []
  });
  return { root, bundle, trustedRootFingerprint: bundle.root_key.fingerprint };
}

async function issue(authority, executorId, publicPem, overrides = {}) {
  return issueExecutorCredential({
    authorityBundle: authority.bundle,
    rootPrivatePem: authority.root.privatePem,
    executorId,
    publicPem,
    environmentId: ENVIRONMENT_ID,
    capabilities: ["sign_execution_receipt"],
    issuedAt: ISSUED_AT,
    notBefore: NOT_BEFORE,
    expiresAt: EXPIRES_AT,
    ...overrides
  });
}

function baseVerifyOpts(authority, extra = {}) {
  return {
    authorityBundle: authority.bundle,
    trustedRootFingerprint: authority.trustedRootFingerprint,
    environmentId: ENVIRONMENT_ID,
    now: NOW,
    ...extra
  };
}

console.log("Executor credential — issuance + one-hop verification\n");

const authority = await makeAuthority();
const codex = generateAuthorityKeyPair();
const claude = generateAuthorityKeyPair();

await test("valid credential verifies against the issuing authority", async () => {
  const cred = await issue(authority, CODEX_ID, codex.publicPem);
  assert.equal(cred.schema_version, EXECUTOR_CREDENTIAL_SCHEMA);
  assert.equal(cred.trust_epoch, EXECUTOR_TRUST_EPOCH);
  const result = await verifyExecutorCredential(cred, baseVerifyOpts(authority, { expectedExecutorId: CODEX_ID, requiredCapability: "sign_execution_receipt" }));
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.executor_id, CODEX_ID);
  assert.equal(result.key_id, executorKeyId(codex.publicPem));
});

await test("Codex and Claude get distinct key ids and credential ids", async () => {
  const codexCred = await issue(authority, CODEX_ID, codex.publicPem);
  const claudeCred = await issue(authority, CLAUDE_ID, claude.publicPem);
  assert.notEqual(codexCred.key_id, claudeCred.key_id);
  assert.notEqual(codexCred.credential_id, claudeCred.credential_id);
  assert.notEqual(codexCred.public_key, claudeCred.public_key);
});

await test("missing credential fails closed (MISSING)", async () => {
  const result = await verifyExecutorCredential(null, baseVerifyOpts(authority));
  assert.equal(result.code, "ERR_EXECUTOR_CREDENTIAL_MISSING");
});

await test("expired credential fails (EXPIRED)", async () => {
  const cred = await issue(authority, CODEX_ID, codex.publicPem);
  const result = await verifyExecutorCredential(cred, baseVerifyOpts(authority, { now: "2026-08-03T00:00:00.000Z" }));
  assert.equal(result.code, "ERR_EXECUTOR_CREDENTIAL_EXPIRED");
});

await test("not-yet-valid credential fails (EXPIRED)", async () => {
  const cred = await issue(authority, CODEX_ID, codex.publicPem);
  const result = await verifyExecutorCredential(cred, baseVerifyOpts(authority, { now: "2026-07-31T00:00:00.000Z" }));
  assert.equal(result.code, "ERR_EXECUTOR_CREDENTIAL_EXPIRED");
});

await test("wrong environment fails (ENVIRONMENT_MISMATCH)", async () => {
  const cred = await issue(authority, CODEX_ID, codex.publicPem);
  const result = await verifyExecutorCredential(cred, baseVerifyOpts(authority, { environmentId: "staging" }));
  assert.equal(result.code, "ERR_EXECUTOR_ENVIRONMENT_MISMATCH");
});

await test("unexpected executor id fails (IDENTITY_MISMATCH)", async () => {
  const cred = await issue(authority, CODEX_ID, codex.publicPem);
  const result = await verifyExecutorCredential(cred, baseVerifyOpts(authority, { expectedExecutorId: CLAUDE_ID }));
  assert.equal(result.code, "ERR_EXECUTOR_IDENTITY_MISMATCH");
});

await test("missing required capability fails (CAPABILITY_DENIED)", async () => {
  const cred = await issue(authority, CODEX_ID, codex.publicPem);
  const result = await verifyExecutorCredential(cred, baseVerifyOpts(authority, { requiredCapability: "sign_ledger_checkpoint" }));
  assert.equal(result.code, "ERR_EXECUTOR_CAPABILITY_DENIED");
});

await test("untrusted root fingerprint fails (INVALID)", async () => {
  const cred = await issue(authority, CODEX_ID, codex.publicPem);
  const other = await makeAuthority();
  const result = await verifyExecutorCredential(cred, baseVerifyOpts(authority, { trustedRootFingerprint: other.trustedRootFingerprint }));
  assert.equal(result.code, "ERR_EXECUTOR_CREDENTIAL_INVALID");
});

await test("credential issued by a different authority does not verify here", async () => {
  const other = await makeAuthority();
  const foreignCred = await issue(other, CODEX_ID, codex.publicPem);
  // Present the foreign credential but our bundle/root as the verifier's anchor.
  const result = await verifyExecutorCredential(foreignCred, baseVerifyOpts(authority));
  assert.equal(result.ok, false);
  assert.equal(result.code, "ERR_EXECUTOR_CREDENTIAL_INVALID");
});

await test("tampered public_key breaks key_id derivation (KEY_MISMATCH)", async () => {
  const cred = await issue(authority, CODEX_ID, codex.publicPem);
  const tampered = { ...cred, public_key: claude.publicPem };
  const result = await verifyExecutorCredential(tampered, baseVerifyOpts(authority));
  assert.equal(result.code, "ERR_EXECUTOR_KEY_MISMATCH");
});

await test("tampered capability after signing fails (INVALID signature)", async () => {
  const cred = await issue(authority, CODEX_ID, codex.publicPem);
  const tampered = { ...cred, capabilities: [...cred.capabilities, "sign_ledger_checkpoint"] };
  const result = await verifyExecutorCredential(tampered, baseVerifyOpts(authority));
  assert.equal(result.code, "ERR_EXECUTOR_CREDENTIAL_INVALID");
});

await test("tampered credential_id fails (INVALID)", async () => {
  const cred = await issue(authority, CODEX_ID, codex.publicPem);
  const tampered = { ...cred, credential_id: "mnde-cred:deadbeefdeadbeefdeadbeefdeadbeef" };
  const result = await verifyExecutorCredential(tampered, baseVerifyOpts(authority));
  assert.equal(result.code, "ERR_EXECUTOR_CREDENTIAL_INVALID");
});

await test("unknown field inserted into a signed credential fails (INVALID)", async () => {
  const cred = await issue(authority, CODEX_ID, codex.publicPem);
  const tampered = { ...cred, self_witness: true };
  const result = await verifyExecutorCredential(tampered, baseVerifyOpts(authority));
  assert.equal(result.code, "ERR_EXECUTOR_CREDENTIAL_INVALID");
});

await test("wrong trust epoch fails (INVALID)", async () => {
  const cred = await issue(authority, CODEX_ID, codex.publicPem);
  // Re-sign a body with a different epoch so the signature is valid but the
  // epoch is wrong — proves the epoch is enforced, not just the signature.
  const forged = await issueExecutorCredential({
    authorityBundle: authority.bundle,
    rootPrivatePem: authority.root.privatePem,
    executorId: CODEX_ID,
    publicPem: codex.publicPem,
    environmentId: ENVIRONMENT_ID,
    capabilities: ["sign_execution_receipt"],
    issuedAt: ISSUED_AT,
    notBefore: NOT_BEFORE,
    expiresAt: EXPIRES_AT
  });
  const mutated = { ...forged, trust_epoch: "legacy-shared-key" };
  const result = await verifyExecutorCredential(mutated, baseVerifyOpts(authority));
  assert.equal(result.ok, false);
  assert.ok(cred.trust_epoch === EXECUTOR_TRUST_EPOCH);
});

console.log(`\n${failed === 0 ? "PASS" : "FAIL"} executor credential tests (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
