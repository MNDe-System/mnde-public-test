// Production authority bundle + key-custody tests.
//
//   npm run test:custody
//
// All offline. Verifies: local-demo works by default and is unchanged; a
// file-backed production bundle verifies offline; expired / revoked / unknown
// keys fail; a tampered bundle fails; a missing bundle fails closed; a stale
// bundle is rejected; and no private key material ever appears in a bundle, a
// signature object, or an error message.

import assert from "node:assert/strict";
import { createPrivateKey } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadSigningConfig } from "../src/authority-signing/index.mjs";
import { canonicalizeJson } from "../shared/json.ts";
import {
  buildAuthorityBundle,
  createCustody,
  createFileBackedProductionCustody,
  createLocalDemoCustody,
  findBundleKey,
  generateAuthorityKeyPair,
  signCanonical,
  verifyAgainstBundle,
  verifyAuthorityBundle
} from "../src/custody/index.mjs";

// CUSTODY-ENC-1 encrypted-key fixtures. A single, obviously-synthetic secret
// marker so any accidental leak of passphrase material into an error, log, or
// serialized object is trivially detectable by the secret-leak tests below.
const SECRET_MARKER = "CUSTODY_ENC_1_SECRET_DO_NOT_PRINT_7f29";
const RECEIPT_PASS = `receipt-${SECRET_MARKER}`;
const LEDGER_PASS = `ledger-${SECRET_MARKER}`;
const POLICY_PASS = `policy-${SECRET_MARKER}`;
const PEM_HEADER = "-----BEGIN ENCRYPTED PRIVATE KEY-----";

// Re-export an unencrypted PKCS#8 PEM as an encrypted PKCS#8 PEM under a
// passphrase. The public counterpart is unchanged, so it still matches the
// bundle entry — only the at-rest private file becomes encrypted.
function encryptPem(privatePem, passphrase) {
  return createPrivateKey(privatePem).export({
    type: "pkcs8",
    format: "pem",
    cipher: "aes-256-cbc",
    passphrase
  });
}

// A production bundle carrying receipt + ledger + policy keys, for cross-role
// passphrase-isolation tests.
async function makeMultiRoleFixture({ now = "2026-06-14T00:00:00.000Z" } = {}) {
  const root = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "prod-receipt-1", ...generateAuthorityKeyPair() };
  const ledger = { keyId: "prod-ledger-1", ...generateAuthorityKeyPair() };
  const policy = { keyId: "prod-policy-1", ...generateAuthorityKeyPair() };
  const window = { validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" };
  const bundle = await buildAuthorityBundle({
    authorityId: "mnde-prod",
    issuedAt: now,
    notAfter: "2027-06-14T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, ...window }],
    ledgerKeys: [{ keyId: ledger.keyId, publicPem: ledger.publicPem, ...window }],
    policyKeys: [{ keyId: policy.keyId, publicPem: policy.publicPem, ...window }],
    revocation: []
  });
  return { root, receipt, ledger, policy, bundle, now };
}

const results = [];
let testChain = Promise.resolve();
function test(name, fn) {
  testChain = testChain.then(async () => {
    try {
      await fn();
      results.push(true);
      console.log(`  [PASS] ${name}`);
    } catch (error) {
      results.push(false);
      console.log(`  [FAIL] ${name}: ${error.message}`);
    }
  });
}

// A reusable production-shaped bundle with a known root + one valid receipt key.
async function makeProductionFixture({ now = "2026-06-14T00:00:00.000Z" } = {}) {
  const root = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "prod-receipt-1", ...generateAuthorityKeyPair() };
  const expired = { keyId: "prod-receipt-old", ...generateAuthorityKeyPair() };
  const revoked = { keyId: "prod-receipt-bad", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "mnde-prod",
    issuedAt: now,
    notAfter: "2027-06-14T00:00:00.000Z",
    root,
    receiptKeys: [
      { keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" },
      { keyId: expired.keyId, publicPem: expired.publicPem, validFrom: "2024-01-01T00:00:00.000Z", validUntil: "2025-01-01T00:00:00.000Z" },
      { keyId: revoked.keyId, publicPem: revoked.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z" }
    ],
    revocation: ["prod-receipt-bad"]
  });
  return { root, receipt, expired, revoked, bundle, now };
}

// ── local-demo (default, unchanged) ──────────────────────────────────────────
test("default custody is local-demo and signs + self-verifies offline", async () => {
  const { ok, provider } = await createCustody({});
  assert.equal(ok, true);
  assert.equal(provider.mode, "local-demo");
  assert.equal(provider.production, false);

  const bundle = provider.getPublicBundle();
  assert.equal((await (await verifyAuthorityBundle(bundle, { trustedRootFingerprint: provider.trustedRootFingerprint }))).ok, true);

  const payload = canonicalizeJson({ hello: "world" });
  const sig = await provider.signReceipt(payload);
  const check = await verifyAgainstBundle(payload, sig.value, "receipt", sig.key_id, "2026-06-14T00:00:00.000Z", bundle);
  assert.equal(check.ok, true);
});

test("createLocalDemoCustody can sign policy + approval and they verify", async () => {
  const p = await createLocalDemoCustody();
  const bundle = p.getPublicBundle();
  const at = "2026-06-14T00:00:00.000Z";
  for (const role of ["policy", "approval"]) {
    const payload = canonicalizeJson({ role });
    const sig = role === "policy" ? await p.signPolicy(payload) : await p.signApproval(payload);
    assert.equal((await verifyAgainstBundle(payload, sig.value, role, sig.key_id, at, bundle)).ok, true, role);
  }
});

// ── production bundle verifies offline ───────────────────────────────────────
test("production bundle verifies offline against trusted root fingerprint", async () => {
  const { bundle, root, now } = await makeProductionFixture();
  const trusted = bundle.root_key.fingerprint;
  assert.equal((await (await verifyAuthorityBundle(bundle, { trustedRootFingerprint: trusted, now }))).ok, true);
  // Wrong trust anchor → rejected.
  assert.equal((await verifyAuthorityBundle(bundle, { trustedRootFingerprint: "deadbeef", now })).reason, "UNTRUSTED_ROOT");
  // Sanity: root fingerprint is derived from the published root public key.
  assert.equal(typeof root.publicPem, "string");
});

test("receipt signed by a production key verifies against the published bundle", async () => {
  const { bundle, receipt, now } = await makeProductionFixture();
  const payload = canonicalizeJson({ decision: "ALLOW", n: 1 });
  const value = await signCanonical(payload, receipt.privatePem);
  assert.equal((await verifyAgainstBundle(payload, value, "receipt", receipt.keyId, now, bundle)).ok, true);
});

// ── expired / revoked / unknown ──────────────────────────────────────────────
test("expired key fails", async () => {
  const { bundle, expired } = await makeProductionFixture();
  // signedAt is after the key's valid_until window.
  const res = findBundleKey(bundle, "receipt", expired.keyId, "2026-06-14T00:00:00.000Z");
  assert.equal(res.ok, false);
  assert.equal(res.reason, "KEY_EXPIRED");
});

test("revoked key fails even within its validity window", async () => {
  const { bundle, revoked } = await makeProductionFixture();
  const res = findBundleKey(bundle, "receipt", revoked.keyId, "2026-06-14T00:00:00.000Z");
  assert.equal(res.ok, false);
  assert.equal(res.reason, "KEY_REVOKED");
});

test("receipt signed by unknown key fails", async () => {
  const { bundle, now } = await makeProductionFixture();
  const stranger = generateAuthorityKeyPair();
  const payload = canonicalizeJson({ decision: "ALLOW" });
  const value = await signCanonical(payload, stranger.privatePem);
  const res = await verifyAgainstBundle(payload, value, "receipt", "not-in-bundle", now, bundle);
  assert.equal(res.ok, false);
  assert.equal(res.reason, "UNKNOWN_KEY");
});

test("valid key id but wrong signing material fails with SIGNATURE_INVALID", async () => {
  const { bundle, receipt, now } = await makeProductionFixture();
  const stranger = generateAuthorityKeyPair();
  const payload = canonicalizeJson({ decision: "ALLOW" });
  const value = await signCanonical(payload, stranger.privatePem); // signed by the wrong key
  const res = await verifyAgainstBundle(payload, value, "receipt", receipt.keyId, now, bundle);
  assert.equal(res.ok, false);
  assert.equal(res.reason, "SIGNATURE_INVALID");
});

// ── tampered / stale ─────────────────────────────────────────────────────────
test("tampered bundle fails signature verification", async () => {
  const { bundle, now } = await makeProductionFixture();
  const tampered = structuredClone(bundle);
  tampered.authority_id = "attacker-controlled";
  const res = await verifyAuthorityBundle(tampered, { trustedRootFingerprint: bundle.root_key.fingerprint, now });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "BUNDLE_SIGNATURE_INVALID");
});

test("swapped root key (fingerprint mismatch) fails", async () => {
  const { bundle, now } = await makeProductionFixture();
  const tampered = structuredClone(bundle);
  tampered.root_key.public_key = generateAuthorityKeyPair().publicPem; // fingerprint no longer matches
  const res = await verifyAuthorityBundle(tampered, { now });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "ROOT_FINGERPRINT_MISMATCH");
});

test("verifier rejects a stale bundle (past not_after)", async () => {
  const { bundle } = await makeProductionFixture();
  const res = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: bundle.root_key.fingerprint, now: "2028-01-01T00:00:00.000Z" });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "BUNDLE_STALE");
});

test("verifier rejects a bundle older than maxAgeMs", async () => {
  const { bundle, now } = await makeProductionFixture();
  const dayLater = "2026-06-15T00:01:00.000Z";
  const res = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: bundle.root_key.fingerprint, now: dayLater, maxAgeMs: 24 * 60 * 60 * 1000 });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "BUNDLE_STALE");
  // Within maxAge it still passes.
  assert.equal((await (await verifyAuthorityBundle(bundle, { trustedRootFingerprint: bundle.root_key.fingerprint, now, maxAgeMs: 24 * 60 * 60 * 1000 }))).ok, true);
});

// ── file-backed-production: missing/malformed config fails closed ────────────
test("missing bundle fails closed (createCustody returns ok:false)", async () => {
  const res = await createCustody({ MNDE_KEY_CUSTODY: "file-backed-production", MNDE_AUTHORITY_BUNDLE: join(tmpdir(), "does-not-exist-xyz.json") });
  assert.equal(res.ok, false);
  assert.match(res.reason, /cannot read MNDE_AUTHORITY_BUNDLE/);
});

test("unknown custody mode fails closed", async () => {
  const res = await createCustody({ MNDE_KEY_CUSTODY: "magic-vault" });
  assert.equal(res.ok, false);
  assert.match(res.reason, /unknown MNDE_KEY_CUSTODY/);
});

test("file-backed-production loads a real bundle + key and signs verifiably", async () => {
  const dir = mkdtempSync(join(tmpdir(), "mnde-custody-"));
  try {
    const { bundle, receipt } = await makeProductionFixture();
    const bundlePath = join(dir, "authority.bundle.json");
    const keyPath = join(dir, "receipt.key.pem");
    writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
    writeFileSync(keyPath, receipt.privatePem, "utf8");

    const provider = createFileBackedProductionCustody({
      MNDE_AUTHORITY_BUNDLE: bundlePath,
      MNDE_RECEIPT_SIGNING_KEY: keyPath,
      MNDE_RECEIPT_KEY_ID: receipt.keyId
    });
    assert.equal(provider.mode, "file-backed-production");
    assert.equal(provider.production, true);

    const payload = canonicalizeJson({ decision: "ALLOW", from: "file-backed" });
    const sig = await provider.signReceipt(payload);
    const pub = provider.getPublicBundle();
    assert.equal((await verifyAgainstBundle(payload, sig.value, "receipt", sig.key_id, "2026-06-14T00:00:00.000Z", pub)).ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── no secrets anywhere ──────────────────────────────────────────────────────
test("no private key material in bundle, signature, or error output", async () => {
  // Published bundle has zero private keys.
  const demo = await createLocalDemoCustody();
  const bundleJson = JSON.stringify(demo.getPublicBundle());
  assert.ok(!bundleJson.includes("PRIVATE KEY"), "bundle must not contain private keys");

  // Signature objects carry only key id + signature + fingerprint.
  const sig = await demo.signReceipt(canonicalizeJson({ a: 1 }));
  assert.deepEqual(Object.keys(sig).sort(), ["fingerprint", "key_id", "value"]);
  assert.ok(!JSON.stringify(sig).includes("PRIVATE KEY"));

  // Fail-closed error messages reference paths/reasons, never key bytes.
  const dir = mkdtempSync(join(tmpdir(), "mnde-custody-"));
  try {
    const bundlePath = join(dir, "authority.bundle.json");
    const keyPath = join(dir, "secret.key.pem");
    const secret = generateAuthorityKeyPair().privatePem;
    const { bundle } = await makeProductionFixture();
    writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
    writeFileSync(keyPath, secret, "utf8");
    // Wrong key id → error, and the error must not echo the private key.
    const res = await createCustody({
      MNDE_KEY_CUSTODY: "file-backed-production",
      MNDE_AUTHORITY_BUNDLE: bundlePath,
      MNDE_RECEIPT_SIGNING_KEY: keyPath,
      MNDE_RECEIPT_KEY_ID: "no-such-key"
    });
    assert.equal(res.ok, false);
    assert.ok(!res.reason.includes("PRIVATE KEY"), "error must not contain key material");
    assert.ok(!res.reason.includes(secret.slice(40, 80)), "error must not contain key bytes");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── CUSTODY-ENC-1: passphrase-protected file-backed keys ─────────────────────
// Helper: lay down a bundle + a set of role key files in a fresh temp dir and
// return the env pointing at them. `keys` maps role -> { keyEnv, idEnv, keyId,
// pem }. Caller sets passphrase env vars itself.
function writeCustodyDir(bundle, keys) {
  const dir = mkdtempSync(join(tmpdir(), "mnde-custody-enc-"));
  const env = { MNDE_KEY_CUSTODY: "file-backed-production", MNDE_AUTHORITY_BUNDLE: join(dir, "authority.bundle.json") };
  writeFileSync(env.MNDE_AUTHORITY_BUNDLE, JSON.stringify(bundle), "utf8");
  for (const [role, k] of Object.entries(keys)) {
    const keyPath = join(dir, `${role}.key.pem`);
    writeFileSync(keyPath, k.pem, "utf8");
    env[k.keyEnv] = keyPath;
    env[k.idEnv] = k.keyId;
  }
  return { dir, env };
}

// Encrypted receipt key + correct passphrase → loads, signs, verifies.
test("ENC: encrypted receipt key loads with correct passphrase and signs verifiably", async () => {
  const { bundle, receipt, now } = await makeMultiRoleFixture();
  const { dir, env } = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: encryptPem(receipt.privatePem, RECEIPT_PASS) }
  });
  env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = RECEIPT_PASS;
  try {
    const res = await createCustody(env);
    assert.equal(res.ok, true, res.reason);
    const payload = canonicalizeJson({ decision: "ALLOW", enc: true });
    const sig = await res.provider.signReceipt(payload);
    assert.equal((await verifyAgainstBundle(payload, sig.value, "receipt", sig.key_id, now, res.provider.getPublicBundle())).ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Byte-compat: an encrypted key and the same key unencrypted produce the SAME
// signature bytes, the same key id, and the same fingerprint.
test("ENC: encrypted vs unencrypted same key → identical signature, key id, fingerprint", async () => {
  const { bundle, receipt, now } = await makeMultiRoleFixture();
  const payload = canonicalizeJson({ decision: "ALLOW", stable: 1 });

  const plain = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: receipt.privatePem }
  });
  const enc = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: encryptPem(receipt.privatePem, RECEIPT_PASS) }
  });
  enc.env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = RECEIPT_PASS;
  try {
    const a = await createCustody(plain.env);
    const b = await createCustody(enc.env);
    assert.equal(a.ok && b.ok, true);
    const sa = await a.provider.signReceipt(payload);
    const sb = await b.provider.signReceipt(payload);
    assert.equal(sa.value, sb.value, "Ed25519 is deterministic — encryption at rest must not change signature bytes");
    assert.equal(sa.key_id, sb.key_id);
    assert.equal(sa.fingerprint, sb.fingerprint);
    void now;
  } finally {
    rmSync(plain.dir, { recursive: true, force: true });
    rmSync(enc.dir, { recursive: true, force: true });
  }
});

// Missing passphrase for an encrypted key fails closed with the required code.
test("ENC: encrypted receipt key WITHOUT passphrase fails closed (PASSPHRASE_REQUIRED)", async () => {
  const { bundle, receipt } = await makeMultiRoleFixture();
  const { dir, env } = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: encryptPem(receipt.privatePem, RECEIPT_PASS) }
  });
  try {
    const res = await createCustody(env);
    assert.equal(res.ok, false);
    assert.equal(res.custodyCode, "PASSPHRASE_REQUIRED");
    assert.equal(res.reason, "custody: MNDE_RECEIPT_SIGNING_KEY requires MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE");
    // Maps to the public reason code (not a missing-key code).
    const cfg = await loadSigningConfig({ ...env, MNDE_RECEIPT_SIGNING_MODE: "custody" });
    assert.equal(cfg.ok, false);
    assert.equal(cfg.reason_code, "ERR_CUSTODY_KEY_PASSPHRASE_REQUIRED");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Empty passphrase behaves exactly as missing.
test("ENC: empty passphrase behaves as missing (PASSPHRASE_REQUIRED)", async () => {
  const { bundle, receipt } = await makeMultiRoleFixture();
  const { dir, env } = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: encryptPem(receipt.privatePem, RECEIPT_PASS) }
  });
  env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = "";
  try {
    const res = await createCustody(env);
    assert.equal(res.ok, false);
    assert.equal(res.custodyCode, "PASSPHRASE_REQUIRED");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Wrong passphrase fails closed with the invalid code.
test("ENC: wrong receipt passphrase fails closed (PASSPHRASE_INVALID)", async () => {
  const { bundle, receipt } = await makeMultiRoleFixture();
  const { dir, env } = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: encryptPem(receipt.privatePem, RECEIPT_PASS) }
  });
  env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = "not-the-right-passphrase";
  try {
    const res = await createCustody(env);
    assert.equal(res.ok, false);
    assert.equal(res.custodyCode, "PASSPHRASE_INVALID");
    assert.equal(res.reason, "custody: passphrase for MNDE_RECEIPT_SIGNING_KEY is invalid");
    const cfg = await loadSigningConfig({ ...env, MNDE_RECEIPT_SIGNING_MODE: "custody" });
    assert.equal(cfg.reason_code, "ERR_CUSTODY_KEY_PASSPHRASE_INVALID");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// A one-character whitespace passphrase " " is a real, untrimmed passphrase.
test("ENC: single-space passphrase is honored (not trimmed to empty)", async () => {
  const { bundle, receipt, now } = await makeMultiRoleFixture();
  const { dir, env } = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: encryptPem(receipt.privatePem, " ") }
  });
  env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = " ";
  try {
    const res = await createCustody(env);
    assert.equal(res.ok, true, res.reason);
    const payload = canonicalizeJson({ decision: "ALLOW" });
    const sig = await res.provider.signReceipt(payload);
    assert.equal((await verifyAgainstBundle(payload, sig.value, "receipt", sig.key_id, now, res.provider.getPublicBundle())).ok, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Unencrypted key + a supplied passphrase → provider ignores it; still signs,
// and the signature is unchanged.
test("ENC: passphrase supplied for an UNENCRYPTED key does not alter signatures", async () => {
  const { bundle, receipt, now } = await makeMultiRoleFixture();
  const payload = canonicalizeJson({ decision: "ALLOW", u: 1 });
  const plain = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: receipt.privatePem }
  });
  const withPass = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: receipt.privatePem }
  });
  withPass.env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = "ignored-because-key-is-plaintext";
  try {
    const a = await createCustody(plain.env);
    const b = await createCustody(withPass.env);
    assert.equal(a.ok && b.ok, true);
    const sa = await a.provider.signReceipt(payload);
    const sb = await b.provider.signReceipt(payload);
    assert.equal(sa.value, sb.value);
    assert.equal((await verifyAgainstBundle(payload, sb.value, "receipt", sb.key_id, now, b.provider.getPublicBundle())).ok, true);
  } finally {
    rmSync(plain.dir, { recursive: true, force: true });
    rmSync(withPass.dir, { recursive: true, force: true });
  }
});

// Ledger role: loads + signs; and per-role passphrase isolation both ways.
test("ENC: ledger role loads with its own passphrase and cross-role passphrases do not unlock", async () => {
  const { bundle, receipt, ledger, now } = await makeMultiRoleFixture();
  const encReceipt = encryptPem(receipt.privatePem, RECEIPT_PASS);
  const encLedger = encryptPem(ledger.privatePem, LEDGER_PASS);

  // Correct per-role passphrases: both load, ledger signs + verifies.
  const good = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: encReceipt },
    ledger: { keyEnv: "MNDE_LEDGER_SIGNING_KEY", idEnv: "MNDE_LEDGER_KEY_ID", keyId: ledger.keyId, pem: encLedger }
  });
  good.env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = RECEIPT_PASS;
  good.env.MNDE_LEDGER_SIGNING_KEY_PASSPHRASE = LEDGER_PASS;
  try {
    const res = await createCustody(good.env);
    assert.equal(res.ok, true, res.reason);
    const payload = canonicalizeJson({ ledger: "checkpoint" });
    const sig = await res.provider.signLedger(payload);
    assert.equal((await verifyAgainstBundle(payload, sig.value, "ledger", sig.key_id, now, res.provider.getPublicBundle())).ok, true);
  } finally {
    rmSync(good.dir, { recursive: true, force: true });
  }

  // Receipt's passphrase must NOT unlock the ledger key (and vice versa).
  const swapped = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: encReceipt },
    ledger: { keyEnv: "MNDE_LEDGER_SIGNING_KEY", idEnv: "MNDE_LEDGER_KEY_ID", keyId: ledger.keyId, pem: encLedger }
  });
  swapped.env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = LEDGER_PASS; // wrong for receipt
  swapped.env.MNDE_LEDGER_SIGNING_KEY_PASSPHRASE = RECEIPT_PASS; // wrong for ledger
  try {
    const res = await createCustody(swapped.env);
    assert.equal(res.ok, false);
    assert.equal(res.custodyCode, "PASSPHRASE_INVALID");
  } finally {
    rmSync(swapped.dir, { recursive: true, force: true });
  }
});

// Optional policy role: missing passphrase when configured fails; wrong → invalid.
test("ENC: configured encrypted policy key requires + validates its own passphrase", async () => {
  const { bundle, receipt, policy } = await makeMultiRoleFixture();
  const encReceipt = encryptPem(receipt.privatePem, RECEIPT_PASS);
  const encPolicy = encryptPem(policy.privatePem, POLICY_PASS);

  // Missing policy passphrase → fails even though it is an "optional" role.
  const missing = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: encReceipt },
    policy: { keyEnv: "MNDE_POLICY_SIGNING_KEY", idEnv: "MNDE_POLICY_KEY_ID", keyId: policy.keyId, pem: encPolicy }
  });
  missing.env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = RECEIPT_PASS;
  try {
    const res = await createCustody(missing.env);
    assert.equal(res.ok, false);
    assert.equal(res.custodyCode, "PASSPHRASE_REQUIRED");
    assert.equal(res.reason, "custody: MNDE_POLICY_SIGNING_KEY requires MNDE_POLICY_SIGNING_KEY_PASSPHRASE");
  } finally {
    rmSync(missing.dir, { recursive: true, force: true });
  }

  // Wrong policy passphrase → invalid code.
  const wrong = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: encReceipt },
    policy: { keyEnv: "MNDE_POLICY_SIGNING_KEY", idEnv: "MNDE_POLICY_KEY_ID", keyId: policy.keyId, pem: encPolicy }
  });
  wrong.env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = RECEIPT_PASS;
  wrong.env.MNDE_POLICY_SIGNING_KEY_PASSPHRASE = "wrong-policy-pass";
  try {
    const res = await createCustody(wrong.env);
    assert.equal(res.ok, false);
    assert.equal(res.custodyCode, "PASSPHRASE_INVALID");
    assert.equal(res.reason, "custody: passphrase for MNDE_POLICY_SIGNING_KEY is invalid");
  } finally {
    rmSync(wrong.dir, { recursive: true, force: true });
  }
});

// Retained role object shape: privateKey handle, no privatePem / passphrase.
test("ENC: file-backed role objects retain an opaque handle, never PEM or passphrase", async () => {
  const { bundle, receipt } = await makeMultiRoleFixture();
  const { dir, env } = writeCustodyDir(bundle, {
    receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: encryptPem(receipt.privatePem, RECEIPT_PASS) }
  });
  env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = RECEIPT_PASS;
  try {
    const res = await createCustody(env);
    assert.equal(res.ok, true, res.reason);
    // The provider is a closure; assert via its serialized form that no secret
    // leaks and that signing still works through the opaque handle.
    const serialized = JSON.stringify(res.provider, (_k, v) => (typeof v === "function" ? "[fn]" : v));
    assert.ok(!serialized.includes("PRIVATE KEY"), "provider must not serialize any PEM");
    assert.ok(!serialized.includes(SECRET_MARKER), "provider must not serialize the passphrase");
    assert.ok(!serialized.includes("privatePem"), "no privatePem field on file-backed roles");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Secret-leak sweep: neither failure surface may echo passphrase or PEM material.
test("ENC: no failure surface leaks passphrase or PEM material", async () => {
  const { bundle, receipt } = await makeMultiRoleFixture();
  const encReceipt = encryptPem(receipt.privatePem, RECEIPT_PASS);

  for (const [label, passOverride] of [["missing", undefined], ["invalid", "the-wrong-secret-value"]]) {
    const { dir, env } = writeCustodyDir(bundle, {
      receipt: { keyEnv: "MNDE_RECEIPT_SIGNING_KEY", idEnv: "MNDE_RECEIPT_KEY_ID", keyId: receipt.keyId, pem: encReceipt }
    });
    if (passOverride !== undefined) env.MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE = passOverride;
    try {
      const res = await createCustody(env);
      const cfg = await loadSigningConfig({ ...env, MNDE_RECEIPT_SIGNING_MODE: "custody" });
      const surfaces = [
        res.reason,
        res.custodyCode,
        cfg.reason_code,
        cfg.detail,
        JSON.stringify(res),
        JSON.stringify(cfg)
      ].join("\n");
      assert.ok(!surfaces.includes(SECRET_MARKER), `${label}: must not contain passphrase marker`);
      assert.ok(!surfaces.includes(PEM_HEADER), `${label}: must not contain PEM header`);
      assert.ok(!surfaces.includes("aes-256-cbc"), `${label}: must not contain cipher/openssl detail`);
      assert.ok(!surfaces.includes(encReceipt.slice(40, 90)), `${label}: must not contain PEM body bytes`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

await testChain;
const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL custody tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS custody tests (${results.length}/${results.length})`);
