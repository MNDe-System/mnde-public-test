#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { activateSignedPolicyBundle } from "../src/policy-bundles/index.mjs";

const NOW = "2026-08-15T12:00:00.000Z";
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = join(repoRoot, "tools", "sign-policy-bundle.mjs");

// Temp-dir teardown is best-effort and must never fail a test. On Windows a
// recursive rmSync of a just-spawned child's working dir can transiently throw
// EBUSY/EPERM when AV/indexer/a lingering handle holds a file — more likely
// under full-suite load, which is why this suite passed in isolation but
// occasionally failed in the full run. Retry, then swallow.
function safeCleanup(dir) {
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
  } catch {
    // ignore: cleanup of a scratch temp dir is not part of the assertion under test
  }
}
let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function policy(version = "1.0.0") {
  return {
    schema_version: "1.0",
    policy_id: "editor-policy",
    version,
    state: "ACTIVE",
    rules: [{ rule_id: "allow-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }]
  };
}

async function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "mnde-sign-policy-cli-"));
  const root = { keyId: "root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const authorityBundle = await buildAuthorityBundle({
    authorityId: "mnde-sign-policy-cli-test",
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const keyPath = join(dir, "policy-key.pem");
  writeFileSync(keyPath, policyKey.privatePem, "utf8");
  return { dir, policyKey, authorityBundle, keyPath, statePath: join(dir, "state.json") };
}

function runCli(f, { serial = 1, document = policy(), keyPath = f.keyPath, keyId = f.policyKey.keyId, outName = `bundle-${serial}.json`, extra = [] } = {}) {
  const policyPath = join(f.dir, `policy-${serial}-${document.version ?? "unknown"}.json`);
  const outPath = join(f.dir, outName);
  writeFileSync(policyPath, JSON.stringify(document), "utf8");
  const result = spawnSync(process.execPath, [
    cliPath,
    policyPath,
    "--key", keyPath,
    "--key-id", keyId,
    "--serial", String(serial),
    "--issued-at", NOW,
    "--out", outPath,
    ...extra
  ], { cwd: repoRoot, encoding: "utf8", windowsHide: true });
  return { result, policyPath, outPath, bundle: result.status === 0 ? JSON.parse(readFileSync(outPath, "utf8")) : null };
}

async function activate(f, bundle) {
  return await activateSignedPolicyBundle({
    bundle,
    authorityBundle: f.authorityBundle,
    trustedRootFingerprint: f.authorityBundle.root_key.fingerprint,
    statePath: f.statePath,
    now: NOW
  });
}

console.log("Policy bundle signing CLI — end-to-end and hostile tests\n");

await test("CLI output activates through the real signed-bundle gate", async () => {
  const f = await fixture();
  try {
    const { result, bundle } = runCli(f);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(bundle.schema_version, "mnde.policy.bundle.v1");
    assert.equal(bundle.signing_key_id, f.policyKey.keyId);
    const activated = await activate(f, bundle);
    assert.equal(activated.ok, true, activated.reason);
    assert.equal(activated.policy.policy_id, "editor-policy");
  } finally { safeCleanup(f.dir); }
});

await test("tampering the signed policy is rejected by its policy hash", async () => {
  const f = await fixture();
  try {
    const { bundle } = runCli(f);
    bundle.policy_document.version = "tampered";
    const result = await activate(f, bundle);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "POLICY_BUNDLE_POLICY_HASH_MISMATCH");
  } finally { safeCleanup(f.dir); }
});

await test("tampering the signature is rejected", async () => {
  const f = await fixture();
  try {
    const { bundle } = runCli(f);
    // Flip one bit of the first signature byte. A bit flip cannot be a no-op,
    // and it does not depend on how the byte happens to be spelled.
    //
    // This mutation used to rewrite the first hex CHARACTER to "A". Signatures
    // are lowercase hex and hex decoding is case-insensitive, so whenever a
    // signature began with "a" the rewrite produced identical bytes, the
    // verifier correctly accepted an untampered signature, and this test either
    // failed for no reason or — the half that matters — asserted nothing at all.
    // Measured at ~6.29% of signatures, i.e. roughly one run in sixteen.
    const original = Buffer.from(bundle.signature.value, "hex");
    const tampered = Buffer.from(original);
    tampered[0] ^= 0x01;
    bundle.signature.value = tampered.toString("hex");
    // Assert on what the verifier will actually decode, not on what we meant to
    // write. That distinction is precisely what the old mutation got wrong, so
    // the guard has to re-parse the field rather than trust the buffer above.
    assert.notDeepEqual(
      Buffer.from(bundle.signature.value, "hex"),
      original,
      "the tampered signature must differ from the original at the decoded-byte level"
    );
    const result = await activate(f, bundle);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "POLICY_BUNDLE_SIGNATURE_INVALID");
  } finally { safeCleanup(f.dir); }
});

await test("a foreign private key cannot impersonate the trusted policy key id", async () => {
  const f = await fixture();
  try {
    const foreign = generateAuthorityKeyPair();
    const foreignPath = join(f.dir, "foreign-key.pem");
    writeFileSync(foreignPath, foreign.privatePem, "utf8");
    const { result: cli, bundle } = runCli(f, { keyPath: foreignPath });
    assert.equal(cli.status, 0, cli.stderr);
    const result = await activate(f, bundle);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "POLICY_BUNDLE_SIGNATURE_INVALID");
  } finally { safeCleanup(f.dir); }
});

await test("serial reuse with different signed content is refused", async () => {
  const f = await fixture();
  try {
    const first = runCli(f, { serial: 7, document: policy("7.0.0"), outName: "first.json" }).bundle;
    assert.equal((await activate(f, first)).ok, true);
    const replacement = runCli(f, { serial: 7, document: policy("7.0.1"), outName: "replacement.json" }).bundle;
    const result = await activate(f, replacement);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "POLICY_BUNDLE_SERIAL_REUSE_REFUSED");
  } finally { safeCleanup(f.dir); }
});

await test("serial rollback without authorization is refused", async () => {
  const f = await fixture();
  try {
    const current = runCli(f, { serial: 9, document: policy("9.0.0"), outName: "current.json" }).bundle;
    assert.equal((await activate(f, current)).ok, true);
    const stale = runCli(f, { serial: 8, document: policy("8.0.0"), outName: "stale.json" }).bundle;
    const result = await activate(f, stale);
    assert.equal(result.ok, false);
    assert.equal(result.reason, "POLICY_BUNDLE_SERIAL_ROLLBACK_REFUSED");
  } finally { safeCleanup(f.dir); }
});

await test("CLI rejects malformed input and dangerous output paths without leaking key material", async () => {
  const f = await fixture();
  try {
    const badSchema = runCli(f, { document: { ...policy(), schema_version: "2.0" }, outName: "bad-schema.json" });
    assert.equal(badSchema.result.status, 1);
    assert.equal(badSchema.result.stdout, "");

    const badSerial = runCli(f, { extra: ["--serial", "0"], outName: "bad-serial.json" });
    assert.equal(badSerial.result.status, 1);

    const unknown = runCli(f, { extra: ["--typo", "value"], outName: "unknown.json" });
    assert.equal(unknown.result.status, 1);
    assert.match(unknown.result.stderr, /unknown option --typo/);

    const policyPath = join(f.dir, "overwrite-policy.json");
    writeFileSync(policyPath, JSON.stringify(policy()), "utf8");
    const overwrite = spawnSync(process.execPath, [cliPath, policyPath, "--key", f.keyPath, "--key-id", f.policyKey.keyId, "--serial", "1", "--out", f.keyPath], { cwd: repoRoot, encoding: "utf8", windowsHide: true });
    assert.equal(overwrite.status, 1);
    assert.match(overwrite.stderr, /must not overwrite the signing key/);
    assert.ok(!`${badSchema.result.stderr}${badSerial.result.stderr}${unknown.result.stderr}${overwrite.stderr}`.includes(f.policyKey.privatePem));
  } finally { safeCleanup(f.dir); }
});

console.log(`\n${failed === 0 ? "PASS" : "FAIL"} policy bundle signing CLI (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
