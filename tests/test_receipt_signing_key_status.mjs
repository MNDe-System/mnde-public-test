#!/usr/bin/env node

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

if (process.argv[2] === "--probe") {
  const { receiptSigningKeyStatus } = await import("../shared/receipt-signing.ts");
  process.stdout.write(`${JSON.stringify(receiptSigningKeyStatus())}\n`);
} else {

const thisFile = fileURLToPath(import.meta.url);

function generatePair() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicPem: publicKey.export({ type: "spki", format: "pem" })
  };
}

function keyPaths(home) {
  const keyDir = join(home, "shared", "receipt_keys");
  return {
    keyDir,
    privatePath: join(keyDir, "receipt_signing_private.pem"),
    publicPath: join(keyDir, "receipt_signing_public.pem")
  };
}

function writePair(home, pair = generatePair()) {
  const paths = keyPaths(home);
  mkdirSync(paths.keyDir, { recursive: true });
  writeFileSync(paths.privatePath, pair.privatePem);
  writeFileSync(paths.publicPath, pair.publicPem);
  return { ...paths, pair };
}

function probe(home) {
  const result = spawnSync(process.execPath, [thisFile, "--probe"], {
    encoding: "utf8",
    env: { ...process.env, MNDE_HOME: home }
  });
  assert.equal(result.status, 0, `key-status probe failed:\n${result.stdout}\n${result.stderr}`);
  return JSON.parse(result.stdout);
}

const cases = [];
function test(name, fn) {
  const home = mkdtempSync(join(tmpdir(), "mnde-key-status-"));
  try {
    fn(home);
    cases.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    cases.push(false);
    console.error(`  [FAIL] ${name}: ${error.message}`);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

test("valid private/public pair passes", (home) => {
  writePair(home);
  assert.deepEqual(probe(home), { ok: true, reason: null });
});

test("individually valid but mismatched pair fails", (home) => {
  const first = generatePair();
  const second = generatePair();
  const paths = writePair(home, first);
  writeFileSync(paths.publicPath, second.publicPem);
  const status = probe(home);
  assert.equal(status.ok, false);
  assert.match(status.reason, /^ERR_RECEIPT_SIGNING_KEYS_MISMATCHED:/);
});

test("malformed private key fails with a private-key diagnostic", (home) => {
  const paths = writePair(home);
  writeFileSync(paths.privatePath, "not a private key");
  const status = probe(home);
  assert.equal(status.ok, false);
  assert.match(status.reason, /^ERR_RECEIPT_SIGNING_PRIVATE_KEY_INVALID:/);
});

test("malformed public key fails without making the module unimportable", (home) => {
  const paths = writePair(home);
  writeFileSync(paths.publicPath, "not a public key");
  const status = probe(home);
  assert.equal(status.ok, false);
  assert.match(status.reason, /^ERR_RECEIPT_SIGNING_PUBLIC_KEY_INVALID:/);
});

test("missing private key fails", (home) => {
  const paths = writePair(home);
  unlinkSync(paths.privatePath);
  const status = probe(home);
  assert.equal(status.ok, false);
  assert.match(status.reason, /^ERR_RECEIPT_SIGNING_KEYS_MISSING:/);
});

test("missing public key fails", (home) => {
  const paths = writePair(home);
  unlinkSync(paths.publicPath);
  const status = probe(home);
  assert.equal(status.ok, false);
  assert.match(status.reason, /^ERR_RECEIPT_SIGNING_KEYS_MISSING:/);
});

test("both key files missing fails", (home) => {
  const paths = keyPaths(home);
  mkdirSync(dirname(paths.privatePath), { recursive: true });
  const status = probe(home);
  assert.equal(status.ok, false);
  assert.match(status.reason, /^ERR_RECEIPT_SIGNING_KEYS_MISSING:/);
});

const passed = cases.filter(Boolean).length;
if (passed !== cases.length) {
  console.error(`\nFAIL receipt signing key status tests (${passed}/${cases.length})`);
  process.exit(1);
}
console.log(`\nPASS receipt signing key status tests (${passed}/${cases.length})`);
}
