// Crypto provider tests — private-key import + signing (CUSTODY-ENC-1).
//
//   npm run test:crypto-provider
//
// Focused, offline coverage of the provider seam's new importPrivateKey() and of
// sign() accepting either a PEM string (unchanged path) or an imported opaque
// KeyObject handle. Ed25519 only. Does NOT assert raw OpenSSL error text.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import { importPrivateKey, sign, verify } from "../src/crypto/provider.mjs";

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

const TEST_PASSPHRASE = "custody-enc-1-test-only-passphrase";

// A fresh Ed25519 keypair as PEMs: public (SPKI), private plaintext (PKCS#8),
// and private encrypted (PKCS#8, aes-256-cbc) under TEST_PASSPHRASE.
function makeKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicPem: publicKey.export({ type: "spki", format: "pem" }),
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }),
    encryptedPem: privateKey.export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: TEST_PASSPHRASE })
  };
}

const MESSAGE = '{"mnde.provider.selftest":true}';

await test("imports a valid unencrypted Ed25519 PKCS#8 key", async () => {
  const k = makeKey();
  const handle = importPrivateKey(k.privatePem);
  assert.equal(handle.type, "private");
  assert.equal(handle.asymmetricKeyType, "ed25519");
});

await test("imports a valid encrypted Ed25519 PKCS#8 key with the correct passphrase", async () => {
  const k = makeKey();
  const handle = importPrivateKey(k.encryptedPem, { passphrase: TEST_PASSPHRASE });
  assert.equal(handle.type, "private");
  assert.equal(handle.asymmetricKeyType, "ed25519");
});

await test("rejects an encrypted key with no passphrase", async () => {
  const k = makeKey();
  assert.throws(() => importPrivateKey(k.encryptedPem));
});

await test("rejects an encrypted key with the wrong passphrase", async () => {
  const k = makeKey();
  assert.throws(() => importPrivateKey(k.encryptedPem, { passphrase: "wrong" }));
});

await test("signs with an imported unencrypted handle and verifies", async () => {
  const k = makeKey();
  const handle = importPrivateKey(k.privatePem);
  const sig = await sign(MESSAGE, handle);
  assert.match(sig, /^[0-9a-f]+$/);
  assert.equal(await verify(MESSAGE, sig, k.publicPem), true);
});

await test("signs with an imported encrypted handle and verifies", async () => {
  const k = makeKey();
  const handle = importPrivateKey(k.encryptedPem, { passphrase: TEST_PASSPHRASE });
  const sig = await sign(MESSAGE, handle);
  assert.equal(await verify(MESSAGE, sig, k.publicPem), true);
});

await test("PEM-string signing (legacy path) still works", async () => {
  const k = makeKey();
  const sig = await sign(MESSAGE, k.privatePem);
  assert.equal(await verify(MESSAGE, sig, k.publicPem), true);
});

await test("handle and PEM paths produce identical (deterministic) signature bytes", async () => {
  const k = makeKey();
  const viaPem = await sign(MESSAGE, k.privatePem);
  const viaPlainHandle = await sign(MESSAGE, importPrivateKey(k.privatePem));
  const viaEncHandle = await sign(MESSAGE, importPrivateKey(k.encryptedPem, { passphrase: TEST_PASSPHRASE }));
  assert.equal(viaPlainHandle, viaPem);
  assert.equal(viaEncHandle, viaPem);
});

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL crypto provider tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS crypto provider tests (${results.length}/${results.length})`);
