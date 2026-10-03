// Crypto provider seam.
//
// All node:crypto usage in MNDe is funneled through one of the provider modules
// in this directory so the same code runs on Node today and on an edge runtime
// (WebCrypto) later. Outside src/crypto/, nothing imports node:crypto directly,
// except Node-only key-authoring / lifecycle tooling (key generation, PEM
// authoring) which has no edge equivalent.
//
// Async contract:
//   sign() and verify() are ASYNC because the future WebCrypto provider's
//   SubtleCrypto.sign / SubtleCrypto.verify are async-only. Every caller must
//   await them.
//
//   sha256(), spkiFingerprint(), constantTimeEqual(), randomBytes(),
//   generateKeyPair() and now() are SYNCHRONOUS — each is implementable
//   synchronously in both Node and edge runtimes, so they never went async.
//
// Provider selection is via MNDE_CRYPTO_PROVIDER (default "node"). The WebCrypto
// provider arrives in Track A.3; until then any other value fails loud.

import * as nodeProvider from "./node-provider.mjs";

function select() {
  const requested =
    (typeof process !== "undefined" && process.env && process.env.MNDE_CRYPTO_PROVIDER) || "node";
  if (requested === "node") return nodeProvider;
  throw new Error(`crypto provider: unsupported MNDE_CRYPTO_PROVIDER '${requested}' (only "node" is available)`);
}

const active = select();

export const PROVIDER_NAME = active.PROVIDER_NAME;

// Synchronous primitives.
export const sha256 = active.sha256;
export const spkiFingerprint = active.spkiFingerprint;
export const constantTimeEqual = active.constantTimeEqual;
export const randomBytes = active.randomBytes;
export const generateKeyPair = active.generateKeyPair;
export const now = active.now;

// Import private signing material into an opaque, provider-specific handle.
// Callers must not inspect, serialize, or export private material from it; they
// pass it straight back to sign(). Synchronous in both Node and edge runtimes.
export const importPrivateKey = active.importPrivateKey;

// Asynchronous primitives (WebCrypto-compatible signature).
export const sign = active.sign;
export const verify = active.verify;
