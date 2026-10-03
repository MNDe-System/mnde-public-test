// Root-signing capability.
//
// Root-authority operations consume this capability instead of assuming that
// the root private key is present in process memory. The adapters below preserve
// the existing Ed25519 wire format while allowing the key to live behind an
// isolated command/HSM boundary. Every signature is verified before it leaves
// the capability.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { sign as providerSign, spkiFingerprint, verify as providerVerify } from "../crypto/provider.mjs";

const DEFAULT_TIMEOUT_MS = 5000;
const ED25519_SIG_HEX = /^[0-9a-f]{128}$/i;

export const ROOT_SIGNER_ERRORS = Object.freeze({
  INVALID: "ERR_ROOT_SIGNER_INVALID",
  KEY_MISMATCH: "ERR_ROOT_SIGNER_KEY_MISMATCH",
  SIGNING_FAILED: "ERR_ROOT_SIGNER_FAILED",
  SIGNATURE_INVALID: "ERR_ROOT_SIGNER_SIGNATURE_INVALID",
  PEM_FALLBACK_FORBIDDEN: "ERR_ROOT_PEM_FALLBACK_FORBIDDEN"
});

export class RootSignerError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "RootSignerError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new RootSignerError(code, message);
}

function nonEmpty(value) {
  return typeof value === "string" && value.length > 0;
}

function parseArgv(cmd, envName) {
  if (!nonEmpty(cmd?.trim())) fail(ROOT_SIGNER_ERRORS.INVALID, `${envName} not configured`);
  const text = cmd.trim();
  if (text.startsWith("[")) {
    let argv;
    try { argv = JSON.parse(text); } catch { fail(ROOT_SIGNER_ERRORS.INVALID, `${envName} is not a valid JSON array`); }
    if (!Array.isArray(argv) || argv.length === 0 || !argv.every(nonEmpty)) {
      fail(ROOT_SIGNER_ERRORS.INVALID, `${envName} must be a non-empty array of strings`);
    }
    return argv;
  }
  return text.split(/\s+/u);
}

function loadPublicKey(value, envName) {
  if (!nonEmpty(value)) fail(ROOT_SIGNER_ERRORS.INVALID, `${envName} not configured`);
  let publicKeyPem = value;
  if (!value.includes("BEGIN PUBLIC KEY")) {
    try { publicKeyPem = readFileSync(value, "utf8"); }
    catch { fail(ROOT_SIGNER_ERRORS.INVALID, `cannot read ${envName} at ${value}`); }
  }
  try { spkiFingerprint(publicKeyPem); }
  catch { fail(ROOT_SIGNER_ERRORS.INVALID, `${envName} is not a valid public key`); }
  return publicKeyPem;
}

function normalizeRoot(root = {}) {
  const keyId = root.keyId ?? root.key_id;
  const publicKeyPem = root.publicKeyPem ?? root.publicPem ?? root.public_key;
  if (!nonEmpty(keyId) || !nonEmpty(publicKeyPem)) {
    fail(ROOT_SIGNER_ERRORS.INVALID, "root key id and public key are required");
  }
  let fingerprint;
  try { fingerprint = spkiFingerprint(publicKeyPem); }
  catch { fail(ROOT_SIGNER_ERRORS.INVALID, "root public key is invalid"); }
  if (nonEmpty(root.fingerprint) && root.fingerprint !== fingerprint) {
    fail(ROOT_SIGNER_ERRORS.KEY_MISMATCH, "root public-key fingerprint does not match");
  }
  return { keyId, publicKeyPem, fingerprint };
}

export function assertRootSignerIdentity(rootSigner, root) {
  const expected = normalizeRoot(root);
  if (!rootSigner || typeof rootSigner.sign !== "function") {
    fail(ROOT_SIGNER_ERRORS.INVALID, "root signer capability is missing sign(payload)");
  }
  if (!nonEmpty(rootSigner.keyId) || !nonEmpty(rootSigner.publicKeyPem) || !nonEmpty(rootSigner.fingerprint)) {
    fail(ROOT_SIGNER_ERRORS.INVALID, "root signer identity is incomplete");
  }
  let signerFingerprint;
  try { signerFingerprint = spkiFingerprint(rootSigner.publicKeyPem); }
  catch { fail(ROOT_SIGNER_ERRORS.INVALID, "root signer public key is invalid"); }
  if (
    rootSigner.keyId !== expected.keyId
    || rootSigner.fingerprint !== signerFingerprint
    || signerFingerprint !== expected.fingerprint
  ) {
    fail(ROOT_SIGNER_ERRORS.KEY_MISMATCH, "root signer does not match the published root key");
  }
  return rootSigner;
}

async function verifiedResult(payload, result, identity) {
  if (
    !result
    || result.key_id !== identity.keyId
    || result.fingerprint !== identity.fingerprint
    || !nonEmpty(result.value)
    || !ED25519_SIG_HEX.test(result.value)
  ) {
    fail(ROOT_SIGNER_ERRORS.SIGNATURE_INVALID, "root signer returned malformed or mismatched signature metadata");
  }
  let verified = false;
  try { verified = await providerVerify(payload, result.value, identity.publicKeyPem); }
  catch { verified = false; }
  if (!verified) fail(ROOT_SIGNER_ERRORS.SIGNATURE_INVALID, "root signature did not verify against the published root key");
  return { key_id: identity.keyId, value: result.value.toLowerCase(), fingerprint: identity.fingerprint };
}

export function createFileRootSigner({ keyId, publicKeyPem, privateKeyPem } = {}) {
  const identity = normalizeRoot({ keyId, publicPem: publicKeyPem });
  if (!nonEmpty(privateKeyPem)) fail(ROOT_SIGNER_ERRORS.INVALID, "root private key is required for file-backed signing");
  return Object.freeze({
    mode: "file-root-signer",
    ...identity,
    async sign(payload) {
      if (!nonEmpty(payload)) fail(ROOT_SIGNER_ERRORS.INVALID, "root signing payload must be a non-empty string");
      let value;
      try { value = await providerSign(payload, privateKeyPem); }
      catch { fail(ROOT_SIGNER_ERRORS.SIGNING_FAILED, "file-backed root signer failed"); }
      return verifiedResult(payload, { key_id: identity.keyId, value, fingerprint: identity.fingerprint }, identity);
    }
  });
}

export function createExternalRootSigner(env = process.env, options = {}) {
  const argv = parseArgv(env.MNDE_EXTERNAL_ROOT_SIGNER_CMD, "MNDE_EXTERNAL_ROOT_SIGNER_CMD");
  const publicKeyPem = loadPublicKey(
    env.MNDE_EXTERNAL_ROOT_SIGNER_PUBLIC_KEY ?? options.publicKeyPem,
    "MNDE_EXTERNAL_ROOT_SIGNER_PUBLIC_KEY"
  );
  const keyId = env.MNDE_EXTERNAL_ROOT_SIGNER_KEY_ID ?? options.keyId;
  const identity = normalizeRoot({ keyId, publicPem: publicKeyPem });
  const rawTimeout = Number(env.MNDE_EXTERNAL_ROOT_SIGNER_TIMEOUT_MS);
  const timeoutMs = Number.isFinite(rawTimeout) && rawTimeout > 0 ? rawTimeout : DEFAULT_TIMEOUT_MS;

  return Object.freeze({
    mode: "external-root-signer",
    ...identity,
    async sign(payload) {
      if (!nonEmpty(payload)) fail(ROOT_SIGNER_ERRORS.INVALID, "root signing payload must be a non-empty string");
      const result = spawnSync(argv[0], argv.slice(1), {
        input: Buffer.from(payload, "utf8"),
        timeout: timeoutMs,
        maxBuffer: 1024 * 1024
      });
      if (result.error) fail(ROOT_SIGNER_ERRORS.SIGNING_FAILED, `external root signer failed (${result.error.code ?? result.error.message ?? "spawn error"})`);
      if (result.status !== 0) {
        fail(ROOT_SIGNER_ERRORS.SIGNING_FAILED, `external root signer exited ${result.status === null ? `via signal ${result.signal}` : `with code ${result.status}`}`);
      }
      const value = (result.stdout ? result.stdout.toString("utf8") : "").trim();
      return verifiedResult(payload, { key_id: identity.keyId, value, fingerprint: identity.fingerprint }, identity);
    }
  });
}

// Mandatory production boundary: callers that select external-root mode must
// obtain their capability here. A configured external signer can never fall
// back to a supplied PEM, even when the command is unavailable or misconfigured.
export function resolveRootSigner({ env = process.env, root, rootSigner, rootPrivateKeyPem } = {}) {
  const expected = normalizeRoot(root);
  const externalMode = nonEmpty(env.MNDE_EXTERNAL_ROOT_SIGNER_CMD?.trim());
  if (externalMode && nonEmpty(rootPrivateKeyPem)) {
    fail(ROOT_SIGNER_ERRORS.PEM_FALLBACK_FORBIDDEN, "external-root mode forbids root PEM fallback");
  }
  const resolved = rootSigner
    ?? (externalMode
      ? createExternalRootSigner(env, expected)
      : createFileRootSigner({ ...expected, privateKeyPem: rootPrivateKeyPem }));
  if (externalMode && resolved.mode === "file-root-signer") {
    fail(ROOT_SIGNER_ERRORS.PEM_FALLBACK_FORBIDDEN, "external-root mode forbids a file-backed root signer");
  }
  return assertRootSignerIdentity(resolved, expected);
}

export async function signWithRootSigner(rootSigner, payload, root) {
  const signer = assertRootSignerIdentity(rootSigner, root);
  let result;
  try { result = await signer.sign(payload); }
  catch (error) {
    if (error instanceof RootSignerError) throw error;
    fail(ROOT_SIGNER_ERRORS.SIGNING_FAILED, "root signer failed");
  }
  return verifiedResult(payload, result, normalizeRoot(root));
}
