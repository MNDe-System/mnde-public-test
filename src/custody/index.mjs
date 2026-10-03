// Key-custody abstraction.
//
// MNDe needs signing material to live SOMEWHERE. For local development and demos
// that is an ephemeral in-process keypair. For production it must be a managed
// trust root whose private keys never leave the custody boundary. This module
// hides that choice behind one interface so the rest of the system never holds a
// private key directly and never has to know where signing happens.
//
//   provider.signReceipt(canonicalPayload)  -> { key_id, value, fingerprint }
//   provider.signPolicy(canonicalPayload)   -> { key_id, value, fingerprint }
//   provider.signApproval(canonicalPayload) -> { key_id, value, fingerprint }
//   provider.signResult(canonicalPayload)   -> { key_id, value, fingerprint }
//   provider.signLedger(canonicalPayload)   -> { key_id, value, fingerprint }
//   provider.getPublicBundle()              -> mnde.authority.bundle.v1 (public only)
//
// Selection is opt-in and fails closed:
//
//   MNDE_KEY_CUSTODY unset / "local-demo"        -> local-demo  (DEFAULT)
//   MNDE_KEY_CUSTODY = "file-backed-production"  -> file-backed-production (opt-in)
//
// Any production misconfiguration (missing / malformed / unsigned / unverifiable
// bundle, missing signing key) makes createCustody() return { ok:false } rather
// than silently degrading to demo keys.
//
// FUTURE PROVIDER SLOTS (documented, intentionally not implemented here):
//   - aws-kms        sign via AWS KMS asymmetric key; private key never exported
//   - azure-key-vault sign via Azure Key Vault
//   - gcp-kms        sign via Google Cloud KMS
//   - hsm-pkcs11     sign via on-prem HSM through PKCS#11
// Each would implement the same four methods; only getPublicBundle() + the sign*
// calls change. Verification (verifyAuthorityBundle / verifyAgainstBundle) is
// provider-independent and stays offline.

import { readFileSync } from "node:fs";

import { importPrivateKey } from "../crypto/provider.mjs";
import {
  buildAuthorityBundle,
  generateAuthorityKeyPair,
  signCanonical
} from "./bundle.mjs";

export * from "./bundle.mjs";
export { createExternalSignerCustody } from "./external-signer.mjs";
export * from "./root-signer.mjs";

export const KNOWN_PROVIDERS = Object.freeze(["local-demo", "file-backed-production", "external-signer"]);
export const FUTURE_PROVIDERS = Object.freeze(["aws-kms", "azure-key-vault", "gcp-kms", "hsm-pkcs11"]);

const FAR_FUTURE = "2999-01-01T00:00:00.000Z";
const EPOCH = "1970-01-01T00:00:00.000Z";

// ── local-demo (DEFAULT) ─────────────────────────────────────────────────────
// Ephemeral in-process keys. NOT production custody: keys live in memory, the
// root is self-asserted, and nothing is durable. Good enough to develop and
// demo the full sign/verify loop offline.
export async function createLocalDemoCustody(options = {}) {
  const issuedAt = options.now ?? new Date().toISOString();
  const root = { keyId: "local-demo-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "local-demo-receipt", ...generateAuthorityKeyPair() };
  const policy = { keyId: "local-demo-policy", ...generateAuthorityKeyPair() };
  const approval = { keyId: "local-demo-approval", ...generateAuthorityKeyPair() };
  const result = { keyId: "local-demo-result", ...generateAuthorityKeyPair() };
  const ledger = { keyId: "local-demo-ledger", ...generateAuthorityKeyPair() };
  const activation = { keyId: "local-demo-activation", ...generateAuthorityKeyPair() };

  const bundle = await buildAuthorityBundle({
    authorityId: "mnde-local-demo",
    issuedAt,
    notAfter: FAR_FUTURE,
    root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: EPOCH, validUntil: FAR_FUTURE }],
    policyKeys: [{ keyId: policy.keyId, publicPem: policy.publicPem, validFrom: EPOCH, validUntil: FAR_FUTURE }],
    approvalKeys: [{ keyId: approval.keyId, publicPem: approval.publicPem, validFrom: EPOCH, validUntil: FAR_FUTURE }],
    resultKeys: [{ keyId: result.keyId, publicPem: result.publicPem, validFrom: EPOCH, validUntil: FAR_FUTURE }],
    ledgerKeys: [{ keyId: ledger.keyId, publicPem: ledger.publicPem, validFrom: EPOCH, validUntil: FAR_FUTURE }],
    activationKeys: [{ keyId: activation.keyId, publicPem: activation.publicPem, validFrom: EPOCH, validUntil: FAR_FUTURE }],
    revocation: []
  });

  const signWith = (role, key) => async (payload) => ({
    key_id: key.keyId,
    value: await signCanonical(payload, key.privatePem),
    fingerprint: bundle.keys[role][0].fingerprint
  });

  return {
    mode: "local-demo",
    production: false,
    trustedRootFingerprint: bundle.root_key.fingerprint,
    signReceipt: signWith("receipt", receipt),
    signPolicy: signWith("policy", policy),
    signApproval: signWith("approval", approval),
    signResult: signWith("result", result),
    signLedger: signWith("ledger", ledger),
    signActivation: signWith("activation", activation),
    getPublicBundle: () => structuredClone(bundle)
  };
}

// ── file-backed-production (opt-in) ──────────────────────────────────────────
// Loads a published PUBLIC bundle plus the role private keys from the filesystem.
// This is a real, deployable custody mode (keys outside the codebase, durable,
// rotatable, revocable) and the reference for how a KMS/HSM provider plugs in.
// Errors here are thrown (never logged with key material) so createCustody()
// can fail closed.
function readKeyFile(label, path) {
  if (typeof path !== "string" || path.length === 0) {
    throw new Error(`custody: ${label} not configured`);
  }
  try {
    return readFileSync(path, "utf8");
  } catch {
    // Deliberately does NOT include file contents — only the path it tried.
    throw new Error(`custody: cannot read ${label} at ${path}`);
  }
}

// Custody-owned configuration error. Carries only SAFE metadata: a stable
// custodyCode and the two env-variable NAMES involved. It never carries the
// passphrase, the PEM, a file buffer, or the underlying provider error — nothing
// downstream (logger, HTTP serializer) can traverse it to a secret.
export class CustodyConfigurationError extends Error {
  constructor(custodyCode, { keyEnv, passphraseEnv, message }) {
    super(message);
    this.name = "CustodyConfigurationError";
    this.custodyCode = custodyCode;
    this.keyEnv = keyEnv;
    this.passphraseEnv = passphraseEnv;
  }
}

// Detect a passphrase-protected PKCS#8 key by inspecting the PEM opening label.
// Used ONLY to distinguish a missing required passphrase from malformed material;
// Node still owns all real parsing, decryption, and validation.
//
// Implementation note: it parses the first BEGIN header's type field and checks
// whether that type carries the "ENCRYPTED" marker — the encrypted PKCS#8 type is
// the only standard PEM label that does. This deliberately references NO literal
// private-key header string, so the shipped source stays clean of one: the build
// content scanner (build/lib/private-key-scan.mjs) treats any such header in dist/
// as shipped key material and fails the release. Unencrypted PKCS#8, PKCS#1
// RSA/EC keys, and public-key labels all lack the ENCRYPTED marker and are not
// classified as encrypted here.
function isEncryptedPkcs8Pem(privateKeyPem) {
  if (typeof privateKeyPem !== "string") return false;
  const firstLine = privateKeyPem.split(/\r?\n/, 1)[0].trim();
  const header = firstLine.match(/^-----BEGIN ([A-Z0-9 ]+)-----$/);
  return header !== null && header[1].split(" ").includes("ENCRYPTED");
}

export function createFileBackedProductionCustody(env = process.env) {
  const bundleRaw = readKeyFile("MNDE_AUTHORITY_BUNDLE", env.MNDE_AUTHORITY_BUNDLE);
  let bundle;
  try {
    bundle = JSON.parse(bundleRaw);
  } catch {
    throw new Error("custody: MNDE_AUTHORITY_BUNDLE is not valid JSON");
  }
  if (bundle?.schema_version !== "mnde.authority.bundle.v1") {
    throw new Error("custody: MNDE_AUTHORITY_BUNDLE is not an mnde.authority.bundle.v1");
  }

  // Load one file-backed signing role. Reads the PEM, resolves an optional
  // passphrase (undefined/empty => none, whitespace preserved — never trimmed),
  // and imports the key into an opaque handle at STARTUP so a wrong/missing
  // passphrase or malformed key fails before readiness, not on the first request.
  const roleKey = (role, keyEnv, idEnv, passphraseEnv) => {
    const privatePem = readKeyFile(keyEnv, env[keyEnv]);

    const rawPassphrase = env[passphraseEnv];
    const passphrase =
      typeof rawPassphrase === "string" && rawPassphrase.length > 0 ? rawPassphrase : undefined;

    const encrypted = isEncryptedPkcs8Pem(privatePem);
    if (encrypted && passphrase === undefined) {
      // Classified WITHOUT calling the provider: no passphrase for encrypted material.
      throw new CustodyConfigurationError("PASSPHRASE_REQUIRED", {
        keyEnv,
        passphraseEnv,
        message: `custody: ${keyEnv} requires ${passphraseEnv}`
      });
    }

    let privateKey;
    try {
      privateKey = importPrivateKey(privatePem, { passphrase });
    } catch (error) {
      if (encrypted) {
        // Sanitized: any provider import failure for encrypted material with a
        // supplied passphrase is reported as invalid — deliberately hiding
        // whether the file is corrupt, truncated, unsupported, or wrong-passphrase.
        throw new CustodyConfigurationError("PASSPHRASE_INVALID", {
          keyEnv,
          passphraseEnv,
          message: `custody: passphrase for ${keyEnv} is invalid`
        });
      }
      // Unencrypted malformed material: preserve the existing signing-key failure
      // classification (path/reason only, never key bytes or the provider error).
      throw new Error(`custody: ${keyEnv} is not a valid signing key`);
    }

    const published = Array.isArray(bundle.keys?.[role]) ? bundle.keys[role] : [];
    const keyId = env[idEnv] ?? published[0]?.key_id;
    const entry = published.find((k) => k.key_id === keyId);
    if (!entry) throw new Error(`custody: no published ${role} key '${keyId ?? "?"}' in bundle`);
    return { keyId, privateKey, fingerprint: entry.fingerprint };
  };

  const receipt = roleKey("receipt", "MNDE_RECEIPT_SIGNING_KEY", "MNDE_RECEIPT_KEY_ID", "MNDE_RECEIPT_SIGNING_KEY_PASSPHRASE");
  // Policy/approval/result/ledger/activation signing keys are optional for a deploy that only signs receipts.
  const optionalRoleKey = (role, keyEnv, idEnv, passphraseEnv) => (env[keyEnv] ? roleKey(role, keyEnv, idEnv, passphraseEnv) : null);
  const policy = optionalRoleKey("policy", "MNDE_POLICY_SIGNING_KEY", "MNDE_POLICY_KEY_ID", "MNDE_POLICY_SIGNING_KEY_PASSPHRASE");
  const approval = optionalRoleKey("approval", "MNDE_APPROVAL_SIGNING_KEY", "MNDE_APPROVAL_KEY_ID", "MNDE_APPROVAL_SIGNING_KEY_PASSPHRASE");
  const resultKey = optionalRoleKey("result", "MNDE_RESULT_SIGNING_KEY", "MNDE_RESULT_KEY_ID", "MNDE_RESULT_SIGNING_KEY_PASSPHRASE");
  const ledgerKey = optionalRoleKey("ledger", "MNDE_LEDGER_SIGNING_KEY", "MNDE_LEDGER_KEY_ID", "MNDE_LEDGER_SIGNING_KEY_PASSPHRASE");
  const activationKey = optionalRoleKey("activation", "MNDE_ACTIVATION_SIGNING_KEY", "MNDE_ACTIVATION_KEY_ID", "MNDE_ACTIVATION_SIGNING_KEY_PASSPHRASE");

  const signer = (key, role) => {
    if (!key) return () => { throw new Error(`custody: no ${role} signing key configured`); };
    return async (payload) => ({ key_id: key.keyId, value: await signCanonical(payload, key.privateKey), fingerprint: key.fingerprint });
  };

  return {
    mode: "file-backed-production",
    production: true,
    trustedRootFingerprint: bundle.root_key?.fingerprint ?? null,
    signReceipt: signer(receipt, "receipt"),
    signPolicy: signer(policy, "policy"),
    signApproval: signer(approval, "approval"),
    signResult: signer(resultKey, "result"),
    signLedger: signer(ledgerKey, "ledger"),
    signActivation: signer(activationKey, "activation"),
    getPublicBundle: () => structuredClone(bundle)
  };
}

// Factory. Default local-demo; production opt-in; fail closed on bad config.
export async function createCustody(env = process.env) {
  const requested = env.MNDE_KEY_CUSTODY;
  if (requested === "file-backed-production") {
    try {
      return { ok: true, provider: createFileBackedProductionCustody(env) };
    } catch (error) {
      // error.message is path/reason only — never key material. custodyCode is a
      // stable structured classification (e.g. PASSPHRASE_REQUIRED) when present.
      return { ok: false, reason: error?.message ?? String(error), custodyCode: error?.custodyCode };
    }
  }
  if (requested && !KNOWN_PROVIDERS.includes(requested)) {
    return { ok: false, reason: `custody: unknown MNDE_KEY_CUSTODY '${requested}'` };
  }
  return { ok: true, provider: await createLocalDemoCustody() };
}
