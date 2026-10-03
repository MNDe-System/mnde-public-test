import { createHash, createPrivateKey, createPublicKey, sign, verify } from "crypto";
import { existsSync, readFileSync } from "fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { AUTHORITY_ID, RECEIPT_KEY_ID } from "./authority-manifest.mjs";

// Default: relative to this file's own install location (unchanged behavior —
// every existing test/clone-based flow relies on this). MNDE_HOME overrides it
// for the packaged CLI, which must read/write signing keys under the caller's
// own directory, never inside node_modules. Read once at module load, which is
// safe here: MNDE_HOME is set (or not) by the parent process's env before this
// module is ever imported by a child process.
const PRIVATE_KEY_URL = process.env.MNDE_HOME
  ? pathToFileURL(join(resolve(process.env.MNDE_HOME), "shared", "receipt_keys", "receipt_signing_private.pem"))
  : new URL("./receipt_keys/receipt_signing_private.pem", import.meta.url);
const PUBLIC_KEY_URL = process.env.MNDE_HOME
  ? pathToFileURL(join(resolve(process.env.MNDE_HOME), "shared", "receipt_keys", "receipt_signing_public.pem"))
  : new URL("./receipt_keys/receipt_signing_public.pem", import.meta.url);
const PUBLIC_KEY_PEM = existsSync(PUBLIC_KEY_URL) ? readFileSync(PUBLIC_KEY_URL, "utf8") : "";
function parsePublicKeyOrNull(publicKeyPem: string) {
  if (!publicKeyPem) return null;
  try {
    return createPublicKey(publicKeyPem);
  } catch {
    return null;
  }
}
// Constants exported from this module must not make the module itself
// unimportable when the configured public key is malformed. Callers need to be
// able to import receiptSigningKeyStatus() and receive a fail-closed diagnostic.
const PUBLIC_KEY_OBJECT = parsePublicKeyOrNull(PUBLIC_KEY_PEM);
const PUBLIC_KEY_DER = PUBLIC_KEY_OBJECT?.export({ format: "der", type: "spki" }) ?? Buffer.alloc(0);

export const RECEIPT_PUBLIC_KEY_PEM = PUBLIC_KEY_PEM;
export const RECEIPT_SIGNATURE_ALGORITHM = "ED25519";
export const RECEIPT_PUBLIC_KEY_FINGERPRINT = createHash("sha256")
  .update(PUBLIC_KEY_DER)
  .digest("hex");
export const RECEIPT_SIGNATURE_KEY_ID = `receipt-ed25519-${RECEIPT_PUBLIC_KEY_FINGERPRINT.slice(0, 16)}`;
export const RECEIPT_AUTHORITY_ID = AUTHORITY_ID;
export const RECEIPT_AUTHORITY_KEY_ID = RECEIPT_KEY_ID;

export function receiptSigningKeyStatus(): { ok: boolean; reason: string | null } {
  if (!existsSync(PRIVATE_KEY_URL)) {
    return { ok: false, reason: "ERR_RECEIPT_SIGNING_KEYS_MISSING: shared/receipt_keys/receipt_signing_private.pem is missing. Run npm run tester:init -- TESTER-001 before starting MNDe." };
  }
  if (!existsSync(PUBLIC_KEY_URL)) {
    return { ok: false, reason: "ERR_RECEIPT_SIGNING_KEYS_MISSING: shared/receipt_keys/receipt_signing_public.pem is missing. Run npm run tester:init -- TESTER-001 before starting MNDe." };
  }
  let privateKeyObject: ReturnType<typeof createPrivateKey>;
  try {
    privateKeyObject = createPrivateKey(readFileSync(PRIVATE_KEY_URL, "utf8"));
  } catch (error) {
    return { ok: false, reason: `ERR_RECEIPT_SIGNING_PRIVATE_KEY_INVALID: ${error instanceof Error ? error.message : String(error)}` };
  }
  let publicKeyObject: ReturnType<typeof createPublicKey>;
  try {
    publicKeyObject = createPublicKey(readFileSync(PUBLIC_KEY_URL, "utf8"));
  } catch (error) {
    return { ok: false, reason: `ERR_RECEIPT_SIGNING_PUBLIC_KEY_INVALID: ${error instanceof Error ? error.message : String(error)}` };
  }
  // Each file can parse as SOME valid key without the two actually forming a
  // matching pair (e.g. a public key file left over from a previous keypair) —
  // an independent review found this went undetected. Derive the public key
  // from the private key and compare, rather than only checking each parses.
  const derivedPublicDer = createPublicKey(privateKeyObject).export({ format: "der", type: "spki" });
  const storedPublicDer = publicKeyObject.export({ format: "der", type: "spki" });
  if (!derivedPublicDer.equals(storedPublicDer)) {
    return { ok: false, reason: "ERR_RECEIPT_SIGNING_KEYS_MISMATCHED: shared/receipt_keys/receipt_signing_private.pem and receipt_signing_public.pem do not form a matching keypair." };
  }
  return { ok: true, reason: null };
}

export function assertReceiptSigningKeysAvailable(): void {
  const status = receiptSigningKeyStatus();
  if (!status.ok) {
    throw new Error(status.reason ?? "ERR_RECEIPT_SIGNING_KEYS_INVALID");
  }
}

export function signReceiptPayload(payload: string): string {
  assertReceiptSigningKeysAvailable();
  const privateKeyPem = readFileSync(PRIVATE_KEY_URL, "utf8");
  const privateKeyObject = createPrivateKey(privateKeyPem);
  return sign(null, Buffer.from(payload, "utf8"), privateKeyObject).toString("hex");
}

export function verifyReceiptPayloadSignature(payload: string, signatureHex: string, publicKeyPem?: string): boolean {
  if (typeof publicKeyPem !== "string" || publicKeyPem.trim().length === 0) {
    throw new Error("ERR_RECEIPT_VERIFICATION_KEY_REQUIRED");
  }
  const publicKey = createPublicKey(publicKeyPem);
  return verify(null, Buffer.from(payload, "utf8"), publicKey, Buffer.from(signatureHex, "hex"));
}
