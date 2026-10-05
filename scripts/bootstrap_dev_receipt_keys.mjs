import { createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { LOCAL_AUTHORITY_ID, LOCAL_AUTHORITY_NAME, authorityPaths, writeSignedAuthorityManifest } from "../shared/authority-manifest.mjs";

// Thrown instead of silently regenerating whenever an existing keypair is
// incomplete, corrupt, or mismatched — see inspectKeyPair() below for why.
export class KeypairFailClosedError extends Error {}

const CONTINUITY_WARNING =
  "Refusing to regenerate automatically: replacing either half of an existing " +
  "keypair would silently invalidate the verifiability of every receipt or " +
  "manifest already signed with it, with no way to tell afterward that it " +
  "happened. Resolve manually — restore the missing/matching file from " +
  "backup — or pass force:true to bootstrapReceiptKeys() to intentionally " +
  "generate a brand-new keypair (this deliberately breaks continuity with " +
  "anything signed by the old one).";

// Inspects an existing (private, public) PEM pair on disk without ever
// writing anything. Returns one of:
//   { state: "absent" }               — neither file exists (safe to generate)
//   { state: "ok", ... }              — both exist, both parse, and the
//                                        public key derived from the private
//                                        key matches the stored public key
//                                        exactly (safe to leave untouched)
//   { state: "fail", reason }         — anything else: one file present and
//                                        the other missing, either file
//                                        corrupt/unparseable, or a pair that
//                                        parses fine individually but does
//                                        not cryptographically match
function inspectKeyPair(privateKeyPath, publicKeyPath, label) {
  const privateExists = existsSync(privateKeyPath);
  const publicExists = existsSync(publicKeyPath);

  if (!privateExists && !publicExists) return { state: "absent" };

  if (privateExists && !publicExists) {
    return { state: "fail", reason: `${label}: private key present but public key is missing (${publicKeyPath}).` };
  }
  if (!privateExists && publicExists) {
    return { state: "fail", reason: `${label}: public key present but private key is missing (${privateKeyPath}).` };
  }

  let privateKeyObject;
  try {
    privateKeyObject = createPrivateKey(readFileSync(privateKeyPath, "utf8"));
  } catch (error) {
    return { state: "fail", reason: `${label}: private key file is corrupt or unreadable (${privateKeyPath}): ${error.message}` };
  }
  let publicKeyObject;
  try {
    publicKeyObject = createPublicKey(readFileSync(publicKeyPath, "utf8"));
  } catch (error) {
    return { state: "fail", reason: `${label}: public key file is corrupt or unreadable (${publicKeyPath}): ${error.message}` };
  }

  const derivedPublicPem = createPublicKey(privateKeyObject).export({ type: "spki", format: "pem" });
  const storedPublicPem = publicKeyObject.export({ type: "spki", format: "pem" });
  if (derivedPublicPem !== storedPublicPem) {
    return { state: "fail", reason: `${label}: private and public key files do not form a matching pair (${privateKeyPath} / ${publicKeyPath}).` };
  }

  return { state: "ok" };
}

export function bootstrapReceiptKeys({ repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), ".."), force = false } = {}) {
  const keyDir = join(repoRoot, "shared", "receipt_keys");
  const privateKeyPath = join(keyDir, "receipt_signing_private.pem");
  const publicKeyPath = join(keyDir, "receipt_signing_public.pem");
  const authority = authorityPaths(repoRoot, { kind: "local" });

  mkdirSync(keyDir, { recursive: true });
  mkdirSync(dirname(authority.manifestPath), { recursive: true });

  const receiptStatus = force ? { state: "absent" } : inspectKeyPair(privateKeyPath, publicKeyPath, "receipt signing key");
  if (receiptStatus.state === "fail") {
    throw new KeypairFailClosedError(`ERR_RECEIPT_KEYPAIR_INCOMPLETE: ${receiptStatus.reason} ${CONTINUITY_WARNING}`);
  }

  const authorityStatus = force ? { state: "absent" } : inspectKeyPair(authority.rootPrivateKeyPath, authority.rootPublicKeyPath, "root authority key");
  if (authorityStatus.state === "fail") {
    throw new KeypairFailClosedError(`ERR_AUTHORITY_KEYPAIR_INCOMPLETE: ${authorityStatus.reason} ${CONTINUITY_WARNING}`);
  }

  const receiptExisted = receiptStatus.state === "ok";
  const authorityExisted = authorityStatus.state === "ok";

  if (force || !receiptExisted) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    writeFileSync(privateKeyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "w", mode: 0o600 });
    writeFileSync(publicKeyPath, publicKey.export({ type: "spki", format: "pem" }), { flag: "w", mode: 0o644 });
  }

  if (force || !authorityExisted) {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    writeFileSync(authority.rootPrivateKeyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { flag: "w", mode: 0o600 });
    writeFileSync(authority.rootPublicKeyPath, publicKey.export({ type: "spki", format: "pem" }), { flag: "w", mode: 0o644 });
  }

  writeSignedAuthorityManifest({
    repoRoot,
    kind: "local",
    authorityId: LOCAL_AUTHORITY_ID,
    authorityName: LOCAL_AUTHORITY_NAME,
    rootPrivateKeyPem: readFileSync(authority.rootPrivateKeyPath, "utf8"),
    rootPublicKeyPem: readFileSync(authority.rootPublicKeyPath, "utf8"),
    receiptPublicKeyPem: readFileSync(publicKeyPath, "utf8")
  });

  const bothExisted = receiptExisted && authorityExisted;
  return {
    status: force ? "created" : bothExisted ? "exists" : "created",
    privateKeyPath,
    publicKeyPath,
    manifestPath: authority.manifestPath,
    message: force
      ? "Local development receipt signing keys generated (forced) and authority manifest signed."
      : bothExisted
        ? "Receipt signing keys and authority manifest are ready."
        : "Local development receipt signing keys generated and authority manifest signed."
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const force = process.argv.includes("--force");
  try {
    const result = bootstrapReceiptKeys({ force });
    console.log(result.message);
    console.log(`private: ${result.privateKeyPath}`);
    console.log(`public:  ${result.publicKeyPath}`);
    process.exit(0);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
