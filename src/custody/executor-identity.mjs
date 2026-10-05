// Executor identity — explicit Codex/Claude configuration + runtime signer load.
//
// Phase 0 / Design A: an executor is a distinct agent instance that signs the
// execution receipt with its OWN Ed25519 key before the custody receipt-role key
// countersigns. Identities are explicit and stable; private keys live OUTSIDE
// tracked repository paths and are loaded fail-closed at runtime.
//
// This module holds NO key material and imports NO node:crypto directly — all
// cryptography goes through the provider seam (src/crypto). It defines the
// canonical identities and loads a signer from operator-supplied, out-of-repo
// paths.

import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { platform } from "node:os";
import { isAbsolute, join, parse, relative, resolve, sep } from "node:path";

import { sign as providerSign, verify as providerVerify } from "../crypto/provider.mjs";
import { verifyExecutorCredential } from "./executor-credential.mjs";

// The capability an executor credential must grant to sign execution receipts.
export const EXECUTOR_RECEIPT_CAPABILITY = "sign_execution_receipt";

// Canonical, explicit executor identities. Codex and Claude are configured
// separately and never share key material. The concrete organization/environment
// components may be overridden per deployment, but the two agents stay distinct.
export const EXECUTOR_IDENTITIES = Object.freeze({
  codex: Object.freeze({ agent: "codex", executor_id: "mnde:local:prod:executor:codex:01" }),
  claude: Object.freeze({ agent: "claude", executor_id: "mnde:local:prod:executor:claude:01" })
});

export const EXECUTOR_IDENTITY_ERRORS = Object.freeze({
  MISSING: "ERR_EXECUTOR_KEY_MISSING",
  UNREADABLE: "ERR_EXECUTOR_KEY_UNREADABLE",
  CREDENTIAL_MISSING: "ERR_EXECUTOR_CREDENTIAL_MISSING",
  KEY_MISMATCH: "ERR_EXECUTOR_KEY_MISMATCH",
  IDENTITY_MISMATCH: "ERR_EXECUTOR_IDENTITY_MISMATCH",
  KEY_PATH_UNSAFE: "ERR_EXECUTOR_KEY_REPOSITORY_CONTAINED",
  KEY_REPOSITORY_CONTAINED: "ERR_EXECUTOR_KEY_REPOSITORY_CONTAINED",
  KEY_SYMLINK: "ERR_EXECUTOR_KEY_SYMLINK",
  KEY_UNSUPPORTED_TYPE: "ERR_EXECUTOR_KEY_UNSUPPORTED_TYPE",
  KEY_PERMISSIONS: "ERR_EXECUTOR_KEY_PERMISSIONS",
  KEY_CHANGED: "ERR_EXECUTOR_KEY_CHANGED",
  INVALID: "ERR_EXECUTOR_CREDENTIAL_INVALID"
});

function comparisonPath(value) {
  const normalized = resolve(value);
  return platform() === "win32" ? normalized.toLowerCase() : normalized;
}

// Segment-aware containment for already-canonical paths. Raw prefix comparisons
// confuse e.g. C:\repo and C:\repository-other and are intentionally forbidden.
export function isRepoContainedPath(candidatePath, repoRoot) {
  if (typeof candidatePath !== "string" || candidatePath.length === 0) return true;
  if (typeof repoRoot !== "string" || repoRoot.length === 0) return false;
  const candidate = comparisonPath(candidatePath);
  const root = comparisonPath(repoRoot);
  const rel = relative(root, candidate);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function fail(code, detail) {
  return { ok: false, code, detail };
}

function pathComponents(absolutePath) {
  const root = parse(absolutePath).root;
  const tail = absolutePath.slice(root.length).split(/[\\/]+/u).filter(Boolean);
  const components = [];
  let current = root;
  for (const part of tail) {
    current = join(current, part);
    components.push(current);
  }
  return components;
}

function fsErrorCode(error) {
  if (error?.code === "ENOENT" || error?.code === "ENOTDIR") return EXECUTOR_IDENTITY_ERRORS.MISSING;
  return EXECUTOR_IDENTITY_ERRORS.UNREADABLE;
}

function sameFile(before, after) {
  if (!before || !after) return false;
  if (before.dev !== after.dev || before.ino !== after.ino) return false;
  return before.size === after.size;
}

// Validate and read exactly one filesystem object. Every existing component is
// lstat'd so a file symlink, parent symlink, Windows junction, or other Node-
// visible reparse indirection is rejected before realpath containment is checked.
// The opened descriptor is then compared with the validated object to reduce
// time-of-check/time-of-use replacement risk.
export async function readSecureExecutorPrivateKey(privateKeyPath, repoRoot) {
  if (typeof privateKeyPath !== "string" || privateKeyPath.length === 0) {
    return fail(EXECUTOR_IDENTITY_ERRORS.MISSING, "executor private key path is required");
  }
  if (typeof repoRoot !== "string" || repoRoot.length === 0) {
    return fail(EXECUTOR_IDENTITY_ERRORS.KEY_REPOSITORY_CONTAINED, "repository root is required for key containment validation");
  }

  const absolutePath = resolve(privateKeyPath);
  let validatedStat;
  try {
    const components = pathComponents(absolutePath);
    for (let index = 0; index < components.length; index += 1) {
      const stats = await lstat(components[index], { bigint: true });
      if (stats.isSymbolicLink()) {
        return fail(EXECUTOR_IDENTITY_ERRORS.KEY_SYMLINK, "executor private key path contains a symbolic link or junction");
      }
      const isLast = index === components.length - 1;
      if (!isLast && !stats.isDirectory()) {
        return fail(EXECUTOR_IDENTITY_ERRORS.KEY_UNSUPPORTED_TYPE, "executor private key parent is not a directory");
      }
      if (isLast) validatedStat = stats;
    }
  } catch (error) {
    return fail(fsErrorCode(error), "executor private key path cannot be validated");
  }

  if (!validatedStat?.isFile()) {
    return fail(EXECUTOR_IDENTITY_ERRORS.KEY_UNSUPPORTED_TYPE, "executor private key must be a regular file");
  }
  if (platform() !== "win32" && (Number(validatedStat.mode) & 0o022) !== 0) {
    return fail(EXECUTOR_IDENTITY_ERRORS.KEY_PERMISSIONS, "executor private key must not be group- or world-writable");
  }

  let canonicalPath;
  let canonicalRepoRoot;
  try {
    [canonicalPath, canonicalRepoRoot] = await Promise.all([realpath(absolutePath), realpath(resolve(repoRoot))]);
  } catch (error) {
    return fail(fsErrorCode(error), "executor private key canonical path cannot be resolved");
  }
  if (isRepoContainedPath(canonicalPath, canonicalRepoRoot)) {
    return fail(EXECUTOR_IDENTITY_ERRORS.KEY_REPOSITORY_CONTAINED, "executor private key resolves inside the repository");
  }

  let handle;
  try {
    const noFollow = typeof fsConstants.O_NOFOLLOW === "number" ? fsConstants.O_NOFOLLOW : 0;
    handle = await open(absolutePath, fsConstants.O_RDONLY | noFollow);
    const openedStat = await handle.stat({ bigint: true });
    if (!openedStat.isFile()) {
      return fail(EXECUTOR_IDENTITY_ERRORS.KEY_UNSUPPORTED_TYPE, "executor private key must be a regular file");
    }
    if (!sameFile(validatedStat, openedStat)) {
      return fail(EXECUTOR_IDENTITY_ERRORS.KEY_CHANGED, "executor private key changed during validation");
    }
    const privatePem = await handle.readFile({ encoding: "utf8" });
    const canonicalAfterOpen = await realpath(absolutePath);
    if (comparisonPath(canonicalAfterOpen) !== comparisonPath(canonicalPath)) {
      return fail(EXECUTOR_IDENTITY_ERRORS.KEY_CHANGED, "executor private key target changed during validation");
    }
    return { ok: true, privatePem, canonicalPath };
  } catch (error) {
    if (error?.code === "ELOOP") {
      return fail(EXECUTOR_IDENTITY_ERRORS.KEY_SYMLINK, "executor private key path contains a symbolic link or junction");
    }
    return fail(fsErrorCode(error), "executor private key cannot be opened securely");
  } finally {
    await handle?.close().catch(() => {});
  }
}

// Load an executor signer from explicit, out-of-repo material. Fails closed on
// anything missing, mismatched, or key material located inside the repository.
// Async because the provider sign/verify round-trip (key-match proof) is async.
//
// options:
//   executorId       expected stable executor id (explicit configuration)
//   privateKeyPath    path to the executor Ed25519 private key PEM (outside repo)
//   credential        the authority-signed executor credential object
//   repoRoot          repository root, to reject in-repo key paths
//   authorityBundle        issuing custody bundle (to verify the credential)
//   trustedRootFingerprint out-of-band root anchor
//   environmentId          expected runtime environment
//   now                    ISO-8601 verification time
//
// Error results carry only stable codes and paths/reasons — never key material.
export async function loadExecutorSigner(options = {}) {
  const {
    executorId,
    privateKeyPath,
    credential,
    repoRoot,
    authorityBundle,
    trustedRootFingerprint,
    environmentId,
    now
  } = options;

  if (typeof executorId !== "string" || executorId.length === 0) {
    return fail(EXECUTOR_IDENTITY_ERRORS.IDENTITY_MISMATCH, "executorId is required");
  }
  if (typeof privateKeyPath !== "string" || privateKeyPath.length === 0) {
    return fail(EXECUTOR_IDENTITY_ERRORS.MISSING, "executor private key path is required");
  }
  if (credential === null || credential === undefined) {
    return fail(EXECUTOR_IDENTITY_ERRORS.CREDENTIAL_MISSING, "executor credential is required");
  }

  // Fully verify the credential against the authority BEFORE trusting the key:
  // issuer signature, expiry, environment, executor identity, and capability.
  // Fail closed with the credential's own stable error code (e.g. EXPIRED).
  const credRes = await verifyExecutorCredential(credential, {
    authorityBundle,
    trustedRootFingerprint,
    environmentId,
    expectedExecutorId: executorId,
    requiredCapability: EXECUTOR_RECEIPT_CAPABILITY,
    now
  });
  if (!credRes.ok) return fail(credRes.code, credRes.detail);

  const keyRead = await readSecureExecutorPrivateKey(privateKeyPath, repoRoot);
  if (!keyRead.ok) return keyRead;
  let privatePem = keyRead.privatePem;

  // Prove the loaded private key corresponds to the credential's public key with
  // a sign/verify round-trip through the provider seam (no direct node:crypto).
  const probe = `mnde-executor-keycheck:${credRes.credential_id}`;
  let signature;
  try {
    signature = await providerSign(probe, privatePem);
  } catch (error) {
    return fail(EXECUTOR_IDENTITY_ERRORS.INVALID, `executor private key invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
  const matches = await providerVerify(probe, signature, credRes.public_key);
  if (!matches) {
    return fail(EXECUTOR_IDENTITY_ERRORS.KEY_MISMATCH, "executor private key does not match credential public key");
  }

  const signer = Object.freeze({
    async sign(canonicalPayload) {
      if (privatePem === null) throw new Error("ERR_EXECUTOR_SIGNER_MISSING");
      return providerSign(canonicalPayload, privatePem);
    },
    destroy() {
      privatePem = null;
    }
  });

  return {
    ok: true,
    executorId,
    keyId: credRes.key_id,
    credentialId: credRes.credential_id,
    credential: structuredClone(credential),
    signer
  };
}
