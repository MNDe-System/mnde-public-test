// Executor-identity runtime readiness gate.
//
// Executor identity is OPT-IN. When the MNDE_EXECUTOR_* environment is absent,
// this is a no-op and MNDe runs exactly as before (authority-only). When it is
// configured, the material MUST be usable: the credential verifies against the
// authority, is unexpired, matches the environment and executor id, and the
// out-of-repo private key matches the credential. Anything else fails closed, so
// a configured-but-broken executor identity refuses startup rather than silently
// producing authority-only receipts.

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { loadExecutorSigner } from "./executor-identity.mjs";

// Repo/package root (src/custody -> up two). Executor private keys under this
// tree are rejected by loadExecutorSigner's in-repo guard.
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

export const EXECUTOR_READINESS_ERRORS = Object.freeze({
  INCOMPLETE: "ERR_EXECUTOR_IDENTITY_INCOMPLETE",
  CREDENTIAL_UNREADABLE: "ERR_EXECUTOR_CREDENTIAL_INVALID",
  CUSTODY_UNAVAILABLE: "ERR_CUSTODY_UNAVAILABLE"
});

function fail(reason_code, detail) {
  return { ok: false, configured: true, reason_code, detail };
}

// Assert executor-identity readiness.
//
// env keys:
//   MNDE_EXECUTOR_ID           stable executor id (explicit configuration)
//   MNDE_EXECUTOR_PRIVATE_KEY   path to the executor private key (outside repo)
//   MNDE_EXECUTOR_CREDENTIAL    path to the authority-signed credential JSON
//   MNDE_EXECUTOR_ENVIRONMENT   expected environment id
//
// options:
//   authorityBundle / trustedRootFingerprint  the issuing custody bundle; if
//     omitted they are loaded from custody (createCustody) on demand.
//   now  ISO-8601 verification time
export async function assertExecutorIdentityReadiness(env = process.env, options = {}) {
  const executorId = env.MNDE_EXECUTOR_ID;
  const privateKeyPath = env.MNDE_EXECUTOR_PRIVATE_KEY;
  const credentialPath = env.MNDE_EXECUTOR_CREDENTIAL;
  const environmentId = env.MNDE_EXECUTOR_ENVIRONMENT;

  const anyConfigured = [executorId, privateKeyPath, credentialPath, environmentId].some((v) => typeof v === "string" && v.length > 0);
  if (!anyConfigured) {
    // Authority-only mode — unchanged.
    return { ok: true, configured: false };
  }

  const missing = [];
  if (!executorId) missing.push("MNDE_EXECUTOR_ID");
  if (!privateKeyPath) missing.push("MNDE_EXECUTOR_PRIVATE_KEY");
  if (!credentialPath) missing.push("MNDE_EXECUTOR_CREDENTIAL");
  if (!environmentId) missing.push("MNDE_EXECUTOR_ENVIRONMENT");
  if (missing.length > 0) {
    return fail(EXECUTOR_READINESS_ERRORS.INCOMPLETE, `executor identity is partially configured; missing: ${missing.join(", ")}`);
  }

  let credential;
  try {
    credential = JSON.parse(readFileSync(credentialPath, "utf8"));
  } catch {
    return fail(EXECUTOR_READINESS_ERRORS.CREDENTIAL_UNREADABLE, "executor credential cannot be read or parsed");
  }

  // Resolve the issuing bundle (injected for tests; else from custody).
  let authorityBundle = options.authorityBundle;
  let trustedRootFingerprint = options.trustedRootFingerprint;
  if (!authorityBundle || !trustedRootFingerprint) {
    const { createCustody } = await import("./index.mjs");
    const custody = await createCustody(env);
    if (!custody.ok) {
      return fail(EXECUTOR_READINESS_ERRORS.CUSTODY_UNAVAILABLE, `custody unavailable: ${custody.reason ?? "unknown"}`);
    }
    authorityBundle = custody.provider.getPublicBundle();
    trustedRootFingerprint = custody.provider.trustedRootFingerprint;
  }

  const signer = await loadExecutorSigner({
    executorId,
    privateKeyPath,
    credential,
    repoRoot: PACKAGE_ROOT,
    authorityBundle,
    trustedRootFingerprint,
    environmentId,
    now: options.now
  });
  if (!signer.ok) {
    return fail(signer.code, signer.detail ?? "executor identity is not usable");
  }

  return {
    ok: true,
    configured: true,
    executor_id: signer.executorId,
    executor_key_id: signer.keyId,
    credential_id: signer.credentialId,
    environment_id: environmentId,
    credential: signer.credential,
    signer: signer.signer
  };
}
