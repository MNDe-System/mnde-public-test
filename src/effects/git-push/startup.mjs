// git.push executor startup configuration, read from the deployment's environment.
//
// This is the operator's wiring for createGitPushExecutor(), and nothing else.
// It is read from environment variables and the files they name, all set by
// whoever deployed the executor. A request never reaches this module: the one
// caller, bin/mnde-git-push.mjs, loads it before and independently of the
// request file, and passes the request only to executeGitPush().
//
// What it does NOT do, deliberately:
//   - open, configure or substitute the claim store. MNDE_CLAIM_CONFIG is only
//     checked for presence; the executor's own adapter
//     (src/freshness/postgres_claim.mjs) reads and validates it.
//   - decide anything about authorization. Every trust input is handed to the
//     executor, which remains the only place a push is allowed or refused.
//   - default a security value. Every required variable must be set; there is
//     no development fallback, no demo key and no in-repository trust root.
//
// Existing conventions are reused rather than restated: MNDE_VERIFY_* are the
// executor verification variables of executor/index.mjs, and MNDE_EXECUTOR_* are
// loaded by assertExecutorIdentityReadiness(), which verifies the credential
// against the configured bundle and proves the out-of-repository private key
// matches it before returning a signer.

import { readFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { fingerprintOf } from "../../custody/bundle.mjs";
import { assertExecutorIdentityReadiness } from "../../custody/executor-readiness.mjs";
import { parseRuntimeProfile } from "../../../shared/runtime-profile.mjs";
import { inspectSecretFile } from "./secret-files.mjs";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

export const ERR_GIT_PUSH_CLI_CONFIG = "ERR_GIT_PUSH_CLI_CONFIG";
export const ERR_DEMO_TRUST_MATERIAL = "ERR_GIT_PUSH_DEMO_TRUST_MATERIAL";
export const ERR_TRUST_ROLE_REUSE = "ERR_GIT_PUSH_TRUST_ROLE_REUSE";
export const ERR_TRUST_FILE_INSECURE = "ERR_GIT_PUSH_TRUST_FILE_INSECURE";

// Files that decide what the executor trusts, and whether each is secret.
// Whoever could rewrite one of these could substitute a trust root, a claim
// store, an executor identity or a push credential, so each must be owned by
// the executor's OS user (configuration: or root) and writable by no one else.
// The push credential config and its secrets are checked by the provider.
const TRUST_FILES = Object.freeze([
  ["MNDE_VERIFY_AUTHORITY_BUNDLE", false],
  ["MNDE_CLAIM_CONFIG", false],
  ["MNDE_EXECUTOR_CREDENTIAL", false],
  ["MNDE_EXECUTOR_PRIVATE_KEY", true],
  ["MNDE_GIT_PUSH_TRANSPORT_ENV", false]
]);

// Root fingerprints of trust material that ships with MNDe or is otherwise
// public, and so can never anchor a production deployment. The demo authority
// is authority/authority-manifest.json in this repository and in the package.
// Test suites mint fresh roots per run, which cannot be listed and do not need
// to be: their private keys never outlive the test.
export const KNOWN_NON_PRODUCTION_ROOT_FINGERPRINTS = Object.freeze([
  "6e987c47fe1144c9a9e957b1c9f45f50e37df8892e2f0b3ad80b6d2a20ec4efa"
]);

function normalizeFingerprint(value) {
  return String(value ?? "").trim().toLowerCase().replace(/^sha256:/, "");
}

export const REQUIRED_STARTUP_ENV = Object.freeze([
  "MNDE_PROFILE",
  "MNDE_CLAIM_CONFIG",
  "MNDE_GIT_CREDENTIAL_CONFIG",
  "MNDE_GIT_PUSH_REPO_PATH",
  "MNDE_GIT_PUSH_NAMESPACE",
  "MNDE_GIT_PUSH_EVIDENCE_DIR",
  "MNDE_VERIFY_AUTHORITY_BUNDLE",
  "MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT",
  "MNDE_VERIFY_ENVIRONMENT_ID",
  "MNDE_VERIFY_EXPECTED_EXECUTOR_ID",
  "MNDE_EXECUTOR_ID",
  "MNDE_EXECUTOR_PRIVATE_KEY",
  "MNDE_EXECUTOR_CREDENTIAL",
  "MNDE_EXECUTOR_ENVIRONMENT"
]);

// Paths are required to be absolute so their meaning does not depend on the
// directory the command happens to be started from.
const ABSOLUTE_PATH_ENV = Object.freeze([
  "MNDE_CLAIM_CONFIG",
  "MNDE_GIT_CREDENTIAL_CONFIG",
  "MNDE_GIT_PUSH_REPO_PATH",
  "MNDE_GIT_PUSH_EVIDENCE_DIR",
  "MNDE_VERIFY_AUTHORITY_BUNDLE",
  "MNDE_EXECUTOR_PRIVATE_KEY",
  "MNDE_EXECUTOR_CREDENTIAL"
]);

const SCHEME = /^[a-z][a-z0-9+.-]*$/;

function fail(detail, reason_code = ERR_GIT_PUSH_CLI_CONFIG) {
  return { ok: false, reason_code, detail };
}

function readJsonFile(path, name) {
  try {
    return { ok: true, value: JSON.parse(readFileSync(path, "utf8")) };
  } catch (error) {
    // The code only: a parse message can quote file contents.
    return { ok: false, detail: `${name} could not be read as JSON (${error?.code ?? error?.name ?? "error"})` };
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// Returns { ok: true, startup, signer } or { ok: false, reason_code, detail }.
// `startup` is exactly the argument createGitPushExecutor() takes; `signer` is
// the same executor signer, returned separately so the caller can destroy it.
export async function loadGitPushStartup(env = process.env) {
  const missing = REQUIRED_STARTUP_ENV.filter((name) => typeof env[name] !== "string" || env[name].length === 0);
  if (missing.length > 0) return fail(`required startup configuration is not set: ${missing.join(", ")}`);

  const profile = parseRuntimeProfile(env.MNDE_PROFILE);
  if (!profile.ok || profile.profile !== "production") {
    return fail(`MNDE_PROFILE must be 'production'; got ${profile.ok ? profile.profile : profile.reason_code}`);
  }

  const relative = ABSOLUTE_PATH_ENV.filter((name) => !isAbsolute(env[name]));
  if (relative.length > 0) return fail(`these must be absolute paths: ${relative.join(", ")}`);

  for (const [name, secret] of TRUST_FILES) {
    if (env[name] === undefined) continue;
    const inspected = inspectSecretFile(env[name], { secret, forbiddenRoots: [env.MNDE_GIT_PUSH_REPO_PATH, PACKAGE_ROOT] });
    if (!inspected.ok) return fail(`${name} ${inspected.detail}`, inspected.missing ? ERR_GIT_PUSH_CLI_CONFIG : ERR_TRUST_FILE_INSECURE);
  }

  const bundle = readJsonFile(env.MNDE_VERIFY_AUTHORITY_BUNDLE, "MNDE_VERIFY_AUTHORITY_BUNDLE");
  if (!bundle.ok) return fail(bundle.detail);
  if (!isPlainObject(bundle.value)) return fail("MNDE_VERIFY_AUTHORITY_BUNDLE must contain a JSON object");

  // Identifiable non-production trust. The executor's posture gate already
  // refuses a bundle PATH inside the package; this refuses the demo root by
  // what it is, wherever it was copied to, and a bundle that names itself a
  // local or demo authority, matching the sidecar's own production gate.
  const pinned = normalizeFingerprint(env.MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT);
  const bundleRoot = normalizeFingerprint(bundle.value.root_key?.fingerprint);
  if (KNOWN_NON_PRODUCTION_ROOT_FINGERPRINTS.some((fp) => fp === pinned || fp === bundleRoot)) {
    return fail("the configured trust root is MNDe's shipped demo root; production needs an independently generated root", ERR_DEMO_TRUST_MATERIAL);
  }
  const authorityId = String(bundle.value.authority_id ?? "");
  const rootKeyId = String(bundle.value.root_key?.key_id ?? "");
  if (/local|demo/i.test(authorityId) || /local|demo/i.test(rootKeyId)) {
    return fail(`authority bundle '${authorityId}' (root key '${rootKeyId}') is a local or demo authority`, ERR_DEMO_TRUST_MATERIAL);
  }

  // Unset means the executor's own default (https, ssh). Set means exactly the
  // listed schemes; a malformed list is refused rather than trimmed into shape.
  let allowedSchemes;
  if (env.MNDE_GIT_PUSH_ALLOWED_SCHEMES !== undefined) {
    allowedSchemes = env.MNDE_GIT_PUSH_ALLOWED_SCHEMES.split(",");
    if (allowedSchemes.some((scheme) => !SCHEME.test(scheme))) {
      return fail("MNDE_GIT_PUSH_ALLOWED_SCHEMES must be a comma-separated list of lowercase URL schemes with no spaces");
    }
  }

  // The only way to give git its credentials (ssh key, known_hosts, agent). The
  // executor accepts only its own allowlist of variable names and refuses the
  // rest, so this is passed through as read.
  let transportEnv = {};
  if (env.MNDE_GIT_PUSH_TRANSPORT_ENV !== undefined) {
    if (!isAbsolute(env.MNDE_GIT_PUSH_TRANSPORT_ENV)) return fail("MNDE_GIT_PUSH_TRANSPORT_ENV must be an absolute path");
    const read = readJsonFile(env.MNDE_GIT_PUSH_TRANSPORT_ENV, "MNDE_GIT_PUSH_TRANSPORT_ENV");
    if (!read.ok) return fail(read.detail);
    if (!isPlainObject(read.value)) return fail("MNDE_GIT_PUSH_TRANSPORT_ENV must contain a JSON object");
    transportEnv = read.value;
  }

  const identity = await assertExecutorIdentityReadiness(env, {
    authorityBundle: bundle.value,
    trustedRootFingerprint: env.MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT
  });
  if (!identity.ok) return fail(identity.detail ?? "executor identity is not usable", identity.reason_code ?? ERR_GIT_PUSH_CLI_CONFIG);
  if (identity.configured !== true || typeof identity.signer?.sign !== "function") {
    return fail("executor identity did not produce a signer");
  }

  // One key, one role. The executor key signs evidence of what happened; the
  // authority keys sign what may happen. If they are the same key, whoever
  // holds the executor (which runs next to the remote credential) can also
  // authorize, and the two statements stop being independent.
  let executorFingerprint = null;
  try { executorFingerprint = normalizeFingerprint(fingerprintOf(identity.credential?.public_key)); } catch { executorFingerprint = null; }
  if (!executorFingerprint) return fail("executor credential carries no usable public key");
  const authorityFingerprints = [bundleRoot];
  for (const keys of Object.values(isPlainObject(bundle.value.keys) ? bundle.value.keys : {})) {
    if (Array.isArray(keys)) for (const key of keys) authorityFingerprints.push(normalizeFingerprint(key?.fingerprint));
  }
  if (authorityFingerprints.includes(executorFingerprint)) {
    identity.signer.destroy?.();
    return fail("the executor signing key is also an authority key; each trust role needs its own key", ERR_TRUST_ROLE_REUSE);
  }

  const startup = Object.freeze({
    repoPath: env.MNDE_GIT_PUSH_REPO_PATH,
    namespace: env.MNDE_GIT_PUSH_NAMESPACE,
    authorityBundle: bundle.value,
    authorityBundlePath: env.MNDE_VERIFY_AUTHORITY_BUNDLE,
    trustedRootFingerprint: env.MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT,
    environmentId: env.MNDE_VERIFY_ENVIRONMENT_ID,
    expectedExecutorId: env.MNDE_VERIFY_EXPECTED_EXECUTOR_ID,
    allowedSchemes,
    transportEnv,
    evidenceDir: env.MNDE_GIT_PUSH_EVIDENCE_DIR,
    executorIdentity: Object.freeze({
      executor_id: identity.executor_id,
      key_id: identity.executor_key_id,
      credential_id: identity.credential_id,
      environment_id: identity.environment_id,
      credential: identity.credential
    }),
    executorSigner: identity.signer,
    env
  });
  return { ok: true, startup, signer: identity.signer };
}
