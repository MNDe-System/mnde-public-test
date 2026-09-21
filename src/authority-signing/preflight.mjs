// Trust-root pre-flight (S-02 / P-01).
//
// MNDe must never enter production/live enforcement while signing receipts with
// development/demo keys. This is the single, deterministic gate the sidecar runs
// before the decision server accepts traffic.
//
// Runtime profile (`MNDE_PROFILE`):
//   unset / "local"  -> local/demo mode. Anything goes (legacy signing or
//                       local-demo custody). Existing behavior is preserved.
//   "production"     -> live enforcement. Requires an explicitly configured,
//                       valid production custody provider; refuses to start on
//                       any demo/dev key material.
//
// The check is pure (env in, result out) so it is unit-testable without a
// running server. In `local` profile it does NOT import custody — legacy mode
// stays free of the custody subsystem.

import { readFileSync } from "node:fs";
import { resolve, sep } from "node:path";

import { parseRuntimeProfile } from "../../shared/runtime-profile.mjs";

function fail(reason_code, detail) {
  return { ok: false, reason_code, detail };
}

// Read and parse the activation record at MNDE_ACTIVATION_RECORD.
// Returns { ok, record } or a fail() result. Never throws.
function readActivationRecord(path) {
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return fail("ERR_ACTIVATION_INVALID", `cannot read activation record at ${path}`);
  }
  try {
    return { ok: true, record: JSON.parse(raw) };
  } catch {
    return fail("ERR_ACTIVATION_INVALID", `activation record at ${path} is not valid JSON`);
  }
}

// Directories under a checkout or an install that hold development key material.
function devKeyDirs(repoRoot) {
  return repoRoot
    ? [resolve(repoRoot, "shared", "receipt_keys"), resolve(repoRoot, ".mnde-test"), resolve(repoRoot, "authority")]
    : [];
}

// Is this one path known development key material? Exported so every gate that
// has to make this judgement asks the same question. A second, slightly
// different definition living somewhere else is how a demo key eventually gets
// accepted in production by a check that was written to reject it.
export function isDevKeyMaterialPath(candidate, repoRoot) {
  if (typeof candidate !== "string" || candidate.length === 0) return false;
  const resolved = resolve(candidate);
  if (devKeyDirs(repoRoot).some((dir) => resolved === dir || resolved.startsWith(dir + sep))) return true;
  if (/receipt_signing_private\.pem$/.test(resolved)) return true;
  return /(^|[\\/])(local-demo|demo)([\\/]|$)/i.test(resolved);
}

// True path (string) of the first env-configured key/bundle that points at known
// development key material in the repository, else null.
export function detectDevKeyPath(env = process.env, repoRoot) {
  const candidates = [
    env.MNDE_AUTHORITY_BUNDLE,
    env.MNDE_RECEIPT_SIGNING_KEY,
    env.MNDE_LEDGER_SIGNING_KEY,
    env.MNDE_POLICY_SIGNING_KEY,
    env.MNDE_APPROVAL_SIGNING_KEY,
    env.MNDE_EXTERNAL_SIGNER_PUBLIC_KEY,
    env.MNDE_EXTERNAL_LEDGER_SIGNER_PUBLIC_KEY
  ].filter((p) => typeof p === "string" && p.length > 0);

  for (const candidate of candidates) {
    if (isDevKeyMaterialPath(candidate, repoRoot)) return candidate;
  }
  return null;
}

// Verify the trust root for the current runtime profile. Returns
// { ok:true, profile } or { ok:false, reason_code, detail }.
export async function assertTrustRoot(env = process.env, options = {}) {
  const profileResult = parseRuntimeProfile(env.MNDE_PROFILE);
  if (!profileResult.ok) return fail(profileResult.reason_code, profileResult.detail);
  const profile = profileResult.profile;

  if (profile !== "production") {
    // Local/demo mode. An activation record is optional here, but a configured
    // record that is structurally invalid fails startup in EVERY profile —
    // there is no profile in which broken activation evidence is acceptable.
    // Structural check only: local mode never loads custody, and signature
    // verification needs the authority bundle custody provides.
    if (typeof env.MNDE_ACTIVATION_RECORD === "string" && env.MNDE_ACTIVATION_RECORD.length > 0) {
      const loaded = readActivationRecord(env.MNDE_ACTIVATION_RECORD);
      if (!loaded.ok) return loaded;
      const { validateActivationStructure } = await import("../activation/index.mjs");
      const check = validateActivationStructure(loaded.record);
      if (!check.ok) return fail(check.reason_code, check.detail);
      return { ok: true, profile: "local", activation_id: check.activation_id };
    }
    return { ok: true, profile: "local" };
  }

  // 1) Production must sign through custody — legacy signing uses dev keys.
  //    Accepts "custody" (file-backed) or "external-signer" (HSM / PKCS#11).
  const signingMode = env.MNDE_RECEIPT_SIGNING_MODE;
  if (signingMode !== "custody" && signingMode !== "external-signer") {
    return fail(
      "ERR_TRUST_ROOT_REQUIRES_CUSTODY",
      "MNDE_PROFILE=production requires MNDE_RECEIPT_SIGNING_MODE=custody or external-signer. Legacy signing uses development keys and cannot anchor production trust. Configure a production custody provider, or run with MNDE_PROFILE=local for demo use."
    );
  }

  // 2) For file-backed custody, the provider must be the production one (not
  //    the ephemeral local-demo). External-signer carries no local private key,
  //    so this check does not apply to it.
  if (signingMode === "custody" && env.MNDE_KEY_CUSTODY !== "file-backed-production") {
    return fail(
      "ERR_TRUST_ROOT_DEMO_CUSTODY",
      "MNDE_PROFILE=production with MNDE_RECEIPT_SIGNING_MODE=custody requires MNDE_KEY_CUSTODY=file-backed-production. local-demo custody uses ephemeral, self-asserted development keys and must not anchor production trust."
    );
  }

  // 3) Reject any env path that points at repository dev key material.
  const devPath = detectDevKeyPath(env, options.repoRoot);
  if (devPath) {
    return fail(
      "ERR_TRUST_ROOT_DEV_KEY",
      `MNDE_PROFILE=production refuses development key material: ${devPath}. Point bundle and key paths at production material stored outside the repository.`
    );
  }

  // 4) The custody provider must load and self-verify. For external-signer this
  //    validates the bundle, that the key id exists, is active, is not revoked,
  //    and that the configured public key matches the bundle key.
  //    Imported lazily so local profile never loads the custody subsystem.
  const { loadSigningConfig } = await import("./index.mjs");
  // Same instant as step 6's ledger self-test below. A pre-flight that judged
  // the bundle's expiry at one time and the ledger key at another would not be
  // the single deterministic gate this file claims to be.
  const signing = await loadSigningConfig(env, { now: options.now });
  if (!signing.ok) {
    return fail(
      signing.reason_code ?? "ERR_CUSTODY_UNAVAILABLE",
      `MNDE_PROFILE=production custody is not usable (${signing.reason_code ?? "unknown"}: ${signing.detail ?? "no detail"}).`
    );
  }

  // 4b) External-signer: run a real self-test signature through the command and
  //     verify it before accepting the trust root.
  if (signing.signer_mode === "external-signer") {
    try {
      await signing.provider.selfTest();
    } catch (error) {
      return fail(
        "ERR_TRUST_ROOT_SIGNER_SELFTEST",
        `MNDE_PROFILE=production external signer self-test failed: ${error instanceof Error ? error.message : String(error)}.`
      );
    }
  }

  // 5) Guard against pointing custody at an exported demo bundle.
  const bundle = signing.provider.getPublicBundle();
  const authorityId = String(bundle?.authority_id ?? "");
  const rootKeyId = String(bundle?.root_key?.key_id ?? "");
  if (/local|demo/i.test(authorityId) || /local|demo/i.test(rootKeyId)) {
    return fail(
      "ERR_TRUST_ROOT_DEV_KEY",
      `Configured authority bundle '${authorityId}' (root key '${rootKeyId}') is a development/demo bundle. Production must use a published production authority bundle, not an exported local-demo one.`
    );
  }

  // 6) The production ledger is always enabled. Prove that its signer works and
  //    that the resulting signature verifies against the published ledger key.
  const ledgerProbe = '{"mnde.ledger_signer.selftest":true}';
  let ledgerSignature;
  try {
    ledgerSignature = await signing.provider.signLedger(ledgerProbe);
  } catch (error) {
    return fail(
      "ERR_TRUST_ROOT_LEDGER_SIGNER",
      `MNDE_PROFILE=production ledger signer self-test failed: ${error instanceof Error ? error.message : String(error)}.`
    );
  }
  const { verifyAgainstBundle } = await import("../custody/index.mjs");
  const ledgerCheck = await verifyAgainstBundle(
    ledgerProbe,
    ledgerSignature?.value,
    "ledger",
    ledgerSignature?.key_id,
    options.now ?? new Date().toISOString(),
    bundle
  );
  if (!ledgerCheck.ok) {
    return fail(
      "ERR_TRUST_ROOT_LEDGER_SIGNER",
      `MNDE_PROFILE=production ledger signer self-test did not verify against the published ledger key (${ledgerCheck.reason ?? "unknown"}).`
    );
  }

  // 7) Activation authority (mnde.activation.v1). The active authority
  //    transition must be verified before any execution decision is served:
  //    the record verifies offline against the SAME bundle custody signs with
  //    (signature by an `activation` role key, validity, revocation, recomputed
  //    activation_id, genesis constraints). Fail closed — no downgrade.
  //
  //    Staging: a configured record is always fully verified. REQUIRING a
  //    record in production is opt-in via MNDE_REQUIRE_ACTIVATION=1 until the
  //    release/activation tooling ships (deployments cannot yet mint records
  //    through a supported path); it then becomes the production default.
  const recordPath = env.MNDE_ACTIVATION_RECORD;
  const requireActivation = env.MNDE_REQUIRE_ACTIVATION === "1" || env.MNDE_REQUIRE_ACTIVATION === "true";
  if (typeof recordPath !== "string" || recordPath.length === 0) {
    if (requireActivation) {
      return fail(
        "ERR_ACTIVATION_MISSING",
        "MNDE_REQUIRE_ACTIVATION is set but MNDE_ACTIVATION_RECORD is not configured. Production requires a verified mnde.activation.v1 record — no execution may proceed until the active authority transition has been verified."
      );
    }
    return { ok: true, profile: "production", authority_id: authorityId, activation_id: null };
  }

  const loaded = readActivationRecord(recordPath);
  if (!loaded.ok) return loaded;
  const { verifyActivationRecord } = await import("../activation/index.mjs");
  const activation = await verifyActivationRecord(loaded.record, {
    authorityBundle: bundle,
    trustedRootFingerprint: signing.provider.trustedRootFingerprint
  });
  if (!activation.ok) return fail(activation.reason_code, activation.detail);
  if (activation.revoked_now) {
    // Revoked-now is advisory for HISTORICAL evidence, but a runtime must not
    // START under an authority transition that is currently revoked.
    return fail("ERR_ACTIVATION_UNTRUSTED", "activation record is revoked as of now (REVOKED_NOW); re-activate a non-revoked release before serving traffic.");
  }

  return { ok: true, profile: "production", authority_id: authorityId, activation_id: activation.activation_id };
}
