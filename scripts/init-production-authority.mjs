#!/usr/bin/env node
// Build a production trust root.
//
//   node scripts/init-production-authority.mjs --out /secure/path --authority-id acme-prod
//
// Generates the long-lived ROOT authority key plus receipt and ledger signing keys,
// or uses MNDE_EXTERNAL_ROOT_SIGNER_CMD with an already-provisioned root. It builds
// a root-signed mnde.authority.bundle.v1 and verifies it before writing anything.
// Secrets are written outside the repository with 0600 permissions.
//
// What comes out:
//   <out>/root.key.pem            ROOT private key (file mode only). Move this
//                                 offline / into an HSM or escrow. It is NOT
//                                 needed on the serving host; it authorizes
//                                 infrequent authority artifacts.
//   <out>/root.pub.pem            ROOT public key.
//   <out>/receipt-signing.key.pem Receipt signing private key — this is the only
//                                 secret the sidecar needs (file-backed-production).
//   <out>/authority.bundle.json   Public bundle to publish; verifiers pin its root
//                                 fingerprint out of band.
//
// Fail-closed: refuses to write into the repository, refuses to overwrite, and
// refuses to finish if the produced bundle does not verify.

import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildAuthorityBundle,
  createExternalRootSigner,
  generateAuthorityKeyPair,
  resolveRootSigner,
  signCanonical,
  verifyAuthorityBundle,
  verifyAgainstBundle
} from "../src/custody/index.mjs";
import { canonicalizeJson } from "../shared/json.ts";
import { isRepoContained } from "../src/authority-signing/repo-containment.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function addDaysIso(nowIso, days) {
  const t = Date.parse(nowIso);
  return new Date(t + days * 24 * 60 * 60 * 1000).toISOString();
}

// Pure, testable core. Returns { ok, ... } or { ok:false, reason }.
export async function initProductionAuthority(options = {}) {
  const {
    outDir,
    authorityId,
    now = new Date().toISOString(),
    validDays = 365,
    bundleDays = 90,
    receiptKeyId = "receipt-1",
    ledgerKeyId = "ledger-1",
    activationKeyId = "activation-1",
    rootKeyId = "root-1",
    rootSigner = null,
    rootPublicPem = null,
    repoRoot = REPO_ROOT
  } = options;

  if (typeof outDir !== "string" || outDir.length === 0) return { ok: false, reason: "outDir is required" };
  if (typeof authorityId !== "string" || authorityId.length === 0) return { ok: false, reason: "authorityId is required" };
  if (/local|demo/i.test(authorityId)) return { ok: false, reason: "authorityId must not contain 'local' or 'demo' (those mark development bundles)" };

  const out = resolve(outDir);
  // F4: reject any destination that resolves INTO the repository, including path
  // aliases (relative traversal, drive-letter/dir casing on Windows, existing
  // symlinks/junctions). Canonical filesystem resolution, not string prefixing.
  if (isRepoContained(out, repoRoot)) {
    return { ok: false, reason: "refusing to write keys inside the repository (after canonical path resolution); choose an --out path outside the project" };
  }

  const externalRoot = rootSigner !== null;
  if (externalRoot && (typeof rootPublicPem !== "string" || rootPublicPem.length === 0)) {
    return { ok: false, reason: "rootPublicPem is required with rootSigner" };
  }

  const paths = {
    rootPrivate: externalRoot ? null : resolve(out, "root.key.pem"),
    rootPublic: resolve(out, "root.pub.pem"),
    receiptPrivate: resolve(out, "receipt-signing.key.pem"),
    ledgerPrivate: resolve(out, "ledger-signing.key.pem"),
    activationPrivate: resolve(out, "activation-signing.key.pem"),
    bundle: resolve(out, "authority.bundle.json")
  };
  for (const p of Object.values(paths).filter(Boolean)) {
    if (existsSync(p)) return { ok: false, reason: `refusing to overwrite existing file: ${p}` };
  }

  // Production callers must obtain rootSigner through resolveRootSigner. When
  // present, no root private key is generated or written by this ceremony.
  const root_ = externalRoot
    ? { keyId: rootKeyId, publicPem: rootPublicPem, signer: rootSigner }
    : { keyId: rootKeyId, ...generateAuthorityKeyPair() };
  const receipt = { keyId: receiptKeyId, ...generateAuthorityKeyPair() };
  const ledger = { keyId: ledgerKeyId, ...generateAuthorityKeyPair() };
  const activation = { keyId: activationKeyId, ...generateAuthorityKeyPair() };

  const bundle = await buildAuthorityBundle({
    authorityId,
    issuedAt: now,
    notAfter: addDaysIso(now, bundleDays),
    root: root_,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: now, validUntil: addDaysIso(now, validDays) }],
    ledgerKeys: [{ keyId: ledger.keyId, publicPem: ledger.publicPem, validFrom: now, validUntil: addDaysIso(now, validDays) }],
    activationKeys: [{ keyId: activation.keyId, publicPem: activation.publicPem, validFrom: now, validUntil: addDaysIso(now, validDays) }],
    revocation: []
  });

  // Verify the produced trust root before writing anything (fail closed).
  const bundleCheck = await verifyAuthorityBundle(bundle, { trustedRootFingerprint: bundle.root_key.fingerprint, now });
  if (!bundleCheck.ok) return { ok: false, reason: `produced bundle failed verification: ${bundleCheck.reason}` };
  // F3: prove possession of each generated private key by signing a deterministic
  // probe and CRYPTOGRAPHICALLY verifying it against the PUBLISHED public key that
  // downstream verifiers will actually use (looked up by role + key id in the
  // bundle, honoring validity/revocation). A non-empty signature is not enough —
  // the bytes must verify. Reuses the same verifyAgainstBundle primitive used at
  // serve time; no init-only signature format.
  for (const probe of [
    { role: "receipt", keyId: receipt.keyId, privatePem: receipt.privatePem },
    { role: "ledger", keyId: ledger.keyId, privatePem: ledger.privatePem },
    { role: "activation", keyId: activation.keyId, privatePem: activation.privatePem }
  ]) {
    const payload = canonicalizeJson({ "mnde.init_probe.v1": true, role: probe.role, key_id: probe.keyId });
    const signature = await signCanonical(payload, probe.privatePem);
    const verified = await verifyAgainstBundle(payload, signature, probe.role, probe.keyId, now, bundle);
    if (!verified.ok) {
      return { ok: false, reason: `${probe.role} key probe did not verify against the published bundle key (${verified.reason ?? "unknown"})` };
    }
  }

  mkdirSync(out, { recursive: true });
  // F2: exclusive creation (flag "wx") — never truncate or replace an existing
  // trust artifact, even under a race between the existence check above and here.
  // If any write fails, remove the files THIS ceremony created so no partial,
  // half-valid trust root is left behind.
  const written = [];
  for (const w of [
    ...(externalRoot ? [] : [{ path: paths.rootPrivate, data: root_.privatePem, mode: 0o600 }]),
    { path: paths.rootPublic, data: root_.publicPem, mode: 0o644 },
    { path: paths.receiptPrivate, data: receipt.privatePem, mode: 0o600 },
    { path: paths.ledgerPrivate, data: ledger.privatePem, mode: 0o600 },
    { path: paths.activationPrivate, data: activation.privatePem, mode: 0o600 },
    { path: paths.bundle, data: `${JSON.stringify(bundle, null, 2)}\n`, mode: 0o644 }
  ]) {
    try {
      writeFileSync(w.path, w.data, { mode: w.mode, flag: "wx" });
      written.push(w.path);
    } catch (error) {
      for (const done of [...written].reverse()) {
        try { rmSync(done, { force: true }); } catch { /* best-effort cleanup of this ceremony's files */ }
      }
      const why = error && error.code === "EEXIST"
        ? `refusing to overwrite existing file: ${w.path}`
        : `failed to write ${w.path}: ${error?.message ?? String(error)}`;
      return { ok: false, reason: why };
    }
  }

  return {
    ok: true,
    authorityId,
    rootFingerprint: bundle.root_key.fingerprint,
    receiptKeyId: receipt.keyId,
    ledgerKeyId: ledger.keyId,
    activationKeyId: activation.keyId,
    bundleNotAfter: bundle.not_after,
    receiptKeyValidUntil: bundle.keys.receipt[0].valid_until,
    paths
  };
}

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

async function main() {
  const outDir = arg("--out");
  const authorityId = arg("--authority-id");
  if (!outDir || !authorityId) {
    process.stderr.write("usage: node scripts/init-production-authority.mjs --out <dir-outside-repo> --authority-id <id> [--valid-days 365] [--bundle-days 90] [--receipt-key-id receipt-1] [--ledger-key-id ledger-1] [--root-key-id root-1]\n");
    process.exit(2);
  }
  const rootKeyId = arg("--root-key-id", "root-1");
  let rootSigner = null;
  let rootPublicPem = null;
  if (typeof process.env.MNDE_EXTERNAL_ROOT_SIGNER_CMD === "string" && process.env.MNDE_EXTERNAL_ROOT_SIGNER_CMD.trim().length > 0) {
    try {
      const external = createExternalRootSigner(process.env, { keyId: rootKeyId });
      rootSigner = resolveRootSigner({
        env: process.env,
        root: { keyId: external.keyId, publicPem: external.publicKeyPem, fingerprint: external.fingerprint },
        rootSigner: external
      });
      rootPublicPem = external.publicKeyPem;
    } catch (error) {
      process.stderr.write(`init-production-authority: root signer unavailable (${error?.code ?? "ERR_ROOT_SIGNER"}): ${error?.message ?? String(error)}\n`);
      process.exit(1);
    }
  }
  const result = await initProductionAuthority({
    outDir,
    authorityId,
    validDays: Number(arg("--valid-days", "365")),
    bundleDays: Number(arg("--bundle-days", "90")),
    receiptKeyId: arg("--receipt-key-id", "receipt-1"),
    ledgerKeyId: arg("--ledger-key-id", "ledger-1"),
    rootKeyId,
    rootSigner,
    rootPublicPem
  });
  if (!result.ok) {
    process.stderr.write(`init-production-authority: ${result.reason}\n`);
    process.exit(1);
  }
  const e = (k, v) => process.stdout.write(`  ${k}=${v}\n`);
  process.stdout.write("\nProduction trust root created.\n\n");
  process.stdout.write(`Authority id:      ${result.authorityId}\n`);
  process.stdout.write(`Root fingerprint:  ${result.rootFingerprint}\n`);
  process.stdout.write("  ^ publish this and have verifiers PIN it out of band (site, signed release notes).\n\n");
  process.stdout.write("Files written:\n");
  process.stdout.write(`  ${result.paths.bundle}        (public — publish this)\n`);
  process.stdout.write(`  ${result.paths.receiptPrivate}  (sidecar secret — keep on the serving host)\n`);
  process.stdout.write(`  ${result.paths.ledgerPrivate}  (sidecar secret — signs execution-ledger entries)\n`);
  process.stdout.write(`  ${result.paths.activationPrivate}  (activation secret — signs install/upgrade/rollback transitions; not needed by the serving sidecar)\n`);
  if (result.paths.rootPrivate) {
    process.stdout.write(`  ${result.paths.rootPrivate}             (CROWN JEWEL — move OFFLINE / to HSM/escrow; not needed on the host)\n`);
  } else {
    process.stdout.write("  root private key not created (external root signer)\n");
  }
  process.stdout.write(`  ${result.paths.rootPublic}\n\n`);
  process.stdout.write("Run the sidecar against this trust root:\n");
  e("MNDE_PROFILE", "production");
  e("MNDE_RECEIPT_SIGNING_MODE", "custody");
  e("MNDE_KEY_CUSTODY", "file-backed-production");
  e("MNDE_AUTHORITY_BUNDLE", result.paths.bundle);
  e("MNDE_RECEIPT_SIGNING_KEY", result.paths.receiptPrivate);
  e("MNDE_RECEIPT_KEY_ID", result.receiptKeyId);
  e("MNDE_LEDGER_SIGNING_KEY", result.paths.ledgerPrivate);
  e("MNDE_LEDGER_KEY_ID", result.ledgerKeyId);
  process.stdout.write(`\nReceipt key valid until ${result.receiptKeyValidUntil}; bundle stale after ${result.bundleNotAfter}.\n`);
  process.stdout.write("Rotate with: npm run authority -- rotate ...   Revoke with: npm run authority -- revoke ...\n");
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    process.stderr.write(`init-production-authority: ${error?.message ?? String(error)}\n`);
    process.exit(1);
  });
}
