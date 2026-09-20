// Production trust-root bootstrap tests.
//
//   npm run test:authority-init
//
// Proves `init-production-authority` builds a real, usable trust root: the
// produced bundle verifies, loads through file-backed-production custody, passes
// the production trust-root pre-flight, and signs a receipt that verifies against
// the bundle. Guards (in-repo path, overwrite, demo authority id) fail closed.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { initProductionAuthority } from "../scripts/init-production-authority.mjs";
import { createFileBackedProductionCustody, verifyAgainstBundle } from "../src/custody/index.mjs";
import { canonicalizeJson } from "../shared/json.ts";
import { assertTrustRoot } from "../src/authority-signing/preflight.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const NOW = "2026-06-14T00:00:00.000Z";

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
  catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.message}`); }
}

async function main() {
  console.log("MNDe production trust-root bootstrap\n");
  const base = mkdtempSync(join(tmpdir(), "mnde-authinit-"));
  try {
    const outDir = join(base, "root");
    const res = await initProductionAuthority({ outDir, authorityId: "acme-prod", now: NOW });

    await test("creates a verifiable trust root and reports the fingerprint", () => {
      assert.equal(res.ok, true, res.reason);
      assert.ok(/^[0-9a-f]{64}$/.test(res.rootFingerprint), "root fingerprint is a sha256 hex");
      const bundle = JSON.parse(readFileSync(res.paths.bundle, "utf8"));
      assert.equal(bundle.schema_version, "mnde.authority.bundle.v1");
      assert.equal(bundle.authority_id, "acme-prod");
      assert.equal(bundle.root_key.fingerprint, res.rootFingerprint);
      assert.ok(!JSON.stringify(bundle).includes("PRIVATE KEY"), "published bundle carries no private key");
    });

    await test("loads through file-backed-production custody and signs a verifiable receipt", async () => {
      const provider = createFileBackedProductionCustody({
        MNDE_AUTHORITY_BUNDLE: res.paths.bundle,
        MNDE_RECEIPT_SIGNING_KEY: res.paths.receiptPrivate,
        MNDE_RECEIPT_KEY_ID: res.receiptKeyId,
        MNDE_LEDGER_SIGNING_KEY: res.paths.ledgerPrivate,
        MNDE_LEDGER_KEY_ID: res.ledgerKeyId
      });
      const payload = canonicalizeJson({ decision: "ALLOW" });
      const sig = await provider.signReceipt(payload);
      const bundle = provider.getPublicBundle();
      assert.equal((await verifyAgainstBundle(payload, sig.value, "receipt", sig.key_id, NOW, bundle)).ok, true);
      const ledgerSig = await provider.signLedger(payload);
      assert.equal((await verifyAgainstBundle(payload, ledgerSig.value, "ledger", ledgerSig.key_id, NOW, bundle)).ok, true);
    });

    await test("passes the production trust-root pre-flight", async () => {
      const trust = await assertTrustRoot({
        MNDE_PROFILE: "production",
        MNDE_RECEIPT_SIGNING_MODE: "custody",
        MNDE_KEY_CUSTODY: "file-backed-production",
        MNDE_AUTHORITY_BUNDLE: res.paths.bundle,
        MNDE_RECEIPT_SIGNING_KEY: res.paths.receiptPrivate,
        MNDE_RECEIPT_KEY_ID: res.receiptKeyId,
        MNDE_LEDGER_SIGNING_KEY: res.paths.ledgerPrivate,
        MNDE_LEDGER_KEY_ID: res.ledgerKeyId
      }, { repoRoot, now: NOW });
      assert.equal(trust.ok, true, trust.detail || trust.reason_code);
      assert.equal(trust.profile, "production");
    });

    await test("refuses to overwrite an existing trust root", async () => {
      const again = await initProductionAuthority({ outDir, authorityId: "acme-prod", now: NOW });
      assert.equal(again.ok, false);
      assert.match(again.reason, /overwrite/);
    });

    await test("refuses to write inside the repository", async () => {
      const r = await initProductionAuthority({ outDir: join(repoRoot, "tmp-root"), authorityId: "acme-prod", now: NOW, repoRoot });
      assert.equal(r.ok, false);
      assert.match(r.reason, /inside the repository/);
    });

    await test("refuses a demo/local authority id", async () => {
      const r = await initProductionAuthority({ outDir: join(base, "root2"), authorityId: "mnde-local-demo", now: NOW });
      assert.equal(r.ok, false);
      assert.match(r.reason, /local.*demo|demo/);
    });

    // The pre-flight evaluates every step at ONE instant. It used to judge the
    // bundle's expiry window at the wall clock while judging the ledger key at
    // the injected `now`, so this suite's own fixture — minted at NOW with a
    // 90-day bundle lifetime — began failing as BUNDLE_STALE the moment real
    // time passed NOW + 90 days, on every branch at once.
    //
    // Both halves matter. Honouring the clock must not become a way to accept
    // an expired bundle in production, where no caller passes one.
    const preflightEnv = {
      MNDE_PROFILE: "production",
      MNDE_RECEIPT_SIGNING_MODE: "custody",
      MNDE_KEY_CUSTODY: "file-backed-production",
      MNDE_AUTHORITY_BUNDLE: res.paths.bundle,
      MNDE_RECEIPT_SIGNING_KEY: res.paths.receiptPrivate,
      MNDE_RECEIPT_KEY_ID: res.receiptKeyId,
      MNDE_LEDGER_SIGNING_KEY: res.paths.ledgerPrivate,
      MNDE_LEDGER_KEY_ID: res.ledgerKeyId
    };

    await test("the pre-flight judges bundle expiry at the instant it was given", async () => {
      // Inside the bundle's window, whatever the wall clock says today.
      const inside = await assertTrustRoot(preflightEnv, { repoRoot, now: NOW });
      assert.equal(inside.ok, true, inside.detail || inside.reason_code);
    });

    await test("an expired bundle still fails closed", async () => {
      // One day past not_after (NOW + 90 days). This is the production path:
      // no injected clock means the wall clock, and a bundle past its window
      // must refuse to anchor trust.
      const past = new Date(Date.parse(NOW) + 91 * 24 * 60 * 60 * 1000).toISOString();
      const expired = await assertTrustRoot(preflightEnv, { repoRoot, now: past });
      assert.equal(expired.ok, false, "a bundle past not_after must not pass the pre-flight");
      assert.equal(expired.reason_code, "ERR_CUSTODY_BUNDLE_STALE");
    });
  } finally {
    rmSync(base, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) { console.log(`FAIL authority-init tests (${results.length - failed}/${results.length})`); process.exit(1); }
  console.log(`PASS authority-init tests (${results.length}/${results.length})`);
}

main().catch((error) => { console.error(error); process.exit(1); });
