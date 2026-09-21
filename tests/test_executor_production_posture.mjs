// Executor production posture tests.
//
//   npm run test:executor-posture
//
// Proves the executor refuses to exist in MNDE_PROFILE=production unless the
// trust root and the executor binding were explicitly configured, and that a
// receipt whose only trust source is the authority bundle shipped in the package
// is not accepted there. The sidecar has had a production gate for some time;
// this is the same discipline on the side that consumes receipts.
//
// Refusal cases first, then the configurations that are supposed to work, then
// the development posture that must keep working unchanged.
//
// The live-sidecar cases bind a port chosen by the OS rather than the harness
// default, so this suite cannot collide with another sidecar suite.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createPrivateKey, sign as nodeSign } from "node:crypto";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createMndeExecutor } from "../executor/index.mjs";
import { ERR_EXECUTION_DISABLED } from "../src/execution-availability/index.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair, signCanonical } from "../src/custody/index.mjs";
import { issueExecutorCredential } from "../src/custody/executor-credential.mjs";
import { EXECUTOR_RECEIPT_CAPABILITY } from "../src/custody/executor-identity.mjs";
import { signReceiptForDelivery, LIVE_RECEIPT_SIGNING_MODES } from "../src/authority-signing/index.mjs";
import { buildPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import {
  assertExecutorPosture,
  evaluateExecutorPosture,
  ERR_EXECUTOR_PRODUCTION_TRUST_ROOT_REQUIRED,
  ERR_EXECUTOR_PRODUCTION_DEMO_TRUST_ROOT,
  ERR_EXECUTOR_PRODUCTION_EXECUTOR_BINDING_REQUIRED
} from "../src/executor-posture-preflight.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
bootstrapReceiptKeys({ repoRoot });

const samplePolicy = join(repoRoot, "examples", "policy-engine", "sample-policy.json");
const EXECUTOR_ID = "mnde:test:prod:executor:posture:01";
const ENVIRONMENT_ID = "prod";

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function freePort() {
  const server = createServer();
  await new Promise((done, reject) => server.once("error", reject).listen(0, "127.0.0.1", done));
  const { port } = server.address();
  await new Promise((done) => server.close(done));
  return port;
}

function reasons(result) {
  return result.violations.map((violation) => violation.reason_code);
}

// A real authority bundle at a path that is not development key material, so the
// "correct configuration" cases are configured with trust material of the shape
// production would actually use rather than a stub that happens to parse.
async function productionTrust(dir) {
  const root = { keyId: "posture-test-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "posture-test-receipt", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "mnde-executor-posture-test",
    issuedAt: "2026-01-01T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    ledgerKeys: [],
    policyKeys: [],
    approvalKeys: [],
    revocation: []
  });
  const bundlePath = join(dir, "published-authority-bundle.json");
  writeFileSync(bundlePath, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
  return { bundle, bundlePath, fingerprint: bundle.root_key.fingerprint, root, receipt };
}

// Build the envelope a correctly configured production deployment would accept:
// executor-bound (mnde.signed-receipt.v2), custody-attested by `trust`'s
// authority, carrying a credential that authority issued. Its INNER policy
// receipt is signed by the repo-local demo authority — which is the whole point.
// The verifier drops the configured bundle for an inner receipt whose authority
// id is not the configured one, so the inner decision falls back to the shipped
// authority while the envelope still reports verified.
async function repoLocalInsideProductionEnvelope(trust) {
  const now = "2026-06-14T00:00:00.000Z";
  const executorKeys = generateAuthorityKeyPair();
  const credential = await issueExecutorCredential({
    authorityBundle: trust.bundle,
    rootPrivatePem: trust.root.privatePem,
    executorId: EXECUTOR_ID,
    publicPem: executorKeys.publicPem,
    environmentId: ENVIRONMENT_ID,
    capabilities: [EXECUTOR_RECEIPT_CAPABILITY],
    issuedAt: now,
    notBefore: "2026-01-01T00:00:00.000Z",
    expiresAt: "2099-01-01T00:00:00.000Z"
  });
  const provider = {
    mode: "file-backed-production",
    production: true,
    trustedRootFingerprint: trust.fingerprint,
    signReceipt: async (payload) => ({
      key_id: trust.receipt.keyId,
      value: await signCanonical(payload, trust.receipt.privatePem),
      fingerprint: trust.bundle.keys.receipt[0].fingerprint
    }),
    signPolicy: () => { throw new Error("n/a"); },
    signApproval: () => { throw new Error("n/a"); },
    getPublicBundle: () => structuredClone(trust.bundle)
  };
  const request = {
    schema_version: "1.0", request_id: "posture-inner-1", timestamp: now,
    principal: { id: "u" }, agent: { id: "a" }, tool: { tool_name: "read_status" },
    parameters: {}, environment: {}, context: {}
  };
  const inner = buildPolicyReceipt(request, JSON.parse(readFileSync(samplePolicy, "utf8")), { now });
  const signed = await signReceiptForDelivery(inner, { mode: "custody", provider }, {
    now,
    signingMode: LIVE_RECEIPT_SIGNING_MODES.EXECUTOR_AND_AUTHORITY,
    executorIdentity: {
      executor_id: EXECUTOR_ID,
      key_id: credential.key_id,
      credential_id: credential.credential_id,
      environment_id: ENVIRONMENT_ID,
      credential
    },
    executorSigner: {
      sign: async (body) => nodeSign(null, Buffer.from(body, "utf8"), createPrivateKey(executorKeys.privatePem)).toString("hex")
    }
  });
  assert.equal(signed.ok, true, `envelope signing failed: ${signed.reason_code ?? ""}`);
  assert.equal(signed.receipt.schema_version, "mnde.signed-receipt.v2");
  return signed.receipt;
}

// A sidecar stand-in that hands back one fixed decision. The real sidecar cannot
// produce the envelope above — that is what a production signer produces — so
// the only way to run it through the executor's own verification path is to
// serve it. Nothing else about the executor is stubbed.
async function cannedSidecar(receipt) {
  const server = createHttpServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ decision: "ALLOW", reason_code: "RULE_MATCH", receipt }));
    });
  });
  await new Promise((done, reject) => server.once("error", reject).listen(0, "127.0.0.1", done));
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    stop: () => new Promise((done) => server.close(done))
  };
}

// Run fn with MNDE_PROFILE set, then put the environment back. The executor
// reads the profile from process.env at construction, so production posture can
// only be exercised in-process this way. Child processes started earlier keep
// the env they were spawned with.
async function withProfile(value, fn) {
  const had = Object.hasOwn(process.env, "MNDE_PROFILE");
  const previous = process.env.MNDE_PROFILE;
  if (value === undefined) delete process.env.MNDE_PROFILE;
  else process.env.MNDE_PROFILE = value;
  try {
    return await fn();
  } finally {
    if (had) process.env.MNDE_PROFILE = previous;
    else delete process.env.MNDE_PROFILE;
  }
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "mnde-executor-posture-"));
  const receiptsDir = join(dir, "receipts");
  const trust = await productionTrust(dir);

  const fullyConfigured = {
    verifyAuthorityBundlePath: trust.bundlePath,
    verifyAuthorityBundleLoaded: true,
    verifyTrustedRootFingerprint: trust.fingerprint,
    verifyEnvironmentId: ENVIRONMENT_ID,
    verifyExpectedExecutorId: EXECUTOR_ID,
    verifyRequireExecutor: true,
    repoRoot
  };

  // ── refusals: missing trust configuration ──────────────────────────────────

  await test("production posture refuses when nothing is configured", () => {
    const result = evaluateExecutorPosture({ repoRoot });
    assert.equal(result.ok, false);
    const codes = reasons(result);
    assert.ok(codes.includes(ERR_EXECUTOR_PRODUCTION_TRUST_ROOT_REQUIRED), JSON.stringify(codes));
    assert.ok(codes.includes(ERR_EXECUTOR_PRODUCTION_EXECUTOR_BINDING_REQUIRED), JSON.stringify(codes));
  });

  await test("production posture refuses a bundle with no pinned root fingerprint", () => {
    const result = evaluateExecutorPosture({ ...fullyConfigured, verifyTrustedRootFingerprint: undefined });
    assert.equal(result.ok, false);
    assert.deepEqual(reasons(result), [ERR_EXECUTOR_PRODUCTION_TRUST_ROOT_REQUIRED]);
  });

  await test("production posture refuses a configured bundle that does not load", () => {
    // loadVerifyBundle swallows a read/parse failure and returns undefined, which
    // would otherwise be indistinguishable from "never configured" and drop the
    // deployment onto the very fallback it meant to replace.
    const result = evaluateExecutorPosture({ ...fullyConfigured, verifyAuthorityBundleLoaded: false });
    assert.equal(result.ok, false);
    assert.deepEqual(reasons(result), [ERR_EXECUTOR_PRODUCTION_TRUST_ROOT_REQUIRED]);
  });

  // ── refusals: repo-local demo trust ────────────────────────────────────────

  await test("production posture refuses the demo authority that ships in the tree", () => {
    const result = evaluateExecutorPosture({
      ...fullyConfigured,
      verifyAuthorityBundlePath: join(repoRoot, "authority", "authority-manifest.json")
    });
    assert.equal(result.ok, false);
    assert.deepEqual(reasons(result), [ERR_EXECUTOR_PRODUCTION_DEMO_TRUST_ROOT]);
  });

  await test("production posture refuses the demo authority shipped inside a package", () => {
    // The published tarball carries dist/authority/, so this is the accident an
    // operator is most likely to have rather than an exotic one.
    const installRoot = join(dir, "node_modules", "mnde-public-test", "dist");
    const result = evaluateExecutorPosture({
      ...fullyConfigured,
      verifyAuthorityBundlePath: join(installRoot, "authority", "authority-manifest.json"),
      repoRoot: installRoot
    });
    assert.equal(result.ok, false);
    assert.deepEqual(reasons(result), [ERR_EXECUTOR_PRODUCTION_DEMO_TRUST_ROOT]);
  });

  // ── refusals: executor binding ─────────────────────────────────────────────

  await test("production posture refuses without an expected executor id", () => {
    const result = evaluateExecutorPosture({ ...fullyConfigured, verifyExpectedExecutorId: undefined, verifyRequireExecutor: false });
    assert.equal(result.ok, false);
    assert.deepEqual(reasons(result), [ERR_EXECUTOR_PRODUCTION_EXECUTOR_BINDING_REQUIRED]);
  });

  await test("production posture refuses without an environment id", () => {
    // Required alongside the executor id, not instead of it: an executor-bound
    // receipt cannot be verified offline without the environment, so demanding
    // one without the other buys a refusal rather than a check.
    const result = evaluateExecutorPosture({ ...fullyConfigured, verifyEnvironmentId: "" });
    assert.equal(result.ok, false);
    assert.deepEqual(reasons(result), [ERR_EXECUTOR_PRODUCTION_EXECUTOR_BINDING_REQUIRED]);
  });

  // ── the configuration that is supposed to work ─────────────────────────────

  await test("a correctly configured production posture passes", () => {
    const result = evaluateExecutorPosture(fullyConfigured);
    assert.deepEqual(result.violations, []);
    assert.equal(result.ok, true);
  });

  // ── the profile signal itself ──────────────────────────────────────────────

  await test("an unset or local profile never enforces production", async () => {
    for (const profile of [undefined, "local"]) {
      const result = await withProfile(profile, () => assertExecutorPosture({ repoRoot }));
      assert.equal(result.ok, true, `profile ${String(profile)} must not enforce`);
      assert.equal(result.enforced, false);
    }
    // An unknown value is not production either — but it is not a silent local
    // default: the canonical parser rejects it, and the sidecar's own trust-root
    // pre-flight is what fails the deployment closed on it.
    const unknown = await withProfile("prod", () => assertExecutorPosture({ repoRoot }));
    assert.equal(unknown.enforced, false);
  });

  await test("MNDE_PROFILE=production enforces", async () => {
    const result = await withProfile("production", () => assertExecutorPosture({ repoRoot }));
    assert.equal(result.ok, false);
    assert.equal(result.enforced, true);
    assert.equal(result.reason_code, ERR_EXECUTOR_PRODUCTION_TRUST_ROOT_REQUIRED);
  });

  // ── construction ───────────────────────────────────────────────────────────

  await test("createMndeExecutor throws in production posture when unconfigured", async () => {
    await withProfile("production", () => {
      assert.throws(
        () => createMndeExecutor({ receiptsDir }),
        (error) => error.code === ERR_EXECUTOR_PRODUCTION_TRUST_ROOT_REQUIRED && Array.isArray(error.violations)
      );
    });
  });

  await test("createMndeExecutor throws in production posture on the demo authority", async () => {
    await withProfile("production", () => {
      assert.throws(
        () => createMndeExecutor({
          receiptsDir,
          verifyAuthorityBundle: join(repoRoot, "authority", "authority-manifest.json"),
          verifyTrustedRootFingerprint: trust.fingerprint,
          verifyEnvironmentId: ENVIRONMENT_ID,
          verifyExpectedExecutorId: EXECUTOR_ID
        }),
        (error) => error.code === ERR_EXECUTOR_PRODUCTION_DEMO_TRUST_ROOT
      );
    });
  });

  await test("createMndeExecutor succeeds in production posture when correctly configured", async () => {
    await withProfile("production", () => {
      const mnde = createMndeExecutor({
        receiptsDir,
        verifyAuthorityBundle: trust.bundlePath,
        verifyTrustedRootFingerprint: trust.fingerprint,
        verifyEnvironmentId: ENVIRONMENT_ID,
        verifyExpectedExecutorId: EXECUTOR_ID
      });
      assert.equal(typeof mnde.execute, "function");
    });
  });

  await test("createMndeExecutor is unchanged outside a production profile", async () => {
    for (const profile of [undefined, "local"]) {
      await withProfile(profile, () => {
        const mnde = createMndeExecutor({ receiptsDir });
        assert.equal(typeof mnde.execute, "function");
      });
    }
  });

  // ── against a real sidecar and a real receipt ──────────────────────────────
  //
  // The two cases below are the same receipt, decided by the same sidecar, read
  // by two executors that differ only in posture. That is what makes the second
  // one evidence: without the first, "production refused it" could just mean the
  // receipt was never any good.

  const port = await freePort();
  const sidecar = await startMndeSidecar({
    url: `http://127.0.0.1:${port}`,
    env: { MNDE_PROFILE: "local", MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: samplePolicy }
  });

  try {
    await test("local posture verifies a receipt trusted only by the shipped authority", async () => {
      await withProfile("local", async () => {
        const mnde = createMndeExecutor({ sidecarUrl: sidecar.url, receiptsDir: join(dir, "receipts-local") });
        const outcome = await mnde.execute({ action: "read_status", input: {}, run: () => "ran" });
        // Verified against the repo-local authority — the fallback this gate is
        // about. Development depends on it and keeps it.
        assert.equal(outcome.verified, true, JSON.stringify(outcome));
        // The receipt cleared the strict gate, and the executor STILL refuses:
        // F-001 holds every protected effect closed. An ALLOW decision is never
        // permission to execute, in any posture, so this is the furthest a
        // request gets today.
        assert.equal(outcome.reason, ERR_EXECUTION_DISABLED, JSON.stringify(outcome));
        assert.equal(outcome.executed, false, JSON.stringify(outcome));
      });
    });

    await test("production posture refuses that same receipt", async () => {
      await withProfile("production", async () => {
        const mnde = createMndeExecutor({
          sidecarUrl: sidecar.url,
          receiptsDir: join(dir, "receipts-prod"),
          verifyAuthorityBundle: trust.bundlePath,
          verifyTrustedRootFingerprint: trust.fingerprint,
          verifyEnvironmentId: ENVIRONMENT_ID,
          verifyExpectedExecutorId: EXECUTOR_ID
        });
        const outcome = await mnde.execute({ action: "read_status", input: {}, run: () => "ran" });
        // Same sidecar, same policy, same ALLOW. The only difference is posture,
        // and the repo-local trust source no longer counts as verification.
        assert.equal(outcome.verified, false, JSON.stringify(outcome));
        assert.equal(outcome.decision, "REFUSE", JSON.stringify(outcome));
        assert.equal(outcome.executed, false, JSON.stringify(outcome));
        assert.equal(outcome.failClosed, true, JSON.stringify(outcome));
        // It must refuse for the RIGHT reason: the receipt did not verify, not
        // the execution hold that would have stopped it a step later anyway.
        assert.equal(outcome.reason, "ERR_RECEIPT_UNVERIFIED", JSON.stringify(outcome));
      });
    });
  } finally {
    await sidecar.stop();
  }

  // ── the fallback the gate exists to close ─────────────────────────────────
  //
  // The cases above are refused for a coarser reason: a policy-engine receipt
  // carries no executor binding, so the strict gate rejects it whatever its
  // trust source. This pair is the narrow one. The envelope IS executor-bound
  // and IS attested by the configured authority; only the decision inside it is
  // signed by the authority that ships in the package. Both executors below get
  // the same envelope and the same verification configuration. The only
  // difference between them is MNDE_PROFILE.

  const forged = await repoLocalInsideProductionEnvelope(trust);
  const canned = await cannedSidecar(forged);
  const verifyConfig = {
    sidecarUrl: canned.url,
    verifyAuthorityBundle: trust.bundlePath,
    verifyTrustedRootFingerprint: trust.fingerprint,
    verifyEnvironmentId: ENVIRONMENT_ID,
    verifyExpectedExecutorId: EXECUTOR_ID
  };

  try {
    await test("outside production posture the envelope verifies, repo-local inner and all", async () => {
      await withProfile("local", async () => {
        const mnde = createMndeExecutor({ ...verifyConfig, receiptsDir: join(dir, "receipts-inner-local") });
        const outcome = await mnde.execute({ action: "read_status", input: {}, run: () => "ran" });
        // This is the hole, stated as a passing assertion: attestation valid,
        // executor binding valid, inner decision signed by demo key material,
        // and the verifier says verified. Without this case the next one could
        // pass because the envelope was simply malformed.
        assert.equal(outcome.verified, true, JSON.stringify(outcome));
      });
    });

    await test("production posture refuses an envelope whose inner decision rests on the shipped authority", async () => {
      await withProfile("production", async () => {
        const mnde = createMndeExecutor({ ...verifyConfig, receiptsDir: join(dir, "receipts-inner-prod") });
        const outcome = await mnde.execute({ action: "read_status", input: {}, run: () => "ran" });
        assert.equal(outcome.verified, false, JSON.stringify(outcome));
        assert.equal(outcome.decision, "REFUSE", JSON.stringify(outcome));
        assert.equal(outcome.executed, false, JSON.stringify(outcome));
        assert.equal(outcome.failClosed, true, JSON.stringify(outcome));
        assert.equal(outcome.reason, "ERR_RECEIPT_UNVERIFIED", JSON.stringify(outcome));
      });
    });
  } finally {
    await canned.stop();
  }

  rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });

  console.log(`\n${failed === 0 ? "PASS" : "FAIL"} executor production posture (${passed}/${passed + failed})`);
  process.exit(failed === 0 ? 0 : 1);
}

await main();
