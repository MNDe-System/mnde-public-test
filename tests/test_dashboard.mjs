// Operational dashboard (no-login) tests.
//
//   npm run test:dashboard
//
// Proves the infrastructure-first repositioning: a fresh user launches MNDe and
// the sidecar serves a local operational dashboard at "/" with NO login, signup,
// account creation, or cloud dependency. The dashboard answers one question —
// "Is routed execution protected right now?" — and reads only local status
// endpoints. The decision/receipt/replay/authority/policy paths are untouched.

import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { normalizeReceipt, readRecentReceipts } from "../sidecar/production_api.mjs";
import { buildSidecarRefusalReceipt } from "../sidecar/refusal_receipt.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { signPolicyBundle } from "../src/policy-bundles/index.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

async function writeProductionCustody(dir) {
  const root = { keyId: "prod-root", ...generateAuthorityKeyPair() };
  const receipt = { keyId: "prod-receipt-1", ...generateAuthorityKeyPair() };
  const ledger = { keyId: "prod-ledger-1", ...generateAuthorityKeyPair() };
  const bundle = await buildAuthorityBundle({
    authorityId: "acme-prod-dashboard",
    issuedAt: "2026-06-14T00:00:00.000Z",
    notAfter: "2099-01-01T00:00:00.000Z",
    root,
    receiptKeys: [{ keyId: receipt.keyId, publicPem: receipt.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }],
    ledgerKeys: [{ keyId: ledger.keyId, publicPem: ledger.publicPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const bundlePath = join(dir, "authority.bundle.json");
  const keyPath = join(dir, "receipt.key.pem");
  const ledgerKeyPath = join(dir, "ledger.key.pem");
  writeFileSync(bundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(keyPath, receipt.privatePem, "utf8");
  writeFileSync(ledgerKeyPath, ledger.privatePem, "utf8");
  return {
    MNDE_PROFILE: "production",
    MNDE_RECEIPT_SIGNING_MODE: "custody",
    MNDE_KEY_CUSTODY: "file-backed-production",
    MNDE_AUTHORITY_BUNDLE: bundlePath,
    MNDE_RECEIPT_SIGNING_KEY: keyPath,
    MNDE_RECEIPT_KEY_ID: receipt.keyId,
    MNDE_LEDGER_SIGNING_KEY: ledgerKeyPath,
    MNDE_LEDGER_KEY_ID: ledger.keyId
  };
}

// Production now also requires caller auth + an enforced signed-bundle policy
// engine (production posture pre-flight); these extras let the production sidecar
// boot under the stricter posture so the read-authorization checks can run.
async function productionEnforcementExtras(dir) {
  const root = { keyId: "pe-root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const authorityBundle = await buildAuthorityBundle({
    authorityId: "mnde-dash-pe", issuedAt: "2026-01-01T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z", root,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
  });
  const bundle = await signPolicyBundle({
    bundle_id: "ops-policy-10-10.0.0", policy_id: "ops-policy", serial: 10, issued_at: "2026-06-23T12:00:00.000Z",
    policy_document: { schema_version: "1.0", policy_id: "ops-policy", version: "10.0.0", state: "ACTIVE", rules: [{ rule_id: "allow-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }] }
  }, { keyId: policyKey.keyId, privateKeyPem: policyKey.privatePem });
  const policyBundlePath = join(dir, "policy-bundle.json");
  const authorityBundlePath = join(dir, "pe-authority-bundle.json");
  writeFileSync(policyBundlePath, JSON.stringify(bundle), "utf8");
  writeFileSync(authorityBundlePath, JSON.stringify(authorityBundle), "utf8");
  return {
    MNDE_SIDECAR_AUTH: "bearer",
    MNDE_SIDECAR_AUTH_TOKENS: JSON.stringify({ "dash-caller-token": "dash-caller" }),
    MNDE_DECISION_ENGINE: "policy-engine",
    MNDE_PE_POLICY_BUNDLE: policyBundlePath,
    MNDE_PE_AUTHORITY_BUNDLE: authorityBundlePath,
    MNDE_PE_POLICY_BUNDLE_STATE: join(dir, "pe-bundle-state.json"),
    MNDE_PE_TRUSTED_ROOT_FINGERPRINT: authorityBundle.root_key.fingerprint,
    MNDE_PE_BUNDLE_NOW: "2026-06-23T12:00:00.000Z"
  };
}

function authorityAssertion(privateKey, overrides = {}) {
  const now = Date.now();
  const nonce = `nonce-${now}-${Math.random().toString(36).slice(2).padEnd(24, "x")}`;
  const payload = {
    issuer: "mnde-desktop",
    audience: "mnde-sidecar",
    subject: "auditor-1",
    nonce,
    session_id: `session-${nonce}`,
    issued_at: now - 1000,
    expires_at: now + 60_000,
    roles: ["AUDITOR"],
    capabilities: ["inspect_receipts", "replay_decisions", "export_audit", "view_dashboard"],
    display_name: "Auditor",
    provider: "test",
    ...overrides
  };
  const payloadPart = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const signaturePart = sign(null, Buffer.from(payloadPart, "utf8"), privateKey).toString("base64url");
  return `${payloadPart}.${signaturePart}`;
}

function tamperAssertion(assertion) {
  const parts = assertion.split(".");
  // Flip a bit in the DECODED signature bytes so the tamper is ALWAYS effective.
  // Editing the last base64url character is unreliable: an Ed25519 signature is
  // 64 bytes, and base64url's final character encodes only 2 significant bits
  // (the last char is always one of {A,Q,g,w}). Flipping it to "A"/"B" changes
  // only don't-care bits ~25% of the time, so the "tampered" assertion decodes
  // byte-for-byte to the original signature, verifies legitimately, and is
  // authorized (HTTP 200) — a false failure of the 403 expectation.
  const sig = Buffer.from(parts[1], "base64url");
  sig[0] ^= 0x01;
  parts[1] = sig.toString("base64url");
  return parts.join(".");
}

async function assertGenericAuthRefusal(url, path, headers = {}) {
  const res = await fetch(`${url}${path}`, { headers });
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.reason_code, "ERR_AUTH_REFUSED");
  assert.equal(body.reason, "ERR_AUTH_REFUSED");
  const text = JSON.stringify(body);
  for (const leaked of ["ERR_AUTH_REQUIRED", "ERR_AUTH_ASSERTION_MALFORMED", "ERR_AUTH_SIGNATURE_INVALID", "ERR_AUTH_EXPIRED", "ERR_AUTH_REPLAY", "ERR_AUTHZ_REFUSED"]) {
    assert.ok(!text.includes(leaked), `external response leaked ${leaked}`);
  }
}

async function main() {
  console.log("MNDe operational dashboard (no login)\n");

  // A handful of tests below (buildSidecarRefusalReceipt-based) sign a real
  // receipt directly, without going through startMndeSidecar — which is what
  // normally bootstraps these dev keys on a fresh checkout. Without this call,
  // this file passes only on a repo where some OTHER test already happened to
  // create shared/receipt_keys/ first: a genuinely fresh checkout (or this
  // file run standalone, e.g. `npm run test:dashboard`, before anything else)
  // fails those tests with ERR_RECEIPT_SIGNING_KEYS_MISSING on the very first
  // run, then passes on every run after (root-caused and reproduced against
  // both main and this branch; not a race — a missing precondition here).
  bootstrapReceiptKeys({ repoRoot });

  await test("receipt timestamps are never fabricated (no epoch-zero fallback)", () => {
    const iso = "2026-07-12T10:00:00.000Z";
    assert.equal(normalizeReceipt({ timestamp: iso }).timestamp, iso);
    assert.equal(normalizeReceipt({ verifiable_signature: { signed_at: iso } }).timestamp, iso);
    assert.equal(normalizeReceipt({ timestamp: "not a date", verifiable_signature: { signed_at: iso } }).timestamp, iso);
    assert.equal(normalizeReceipt({}).timestamp, null);
    assert.equal(normalizeReceipt({ timestamp: 1783824326427 }).timestamp, null);
    assert.equal(normalizeReceipt({ timestamp: "garbage", verifiable_signature: { signed_at: "also garbage" } }).timestamp, null);
    assert.equal(normalizeReceipt({ verifiable_signature: { signed_at: { evil: true } } }).timestamp, null);
    assert.equal(normalizeReceipt({ verifiable_signature: "not-an-object" }).timestamp, null);
  });

  await test("recent receipt reads handle chunk boundaries and stop at the requested window", () => {
    const dir = mkdtempSync(join(tmpdir(), "mnde-recent-receipts-"));
    const receiptPath = join(dir, "receipts.jsonl");
    const warnings = [];
    try {
      const old = { receipt_id: "old", decision_output: { decision: "ALLOW" } };
      const large = { receipt_id: "large", note: "é".repeat(40_000), decision_output: { decision: "REFUSE" } };
      const newest = { receipt_id: "newest", decision_output: { decision: "ALLOW" } };
      writeFileSync(receiptPath, `${JSON.stringify(old)}\nnot-json\n${JSON.stringify(large)}\n${JSON.stringify(newest)}\n`, "utf8");

      const recent = readRecentReceipts(receiptPath, 2, (warning) => warnings.push(warning));
      assert.deepEqual(recent.map((receipt) => receipt.receipt_id), ["newest", "large"]);
      assert.deepEqual(warnings, [], "older malformed history must not be loaded once the recent limit is satisfied");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  await test("recent receipt reads skip malformed tail records while filling the window", () => {
    const dir = mkdtempSync(join(tmpdir(), "mnde-recent-malformed-"));
    const receiptPath = join(dir, "receipts.jsonl");
    const warnings = [];
    try {
      writeFileSync(receiptPath, [
        JSON.stringify({ receipt_id: "older", decision_output: { decision: "REFUSE" } }),
        "not-json",
        JSON.stringify({ receipt_id: "newest", decision_output: { decision: "ALLOW" } }),
        ""
      ].join("\n"), "utf8");
      const recent = readRecentReceipts(receiptPath, 2, (warning) => warnings.push(warning));
      assert.deepEqual(recent.map((receipt) => receipt.receipt_id), ["newest", "older"]);
      assert.equal(warnings.length, 1);
      assert.equal(typeof warnings[0].byte_offset, "number");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  await test("custody envelopes normalize from their signed inner receipt", () => {
    const inner = {
      receipt_id: "receipt-wrapped-1",
      request_hash: "sha256:request",
      canonical_payload_hash: "sha256:payload",
      action: "read_status",
      decision_output: {
        decision: "ALLOW",
        decision_hash: "sha256:decision",
        reason_code: "OK_ALLOW",
        policy_version: "10.0.0",
        policy_hash: "sha256:policy",
        prevented_cost_usd: "12.50"
      },
      verifiable_signature: { signed_at: "2026-07-18T12:34:56.000Z" },
      replay_status: "VALID"
    };
    const envelope = {
      schema_version: "mnde.signed-receipt.v1",
      custody_attestation: { key_id: "custody-key-1" },
      receipt: inner
    };
    const normalized = normalizeReceipt(envelope);

    assert.equal(normalized.receipt_id, inner.receipt_id);
    assert.equal(normalized.timestamp, inner.verifiable_signature.signed_at);
    assert.equal(normalized.verdict, "ALLOW");
    assert.equal(normalized.action, inner.action);
    assert.equal(normalized.reason_code, "OK_ALLOW");
    assert.equal(normalized.policy, "10.0.0");
    assert.equal(normalized.policy_hash, "sha256:policy");
    assert.equal(normalized.request_hash, "sha256:request");
    assert.equal(normalized.decision_hash, "sha256:decision");
    assert.equal(normalized.canonical_payload_hash, "sha256:payload");
    assert.equal(normalized.signature_status, "UNKNOWN");
    assert.equal(normalized.replay_status, "VALID");
    assert.equal(normalized.prevented_cost_usd, 12.5);
    assert.equal(normalized.raw, envelope, "audit output must retain the custody envelope");

    // An unsigned outer decision_output alongside a signed inner receipt must
    // NOT win. The envelope surface is not covered by the custody attestation;
    // letting it override would show the operator a decision the verifier
    // never checked. The signed inner receipt controls the display.
    const outerShadowed = normalizeReceipt({
      decision_output: { decision: "REFUSE", decision_hash: "sha256:top", reason_code: "TOP_LEVEL" },
      receipt: inner
    });
    assert.equal(outerShadowed.verdict, "ALLOW", "signed inner decision must control the verdict");
    assert.equal(outerShadowed.decision_hash, "sha256:decision", "decision_hash must come from the signed inner receipt");
    assert.equal(outerShadowed.reason_code, "OK_ALLOW", "reason_code must come from the signed inner receipt");
  });

  await test("outer envelope fields never override the signed inner decision", () => {
    const signedInner = (decision, extra = {}) => ({
      receipt_id: `receipt-${decision}`,
      request_hash: "sha256:request",
      action: "read_status",
      decision_output: { decision, decision_hash: `sha256:${decision}`, reason_code: `INNER_${decision}` },
      verifiable_signature: { signed_at: "2026-07-18T12:34:56.000Z" },
      ...extra
    });

    // Hostile: outer claims ALLOW, signed inner is REFUSE. Display must refuse.
    const outerAllow = normalizeReceipt({
      decision_output: { decision: "ALLOW", decision_hash: "sha256:forged", reason_code: "OUTER_ALLOW" },
      receipt: signedInner("REFUSE")
    });
    assert.equal(outerAllow.verdict, "REFUSE", "outer ALLOW must not override signed inner REFUSE");
    assert.equal(outerAllow.reason_code, "INNER_REFUSE");
    assert.equal(outerAllow.decision_hash, "sha256:REFUSE");

    // Hostile inverse: outer claims REFUSE, signed inner is ALLOW.
    const outerRefuse = normalizeReceipt({
      decision_output: { decision: "REFUSE", decision_hash: "sha256:forged", reason_code: "OUTER_REFUSE" },
      receipt: signedInner("ALLOW")
    });
    assert.equal(outerRefuse.verdict, "ALLOW", "outer REFUSE must not override signed inner ALLOW");
    assert.equal(outerRefuse.reason_code, "INNER_ALLOW");
    assert.equal(outerRefuse.decision_hash, "sha256:ALLOW");

    // An unsigned outer signature_status must never assert trust for the inner.
    const forgedStatus = normalizeReceipt({
      signature_status: "VALID",
      replay_status: "VALID",
      receipt: signedInner("REFUSE")
    });
    assert.notEqual(forgedStatus.signature_status, "VALID", "unsigned outer signature_status must not be trusted");
    assert.notEqual(forgedStatus.replay_status, "VALID", "unsigned outer replay_status must not be trusted");

    // A valid-looking outer attestation over a tampered inner receipt must not
    // launder trust: normalizeReceipt does not verify, so it may never claim VALID.
    const tampered = normalizeReceipt({
      schema_version: "mnde.signed-receipt.v1",
      custody_attestation: {
        schema_version: "mnde.custody.attestation.v1",
        decision: "REFUSE",
        receipt_hash: "sha256:hash-of-the-ORIGINAL-receipt",
        signing_key_id: "custody-key-1",
        signature: { algorithm: "ED25519", value: "not-checked-here" }
      },
      receipt: signedInner("ALLOW")
    });
    assert.notEqual(tampered.signature_status, "VALID", "an unverified attestation must never yield VALID");
    assert.equal(tampered.verdict, "ALLOW", "display still reflects the inner receipt actually present");
    assert.equal(tampered.raw.custody_attestation.decision, "REFUSE", "raw envelope retained for the verifier to catch the mismatch");
  });

  await test("trust status is never positive without proof", () => {
    const base = { decision_output: { decision: "ALLOW" }, request_hash: "sha256:r" };

    // Missing verification result entirely (no signature material at all).
    const missing = normalizeReceipt({ ...base });
    assert.equal(missing.signature_status, "NOT_REPORTED");
    assert.equal(missing.replay_status, "UNKNOWN");

    // Signature material present but unverified.
    const unverified = normalizeReceipt({ ...base, verifiable_signature: { signed_at: "2026-07-18T12:34:56.000Z" } });
    assert.equal(unverified.signature_status, "UNKNOWN", "present-but-unchecked is UNKNOWN, never VALID");

    // Explicit UNKNOWN and INVALID must survive verbatim and stay non-positive.
    assert.equal(normalizeReceipt({ ...base, signature_status: "UNKNOWN" }).signature_status, "UNKNOWN");
    assert.equal(normalizeReceipt({ ...base, signature_status: "INVALID" }).signature_status, "INVALID");

    // Garbage never coerces into the enum.
    assert.equal(normalizeReceipt({ ...base, signature_status: "TOTALLY_FINE" }).signature_status, "NOT_REPORTED");
    assert.equal(normalizeReceipt({ ...base, replay_status: { evil: true } }).replay_status, "UNKNOWN");

    // The dashboard counts only VALID. Anything else is absence of proof.
    const counted = (status) => [{ signature_status: status }].filter((r) => r.signature_status === "VALID").length;
    assert.equal(counted("VALID"), 1);
    for (const status of ["UNKNOWN", "INVALID", "NOT_REPORTED", undefined, null, "", "valid"]) {
      assert.equal(counted(status), 0, `status ${JSON.stringify(status)} must not count as verified`);
    }
  });

  await test("a valid custody envelope with a valid inner receipt displays the inner receipt", () => {
    const inner = buildSidecarRefusalReceipt({ reason_code: "ERR_NOT_FOUND", policy_hash: "h", policy_version: "v" });
    const envelope = {
      schema_version: "mnde.signed-receipt.v1",
      receipt: inner,
      custody_attestation: {
        schema_version: "mnde.custody.attestation.v1",
        receipt_type: inner.schema_version,
        decision: inner.decision_output?.decision,
        receipt_hash: "sha256:whatever",
        authority_bundle_fingerprint: "fp",
        signing_key_id: "custody-key-1",
        signed_at: "2026-07-18T12:34:56.000Z",
        signature: { algorithm: "ED25519", value: "sig" }
      }
    };
    const normalized = normalizeReceipt(envelope);
    assert.equal(normalized.verdict, "REFUSE");
    assert.equal(normalized.reason_code, "ERR_NOT_FOUND");
    assert.equal(normalized.timestamp, inner.verifiable_signature.signed_at);
    assert.equal(normalized.raw, envelope, "audit output must retain the custody envelope");
    // Still not proof: nothing verified the attestation in this path.
    assert.notEqual(normalized.signature_status, "VALID");
  });

  await test("a real signed refusal receipt normalizes to its signing time", () => {
    const receipt = buildSidecarRefusalReceipt({ reason_code: "ERR_NOT_FOUND", policy_hash: "h", policy_version: "v" });
    const normalized = normalizeReceipt(receipt);
    assert.equal(normalized.timestamp, receipt.verifiable_signature.signed_at);
    assert.ok(Number.isFinite(Date.parse(normalized.timestamp)));
  });

  await test("dashboard counts only cryptographically verified receipts", () => {
    const markup = readFileSync(join(repoRoot, "desktop", "dashboard.html"), "utf8");
    assert.ok(
      markup.includes('r.signature_status === "VALID"'),
      "the signed tally must test for VALID exactly"
    );
    assert.ok(
      !markup.includes('signature_status !== "NOT_REPORTED"'),
      "the permissive not-NOT_REPORTED predicate must not return: it counts UNKNOWN and INVALID as signed"
    );
  });

  const sc = await startMndeSidecar({ url: "http://127.0.0.1:8794", env: { MNDE_BIND_PORT: "8794" } });
  let html = "";
  let contentType = "";
  try {
    await test("GET / serves the operational dashboard as HTML (200, no auth)", async () => {
      const res = await fetch(`${sc.url}/`);
      assert.equal(res.status, 200);
      contentType = res.headers.get("content-type") || "";
      assert.match(contentType, /text\/html/);
      assert.ok((res.headers.get("content-security-policy") || "").includes("frame-ancestors 'none'"));
      assert.equal(res.headers.get("x-content-type-options"), "nosniff");
      assert.equal(res.headers.get("referrer-policy"), "no-referrer");
      html = await res.text();
      assert.ok(html.includes("Is routed execution protected right now?"), "headline question must be present");
    });

    await test("GET /dashboard also serves the dashboard", async () => {
      const res = await fetch(`${sc.url}/dashboard`);
      assert.equal(res.status, 200);
      assert.match(res.headers.get("content-type") || "", /text\/html/);
    });

    await test("status screen shows all seven operational panels", () => {
      for (const panel of ["Protection Status", "Sidecar Status", "Active Policy", "Trust Status", "Last Decision", "Receipt Count", "Protected Sources"]) {
        assert.ok(html.includes(panel), `missing panel: ${panel}`);
      }
    });

    await test("navigation is reduced to Status / Decisions / Policy / Audit / Settings", () => {
      for (const nav of [">Status<", ">Decisions<", ">Policy<", ">Audit<", ">Settings<"]) {
        assert.ok(html.includes(nav), `missing nav item: ${nav}`);
      }
      // No SaaS / marketing nav.
      for (const banned of [">Welcome<", ">Get Started<", ">Sign In<", ">Login<"]) {
        assert.ok(!html.includes(banned), `forbidden nav item: ${banned}`);
      }
    });

    await test("no login / signup / account / marketing CTAs anywhere", () => {
      // The forbidden items are interactive CTAs / screens — checked as their
      // canonical title-case labels. (Repositioning prose like "no login" is fine.)
      for (const banned of ["Login", "Log In", "Sign In", "Sign Up", "Create Account", "Get Started", "Welcome"]) {
        assert.ok(!html.includes(banned), `forbidden CTA present: ${banned}`);
      }
      assert.ok(!/type=["']password["']/.test(html), "no password field allowed");
    });

    await test("no forced cloud dependency (no external origins, no email collection)", () => {
      assert.ok(!html.includes("https://"), "dashboard must not load external resources");
      assert.ok(!/type=["']email["']/.test(html), "no email collection field");
      assert.ok(!/<form\b/.test(html), "no sign-in/sign-up form");
    });

    await test("dashboard reads local status endpoints only (relative URLs)", () => {
      for (const ep of ["/readyz", "/healthz", "/receipts/recent", "/policy/current", "/capabilities", "/identity"]) {
        assert.ok(html.includes(ep), `dashboard should read ${ep}`);
      }
    });

    await test("default CORS is off: localhost origins receive no allow-origin header", async () => {
      const res = await fetch(`${sc.url}/readyz`, { headers: { origin: "http://127.0.0.1:8080" } });
      assert.equal(res.headers.get("access-control-allow-origin"), null);
    });

    await test("decision path is unchanged — sidecar still decides and signs", async () => {
      const res = await fetch(`${sc.url}/v1/decisions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ schema_version: "1.0", request_id: "dash-1", timestamp: new Date().toISOString(), principal: { id: "u" }, agent: { id: "a" }, tool: { tool_name: "read_status" }, parameters: {}, environment: {}, context: {} })
      });
      const body = await res.json();
      assert.ok(body.decision === "ALLOW" || body.decision === "REFUSE", "sidecar still returns a decision");
    });
  } finally {
    await sc.stop();
  }

  const corsConfigured = await startMndeSidecar({ url: "http://127.0.0.1:8795", env: { MNDE_BIND_PORT: "8795", MNDE_ALLOWED_ORIGINS: "http://127.0.0.1:8080" } });
  try {
    await test("configured allowed origin receives CORS headers", async () => {
      const res = await fetch(`${corsConfigured.url}/readyz`, { headers: { origin: "http://127.0.0.1:8080" } });
      assert.equal(res.status, 200);
      assert.equal(res.headers.get("access-control-allow-origin"), "http://127.0.0.1:8080");
      assert.equal(res.headers.get("vary"), "Origin");
    });

    await test("unlisted origin receives no CORS allow-origin header", async () => {
      const res = await fetch(`${corsConfigured.url}/readyz`, { headers: { origin: "http://evil.local:8080" } });
      assert.equal(res.headers.get("access-control-allow-origin"), null);
    });
  } finally {
    await corsConfigured.stop();
  }

  const prodDir = mkdtempSync(join(tmpdir(), "mnde-dashboard-prod-"));
  let prod = null;
  try {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const publicDer = publicKey.export({ format: "der", type: "spki" });
    const auditLog = join(prodDir, "auth-audit.jsonl");
    prod = await startMndeSidecar({
      url: "http://127.0.0.1:8796",
      env: {
        ...(await writeProductionCustody(prodDir)),
        ...(await productionEnforcementExtras(prodDir)),
        MNDE_BIND_PORT: "8796",
        MNDE_AUTH_ASSERTION_PUBLIC_KEY_B64: Buffer.from(publicDer).subarray(-32).toString("base64url"),
        MNDE_AUTH_AUDIT_LOG: auditLog,
        MNDE_AUTH_NONCE_CACHE: join(prodDir, "auth-nonces.json")
      }
    });

    await test("production keeps health and readiness open", async () => {
      for (const ep of ["/healthz", "/readyz"]) {
        const res = await fetch(`${prod.url}${ep}`);
        assert.equal(res.status, 200, `${ep} should stay open`);
      }
    });

    await test("production read endpoints require authority assertion and create audit evidence", async () => {
      const sensitiveReads = ["/", "/dashboard", "/identity", "/metrics", "/receipts/recent", "/policy/current", "/capabilities"];
      for (const ep of sensitiveReads) {
        const res = await fetch(`${prod.url}${ep}`);
        assert.equal(res.status, 403, `${ep} must reject unauthenticated production reads`);
      }
      const lines = readFileSync(auditLog, "utf8").trim().split(/\n/).filter(Boolean).map((line) => JSON.parse(line));
      assert.ok(lines.length >= sensitiveReads.length, "unauthorized production reads must be audited");
      for (const record of lines.slice(-sensitiveReads.length)) {
        assert.equal(record.result, "REFUSE");
        assert.equal(record.reason, "ERR_AUTH_REQUIRED");
      }
    });

    await test("production read endpoint accepts valid authority assertion", async () => {
      const assertion = authorityAssertion(privateKey, { capabilities: ["view_runtime"], roles: ["OPERATOR"] });
      const res = await fetch(`${prod.url}/identity`, { headers: { "x-mnde-authority-assertion": assertion } });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.schema_version, "mnde.sidecar_identity.v1");
    });

    await test("production authority failures return uniform external auth errors", async () => {
      await assertGenericAuthRefusal(prod.url, "/identity");
      await assertGenericAuthRefusal(prod.url, "/identity", { "x-mnde-authority-assertion": "malformed.assertion" });
      await assertGenericAuthRefusal(prod.url, "/identity", { "x-mnde-authority-assertion": tamperAssertion(authorityAssertion(privateKey, { capabilities: ["view_runtime"], roles: ["OPERATOR"] })) });
      await assertGenericAuthRefusal(prod.url, "/identity", { "x-mnde-authority-assertion": authorityAssertion(privateKey, { issued_at: Date.now() - 3_000, expires_at: Date.now() - 1_000, capabilities: ["view_runtime"], roles: ["OPERATOR"] }) });
      const replayed = authorityAssertion(privateKey, { capabilities: ["view_runtime"], roles: ["OPERATOR"] });
      const first = await fetch(`${prod.url}/identity`, { headers: { "x-mnde-authority-assertion": replayed } });
      assert.equal(first.status, 200);
      await assertGenericAuthRefusal(prod.url, "/identity", { "x-mnde-authority-assertion": replayed });
      await assertGenericAuthRefusal(prod.url, "/identity", { "x-mnde-authority-assertion": authorityAssertion(privateKey, { capabilities: ["view_dashboard"], roles: ["VIEWER"] }) });
    });
  } finally {
    if (prod) await prod.stop();
    rmSync(prodDir, { recursive: true, force: true });
  }

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL dashboard tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS dashboard tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
