// UC-002 issuance guard: new authorization must not be issued from a policy whose
// approval gate cannot work, and historical receipts must keep verifying.
//
//   npm run test:issuance-guard
//
// Layers, innermost first: the guard routine, the issuance chokepoint
// (buildPolicyReceiptPayload), the configuration loader on both policy paths
// (file and signed bundle), the real sidecar process, and `mnde decide`.
// Assertions are on outcomes (a receipt exists or it does not, a file was written
// or it was not), not on log text.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { buildAuthorityBundle, generateAuthorityKeyPair } from "../src/custody/index.mjs";
import { signPolicyBundle } from "../src/policy-bundles/index.mjs";
import { evaluatePolicyRequest } from "../src/policy-engine/index.mjs";
import {
  IssuanceRefusedError, KNOWN_RULE_KEYS, checkIssuanceConfiguration, policyDeclaresApprovalRequired, validateApprovalTrustAnchors
} from "../src/policy-engine/issuance-guard.mjs";
import { buildPolicyReceipt, buildPolicyReceiptPayload, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { loadPolicyEngineConfig } from "../src/policy-engine/sidecar-adapter.mjs";
import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
bootstrapReceiptKeys({ repoRoot });
const FIXTURES = join(repoRoot, "tests", "fixtures", "legacy-unenforced-approval");
const NOW = "2026-06-14T12:00:00.000Z";

const results = [];
let chain = Promise.resolve();
function test(name, fn) {
  chain = chain.then(async () => {
    try { await fn(); results.push(true); console.log(`  [PASS] ${name}`); }
    catch (error) { results.push(false); console.log(`  [FAIL] ${name}: ${error.stack?.split("\n").slice(0, 3).join(" | ") ?? error.message}`); }
  });
}

const CODE = {
  NO_ANCHORS: "ERR_PE_APPROVAL_REQUIRED_WITHOUT_TRUST_ANCHORS",
  MALFORMED: "ERR_PE_APPROVAL_REQUIRED_MALFORMED",
  BAD_ANCHORS: "ERR_PE_APPROVAL_ANCHORS_INVALID",
  UNKNOWN_KEY: "ERR_PE_POLICY_UNKNOWN_RULE_KEY"
};

// ── fixtures ────────────────────────────────────────────────────────────────
function ed25519() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { pub: publicKey.export({ type: "spki", format: "pem" }), priv: privateKey.export({ type: "pkcs8", format: "pem" }) };
}
const goodKey = ed25519();
const goodAnchors = () => ({ approval_keys: [{ key_id: "approval-key-1", public_key: goodKey.pub }] });
const rsaPub = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({ type: "spki", format: "pem" });
const ecPub = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({ type: "spki", format: "pem" });
const ed448Pub = generateKeyPairSync("ed448").publicKey.export({ type: "spki", format: "pem" });

const rule = (extra = {}) => ({ rule_id: "r-deploy", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "deploy" }, ...extra });
const plainRule = () => ({ rule_id: "r-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } });
const policyOf = (rules, version = "1") => ({ schema_version: "1.0", policy_id: "guard-policy", version, state: "ACTIVE", rules });
const approvalPolicy = (n = 1) => policyOf([plainRule(), rule({ approval_required: n })]);
const plainPolicy = () => policyOf([plainRule()]);
const request = (tool = "deploy") => ({
  schema_version: "1.0", request_id: `req-${tool}`, timestamp: NOW, principal: { id: "alice" }, agent: { id: "a1" },
  tool: { tool_name: tool }, parameters: {}, environment: {}, context: {}
});

function scratch() { return mkdtempSync(join(tmpdir(), "mnde-guard-")); }
function writeJson(dir, name, value) { const f = join(dir, name); writeFileSync(f, typeof value === "string" ? value : JSON.stringify(value)); return f; }
function filesUnder(dir) { try { return readdirSync(dir); } catch { return []; } }

// Every way the anchors can be wrong, as the value that would be parsed from JSON.
const BAD_ANCHORS = [
  ["null", null], ["false", false], ["zero", 0], ["empty string", ""], ["true", true], ["number", 7], ["string", "anchors"], ["array", []],
  ["empty object", {}], ["empty key set", { approval_keys: [] }], ["approval_keys not array", { approval_keys: {} }],
  ["key not an object", { approval_keys: ["x"] }], ["key_id missing", { approval_keys: [{ public_key: goodKey.pub }] }],
  ["key_id empty", { approval_keys: [{ key_id: "", public_key: goodKey.pub }] }], ["key_id not string", { approval_keys: [{ key_id: 5, public_key: goodKey.pub }] }],
  ["duplicate key_id", { approval_keys: [{ key_id: "a", public_key: goodKey.pub }, { key_id: "a", public_key: goodKey.pub }] }],
  ["public_key missing", { approval_keys: [{ key_id: "a" }] }], ["public_key empty", { approval_keys: [{ key_id: "a", public_key: "  " }] }],
  ["public_key garbage", { approval_keys: [{ key_id: "a", public_key: "not a pem" }] }],
  ["public_key truncated pem", { approval_keys: [{ key_id: "a", public_key: goodKey.pub.slice(0, 60) }] }],
  ["private key given as public", { approval_keys: [{ key_id: "a", public_key: goodKey.priv }] }],
  ["RSA key", { approval_keys: [{ key_id: "a", public_key: rsaPub }] }], ["EC key", { approval_keys: [{ key_id: "a", public_key: ecPub }] }],
  ["Ed448 key", { approval_keys: [{ key_id: "a", public_key: ed448Pub }] }],
  ["valid_from only", { approval_keys: [{ key_id: "a", public_key: goodKey.pub, valid_from: "2026-01-01T00:00:00.000Z" }] }],
  ["valid_until only", { approval_keys: [{ key_id: "a", public_key: goodKey.pub, valid_until: "2099-01-01T00:00:00.000Z" }] }],
  ["unparseable window", { approval_keys: [{ key_id: "a", public_key: goodKey.pub, valid_from: "x", valid_until: "y" }] }],
  ["inverted window", { approval_keys: [{ key_id: "a", public_key: goodKey.pub, valid_from: "2099-01-01T00:00:00.000Z", valid_until: "2026-01-01T00:00:00.000Z" }] }],
  ["one good key and one bad", { approval_keys: [{ key_id: "a", public_key: goodKey.pub }, { key_id: "b", public_key: "junk" }] }]
];
// approval_required values the evaluator can never satisfy, and so must not be accepted.
const BAD_COUNTS = [["false", false], ["null", null], ["zero", 0], ["negative", -1], ["fraction", 1.5], ["string 1", "1"], ["string yes", "yes"], ["object", {}], ["array", [1]], ["unsafe integer", 2 ** 60]];

// ── 1. the guard routine ────────────────────────────────────────────────────
test("guard: approval policy with anchors NOT configured -> refused (UC-002)", () => {
  assert.deepEqual(checkIssuanceConfiguration(approvalPolicy(), {}).code, CODE.NO_ANCHORS);
  assert.deepEqual(checkIssuanceConfiguration(approvalPolicy(), { approvalTrustAnchors: undefined }).code, CODE.NO_ANCHORS);
});
test("guard: approval policy with valid anchors -> ok, for true and for counts", () => {
  for (const n of [true, 1, 2, 5]) assert.equal(checkIssuanceConfiguration(approvalPolicy(n), { approvalTrustAnchors: goodAnchors() }).ok, true, String(n));
});
test("guard: every unusable anchor value is refused, with approval rules and without", () => {
  for (const [label, anchors] of BAD_ANCHORS) {
    for (const [pLabel, pol] of [["approval policy", approvalPolicy()], ["plain policy", plainPolicy()]]) {
      const r = checkIssuanceConfiguration(pol, { approvalTrustAnchors: anchors });
      assert.equal(r.ok, false, `${label} / ${pLabel} was accepted`);
      assert.equal(r.code, CODE.BAD_ANCHORS, `${label} / ${pLabel}: ${r.code}`);
    }
  }
});
test("guard: a falsy-but-present anchor value is a config error, never 'not configured'", () => {
  for (const v of [null, false, 0, ""]) assert.equal(checkIssuanceConfiguration(plainPolicy(), { approvalTrustAnchors: v }).ok, false, JSON.stringify(v));
});
test("guard: every malformed approval_required value is refused, even with valid anchors", () => {
  for (const [label, v] of BAD_COUNTS) {
    const r = checkIssuanceConfiguration(policyOf([plainRule(), rule({ approval_required: v })]), { approvalTrustAnchors: goodAnchors() });
    assert.equal(r.code, CODE.MALFORMED, label);
  }
});
test("guard: malformed approval_required is refused even before anchors are considered", () => {
  assert.equal(checkIssuanceConfiguration(policyOf([rule({ approval_required: false })]), {}).code, CODE.MALFORMED);
});
test("guard: a malformed declaration is never read as 'no approval needed'", () => {
  for (const [label, v] of BAD_COUNTS) {
    assert.equal(policyDeclaresApprovalRequired(policyOf([rule({ approval_required: v })])), true, label);
  }
});
test("guard: policy with no approval requirement is unaffected, anchors or not", () => {
  assert.equal(checkIssuanceConfiguration(plainPolicy(), {}).ok, true);
  assert.equal(checkIssuanceConfiguration(plainPolicy(), { approvalTrustAnchors: goodAnchors() }).ok, true);
});
test("guard: multiple rules — one approval rule among many still requires anchors", () => {
  const many = policyOf([plainRule(), { ...plainRule(), rule_id: "r2" }, rule({ approval_required: 1 }), { ...plainRule(), rule_id: "r4" }]);
  assert.equal(checkIssuanceConfiguration(many, {}).code, CODE.NO_ANCHORS);
  assert.equal(checkIssuanceConfiguration(many, { approvalTrustAnchors: goodAnchors() }).ok, true);
});
test("guard: unknown rule keys are refused (a typo'd gate must not silently disappear)", () => {
  for (const key of ["requires_approval", "approvals_required", "approvalRequired", "approval", "approvers", "require_approval"]) {
    const r = checkIssuanceConfiguration(policyOf([rule({ [key]: 1 })]), { approvalTrustAnchors: goodAnchors() });
    assert.equal(r.code, CODE.UNKNOWN_KEY, key);
  }
  assert.equal(checkIssuanceConfiguration(policyOf([rule({ description: "documented" })]), {}).ok, true);
  assert.deepEqual([...KNOWN_RULE_KEYS].sort(), ["approval_required", "authority_required", "description", "effect", "match", "rule_id"]);
});
test("guard: validateApprovalTrustAnchors accepts the documented schema incl. a validity window", () => {
  const a = { approval_keys: [{ key_id: "a", public_key: goodKey.pub, valid_from: "2026-01-01T00:00:00.000Z", valid_until: "2099-01-01T00:00:00.000Z" }] };
  assert.deepEqual(validateApprovalTrustAnchors(a), { ok: true });
});
test("guard: does not throw on hostile input shapes", () => {
  for (const pol of [undefined, null, 5, "x", [], {}, { rules: "x" }, { rules: [null, 1, "x", []] }, { rules: [{}] }]) {
    assert.doesNotThrow(() => checkIssuanceConfiguration(pol, { approvalTrustAnchors: undefined }));
  }
});

// ── 2. the issuance chokepoint ──────────────────────────────────────────────
test("issuance: buildPolicyReceiptPayload throws IssuanceRefusedError and returns NO payload without anchors", () => {
  let payload;
  assert.throws(() => { payload = buildPolicyReceiptPayload(request(), approvalPolicy(), { now: NOW }); }, (e) => e instanceof IssuanceRefusedError && e.code === CODE.NO_ANCHORS);
  assert.equal(payload, undefined);
});
test("issuance: buildPolicyReceipt (signing) is refused the same way, so nothing is signed", () => {
  assert.throws(() => buildPolicyReceipt(request(), approvalPolicy(), { now: NOW }), (e) => e.code === CODE.NO_ANCHORS);
});
test("issuance: refused for every bad anchor value and every bad count", () => {
  for (const [label, anchors] of BAD_ANCHORS) assert.throws(() => buildPolicyReceiptPayload(request(), approvalPolicy(), { now: NOW, approvalTrustAnchors: anchors }), IssuanceRefusedError, label);
  for (const [label, v] of BAD_COUNTS) assert.throws(() => buildPolicyReceiptPayload(request(), policyOf([rule({ approval_required: v })]), { now: NOW, approvalTrustAnchors: goodAnchors() }), IssuanceRefusedError, label);
});
test("issuance: refused both receipt schemas (v1 and v2)", () => {
  for (const receiptSchema of [undefined, "mnde.pe.receipt.v2"]) {
    assert.throws(() => buildPolicyReceiptPayload(request(), approvalPolicy(), { now: NOW, receiptSchema }), IssuanceRefusedError);
  }
});
test("issuance: correctly configured approval policy behaves normally (REFUSE APPROVAL_REQUIRED without an approval)", () => {
  const p = buildPolicyReceiptPayload(request(), approvalPolicy(), { now: NOW, approvalTrustAnchors: goodAnchors() });
  assert.equal(p.decision_output.decision, "REFUSE");
  assert.equal(p.decision_output.reason_code, "APPROVAL_REQUIRED");
  assert.equal(p.approval_enforced, true);
});
test("issuance: policy without approval requirement keeps its behaviour (ALLOW, not approval-enforced)", () => {
  const p = buildPolicyReceiptPayload(request("read_status"), plainPolicy(), { now: NOW });
  assert.equal(p.decision_output.decision, "ALLOW");
  assert.equal(p.approval_enforced, undefined);
});
test("issuance: an invalid policy still yields a REFUSE receipt (refusal is not authorization), not a throw", () => {
  const p = buildPolicyReceiptPayload(request(), { schema_version: "9", rules: [] }, { now: NOW });
  assert.equal(p.decision_output.decision, "REFUSE");
});
test("issuance: refusal happens before evaluation (no side effect observable from the evaluator)", () => {
  const throwingPolicy = approvalPolicy();
  Object.defineProperty(throwingPolicy, "state", { get() { throw new Error("evaluator touched the policy"); } });
  assert.throws(() => buildPolicyReceiptPayload(request(), throwingPolicy, { now: NOW }), IssuanceRefusedError);
});

// ── 3. historical replay is unchanged ───────────────────────────────────────
const fixtureBundle = () => JSON.parse(readFileSync(join(FIXTURES, "authority-bundle.public.json"), "utf8"));
const fixtureRoot = () => readFileSync(join(FIXTURES, "trusted-root-fingerprint.txt"), "utf8").trim();
const legacy = (label) => JSON.parse(readFileSync(join(FIXTURES, `unenforced-approval-allow.${label}.receipt.json`), "utf8"));
for (const label of ["v1", "v2"]) {
  test(`replay: ${label} receipt issued BEFORE the guard (approval policy, no anchors, ALLOW) still verifies`, async () => {
    const receipt = legacy(label);
    assert.equal(receipt.decision_output.decision, "ALLOW", "fixture is the vulnerable historical artifact");
    assert.equal(receipt.approval_enforced, undefined);
    const v = await verifyPolicyReceipt(receipt, { authorityBundle: fixtureBundle(), trustedRootFingerprint: fixtureRoot() });
    assert.equal(v.verified, true, v.reason);
    assert.equal(v.decision, "ALLOW");
  });
  test(`replay: ${label} fixture is still tamper-evident`, async () => {
    const receipt = legacy(label);
    receipt.decision_output = { ...receipt.decision_output, reason_code: "TAMPERED" };
    assert.equal((await verifyPolicyReceipt(receipt, { authorityBundle: fixtureBundle(), trustedRootFingerprint: fixtureRoot() })).verified, false);
  });
  test(`replay: ${label} fixture does not verify under a different pinned root`, async () => {
    const wrong = "0".repeat(64);
    assert.equal((await verifyPolicyReceipt(legacy(label), { authorityBundle: fixtureBundle(), trustedRootFingerprint: wrong })).verified, false);
  });
}
test("replay: re-issuing the SAME request and policy today is refused — the contrast with the fixture", () => {
  const receipt = legacy("v1");
  assert.throws(() => buildPolicyReceiptPayload(JSON.parse(receipt.canonical_request), JSON.parse(receipt.canonical_policy), { now: NOW }), (e) => e.code === CODE.NO_ANCHORS);
});
test("replay: the evaluator's no-anchor semantics are frozen (replay depends on them)", () => {
  const d = evaluatePolicyRequest(request(), approvalPolicy(), { now: NOW });
  assert.equal(d.decision, "ALLOW");
  assert.equal(d.reason_code, "OK_ALLOW");
});
test("replay: verification stays stable under new and old configurations of the same receipt", async () => {
  const receipt = legacy("v1");
  const a = await verifyPolicyReceipt(receipt, { authorityBundle: fixtureBundle(), trustedRootFingerprint: fixtureRoot() });
  const b = await verifyPolicyReceipt(receipt, { authorityBundle: fixtureBundle(), trustedRootFingerprint: fixtureRoot(), approvalTrustAnchors: goodAnchors() });
  assert.deepEqual([a.verified, a.decision, a.reason_code], [b.verified, b.decision, b.reason_code]);
});

// ── 4. configuration loader: file path and signed-bundle path are equivalent ─
async function signedBundleEnv(dir, policyDocument) {
  const root = { keyId: "root-1", ...generateAuthorityKeyPair() };
  const policyKey = { keyId: "policy-1", ...generateAuthorityKeyPair() };
  const window = { validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" };
  const authorityBundle = await buildAuthorityBundle({
    authorityId: "guard-authority", issuedAt: "2026-01-01T00:00:00.000Z", notAfter: "2099-01-01T00:00:00.000Z", root,
    policyKeys: [{ keyId: policyKey.keyId, publicPem: policyKey.publicPem, ...window }]
  });
  const signed = await signPolicyBundle({ bundle_id: "guard-1", policy_id: policyDocument.policy_id, serial: 1, issued_at: NOW, policy_document: policyDocument },
    { keyId: policyKey.keyId, privateKeyPem: policyKey.privatePem });
  return {
    MNDE_PE_POLICY_BUNDLE: writeJson(dir, "policy-bundle.json", signed),
    MNDE_PE_AUTHORITY_BUNDLE: writeJson(dir, "authority-bundle.json", authorityBundle),
    MNDE_PE_POLICY_BUNDLE_STATE: join(dir, "bundle-state.json"),
    MNDE_PE_TRUSTED_ROOT_FINGERPRINT: authorityBundle.root_key.fingerprint,
    MNDE_PE_BUNDLE_NOW: NOW
  };
}
async function loadBoth(dir, policy, anchorsFile, profile = "local") {
  const file = await loadPolicyEngineConfig({ MNDE_PROFILE: profile, MNDE_PE_POLICY: writeJson(dir, "p.json", policy), ...(anchorsFile ? { MNDE_PE_APPROVAL_TRUST_ANCHORS: anchorsFile } : {}) });
  const bundleDir = mkdtempSync(join(dir, "b-"));
  const bundle = await loadPolicyEngineConfig({ MNDE_PROFILE: profile === "production" ? "production" : "local", ...(await signedBundleEnv(bundleDir, policy)), ...(anchorsFile ? { MNDE_PE_APPROVAL_TRUST_ANCHORS: anchorsFile } : {}) });
  return { file, bundle };
}
test("loader: approval policy, no anchors -> file path and signed-bundle path both refuse with the same code", async () => {
  const dir = scratch();
  try {
    const { file, bundle } = await loadBoth(dir, approvalPolicy());
    for (const r of [file, bundle]) { assert.equal(r.ok, false); assert.equal(r.reason, CODE.NO_ANCHORS); assert.equal(r.policy, undefined, "no usable config may be returned"); }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("loader: signed bundle in the production profile is held to the same rule", async () => {
  const dir = scratch();
  try {
    const bundleDir = mkdtempSync(join(dir, "b-"));
    const r = await loadPolicyEngineConfig({ MNDE_PROFILE: "production", ...(await signedBundleEnv(bundleDir, approvalPolicy())) });
    assert.equal(r.ok, false);
    assert.equal(r.reason, CODE.NO_ANCHORS);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("loader: every bad anchors file is refused on both paths, none falls back to a looser policy", async () => {
  const dir = scratch();
  try {
    for (const [label, anchors] of BAD_ANCHORS) {
      const anchorsFile = writeJson(dir, "anchors.json", JSON.stringify(anchors));
      const { file, bundle } = await loadBoth(dir, approvalPolicy(), anchorsFile);
      for (const [path, r] of [["file", file], ["bundle", bundle]]) {
        assert.equal(r.ok, false, `${label}/${path}`);
        assert.equal(r.reason, CODE.BAD_ANCHORS, `${label}/${path}: ${r.reason}`);
        assert.equal(r.policy, undefined, `${label}/${path}: a config was still returned`);
      }
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("loader: malformed JSON in the anchors file is refused (no silent default)", async () => {
  const dir = scratch();
  try {
    const r = await loadPolicyEngineConfig({ MNDE_PROFILE: "local", MNDE_PE_POLICY: writeJson(dir, "p.json", approvalPolicy()), MNDE_PE_APPROVAL_TRUST_ANCHORS: writeJson(dir, "a.json", "{not json") });
    assert.equal(r.ok, false);
    assert.match(r.reason, /approval trust anchors load failed/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("loader: valid anchors load on both paths and approval policies work", async () => {
  const dir = scratch();
  try {
    const { file, bundle } = await loadBoth(dir, approvalPolicy(), writeJson(dir, "anchors.json", goodAnchors()));
    assert.equal(file.ok, true, file.reason);
    assert.equal(bundle.ok, true, bundle.reason);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("loader: a plain policy with no anchors loads on both paths (no regression)", async () => {
  const dir = scratch();
  try {
    const { file, bundle } = await loadBoth(dir, plainPolicy());
    assert.equal(file.ok, true, file.reason);
    assert.equal(bundle.ok, true, bundle.reason);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("loader: an unknown rule key is refused on both paths", async () => {
  const dir = scratch();
  try {
    const { file, bundle } = await loadBoth(dir, policyOf([rule({ requires_approval: 1 })]), writeJson(dir, "anchors.json", goodAnchors()));
    assert.equal(file.reason, CODE.UNKNOWN_KEY);
    assert.equal(bundle.reason, CODE.UNKNOWN_KEY);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── 5. the real sidecar process ─────────────────────────────────────────────
// A refused configuration still answers: the sidecar signs a REFUSE receipt as
// evidence of the refusal (execution.dispatchable === false). Refusal is not
// authorization, so the invariant tested here is "no ALLOW exists anywhere": not in
// the response, not in the signed receipt, not in the receipt log.
function assertNothingAuthorized(d, logged) {
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "ERR_PE_CONFIG_INVALID");
  assert.equal(d.execution?.dispatchable, false);
  assert.equal(d.receipt?.decision_output?.decision, "REFUSE", "the signed receipt must itself say REFUSE");
  assert.equal(d.receipt?.decision_output?.reason_code, "ERR_PE_CONFIG_INVALID");
  assert.equal(d.receipt?.approval_enforced, undefined);
  for (const line of logged) assert.doesNotMatch(line, /"decision":"ALLOW"/, "an ALLOW receipt was logged");
  assert.equal(logged.filter((line) => /"decision":\s*"ALLOW"/.test(line)).length, 0);
}
async function decide(url, body) {
  const r = await fetch(`${url}/v1/decisions`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return r.json();
}
async function sidecarOutcome(port, dir, policy, anchors /* undefined | raw string */) {
  const log = join(dir, `receipts-${port}.jsonl`);
  const env = {
    MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: writeJson(dir, `p-${port}.json`, policy), MNDE_BIND_PORT: String(port), MNDE_RECEIPT_LOG: log,
    ...(anchors !== undefined ? { MNDE_PE_APPROVAL_TRUST_ANCHORS: writeJson(dir, `a-${port}.json`, anchors) } : {})
  };
  const sidecar = await startMndeSidecar({ url: `http://127.0.0.1:${port}`, env });
  try {
    const deploy = await decide(sidecar.url, { ...request("deploy"), timestamp: new Date().toISOString() });
    const status = await decide(sidecar.url, { ...request("read_status"), timestamp: new Date().toISOString() });
    return { deploy, status, logged: existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean) : [] };
  } finally { await sidecar.stop(); }
}
test("sidecar (real process): approval policy + NO anchors -> every decision REFUSEs, nothing is authorized (UC-002)", async () => {
  const dir = scratch();
  try {
    const o = await sidecarOutcome(8761, dir, approvalPolicy(), undefined);
    for (const d of [o.deploy, o.status]) {
      assertNothingAuthorized(d, o.logged);
      assert.equal(d.policy_engine_error, CODE.NO_ANCHORS);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
for (const [label, anchors] of [["empty key set", { approval_keys: [] }], ["RSA key", { approval_keys: [{ key_id: "a", public_key: rsaPub }] }], ["null", null]]) {
  test(`sidecar (real process): approval policy + bad anchors (${label}) -> REFUSE ${CODE.BAD_ANCHORS}, nothing authorized`, async () => {
    const dir = scratch();
    try {
      const o = await sidecarOutcome(8762, dir, approvalPolicy(), anchors);
      for (const d of [o.deploy, o.status]) assertNothingAuthorized(d, o.logged);
      assert.equal(o.deploy.policy_engine_error, CODE.BAD_ANCHORS);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}
test("sidecar (real process): plain policy + no anchors still decides normally (ALLOW read_status, with a receipt)", async () => {
  const dir = scratch();
  try {
    const o = await sidecarOutcome(8763, dir, plainPolicy(), undefined);
    assert.notEqual(o.status.reason_code, "ERR_PE_CONFIG_INVALID");
    assert.ok(o.status.receipt, "a correctly configured policy must still produce a receipt");
    assert.equal(o.status.receipt.decision_output.decision, "ALLOW");
    assert.equal(o.deploy.receipt.decision_output.decision, "REFUSE");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("sidecar (real process): approval policy + valid anchors -> deploy REFUSE APPROVAL_REQUIRED with an approval-enforced receipt", async () => {
  const dir = scratch();
  try {
    const o = await sidecarOutcome(8764, dir, approvalPolicy(), goodAnchors());
    assert.equal(o.deploy.reason_code, "APPROVAL_REQUIRED");
    assert.equal(o.deploy.receipt.approval_enforced, true);
    assert.equal(o.status.receipt.decision_output.decision, "ALLOW");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── 6. mnde decide ──────────────────────────────────────────────────────────
function runDecide(dir, policy, anchors /* undefined | JSON value */) {
  const out = join(dir, "out.receipt.json");
  rmSync(out, { force: true });
  const args = [join(repoRoot, "bin", "mnde.mjs"), "decide", "--request", writeJson(dir, "req.json", request()), "--policy", writeJson(dir, "pol.json", policy), "--out", out];
  if (anchors !== undefined) args.push("--approval-trust-anchors", writeJson(dir, "anch.json", JSON.stringify(anchors)));
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  return { status: r.status, stdout: r.stdout, written: existsSync(out) };
}
test("mnde decide: approval policy without anchors -> exit 1, NO receipt file", () => {
  const dir = scratch();
  try {
    const r = runDecide(dir, approvalPolicy(), undefined);
    assert.equal(r.status, 1);
    assert.equal(r.written, false);
    assert.match(r.stdout, new RegExp(CODE.NO_ANCHORS));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("mnde decide: bad anchors and malformed counts -> exit 1, NO receipt file", () => {
  const dir = scratch();
  try {
    for (const anchors of [{}, { approval_keys: [] }, { approval_keys: [{ key_id: "a", public_key: ecPub }] }, null]) {
      const r = runDecide(dir, approvalPolicy(), anchors);
      assert.equal(r.status, 1, JSON.stringify(anchors));
      assert.equal(r.written, false);
    }
    const bad = runDecide(dir, policyOf([rule({ approval_required: false })]), goodAnchors());
    assert.equal(bad.status, 1);
    assert.equal(bad.written, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
test("mnde decide: valid anchors -> receipt written; plain policy with no anchors -> receipt written", () => {
  const dir = scratch();
  try {
    assert.equal(runDecide(dir, approvalPolicy(), goodAnchors()).written, true);
    assert.equal(runDecide(dir, plainPolicy(), undefined).written, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// ── 7. every in-repo issuer routes through the chokepoint ───────────────────
test("coverage: every non-test caller of buildPolicyReceipt* is on the reviewed list", () => {
  // If this fails, a new code path issues receipts. Either route it through
  // buildPolicyReceipt / buildPolicyReceiptPayload (guarded) and add it here, or
  // explain in docs/KNOWN-ISSUES.md why it is exempt. Do not just extend the list.
  const REVIEWED = new Set([
    "bin/mnde.mjs", "scripts/authorize-git-push.mjs", "src/hub/authorization.mjs", "src/policy-engine/receipt.mjs", "src/policy-engine/sidecar-adapter.mjs",
    "tests/test_issuance_guard.mjs"
  ]);
  const found = [];
  const skip = new Set(["node_modules", "dist", ".git", "tests", "experiments", "docs", "release"]);
  (function walk(dir) {
    for (const name of readdirSync(dir)) {
      if (skip.has(name)) continue;
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.(mjs|js|ts)$/.test(name) && /\bbuildPolicyReceipt(Payload)?\s*\(/.test(readFileSync(p, "utf8"))) found.push(p.slice(repoRoot.length + 1).replaceAll("\\", "/"));
    }
  })(repoRoot);
  const unexpected = found.filter((f) => !REVIEWED.has(f));
  assert.deepEqual(unexpected, [], "unreviewed receipt issuer(s)");
});
test("coverage: the evaluator is called by new-issuance code only through the chokepoint", () => {
  const callers = [];
  (function walk(dir) {
    for (const name of readdirSync(dir)) {
      if (["node_modules", "dist", ".git", "tests", "experiments", "docs", "release"].includes(name)) continue;
      const p = join(dir, name);
      if (statSync(p).isDirectory()) walk(p);
      else if (/\.(mjs|js|ts)$/.test(name) && /\bevaluatePolicyRequest\s*\(/.test(readFileSync(p, "utf8"))) callers.push(p.slice(repoRoot.length + 1).replaceAll("\\", "/"));
    }
  })(repoRoot);
  // receipt.mjs holds both the guarded issuer and the replaying verifier; index.mjs defines it.
  assert.deepEqual(callers.sort(), ["src/policy-engine/index.mjs", "src/policy-engine/receipt.mjs"]);
});

// ── 7b. exposure audit: find receipts issued while the gate was off ─────────
import { classifyReceipt } from "../tools/audit-unenforced-approvals.mjs";
test("audit: both pre-guard fixtures are flagged as ALLOWED_WITHOUT_ENFORCED_APPROVAL", () => {
  const v2 = classifyReceipt(legacy("v2"));
  assert.equal(v2.finding, "ALLOWED_WITHOUT_ENFORCED_APPROVAL");
  assert.equal(v2.certainty, "CONFIRMED_FROM_RECEIPT_CONTENT");
  assert.equal(v2.rule_id, "allow-deploy-with-approval");
  const v1 = classifyReceipt(legacy("v1"));
  assert.equal(v1.finding, "ALLOWED_WITHOUT_ENFORCED_APPROVAL");
  assert.match(v1.certainty, /^POSSIBLE/, "a v1 receipt does not name the deciding rule, so it cannot be confirmed");
});
test("audit: an approval-enforced receipt, a plain-policy receipt, and non-receipts are not flagged", () => {
  const enforced = buildPolicyReceiptPayload(request(), approvalPolicy(), { now: NOW, approvalTrustAnchors: goodAnchors() });
  assert.equal(classifyReceipt(enforced), null);
  assert.equal(classifyReceipt(buildPolicyReceiptPayload(request("read_status"), plainPolicy(), { now: NOW })), null);
  for (const junk of [null, 5, "x", {}, { canonical_policy: "{not json", schema_version: "mnde.pe.receipt.v1" }, { canonical_policy: "{}", schema_version: "other" }]) assert.equal(classifyReceipt(junk), null);
});
test("audit: a gate-off receipt whose decision was a REFUSE is reported as GATE_NOT_ENFORCED, not as an unauthorized ALLOW", () => {
  const r = JSON.parse(JSON.stringify(legacy("v2")));
  r.decision_output.decision = "REFUSE";
  assert.equal(classifyReceipt(r).finding, "GATE_NOT_ENFORCED");
});
test("audit: the CLI scans a directory, JSONL logs and custody envelopes; exits 1 on findings, 0 on none", () => {
  const dir2 = scratch();
  try {
    writeFileSync(join(dir2, "log.jsonl"), `${JSON.stringify(legacy("v2"))}\n${JSON.stringify({ unrelated: true })}\n`);
    writeFileSync(join(dir2, "envelope.json"), JSON.stringify({ receipt: legacy("v1"), custody_attestation: {} }));
    const hit = spawnSync(process.execPath, [join(repoRoot, "tools", "audit-unenforced-approvals.mjs"), dir2], { encoding: "utf8" });
    assert.equal(hit.status, 1);
    const report = JSON.parse(hit.stdout);
    assert.equal(report.flagged, 2);
    assert.equal(report.allowed_without_enforced_approval, 2);
    const clean = scratch();
    writeFileSync(join(clean, "ok.json"), JSON.stringify(buildPolicyReceiptPayload(request("read_status"), plainPolicy(), { now: NOW })));
    assert.equal(spawnSync(process.execPath, [join(repoRoot, "tools", "audit-unenforced-approvals.mjs"), clean], { encoding: "utf8" }).status, 0);
    rmSync(clean, { recursive: true, force: true });
  } finally { rmSync(dir2, { recursive: true, force: true }); }
});

// ── 8. KNOWN LIMIT (UC-005): approvals are not action-bound ─────────────────
// Characterization, not endorsement. These cases pin what the approval verifier does
// TODAY so that tightening it is a deliberate, visible change. The Hub path is safe
// from this in practice (it only accepts approvals whose scope.request_id is its own
// action record, and keeps the request server-side); the sidecar policy-engine path
// is not, because the caller supplies both request_id and parameters.
import { signApproval } from "../src/policy-engine/authenticated-approvals.mjs";
test("UC-005 (known limit): an approval scoped to a tool name is reusable across requests and parameters until it expires", () => {
  const a = signApproval({ approval_id: "ap1", approver: { id: "carol" }, issuer: { id: "svc" }, issued_at: "2026-06-14T11:00:00.000Z", expires_at: "2026-06-14T13:00:00.000Z", scope: { tool_name: "deploy" } }, { keyId: "approval-key-1", privateKeyPem: goodKey.priv });
  const run = (r) => evaluatePolicyRequest(r, approvalPolicy(), { now: NOW, approvals: [a], approvalTrustAnchors: goodAnchors() }).decision;
  assert.equal(run({ ...request("deploy"), request_id: "A", parameters: { target: "staging" } }), "ALLOW");
  assert.equal(run({ ...request("deploy"), request_id: "B", parameters: { target: "prod" } }), "ALLOW", "UC-005: not bound to parameters or request");
});
test("UC-005 (known limit): a request_id-bound approval still does not bind the parameters, and '*' is an accepted tool scope", () => {
  const sign = (scope) => signApproval({ approval_id: "ap2", approver: { id: "carol" }, issuer: { id: "svc" }, issued_at: "2026-06-14T11:00:00.000Z", expires_at: "2026-06-14T13:00:00.000Z", scope }, { keyId: "approval-key-1", privateKeyPem: goodKey.priv });
  const run = (a, r) => evaluatePolicyRequest(r, approvalPolicy(), { now: NOW, approvals: [a], approvalTrustAnchors: goodAnchors() }).decision;
  const bound = sign({ tool_name: "deploy", request_id: "A" });
  assert.equal(run(bound, { ...request("deploy"), request_id: "B" }), "REFUSE", "a different request_id is refused");
  assert.equal(run(bound, { ...request("deploy"), request_id: "A", parameters: { target: "prod" } }), "ALLOW", "UC-005: same request_id, different parameters");
  assert.equal(run(sign({ tool_name: "*" }), { ...request("deploy"), request_id: "C" }), "ALLOW", "UC-005: wildcard scope");
});

await chain;
const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) { console.log(`FAIL issuance-guard tests (${results.length - failed}/${results.length})`); process.exit(1); }
console.log(`PASS issuance-guard tests (${results.length}/${results.length})`);
