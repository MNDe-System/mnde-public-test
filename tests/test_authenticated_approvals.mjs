// Authenticated approvals tests for the policy engine.
//
//   npm run test:approvals
//
// Proves identity + approval authority: a valid, signed, in-scope, unexpired
// approval from a trusted issuer is required where the policy asks for it, with
// distinct fail-closed reason codes, and the receipt round-trips only under the
// correct verifier-supplied approval trust anchors. No external services.

import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";
import { evaluatePolicyRequest } from "../src/policy-engine/index.mjs";
import { signApproval } from "../src/policy-engine/authenticated-approvals.mjs";
import { buildPolicyReceipt, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { loadPolicyEngineConfig, policyDeclaresApprovalRequired } from "../src/policy-engine/sidecar-adapter.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
bootstrapReceiptKeys({ repoRoot });

const results = [];
let testChain = Promise.resolve();
function test(name, fn) {
  testChain = testChain.then(async () => {
    try {
      await fn();
      results.push(true);
      console.log(`  [PASS] ${name}`);
    } catch (error) {
      results.push(false);
      console.log(`  [FAIL] ${name}: ${error.message}`);
    }
  });
}
function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { pub: publicKey.export({ type: "spki", format: "pem" }), priv: privateKey.export({ type: "pkcs8", format: "pem" }) };
}

const issuerKey = keypair();
const attackerKey = keypair();
const NOW = "2026-06-14T12:00:00.000Z";
const approvalAnchors = { approval_keys: [{ key_id: "approval-key-1", public_key: issuerKey.pub }] };

function request(tool = "deploy") {
  return {
    schema_version: "1.0", request_id: "req-1", timestamp: NOW,
    principal: { id: "alice" }, agent: { id: "agent-1" }, tool: { tool_name: tool },
    parameters: {}, environment: {}, context: {}
  };
}
// A rule that allows `deploy` but requires one approval.
function policy() {
  return {
    schema_version: "1.0", policy_id: "pol-1", version: "1", state: "ACTIVE",
    rules: [{ rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "deploy" }, approval_required: 1 }]
  };
}
function approval(overrides = {}) {
  return {
    approval_id: "appr-1",
    approver: { id: "carol" },
    issuer: { id: "approval-service" },
    issued_at: "2026-06-14T00:00:00.000Z",
    expires_at: "2026-06-15T00:00:00.000Z",
    scope: { tool_name: "deploy" },
    ...overrides
  };
}
function signed(overrides = {}, keyPriv = issuerKey.priv) {
  return signApproval(approval(overrides), { keyId: "approval-key-1", privateKeyPem: keyPriv });
}
function evaluate(approvals) {
  return evaluatePolicyRequest(request(), policy(), { approvals, approvalTrustAnchors: approvalAnchors, now: NOW });
}

test("valid approval -> ALLOW", () => {
  const d = evaluate([signed()]);
  assert.equal(d.decision, "ALLOW");
  assert.equal(d.reason_code, "OK_ALLOW");
  assert.equal(d.approval.enforced, true);
  assert.equal(d.approval.verifications[0].result, "VALID");
});

test("missing approval -> APPROVAL_REQUIRED", () => {
  const d = evaluate([]);
  assert.equal(d.decision, "REFUSE");
  assert.equal(d.reason_code, "APPROVAL_REQUIRED");
});

test("invalid signature -> APPROVAL_SIGNATURE_INVALID", () => {
  const d = evaluate([signed({}, attackerKey.priv)]);
  assert.equal(d.reason_code, "APPROVAL_SIGNATURE_INVALID");
});

test("untrusted issuer key -> APPROVAL_UNTRUSTED_ISSUER", () => {
  const a = signApproval(approval(), { keyId: "unknown-key", privateKeyPem: issuerKey.priv });
  assert.equal(evaluate([a]).reason_code, "APPROVAL_UNTRUSTED_ISSUER");
});

test("expired approval -> APPROVAL_EXPIRED", () => {
  assert.equal(evaluate([signed({ expires_at: "2026-06-14T01:00:00.000Z" })]).reason_code, "APPROVAL_EXPIRED");
});

test("future-dated approval -> APPROVAL_NOT_YET_VALID", () => {
  assert.equal(evaluate([signed({ issued_at: "2026-06-14T18:00:00.000Z", expires_at: "2026-06-15T00:00:00.000Z" })]).reason_code, "APPROVAL_NOT_YET_VALID");
});

test("scope mismatch -> APPROVAL_SCOPE_MISMATCH", () => {
  assert.equal(evaluate([signed({ scope: { tool_name: "read_status" } })]).reason_code, "APPROVAL_SCOPE_MISMATCH");
});

test("malformed approval (missing id) -> APPROVAL_MALFORMED", () => {
  const a = signApproval(approval({ approval_id: "" }), { keyId: "approval-key-1", privateKeyPem: issuerKey.priv });
  assert.equal(evaluate([a]).reason_code, "APPROVAL_MALFORMED");
});

test("unsigned approval -> APPROVAL_UNSIGNED", () => {
  assert.equal(evaluate([approval()]).reason_code, "APPROVAL_UNSIGNED");
});

test("evaluator with no approval anchors: approval_required has no effect (frozen for replay)", () => {
  // The EVALUATOR must keep this behaviour. The receipt verifier replays it, so
  // changing it would make every receipt issued before the change fail replay
  // with "decision drift". The fail-closed control for this case is at
  // configuration load, covered by the "config load" tests below (UC-002).
  // No approvalTrustAnchors -> existing behavior; rule allows without any approval.
  const d = evaluatePolicyRequest(request(), policy(), { now: NOW });
  assert.equal(d.decision, "ALLOW");
  assert.equal(d.approval, undefined);
});

test("receipt round-trips with matching approval anchors", async () => {
  const receipt = buildPolicyReceipt(request(), policy(), { approvals: [signed()], approvalTrustAnchors: approvalAnchors, now: NOW });
  assert.equal(receipt.approval_enforced, true);
  assert.equal(receipt.decision_output.decision, "ALLOW");
  assert.equal(receipt.decision_output.approval.verifications[0].approver, "carol");
  assert.equal((await verifyPolicyReceipt(receipt, { approvalTrustAnchors: approvalAnchors })).verified, true);
});

test("verifier rejects approval-enforced receipt without anchors", async () => {
  const receipt = buildPolicyReceipt(request(), policy(), { approvals: [signed()], approvalTrustAnchors: approvalAnchors, now: NOW });
  assert.equal((await verifyPolicyReceipt(receipt)).verified, false);
});

test("verifier with WRONG approval anchors does not accept the receipt", async () => {
  const receipt = buildPolicyReceipt(request(), policy(), { approvals: [signed()], approvalTrustAnchors: approvalAnchors, now: NOW });
  const wrong = { approval_keys: [{ key_id: "approval-key-1", public_key: attackerKey.pub }] };
  assert.equal((await verifyPolicyReceipt(receipt, { approvalTrustAnchors: wrong })).verified, false);
});

// --- UC-002: configuration load must not accept a policy whose approval gate
// would silently do nothing. -------------------------------------------------

function withPolicyFiles(fn) {
  const dir = mkdtempSync(join(tmpdir(), "mnde-uc002-"));
  const write = (name, value) => { const f = join(dir, name); writeFileSync(f, JSON.stringify(value)); return f; };
  return Promise.resolve(fn(write)).finally(() => rmSync(dir, { recursive: true, force: true }));
}
const plainPolicy = () => ({ ...policy(), rules: [{ rule_id: "r1", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } }] });

test("policyDeclaresApprovalRequired: detects true, counts, malformed values; ignores absent", () => {
  assert.equal(policyDeclaresApprovalRequired(policy()), true);
  assert.equal(policyDeclaresApprovalRequired({ rules: [{ approval_required: true }] }), true);
  assert.equal(policyDeclaresApprovalRequired({ rules: [{ approval_required: 0 }] }), true, "0 is still a declared gate");
  assert.equal(policyDeclaresApprovalRequired({ rules: [{ approval_required: false }] }), true, "false is still declared");
  assert.equal(policyDeclaresApprovalRequired({ rules: [{ approval_required: "yes" }] }), true, "malformed is still declared");
  assert.equal(policyDeclaresApprovalRequired(plainPolicy()), false);
  assert.equal(policyDeclaresApprovalRequired(undefined), false);
  assert.equal(policyDeclaresApprovalRequired({ rules: "nope" }), false);
});

test("config load: approval_required policy without approval anchors is refused", () => withPolicyFiles(async (write) => {
  const config = await loadPolicyEngineConfig({ MNDE_PROFILE: "local", MNDE_PE_POLICY: write("p.json", policy()) });
  assert.equal(config.ok, false);
  assert.equal(config.reason, "ERR_PE_APPROVAL_REQUIRED_WITHOUT_TRUST_ANCHORS");
}));

test("config load: approval_required policy WITH approval anchors loads", () => withPolicyFiles(async (write) => {
  const config = await loadPolicyEngineConfig({
    MNDE_PROFILE: "local", MNDE_PE_POLICY: write("p.json", policy()), MNDE_PE_APPROVAL_TRUST_ANCHORS: write("a.json", approvalAnchors)
  });
  assert.equal(config.ok, true, config.reason);
  assert.ok(config.approvalTrustAnchors);
}));

test("config load: policy without approval_required is unaffected by missing anchors", () => withPolicyFiles(async (write) => {
  const config = await loadPolicyEngineConfig({ MNDE_PROFILE: "local", MNDE_PE_POLICY: write("p.json", plainPolicy()) });
  assert.equal(config.ok, true, config.reason);
}));

test("config load: built-in default-deny policy (no policy configured) still loads", async () => {
  const config = await loadPolicyEngineConfig({ MNDE_PROFILE: "local" });
  assert.equal(config.ok, true, config.reason);
});

test("config load: malformed approval anchors file still reports its own error", () => withPolicyFiles(async (write) => {
  const config = await loadPolicyEngineConfig({
    MNDE_PROFILE: "local", MNDE_PE_POLICY: write("p.json", policy()), MNDE_PE_APPROVAL_TRUST_ANCHORS: join(tmpdir(), "does-not-exist.json")
  });
  assert.equal(config.ok, false);
  assert.match(config.reason, /approval trust anchors load failed/);
}));

test("mnde decide: approval_required policy without --approval-trust-anchors exits non-zero and writes no receipt", () => withPolicyFiles(async (write) => {
  const out = join(tmpdir(), `mnde-uc002-${process.pid}.receipt.json`);
  const run = (extra) => spawnSync(process.execPath, [join(repoRoot, "bin", "mnde.mjs"), "decide", "--request", write("req.json", request()), "--policy", write("p.json", policy()), "--out", out, ...extra], { encoding: "utf8" });
  try {
    const refused = run([]);
    assert.equal(refused.status, 1);
    assert.match(refused.stdout, /ERR_PE_APPROVAL_REQUIRED_WITHOUT_TRUST_ANCHORS/);
    assert.equal(spawnSync(process.execPath, ["-e", `process.exit(require("fs").existsSync(${JSON.stringify(out)})?1:0)`]).status, 0, "no receipt file may be written");
    const ok = run(["--approval-trust-anchors", write("a.json", approvalAnchors)]);
    assert.equal(ok.status ?? 0, 0, ok.stderr);
    assert.match(ok.stdout, /APPROVAL_REQUIRED/);
  } finally { rmSync(out, { force: true }); }
}));

await testChain;
const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL authenticated-approvals tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS authenticated-approvals tests (${results.length}/${results.length})`);
