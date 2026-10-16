#!/usr/bin/env node
// One-off generator for the UC-002 historical-replay fixtures.
//
//   git worktree add <dir> 178342b   # code BEFORE the issuance guard existed
//   node <this file> --repo <dir> --out tests/fixtures/legacy-unenforced-approval
//
// It must be run against pre-guard code: the guard now refuses to build these
// receipts, which is the point. The receipts are what the old code issued for an
// approval_required policy with NO approval anchors: ALLOW, no approval, no
// `approval_enforced` field. They are signed by a throwaway root whose private
// key is generated in memory and discarded when this process exits. Only public
// material is written. The fixtures are evidence that such receipts still verify.
import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { sign } from "node:crypto";

const arg = (name) => process.argv[process.argv.indexOf(name) + 1];
const repo = resolve(arg("--repo"));
const out = resolve(arg("--out"));
const load = (p) => import(pathToFileURL(join(repo, p)).href);

const { buildAuthorityBundle, generateAuthorityKeyPair, fingerprintOf } = await load("src/custody/index.mjs");
const { buildPolicyReceiptPayload, canonicalPayloadWithoutSignature } = await load("src/policy-engine/receipt.mjs");
const { canonicalizeJson } = await load("shared/json.ts");

const root = { keyId: "legacy-fixture-root", ...generateAuthorityKeyPair() };
const receiptKey = { keyId: "legacy-fixture-receipt", ...generateAuthorityKeyPair() };
const bundle = await buildAuthorityBundle({
  authorityId: "legacy-fixture-authority",
  issuedAt: "2026-01-01T00:00:00.000Z",
  notAfter: "2099-01-01T00:00:00.000Z",
  root,
  receiptKeys: [{ keyId: receiptKey.keyId, publicPem: receiptKey.publicPem, validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z" }]
});

const NOW = "2026-06-14T12:00:00.000Z";
const policy = {
  schema_version: "1.0", policy_id: "legacy-approval-policy", version: "1", state: "ACTIVE",
  rules: [
    { rule_id: "allow-read-status", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } },
    { rule_id: "allow-deploy-with-approval", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "deploy" }, approval_required: 1 }
  ]
};
const request = {
  schema_version: "1.0", request_id: "legacy-deploy-1", timestamp: NOW,
  principal: { id: "alice" }, agent: { id: "agent-1" }, tool: { tool_name: "deploy" },
  parameters: {}, environment: {}, context: {}
};

mkdirSync(out, { recursive: true });
const written = {};
for (const [label, receiptSchema] of [["v1", undefined], ["v2", "mnde.pe.receipt.v2"]]) {
  const payload = buildPolicyReceiptPayload(request, policy, { now: NOW, ...(receiptSchema ? { receiptSchema } : {}) });
  const value = sign(null, Buffer.from(canonicalPayloadWithoutSignature(payload), "utf8"), (await import("node:crypto")).createPrivateKey(receiptKey.privatePem)).toString("hex");
  const receipt = { ...payload, verifiable_signature: { algorithm: "ED25519", authority_id: bundle.authority_id, key_id: receiptKey.keyId, public_key_fingerprint: fingerprintOf(receiptKey.publicPem), signed_at: NOW, value } };
  writeFileSync(join(out, `unenforced-approval-allow.${label}.receipt.json`), `${JSON.stringify(receipt, null, 2)}\n`);
  written[label] = { decision: receipt.decision_output.decision, reason_code: receipt.decision_output.reason_code, approval_enforced: receipt.approval_enforced ?? null };
}
writeFileSync(join(out, "authority-bundle.public.json"), `${JSON.stringify(bundle, null, 2)}\n`);
writeFileSync(join(out, "trusted-root-fingerprint.txt"), `${bundle.root_key.fingerprint}\n`);
console.log(JSON.stringify({ written, root_fingerprint: bundle.root_key.fingerprint }, null, 2));
