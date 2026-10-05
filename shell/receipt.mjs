// Signed, offline-verifiable receipt for a shell authorization decision.
//
// This reuses MNDe's existing trust core — the same Ed25519 receipt signing key
// and the same signed authority manifest as every other MNDe receipt. Only the
// schema and the decision logic are shell-specific. Verification recomputes the
// policy decision from the command (replay) AND checks the signature chains to
// the trusted authority. A tampered command or decision fails closed.

import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { canonicalizeJson, parseStrictJson } from "../shared/json.ts";
import { RECEIPT_SIGNATURE_ALGORITHM, signReceiptPayload, verifyReceiptPayloadSignature } from "../shared/index.ts";
import { findAuthorityReceiptKey, loadAuthorityBundle, loadAuthorityBundleForReceipt } from "../shared/authority-manifest.mjs";
import { SHELL_POLICY_ID, decideCommand, shellPolicyHash } from "./policy.mjs";

// Default: relative to this module's own install location (unchanged behavior
// for every source-checkout test/flow). MNDE_HOME overrides it so the packaged
// CLI reads the authority manifest under the caller's own directory, never
// inside node_modules — same override convention as shared/receipt-signing.ts.
const repoRoot = process.env.MNDE_HOME
  ? resolve(process.env.MNDE_HOME)
  : resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA = "mnde.shell.receipt.v1";

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
function decisionHash(requestHash, decision, reasonCode, policyHash) {
  return sha256(canonicalizeJson({ request_hash: requestHash, decision, reason_code: reasonCode, policy_id: SHELL_POLICY_ID, policy_hash: policyHash }));
}

export function buildShellReceipt(command) {
  const policyHash = shellPolicyHash();
  const { decision, reason_code } = decideCommand(command);
  const canonical_request = canonicalizeJson({ schema: "mnde.shell.request.v1", tool: "run_command", command: String(command ?? "") });
  const request_hash = sha256(canonical_request);
  const decision_hash = decisionHash(request_hash, decision, reason_code, policyHash);
  const payload = {
    schema_version: SCHEMA,
    canonical_request,
    request_hash,
    decision_output: { decision, reason_code, request_hash, decision_hash, policy_id: SHELL_POLICY_ID, policy_hash: policyHash }
  };

  // Authority/key info comes from the signed local manifest (robust on a fresh
  // clone regardless of import order), and the signature uses the real key.
  const bundle = loadAuthorityBundle(repoRoot, { kind: "local" });
  if (!bundle.ok) throw new Error(`ERR_AUTHORITY_MANIFEST_INVALID: ${bundle.reason}`);
  const activeKey = bundle.manifest.active_keys?.[0];
  if (!activeKey) throw new Error("ERR_AUTHORITY_NO_ACTIVE_KEY");

  return {
    ...payload,
    verifiable_signature: {
      algorithm: RECEIPT_SIGNATURE_ALGORITHM,
      authority_id: bundle.manifest.authority_id,
      key_id: activeKey.key_id,
      public_key_fingerprint: activeKey.public_key_fingerprint,
      signed_at: new Date().toISOString(),
      value: signReceiptPayload(canonicalPayloadWithoutSignature(payload))
    }
  };
}

function canonicalPayloadWithoutSignature(receiptLike) {
  const { verifiable_signature: _omit, ...payload } = receiptLike;
  return canonicalizeJson(payload);
}

export function writeShellReceipt(receipt, dir, name) {
  const target = resolve(dir);
  mkdirSync(target, { recursive: true });
  const filePath = join(target, name);
  writeFileSync(filePath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
  return filePath;
}

export function verifyShellReceipt(receipt) {
  if (!receipt || receipt.schema_version !== SCHEMA) return { verified: false, reason: "unsupported schema" };
  const parsed = parseStrictJson(receipt.canonical_request);
  if (!parsed.ok) return { verified: false, reason: "canonical_request parse failed" };
  if (sha256(receipt.canonical_request) !== receipt.request_hash) return { verified: false, reason: "request_hash mismatch" };

  const decisionOutput = receipt.decision_output ?? {};
  const policyHash = shellPolicyHash();
  const replay = decideCommand(parsed.value?.command);
  if (replay.decision !== decisionOutput.decision || replay.reason_code !== decisionOutput.reason_code) {
    return { verified: false, reason: "decision drift" };
  }
  if (decisionOutput.policy_hash !== policyHash) return { verified: false, reason: "policy_hash mismatch" };
  if (decisionHash(receipt.request_hash, decisionOutput.decision, decisionOutput.reason_code, policyHash) !== decisionOutput.decision_hash) {
    return { verified: false, reason: "decision_hash mismatch" };
  }

  const signature = receipt.verifiable_signature;
  if (!signature) return { verified: false, reason: "missing signature" };
  const bundle = loadAuthorityBundleForReceipt(repoRoot, signature.authority_id);
  if (!bundle.ok) return { verified: false, reason: bundle.reason };
  // mnde.shell.receipt.v1 has no authenticated decision-time field yet;
  // signature.signed_at is unsigned metadata and must never drive a trust
  // decision. validAt uses the verifier's own current time (computed here,
  // never read from the receipt) — see tools/verify-receipt.mjs for the
  // identical rationale applied to the other format lacking this field.
  const keyResult = findAuthorityReceiptKey(bundle.manifest, { authorityId: signature.authority_id, keyId: signature.key_id, validAt: new Date().toISOString() });
  if (!keyResult.ok) return { verified: false, reason: keyResult.reason };
  if (signature.public_key_fingerprint !== keyResult.key.public_key_fingerprint) return { verified: false, reason: "fingerprint mismatch" };

  const ok = verifyReceiptPayloadSignature(canonicalPayloadWithoutSignature(receipt), signature.value, keyResult.key.public_key);
  return ok
    ? { verified: true, reason: null, decision: decisionOutput.decision, reason_code: decisionOutput.reason_code }
    : { verified: false, reason: "signature invalid" };
}
