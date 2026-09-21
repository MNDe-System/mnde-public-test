#!/usr/bin/env node
// Unified MNDe receipt verifier.
//
//   node tools/verify.mjs <receipt.json> [--authority-bundle <bundle.json>]
//     [--policy-bundle <bundle.json> --policy-authority-bundle <bundle.json>
//      --policy-root-fingerprint <hex>]
//
// One command verifies any MNDe receipt, regardless of which engine produced it
// or whether it carries a production custody attestation:
//   - mnde.signed-receipt.v1 -> custody attestation (offline, against a published
//                               authority bundle) AND the inner receipt
//   - mnde.pe.receipt.v1/v2   -> policy-engine replay + signature (verifyPolicyReceipt)
//   - everything else         -> the existing pipeline verifier (verifyReceiptFile)
//
// Receipt type is auto-detected. The legacy and policy-engine paths are imported
// unchanged, preserving their byte-for-byte verification guarantees. Custody
// verification is additive and depends only on the published bundle (no network).
//
// MNDE_HOME: for a mnde.pe.receipt.v1/v2 receipt signed under a non-default
// MNDE_HOME (e.g. one produced by `npx @mnde/sidecar smoke`), this command
// must be run with that SAME MNDE_HOME set in its environment — verification
// resolves the local authority bundle (and therefore the trusted public key)
// relative to it, the same way init/doctor/smoke do. Without it, this looks
// for the authority bundle at this package's own install location instead and
// fails with "unknown authority_id" — a real gap an independent review found:
// this file had no mention of MNDE_HOME at all, even though its correctness
// depends on it whenever it's run standalone against a receipt saved
// elsewhere. Example: MNDE_HOME=./.mnde node tools/verify.mjs ./.mnde/first-receipt.json

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { verifyReceiptFile, verificationPassed } from "./verify-receipt.mjs";
import { verifyPolicyReceipt, POLICY_RECEIPT_SCHEMA, POLICY_RECEIPT_SCHEMA_V2 } from "../src/policy-engine/receipt.mjs";
import { isSignedReceiptEnvelope, verifyCustodyAttestation } from "../src/authority-signing/index.mjs";
import { REPO_LOCAL_TRUST_SOURCE } from "../shared/authority-manifest.mjs";

// Verify a receipt object (legacy / policy-engine / custody-signed envelope).
export async function verifyAnyReceiptObject(receipt, options = {}) {
  try {
    if (isSignedReceiptEnvelope(receipt)) {
      return verifySignedEnvelope(receipt, options);
    }
    if (receipt?.schema_version === POLICY_RECEIPT_SCHEMA || receipt?.schema_version === POLICY_RECEIPT_SCHEMA_V2) {
      const result = await verifyPolicyReceipt(receipt, {
        trustAnchors: options.trustAnchors,
        approvalTrustAnchors: options.approvalTrustAnchors,
        historicalPolicyBundle: options.historicalPolicyBundle,
        policyAuthorityBundle: options.policyAuthorityBundle,
        policyTrustedRootFingerprint: options.policyTrustedRootFingerprint,
        authorityBundle: options.authorityBundle,
        trustedRootFingerprint: options.trustedRootFingerprint,
        now: options.now
      });
      return { kind: "policy-engine", verified: result.verified, reason: result.reason, decision: result.decision, trust_source: result.trust_source };
    }
    // Legacy pipeline verifier is file-based; round-trip the object through a temp file.
    const dir = mkdtempSync(join(tmpdir(), "mnde-verify-"));
    try {
      const file = join(dir, "receipt.json");
      writeFileSync(file, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
      const report = verifyReceiptFile(file);
      return { kind: "pipeline", verified: verificationPassed(report), report, trust_source: REPO_LOCAL_TRUST_SOURCE };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  } catch {
    const kind = isSignedReceiptEnvelope(receipt)
      ? "custody-signed"
      : (receipt?.schema_version === POLICY_RECEIPT_SCHEMA || receipt?.schema_version === POLICY_RECEIPT_SCHEMA_V2)
        ? "policy-engine"
        : "pipeline";
    return { kind, verified: false, reason: "verification error" };
  }
}

function innerEnvelopeOptions(envelope, options = {}) {
  if (envelope?.receipt?.schema_version !== POLICY_RECEIPT_SCHEMA && envelope?.receipt?.schema_version !== POLICY_RECEIPT_SCHEMA_V2) return options;
  if (!Object.hasOwn(options, "authorityBundle") || options.authorityBundle === undefined) return options;
  const innerAuthority = envelope.receipt?.verifiable_signature?.authority_id;
  if (options.authorityBundle?.authority_id === innerAuthority) return options;
  const { authorityBundle: _authorityBundle, trustedRootFingerprint: _trustedRootFingerprint, ...fallbackOptions } = options;
  return fallbackOptions;
}

// Verify a custody-signed envelope: BOTH the inner receipt and the production
// custody attestation must verify. Fails closed if the authority bundle is absent.
export async function verifySignedEnvelope(envelope, options = {}) {
  const attest = await verifyCustodyAttestation(envelope, options);
  const inner = attest.ok || envelope?.receipt ? await verifyAnyReceiptObject(envelope?.receipt, innerEnvelopeOptions(envelope, options)) : { verified: false, reason: "no inner receipt" };
  const verified = Boolean(attest.ok) && Boolean(inner.verified);
  const reason = !attest.ok ? `attestation: ${attest.reason}` : (!inner.verified ? `inner receipt: ${inner.reason ?? "failed"}` : null);
  return {
    kind: "custody-signed",
    verified,
    reason,
    decision: attest.decision,
    state: attest.state,
    signing_mode: attest.signing_mode,
    executor_id: attest.executor_id,
    reason_code: attest.reason_code,
    custody: attest.ok
      ? { key_id: attest.signing_key_id, authority_fingerprint: attest.authority_fingerprint, trust_chain: "VALID", trust_source: attest.trust_source, revocation: "NOT_REVOKED", signed_at: attest.signed_at }
      : { trust_chain: "INVALID" },
    inner,
    trust_source: attest.ok ? attest.trust_source : undefined,
    verified_at: new Date().toISOString()
  };
}

export async function verifyAnyReceiptFile(filePath, options = {}) {
  let receipt;
  try {
    receipt = JSON.parse(readFileSync(filePath, "utf8").replace(/^﻿/, ""));
  } catch (error) {
    return { kind: "error", verified: false, reason: `unreadable receipt: ${error?.message ?? String(error)}` };
  }
  return verifyAnyReceiptObject(receipt, options);
}

async function main() {
  const args = process.argv.slice(2);
  const valueOf = (flag) => {
    const i = args.indexOf(flag);
    return i >= 0 ? args[i + 1] : undefined;
  };
  const trustAnchorsPath = valueOf("--trust-anchors");
  const approvalAnchorsPath = valueOf("--approval-trust-anchors");
  const authorityBundlePath = valueOf("--authority-bundle");
  const rootFingerprint = valueOf("--root-fingerprint");
  const historicalPolicyBundlePath = valueOf("--policy-bundle");
  const policyAuthorityBundlePath = valueOf("--policy-authority-bundle");
  const policyRootFingerprint = valueOf("--policy-root-fingerprint");
  const executorEnvironment = valueOf("--executor-environment");
  const expectedExecutorId = valueOf("--expected-executor-id");
  const flagValues = new Set([trustAnchorsPath, approvalAnchorsPath, authorityBundlePath, rootFingerprint, historicalPolicyBundlePath, policyAuthorityBundlePath, policyRootFingerprint, executorEnvironment, expectedExecutorId].filter(Boolean));
  const filePath = args.find((a) => !a.startsWith("--") && !flagValues.has(a));
  if (!filePath) {
    process.stderr.write("Usage: node tools/verify.mjs <receipt.json> [--authority-bundle <f>] [--root-fingerprint <hex>] [--executor-environment <id>] [--expected-executor-id <id>] [--policy-bundle <f> --policy-authority-bundle <f> --policy-root-fingerprint <hex>] [--trust-anchors <f>] [--approval-trust-anchors <f>]\n");
    process.exit(2);
  }
  const trustAnchors = trustAnchorsPath ? JSON.parse(readFileSync(trustAnchorsPath, "utf8")) : undefined;
  const approvalTrustAnchors = approvalAnchorsPath ? JSON.parse(readFileSync(approvalAnchorsPath, "utf8")) : undefined;
  const authorityBundle = authorityBundlePath ? JSON.parse(readFileSync(authorityBundlePath, "utf8")) : undefined;
  const historicalPolicyBundle = historicalPolicyBundlePath ? JSON.parse(readFileSync(historicalPolicyBundlePath, "utf8")) : undefined;
  const policyAuthorityBundle = policyAuthorityBundlePath ? JSON.parse(readFileSync(policyAuthorityBundlePath, "utf8")) : undefined;
  const result = await verifyAnyReceiptFile(filePath, {
    trustAnchors,
    approvalTrustAnchors,
    authorityBundle,
    trustedRootFingerprint: rootFingerprint,
    historicalPolicyBundle,
    policyAuthorityBundle,
    policyTrustedRootFingerprint: policyRootFingerprint,
    environmentId: executorEnvironment,
    expectedExecutorId
  });
  process.stdout.write("========================================\n");
  process.stdout.write("MNDe Receipt Verification (unified)\n");
  process.stdout.write("========================================\n");
  process.stdout.write(`Receipt:  ${filePath}\n`);
  process.stdout.write(`Type:     ${result.kind}\n`);
  if (result.decision) process.stdout.write(`Decision: ${result.decision}\n`);
  if (result.signing_mode) process.stdout.write(`Signing mode: ${result.signing_mode}\n`);
  if (result.state) process.stdout.write(`Verification state: ${result.state}\n`);
  if (result.executor_id) process.stdout.write(`Executor: ${result.executor_id}\n`);
  if (result.reason_code) process.stdout.write(`Error code: ${result.reason_code}\n`);
  if (result.trust_source) process.stdout.write(`Trust source: ${result.trust_source}\n`);
  if (result.custody) {
    process.stdout.write(`Key id:      ${result.custody.key_id ?? "-"}\n`);
    process.stdout.write(`Authority:   ${result.custody.authority_fingerprint ?? "-"}\n`);
    process.stdout.write(`Trust chain: ${result.custody.trust_chain}\n`);
    if (result.custody.trust_source) process.stdout.write(`Custody trust source: ${result.custody.trust_source}\n`);
    process.stdout.write(`Revocation:  ${result.custody.revocation ?? "-"}\n`);
  }
  if (result.inner?.trust_source) process.stdout.write(`Inner trust source: ${result.inner.trust_source}\n`);
  if (result.verified_at) process.stdout.write(`Verified at: ${result.verified_at}\n`);
  // A custody envelope carries two trust decisions, and the inner one can fall
  // back to the authority shipped in the tree while the attestation verifies
  // against a pinned root (innerEnvelopeOptions drops the configured bundle for
  // an inner receipt signed by a different authority). Qualify on either layer,
  // so this verdict cannot read cleaner than what an executor in production
  // posture would accept.
  const repoLocalQualifier = result.verified
    && (result.trust_source === REPO_LOCAL_TRUST_SOURCE || result.inner?.trust_source === REPO_LOCAL_TRUST_SOURCE)
    ? " (REPO_LOCAL_TRUST_ONLY)"
    : "";
  process.stdout.write(`FINAL VERDICT: ${result.verified ? `VERIFIED${repoLocalQualifier}` : "FAILED"}${result.reason ? ` (${result.reason})` : ""}\n`);
  process.exit(result.verified ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error?.message ?? String(error)}\n`);
    process.exit(1);
  });
}
