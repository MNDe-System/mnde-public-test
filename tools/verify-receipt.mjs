#!/usr/bin/env node
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { runStrictPreflight } from "../preflight/engine.ts";
import { runStrictOrbit } from "../orbit/engine.ts";
import { resetArmStores, runStrictArm } from "../arm/engine.ts";
import { runStrictRamona } from "../ram0na/engine.ts";
import { REASON_CODES } from "../shared/contracts.ts";
import { canonicalizeJson, parseStrictJson } from "../shared/json.ts";
import { policyHash } from "../shared/policy-trust.ts";
import { findAuthorityReceiptKey, loadAuthorityBundleForReceipt } from "../shared/authority-manifest.mjs";
import { verifyReceiptPayloadSignature } from "../shared/receipt-signing.ts";
import { compareBoundaryReplay, parseBoundaryDecisionHash, sha256Hex, sidecarRefusalReason } from "../shared/receipt-replay.mjs";

const SUPPORTED_SCHEMA = "ecs.receipt.v2";
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function pass() {
  return { ok: true, detail: null };
}

function fail(detail) {
  return { ok: false, detail };
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readReceipt(filePath) {
  let raw;
  try {
    raw = readFileSync(filePath, "utf8").replace(/^\uFEFF/, "");
  } catch (error) {
    return { ok: false, reason: `unable to read receipt: ${error instanceof Error ? error.message : String(error)}` };
  }
  try {
    return { ok: true, raw, receipt: JSON.parse(raw) };
  } catch {
    return { ok: false, reason: "malformed JSON" };
  }
}

function validateSchema(receipt) {
  if (!isObject(receipt)) return fail("receipt must be an object");
  if (receipt.schema_version !== SUPPORTED_SCHEMA) return fail(`unsupported receipt schema ${receipt.schema_version ?? "missing"}`);
  if (typeof receipt.canonical_request !== "string" || receipt.canonical_request.length === 0) return fail("canonical_request is required");
  if (typeof receipt.request_hash !== "string" || receipt.request_hash.length === 0) return fail("request_hash is required");
  if (!isObject(receipt.decision_output)) return fail("decision_output is required");
  const decision = receipt.decision_output;
  if (decision.decision !== "ALLOW" && decision.decision !== "REFUSE") return fail("decision_output.decision must be ALLOW or REFUSE");
  for (const field of ["decision_hash", "request_hash", "reason_code", "policy_version", "policy_hash", "execution_id"]) {
    if (typeof decision[field] !== "string" || decision[field].length === 0) return fail(`decision_output.${field} is required`);
  }
  if (!isObject(receipt.pipeline_trace)) return fail("pipeline_trace is required");
  for (const layer of ["preflight", "orbit", "arm", "ramona"]) {
    if (!isObject(receipt.pipeline_trace[layer])) return fail(`pipeline_trace.${layer} is required`);
  }
  for (const field of ["projected_total_cost_cents", "allowed_cost_cents", "prevented_cost_cents"]) {
    if (!Number.isSafeInteger(receipt.pipeline_trace.arm[field])) return fail(`pipeline_trace.arm.${field} is required`);
  }
  if (typeof receipt.pipeline_trace.arm.execution_id !== "string" || receipt.pipeline_trace.arm.execution_id.length === 0) {
    return fail("pipeline_trace.arm.execution_id is required");
  }
  if (!isObject(receipt.verifiable_signature)) return fail("verifiable_signature is required");
  for (const field of ["algorithm", "authority_id", "key_id", "public_key_fingerprint", "signed_at", "value"]) {
    if (typeof receipt.verifiable_signature[field] !== "string" || receipt.verifiable_signature[field].length === 0) {
      return fail(`verifiable_signature.${field} is required`);
    }
  }
  return pass();
}

function verifyCanonicalization(receipt) {
  const parsed = parseStrictJson(receipt.canonical_request);
  if (!parsed.ok) return fail(`canonical_request parse failed: ${parsed.reason}`);
  let recanonicalized;
  try {
    recanonicalized = canonicalizeJson(parsed.value);
  } catch (error) {
    return fail(`canonical_request canonicalization failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (recanonicalized !== receipt.canonical_request) return fail("canonical_request is not in MNDe canonical form");
  return { ok: true, detail: null, parsed: parsed.value };
}

function verifyRequestHash(receipt) {
  const expected = sha256Hex(receipt.canonical_request);
  if (expected !== receipt.request_hash) return fail(`expected ${expected}, got ${receipt.request_hash}`);
  if (receipt.decision_output?.request_hash && receipt.decision_output.request_hash !== receipt.request_hash) {
    return fail("decision_output.request_hash does not match receipt.request_hash");
  }
  if (receipt.pipeline_trace?.preflight?.request_hash && receipt.pipeline_trace.preflight.request_hash !== receipt.request_hash) {
    return fail("pipeline_trace.preflight.request_hash does not match receipt.request_hash");
  }
  return pass();
}

function recomputeDecisionHash(receipt) {
  const arm = receipt.pipeline_trace.arm;
  const out = receipt.decision_output;
  return sha256Hex(canonicalizeJson({
    request_hash: receipt.request_hash,
    policy_hash: out.policy_hash,
    decision: out.decision,
    reason_code: out.reason_code,
    policy_version: out.policy_version,
    execution_id: arm.execution_id,
    projected_total_cost_cents: arm.projected_total_cost_cents,
    allowed_cost_cents: arm.allowed_cost_cents,
    prevented_cost_cents: arm.prevented_cost_cents,
    total_cost_usd: out.total_cost_usd,
    allowed_cost_usd: out.allowed_cost_usd,
    prevented_cost_usd: out.prevented_cost_usd,
    key_set_version: out.key_set_version
  }));
}

function verifyDecisionHash(receipt) {
  try {
    const parsed = parseStrictJson(receipt.canonical_request);
    const sidecarReason = parsed.ok ? sidecarRefusalReason(parsed.value) : null;
    const preflight = !sidecarReason && parsed.ok ? runStrictPreflight(receipt.canonical_request) : null;
    const expected = sidecarReason
      ? parseBoundaryDecisionHash(receipt.request_hash, sidecarReason)
      : preflight && "parse_boundary" in preflight ? preflight.decision_hash : recomputeDecisionHash(receipt);
    if (expected !== receipt.decision_output.decision_hash) {
      return fail(`expected ${expected}, got ${receipt.decision_output.decision_hash}`);
    }
    return pass();
  } catch (error) {
    return fail(`decision hash recompute failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function verifyPolicyHash(receipt, canonicalRequest) {
  const policy = canonicalRequest?.policy_document;
  if (!isObject(policy)) {
    const decisionPolicy = receipt.decision_output?.policy_hash;
    const tracePolicy = receipt.pipeline_trace?.preflight?.policy_hash;
    return typeof decisionPolicy === "string" && decisionPolicy.length > 0 && decisionPolicy === tracePolicy
      ? pass()
      : fail("canonical_request.policy_document is required");
  }
  const expected = policyHash(policy);
  const reported = receipt.decision_output.policy_hash;
  if (expected !== reported) return fail(`expected ${expected}, got ${reported}`);
  if (receipt.pipeline_trace?.preflight?.policy_hash && receipt.pipeline_trace.preflight.policy_hash !== expected) {
    return fail("pipeline_trace.preflight.policy_hash does not match recomputed policy hash");
  }
  return pass();
}

function verifySignature(receipt) {
  try {
    const bundle = loadAuthorityBundleForReceipt(REPO_ROOT, receipt.verifiable_signature?.authority_id);
    if (!bundle.ok) return fail(`authority manifest invalid: ${bundle.reason}`);
    // ecs.receipt.v2 is frozen (shared/contracts.ts: "no new fields or features
    // are added") and carries no authenticated decision-time field — the only
    // timestamp is verifiable_signature.signed_at, which is unsigned metadata
    // and must never drive a trust decision (shared/authority-manifest.mjs).
    // With no authenticated per-receipt time available, validAt uses the
    // verifier's OWN current time instead — computed here, never read from the
    // receipt, so it cannot be backdated by anything the receipt contains.
    // This checks "is the key valid right now," not "was it valid at signing
    // time," which is a strictly safer question for a format that cannot prove
    // the latter.
    const keyResult = findAuthorityReceiptKey(bundle.manifest, {
      authorityId: receipt.verifiable_signature?.authority_id,
      keyId: receipt.verifiable_signature?.key_id,
      validAt: new Date().toISOString()
    });
    if (!keyResult.ok) return fail(keyResult.reason);
    if (receipt.verifiable_signature.public_key_fingerprint !== keyResult.key.public_key_fingerprint) {
      return fail("receipt key fingerprint does not match authority manifest");
    }
    const { signature: _legacySignature, verifiable_signature: _verifiableSignature, ...payload } = receipt;
    const canonicalPayload = canonicalizeJson(payload);
    return verifyReceiptPayloadSignature(canonicalPayload, receipt.verifiable_signature.value, keyResult.key.public_key)
      ? pass()
      : fail("Ed25519 signature verification failed");
  } catch (error) {
    return fail(`signature verification failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function verifyReplayDeterminism(receipt) {
  try {
    resetArmStores();
    const parsed = parseStrictJson(receipt.canonical_request);
    if (!parsed.ok) return fail(`canonical_request parse failed: ${parsed.reason}`);
    const boundary = compareBoundaryReplay(receipt);
    if (boundary.matched) {
      return boundary.drift ? fail(`${boundary.mismatches[0]?.field ?? "boundary"} mismatch`) : pass();
    }
    const preflight = runStrictPreflight(receipt.canonical_request);
    if ("parse_boundary" in preflight) {
      const original = receipt.decision_output;
      const checks = [
        ["request_hash", receipt.request_hash, preflight.request_hash],
        ["decision", original.decision, preflight.decision],
        ["reason_code", original.reason_code, preflight.reason_code],
        ["decision_hash", original.decision_hash, preflight.decision_hash]
      ];
      const mismatch = checks.find(([, left, right]) => left !== right);
      return mismatch ? fail(`${mismatch[0]} mismatch`) : pass();
    }
    const orbit = runStrictOrbit(preflight.parsed_input);
    const arm = runStrictArm(preflight.parsed_input, orbit, preflight.request_hash);
    const ramona = runStrictRamona(preflight.parsed_input, arm);
    const pipelineAllows = orbit.decision === "ALLOW" && arm.decision === "ALLOW" && ramona.decision === "ALLOW";
    const replayedDecision = pipelineAllows ? "ALLOW" : "REFUSE";
    const replayedReasonCode = pipelineAllows ? REASON_CODES.OkAllow : ramona.reason_code;
    const formatUsd = (cents) => `${Math.floor(cents / 100)}.${String(cents % 100).padStart(2, "0")}`;
    const replayedTotalCostUsd = formatUsd(arm.projected_total_cost_cents);
    const replayedAllowedCostUsd = formatUsd(arm.allowed_cost_cents);
    const replayedPreventedCostUsd = formatUsd(arm.prevented_cost_cents);
    const replayedDecisionHash = sha256Hex(canonicalizeJson({
      request_hash: preflight.request_hash,
      policy_hash: preflight.policy_hash,
      decision: replayedDecision,
      reason_code: replayedReasonCode,
      policy_version: preflight.parsed_input.policy_document.policy_version,
      execution_id: arm.execution_id,
      projected_total_cost_cents: arm.projected_total_cost_cents,
      allowed_cost_cents: arm.allowed_cost_cents,
      prevented_cost_cents: arm.prevented_cost_cents,
      total_cost_usd: replayedTotalCostUsd,
      allowed_cost_usd: replayedAllowedCostUsd,
      prevented_cost_usd: replayedPreventedCostUsd,
      key_set_version: receipt.decision_output.key_set_version ?? "receipt-key-set-v1"
    }));
    const original = receipt.decision_output;
    const checks = [
      ["request_hash", receipt.request_hash, preflight.request_hash],
      ["decision", original.decision, replayedDecision],
      ["reason_code", original.reason_code, replayedReasonCode],
      ["decision_hash", original.decision_hash, replayedDecisionHash],
      ["policy_hash", original.policy_hash, preflight.policy_hash],
      ["policy_version", original.policy_version, preflight.parsed_input.policy_document.policy_version],
      ["execution_id", original.execution_id, arm.execution_id],
      ["total_cost_usd", original.total_cost_usd, formatUsd(arm.projected_total_cost_cents)],
      ["allowed_cost_usd", original.allowed_cost_usd, formatUsd(arm.allowed_cost_cents)],
      ["prevented_cost_usd", original.prevented_cost_usd, formatUsd(arm.prevented_cost_cents)]
    ];
    const mismatch = checks.find(([, left, right]) => left !== right);
    if (mismatch) return fail(`${mismatch[0]} mismatch`);
    return pass();
  } catch (error) {
    return fail(`replay failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export function verifyReceiptFile(filePath) {
  const loaded = readReceipt(filePath);
  if (!loaded.ok) {
    return {
      file: filePath,
      loaded: false,
      load_error: loaded.reason,
      checks: {
        Schema: fail(loaded.reason),
        Canonicalization: fail("not evaluated"),
        "Request Hash": fail("not evaluated"),
        "Decision Hash": fail("not evaluated"),
        "Policy Hash": fail("not evaluated"),
        Signature: fail("not evaluated"),
        "Replay Determinism": fail("not evaluated")
      }
    };
  }

  const receipt = loaded.receipt;
  const checks = {};
  checks.Schema = validateSchema(receipt);
  if (!checks.Schema.ok) {
    checks.Canonicalization = fail("not evaluated");
    checks["Request Hash"] = fail("not evaluated");
    checks["Decision Hash"] = fail("not evaluated");
    checks["Policy Hash"] = fail("not evaluated");
    checks.Signature = fail("not evaluated");
    checks["Replay Determinism"] = fail("not evaluated");
    return { file: filePath, loaded: true, receipt, checks };
  }

  checks.Canonicalization = verifyCanonicalization(receipt);
  const canonicalRequest = checks.Canonicalization.parsed;
  checks["Request Hash"] = checks.Canonicalization.ok ? verifyRequestHash(receipt) : fail("canonicalization failed");
  checks["Decision Hash"] = verifyDecisionHash(receipt);
  checks["Policy Hash"] = checks.Canonicalization.ok ? verifyPolicyHash(receipt, canonicalRequest) : fail("canonicalization failed");
  checks.Signature = verifySignature(receipt);
  checks["Replay Determinism"] = checks.Signature.ok && checks.Canonicalization.ok
    ? verifyReplayDeterminism(receipt)
    : fail("signature or canonicalization failed");
  return { file: filePath, loaded: true, receipt, checks };
}

export function verificationPassed(report) {
  return Object.values(report.checks).every((check) => check.ok);
}

export function formatReport(report) {
  const lines = [
    "========================================",
    "MNDe Receipt Verification",
    "========================================",
    `Receipt File: ${report.file}`
  ];
  for (const [name, result] of Object.entries(report.checks)) {
    lines.push(`${name}: ${result.ok ? "PASS" : "FAIL"}`);
  }
  lines.push(`FINAL VERDICT: ${verificationPassed(report) ? "VERIFIED" : "FAILED"}`);
  return `${lines.join("\n")}\n`;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const receiptPath = process.argv[2];
  if (!receiptPath) {
    process.stderr.write("Usage: node tools/verify-receipt.mjs receipt.json\n");
    process.exit(2);
  }
  const report = verifyReceiptFile(receiptPath);
  process.stdout.write(formatReport(report));
  process.exit(verificationPassed(report) ? 0 : 1);
}
