import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { canonicalizeJson } from "../shared/json.ts";
import { sha256 } from "../src/crypto/provider.mjs";

const RECEIPT_LIMIT_DEFAULT = 100;
const RECEIPT_LIMIT_MIN = 1;
const RECEIPT_LIMIT_MAX = 500;
const RECEIPT_SIGNATURE_STATES = new Set(["VALID", "INVALID", "UNKNOWN", "NOT_REPORTED"]);
const REPLAY_STATES = new Set(["VALID", "DRIFT", "UNKNOWN", "NOT_REPORTED"]);
const FORBIDDEN_AUDIT_PATTERNS = [
  /\.pem$/i,
  /\.key$/i,
  /\.zip$/i,
  /node_modules/i,
  /private/i,
  /secret/i,
  /signing/i
];

export function clampReceiptLimit(value) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed)) return RECEIPT_LIMIT_DEFAULT;
  return Math.max(RECEIPT_LIMIT_MIN, Math.min(RECEIPT_LIMIT_MAX, parsed));
}

// Prefer the receipt's own timestamp, fall back to the signing time already
// present on every signed receipt. Never fabricate a time: a missing or
// unparseable value is reported as null, not epoch zero.
function receiptTimestamp(raw) {
  for (const candidate of [raw?.timestamp, raw?.verifiable_signature?.signed_at]) {
    if (typeof candidate === "string" && Number.isFinite(Date.parse(candidate))) return candidate;
  }
  return null;
}

export function normalizeReceipt(raw) {
  // Custody-backed receipts are persisted as a signed outer envelope whose
  // inner receipt is the signed payload: the custody attestation binds it by
  // receipt_hash. The envelope's own surface (schema_version, and any field an
  // author chose to add alongside `receipt`) is NOT covered by that signature,
  // so it must never override the inner receipt. Resolve the inner receipt
  // first and read every display field from it.
  //
  // This is deliberately the same precedence verifyReceiptContract() uses, so
  // display and verification always resolve the same object. An outer field
  // can never make the operator see a decision the verifier did not check.
  const receipt = raw?.receipt && typeof raw.receipt === "object" && !Array.isArray(raw.receipt)
    ? raw.receipt
    : raw;
  const decision = receipt?.decision_output && typeof receipt.decision_output === "object" ? receipt.decision_output : {};
  const trace = receipt?.pipeline_trace && typeof receipt.pipeline_trace === "object" ? receipt.pipeline_trace : {};
  const receiptId = receipt?.receipt_id ?? receipt?.id ?? decision.decision_hash ?? receipt?.request_hash ?? null;
  const verdict = decision.decision === "ALLOW" ? "ALLOW" : "REFUSE";
  const prevented = Number.parseFloat(String(decision.prevented_cost_usd ?? ""));
  // Trust status is read from the resolved (signed) receipt only. The unsigned
  // envelope surface never contributes it: allowing an outer signature_status
  // to win would let an unsigned field assert the trust of a signed one.
  //
  // NOTE: no verifier writes these fields today, so in practice they resolve to
  // UNKNOWN / NOT_REPORTED. That is correct-by-absence, not proof — presentation
  // must treat anything other than VALID as unproven.
  const signatureStatus = RECEIPT_SIGNATURE_STATES.has(receipt?.signature_status)
    ? receipt.signature_status
    : receipt?.signature || receipt?.verifiable_signature
      ? "UNKNOWN"
      : "NOT_REPORTED";
  const replayStatus = REPLAY_STATES.has(receipt?.replay_status)
    ? receipt.replay_status
    : "UNKNOWN";

  return {
    receipt_id: typeof receiptId === "string" ? receiptId : null,
    timestamp: receiptTimestamp(receipt),
    verdict,
    action: typeof receipt?.action === "string" ? receipt.action : decision.execution_id ? `execution ${decision.execution_id}` : "not reported",
    reason_code: typeof decision.reason_code === "string" ? decision.reason_code : "NOT_REPORTED",
    policy: typeof decision.policy_version === "string" ? decision.policy_version : "NOT_REPORTED",
    policy_hash: typeof decision.policy_hash === "string" ? decision.policy_hash : "NOT_REPORTED",
    request_hash: typeof receipt?.request_hash === "string" ? receipt.request_hash : typeof decision.request_hash === "string" ? decision.request_hash : "NOT_REPORTED",
    decision_hash: typeof decision.decision_hash === "string" ? decision.decision_hash : "NOT_REPORTED",
    canonical_payload_hash: typeof receipt?.canonical_payload_hash === "string" ? receipt.canonical_payload_hash : null,
    signature_status: signatureStatus,
    replay_status: replayStatus,
    prevented_cost_usd: Number.isFinite(prevented) ? prevented : null,
    raw
  };
}

export function readRecentReceipts(receiptPath, limit = RECEIPT_LIMIT_DEFAULT, onMalformed = () => {}) {
  const boundedLimit = clampReceiptLimit(limit);
  if (!existsSync(receiptPath)) return [];
  const source = readFileSync(receiptPath, "utf8").trim();
  if (!source) return [];

  const parsed = [];
  const lines = source.split(/\r?\n/);
  for (let index = lines.length - 1; index >= 0 && parsed.length < boundedLimit; index -= 1) {
    const line = lines[index].trim();
    if (!line) continue;
    try {
      const raw = JSON.parse(line);
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("receipt line is not an object");
      parsed.push(normalizeReceipt(raw));
    } catch (error) {
      onMalformed({ line: index + 1, reason: error instanceof Error ? error.message : "malformed receipt" });
    }
  }
  return parsed;
}

export function verifyReceiptContract(input, verifySignedReceipt) {
  const receipt = input?.receipt && typeof input.receipt === "object" ? input.receipt : input;
  const decision = receipt?.decision_output && typeof receipt.decision_output === "object" ? receipt.decision_output : null;
  const fail = (status, reason) => ({
    status,
    receipt_id: typeof receipt?.receipt_id === "string" ? receipt.receipt_id : null,
    request_hash: typeof receipt?.request_hash === "string" ? receipt.request_hash : typeof decision?.request_hash === "string" ? decision.request_hash : null,
    decision_hash: typeof decision?.decision_hash === "string" ? decision.decision_hash : null,
    policy_hash: typeof decision?.policy_hash === "string" ? decision.policy_hash : null,
    reason
  });

  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) return fail("INVALID", "receipt must be an object");
  if (!decision) return fail("INVALID", "receipt decision_output is required");
  if (!receipt.signature && !receipt.verifiable_signature) return fail("SIGNATURE_FAIL", "receipt signature is missing");
  if (typeof receipt.canonical_request !== "string" || typeof receipt.request_hash !== "string") return fail("INVALID", "canonical request and request hash are required");
  if (decision.request_hash && decision.request_hash !== receipt.request_hash) return fail("DRIFT", "decision request_hash does not match receipt request_hash");
  if (!verifySignedReceipt(receipt)) return fail("SIGNATURE_FAIL", "receipt signature verification failed");

  return {
    status: "VALID",
    receipt_id: typeof receipt.receipt_id === "string" ? receipt.receipt_id : null,
    request_hash: receipt.request_hash,
    decision_hash: typeof decision.decision_hash === "string" ? decision.decision_hash : null,
    policy_hash: typeof decision.policy_hash === "string" ? decision.policy_hash : null,
    reason: null
  };
}

export function replayRecentReceipts(receiptPath, limit, verifySignedReceipt, replayReceipt) {
  const startedAt = new Date().toISOString();
  const malformed = [];
  const receipts = readRecentReceipts(receiptPath, limit, (warning) => malformed.push(warning));
  const failures = [];
  let signatureFailures = 0;
  for (const item of receipts) {
    const result = replayReceipt ? replayReceipt(item.raw) : verifyReceiptContract(item.raw, verifySignedReceipt);
    if (result.status !== "VALID" && result.status !== "PASS") {
      if (result.status === "SIGNATURE_FAIL") signatureFailures += 1;
      failures.push({
        receipt_id: item.receipt_id,
        reason: result.reason ?? result.status,
        request_hash: result.request_hash,
        decision_hash: result.decision_hash
      });
    }
  }
  for (const warning of malformed) {
    failures.push({ receipt_id: null, reason: `malformed receipt line ${warning.line}: ${warning.reason}`, request_hash: null, decision_hash: null });
  }
  const policyHash = receipts.find((receipt) => receipt.policy_hash && receipt.policy_hash !== "NOT_REPORTED")?.policy_hash ?? null;
  return {
    status: summarizeReplayStatus(failures),
    checked: receipts.length,
    drift: failures.length - signatureFailures,
    signature_failures: signatureFailures,
    policy_hash: policyHash,
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    failures
  };
}

function summarizeReplayStatus(failures) {
  if (failures.length === 0) return "PASS";
  if (failures.some((failure) => String(failure.reason).includes("signature"))) return "SIGNATURE_FAIL";
  if (failures.some((failure) => String(failure.reason).includes("unsupported") || String(failure.reason).includes("unavailable"))) return "REPLAY_UNAVAILABLE";
  if (failures.some((failure) => String(failure.reason).includes("malformed"))) return "MALFORMED_RECEIPT";
  return "DRIFT";
}

export function buildCapabilityObject(results) {
  return {
    health: Boolean(results.health),
    ready: Boolean(results.ready),
    metrics: Boolean(results.metrics),
    receipts_recent: Boolean(results.receipts_recent),
    receipt_verify: Boolean(results.receipt_verify),
    replay_recent: Boolean(results.replay_recent),
    policy_activation: Boolean(results.policy_activation),
    audit_bundle: Boolean(results.audit_bundle)
  };
}

export function validatePolicyDocument(policy, verifyPolicySignature) {
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) return { ok: false, reason: "policy must be an object" };
  if (policy.schema_version !== "ecs.policy.v1") return { ok: false, reason: "policy schema_version must be ecs.policy.v1" };
  if (typeof policy.policy_version !== "string" || !policy.policy_version) return { ok: false, reason: "policy_version is required" };
  if (!policy.rules || typeof policy.rules !== "object" || Array.isArray(policy.rules)) return { ok: false, reason: "policy rules object is required" };
  if (policy.trust) {
    const trust = policy.trust;
    if (typeof trust.public_key !== "string" || typeof trust.signature !== "string") return { ok: false, reason: "policy trust signature is incomplete" };
    if (!verifyPolicySignature(trust.public_key, policy, trust.signature)) return { ok: false, reason: "policy signature verification failed" };
  }
  return { ok: true, reason: null };
}

export function createAuditBundle({ outputRoot, recentReceipts, replaySummary, metricsText, readySnapshot, policySummary }) {
  const createdAt = new Date().toISOString();
  const safeStamp = createdAt.replace(/[:.]/g, "-");
  const bundlePath = resolve(outputRoot, `audit-bundle-${safeStamp}`);
  mkdirSync(bundlePath, { recursive: true });
  const files = [];

  function writeJson(name, value) {
    if (FORBIDDEN_AUDIT_PATTERNS.some((pattern) => pattern.test(name))) throw new Error(`forbidden audit file name: ${name}`);
    const target = join(bundlePath, name);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    files.push(name);
  }

  writeJson("policy-summary.json", policySummary);
  writeJson("recent-receipts.json", recentReceipts);
  writeJson("replay-summary.json", replaySummary);
  writeJson("metrics-snapshot.json", { text: metricsText });
  writeJson("readiness-snapshot.json", readySnapshot);

  const manifest = {
    created_at: createdAt,
    files: files.map((file) => {
      const bytes = readFileSync(join(bundlePath, file));
      return { file, sha256: sha256(bytes), bytes: bytes.byteLength };
    })
  };
  writeJson("manifest.json", manifest);
  return { status: "PASS", bundle_path: bundlePath, created_at: createdAt, files, reason: null };
}

export function canonicalHash(value) {
  return sha256(canonicalizeJson(value));
}
