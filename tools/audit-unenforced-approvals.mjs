#!/usr/bin/env node
// Find receipts that were issued while an approval gate was NOT enforced (UC-002).
//
//   node tools/audit-unenforced-approvals.mjs <file-or-directory> [...]
//
// Before the issuance guard, a policy rule with `approval_required` was silently
// skipped whenever no approval trust anchors were configured, and the receipt did
// not say so. Such a receipt can read ALLOW for an action the policy author meant
// to hold for a human. The receipt still verifies (it must: verification replays
// the historical behaviour), so verification cannot find it. This tool does.
//
// A receipt is FLAGGED when its embedded policy declares `approval_required` on any
// rule and the receipt lacks `approval_enforced: true`. It is flagged as
// ALLOWED_WITHOUT_ENFORCED_APPROVAL when its decision is ALLOW and the matching rule
// is one of those; otherwise as GATE_NOT_ENFORCED (the gate was off, but this
// decision happened not to depend on it).
//
// Read-only. It does NOT verify signatures, so a flagged receipt is a lead for the
// operator, not a verdict: run the normal verifier on anything you act on. Accepts
// receipt JSON files, JSONL logs, and custody envelopes that wrap a receipt.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

function* walk(path) {
  const st = statSync(path);
  if (st.isDirectory()) {
    for (const name of readdirSync(path)) {
      if (name === "node_modules" || name === ".git") continue;
      yield* walk(join(path, name));
    }
  } else if (/\.(json|jsonl|ndjson|log)$/i.test(path)) yield path;
}

function* receiptsIn(text) {
  const candidates = [];
  try { candidates.push(JSON.parse(text)); } catch {
    for (const line of text.split("\n")) { if (!line.trim()) continue; try { candidates.push(JSON.parse(line)); } catch { /* not JSON */ } }
  }
  for (const value of candidates.flat()) {
    if (!value || typeof value !== "object") continue;
    yield value.canonical_policy === undefined && value.receipt && typeof value.receipt === "object" ? value.receipt : value;
  }
}

// Pure. Returns null for receipts that are not policy-engine receipts or are fine.
export function classifyReceipt(receipt) {
  if (typeof receipt?.canonical_policy !== "string" || typeof receipt?.schema_version !== "string" || !receipt.schema_version.startsWith("mnde.pe.receipt.")) return null;
  let policy;
  try { policy = JSON.parse(receipt.canonical_policy); } catch { return null; }
  const gated = (Array.isArray(policy?.rules) ? policy.rules : []).filter((r) => r && typeof r === "object" && Object.hasOwn(r, "approval_required"));
  if (gated.length === 0 || receipt.approval_enforced === true) return null;
  const decision = receipt.decision_output?.decision ?? null;
  const ruleId = receipt.decision_output?.rule_id ?? null; // present on v2 receipts only
  const gatedIds = gated.map((r) => r.rule_id);
  const decidedByGatedRule = decision === "ALLOW" && (ruleId === null ? undefined : gatedIds.includes(ruleId));
  return {
    finding: decision === "ALLOW" && decidedByGatedRule !== false ? "ALLOWED_WITHOUT_ENFORCED_APPROVAL" : "GATE_NOT_ENFORCED",
    certainty: decision === "ALLOW" && decidedByGatedRule === undefined ? "POSSIBLE (v1 receipt names no rule: the ALLOW may have come from an ungated rule)" : "CONFIRMED_FROM_RECEIPT_CONTENT",
    schema_version: receipt.schema_version,
    decision, reason_code: receipt.decision_output?.reason_code ?? null, rule_id: ruleId,
    policy_id: policy.policy_id ?? null, policy_hash: receipt.policy_hash ?? null, request_hash: receipt.request_hash ?? null,
    evaluated_at: receipt.decision_output?.evaluated_at ?? null, gated_rule_ids: gatedIds
  };
}

function main() {
  const targets = process.argv.slice(2);
  if (targets.length === 0) { process.stderr.write("usage: node tools/audit-unenforced-approvals.mjs <file-or-directory> [...]\n"); process.exit(2); }
  const findings = []; let scanned = 0; let receipts = 0;
  for (const target of targets) {
    for (const file of walk(target)) {
      scanned += 1;
      let text; try { text = readFileSync(file, "utf8"); } catch { continue; }
      for (const receipt of receiptsIn(text)) { receipts += 1; const f = classifyReceipt(receipt); if (f) findings.push({ file, ...f }); }
    }
  }
  const allowed = findings.filter((f) => f.finding === "ALLOWED_WITHOUT_ENFORCED_APPROVAL");
  process.stdout.write(`${JSON.stringify({ files_scanned: scanned, policy_engine_receipts_seen: receipts, flagged: findings.length, allowed_without_enforced_approval: allowed.length, findings,
    note: "Leads, not verdicts: signatures are not checked here. Verify with `npm run verify` before acting." }, null, 2)}\n`);
  process.exit(findings.length === 0 ? 0 : 1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
