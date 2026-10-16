#!/usr/bin/env node
// Proves the issuance-guard tests detect removal of each part of the fix.
//
//   npm run check:issuance-guard-mutations
//
// For each mutation it copies the working tree to a throwaway directory, breaks one
// thing there, and runs tests/test_issuance_guard.mjs. The mutation must make the
// suite FAIL; a suite that still passes means the tests do not cover that part of
// the fix. The real tree is never modified.
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

const MUTATIONS = [
  { name: "guard routine always says ok", file: "src/policy-engine/issuance-guard.mjs",
    from: "export function checkIssuanceConfiguration(policy, { approvalTrustAnchors } = {}) {", to: "export function checkIssuanceConfiguration(policy, { approvalTrustAnchors } = {}) {\n  return { ok: true };" },
  { name: "chokepoint no longer calls the guard (direct library callers bypass it)", file: "src/policy-engine/receipt.mjs",
    from: "  assertIssuanceConfiguration(policy, { approvalTrustAnchors: options.approvalTrustAnchors });\n", to: "" },
  { name: "loader no longer applies the guard (sidecar/Hub startup)", file: "src/policy-engine/sidecar-adapter.mjs",
    from: "  const issuable = checkIssuanceConfiguration(config.policy, { approvalTrustAnchors: config.approvalTrustAnchors });\n  return issuable.ok ? config : { ok: false, reason: issuable.code, detail: issuable.detail };", to: "  return config;" },
  { name: "mnde decide no longer applies the guard", file: "bin/mnde.mjs",
    from: "    if (!issuable.ok) {", to: "    if (false) {" },
  { name: "missing anchors treated as truthy-configured only (the PR #58 check)", file: "src/policy-engine/issuance-guard.mjs",
    from: "if (policyDeclaresApprovalRequired(policy) && !anchorsConfigured) {", to: "if (policyDeclaresApprovalRequired(policy) && !approvalTrustAnchors && false) {" },
  { name: "anchors schema not validated", file: "src/policy-engine/issuance-guard.mjs",
    from: "if (anchors && !anchors.ok) return anchors;", to: "" },
  { name: "malformed approval_required not rejected", file: "src/policy-engine/issuance-guard.mjs",
    from: "if (Object.hasOwn(rule, \"approval_required\") && !isValidApprovalCount(rule.approval_required)) {", to: "if (false) {" },
  { name: "unknown rule keys not rejected", file: "src/policy-engine/issuance-guard.mjs",
    from: "if (!KNOWN_RULE_KEYS.includes(key)) {", to: "if (false) {" },
  { name: "falsy-but-present anchors treated as 'not configured'", file: "src/policy-engine/issuance-guard.mjs",
    from: "const anchorsConfigured = approvalTrustAnchors !== undefined;", to: "const anchorsConfigured = Boolean(approvalTrustAnchors);" },
  { name: "Hub-only: the loader guard removed but everything else intact (Hub accepts {} anchors again)", file: "src/policy-engine/sidecar-adapter.mjs",
    from: "  const issuable = checkIssuanceConfiguration(config.policy, { approvalTrustAnchors: config.approvalTrustAnchors });\n  return issuable.ok ? config : { ok: false, reason: issuable.code, detail: issuable.detail };", to: "  const issuable = config.approvalTrustAnchors ? { ok: true } : checkIssuanceConfiguration(config.policy, {});\n  return issuable.ok ? config : { ok: false, reason: issuable.code, detail: issuable.detail };" },
  { name: "evaluator semantics changed (breaks historical replay)", file: "src/policy-engine/index.mjs",
    from: "if (!approvalEnforced) return { ok: true };", to: "if (!approvalEnforced) return { ok: false, reason: \"APPROVAL_REQUIRED\" };" }
];

// The guard suite, plus the Hub suite: the Hub is the one issuer that opens its
// authorization lazily, so only its own test shows a mutation reaching it.
function run(dir) {
  const guard = spawnSync(process.execPath, [join(dir, "tests", "test_issuance_guard.mjs")], { cwd: dir, encoding: "utf8", timeout: 240000 });
  const hub = spawnSync(process.execPath, ["--import", "./tests/support/hub_observation_hooks.mjs", join(dir, "tests", "test_hub.mjs")], { cwd: dir, encoding: "utf8", timeout: 240000 });
  const failed = (guard.stdout.match(/\[FAIL\]/g) ?? []).length + (hub.stdout + hub.stderr).split("\n").filter((l) => l.startsWith("FAIL ")).length;
  return { status: guard.status !== 0 || hub.status !== 0 ? 1 : 0, failed, guardStatus: guard.status, hubStatus: hub.status };
}

const baseline = mkdtempSync(join(tmpdir(), "mnde-mut-base-"));
cpSync(repoRoot, baseline, { recursive: true, filter: (p) => !/[\\/](node_modules|\.git|dist)([\\/]|$)/.test(p) });
symlinkSync(join(repoRoot, "node_modules"), join(baseline, "node_modules"), "junction");
const base = run(baseline);
console.log(`unmutated copy: exit ${base.status}, ${base.failed} failing`);
if (base.status !== 0) { console.log("FAIL: the unmutated suite must pass first"); rmSync(baseline, { recursive: true, force: true }); process.exit(1); }

let survived = 0;
for (const m of MUTATIONS) {
  const dir = mkdtempSync(join(tmpdir(), "mnde-mut-"));
  cpSync(baseline, dir, { recursive: true, filter: (p) => !/[\\/]node_modules$/.test(p) });
  symlinkSync(join(repoRoot, "node_modules"), join(dir, "node_modules"), "junction");
  const path = join(dir, m.file);
  const source = readFileSync(path, "utf8");
  if (!source.includes(m.from)) { console.log(`ERROR  ${m.name}: mutation anchor not found in ${m.file}`); survived++; rmSync(dir, { recursive: true, force: true }); continue; }
  writeFileSync(path, source.replace(m.from, m.to));
  const r = run(dir);
  const caught = r.status !== 0;
  if (!caught) survived++;
  console.log(`${caught ? "CAUGHT  " : "SURVIVED"} ${m.name} (${r.failed} failing; guard suite exit ${r.guardStatus}, hub suite exit ${r.hubStatus})`);
  rmSync(dir, { recursive: true, force: true });
}
rmSync(baseline, { recursive: true, force: true });
console.log(survived === 0 ? `\nPASS: all ${MUTATIONS.length} mutations are caught` : `\nFAIL: ${survived} mutation(s) not caught`);
process.exit(survived === 0 ? 0 : 1);
