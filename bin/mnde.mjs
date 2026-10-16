#!/usr/bin/env node
// MNDe onboarding CLI.
//
//   mnde init              discovery + recommendations (no changes)
//   mnde init --dry-run    full wiring plan (no changes)
//   mnde init --apply      apply approved wiring (creates backups first)
//   mnde uninstall         restore original configurations from backups
//   mnde status            show what is protected, plus policy/authority status
//
// Onboarding only. It does not make authority decisions. Nothing is modified
// unless you run `--apply`, and every `--apply` is reversible with `uninstall`.

import { readFileSync, writeFileSync } from "node:fs";

import { buildContext, discover, planDeployment, buildDraft, apply, uninstall, status } from "../src/onboarding/index.mjs";
import { buildPolicyReceipt, verifyPolicyReceipt } from "../src/policy-engine/receipt.mjs";
import { policyDeclaresApprovalRequired } from "../src/policy-engine/sidecar-adapter.mjs";
import { getReleaseIdentity, formatReleaseIdentity } from "../src/release/identity.mjs";

const argv = process.argv.slice(2);
const command = argv[0];
const has = (flag) => argv.includes(flag);
const flagValue = (flag) => {
  const i = argv.indexOf(flag);
  return i >= 0 ? argv[i + 1] : undefined;
};

function line(text = "") {
  process.stdout.write(`${text}\n`);
}
function rule() {
  line("------------------------------------------------------------");
}
function banner(text) {
  rule();
  line(text);
  rule();
}

function renderDiscovery(discovery) {
  const env = discovery.environment;
  line("Environment");
  line(`  OS:              ${env.os}`);
  line(`  Node:            ${env.runtime.node}`);
  line(`  Package manager: ${env.packageManager ?? "none detected"}`);
  line(`  Project type:    ${env.projectTypes.join(", ")}`);
  line("");
  line("MCP clients");
  for (const client of discovery.clients) {
    const state = client.error ? "unreadable (skipped)" : client.exists ? `${client.servers.length} server(s)` : "not found";
    line(`  ${client.name.padEnd(22)} ${state}`);
    line(`    ${client.configPath}`);
    if (client.error) line(`    ! ${client.error}`);
    for (const server of client.servers) {
      line(`    - ${server.name}${server.wrapped ? "  [already protected]" : ""}`);
    }
  }
  line("");
  line(`Found ${discovery.summary.serversFound} server(s) across ${discovery.summary.clientsFound} client(s); ${discovery.summary.serversUnwrapped} not yet protected.`);
}

function renderPlan(plan) {
  if (plan.changeCount === 0) {
    line("No changes proposed. Either no MCP clients/servers were found, or everything is already protected.");
    return;
  }
  line(`Proposed wiring (${plan.changeCount} server(s)); MNDe sidecar: ${plan.sidecarUrl}`);
  line("");
  for (const mod of plan.modifications) {
    line(`File: ${mod.configPath}   (${mod.clientName})`);
    line(`  Backup:  ${mod.backupPath}`);
    line(`  Metadata:${mod.backupMetadataPath}`);
    line(`  Restore: ${mod.restoreCommand}`);
    for (const sm of mod.servers) {
      const beforeCmd = `${sm.before?.command ?? "?"} ${(sm.before?.args ?? []).join(" ")}`.trim();
      line(`  - ${sm.server}`);
      line(`      before: ${beforeCmd}`);
      line(`      after:  node mcp/mnde-mcp-proxy.mjs  (MNDe in front; upstream preserved)`);
    }
    line("");
  }
}

async function main() {
  // Report the identity of the installed artifact. Reads embedded release
  // metadata only — never inspects Git — so it is truthful from a packaged
  // install with no repository present.
  if (command === "version" || command === "--version" || command === "-v") {
    const identity = getReleaseIdentity();
    if (has("--json")) {
      line(JSON.stringify(identity, null, 2));
    } else {
      line(formatReleaseIdentity(identity));
    }
    return;
  }

  const ctx = buildContext();

  if (command === "init") {
    const { discovery, plan } = planDeployment(ctx);

    if (has("--apply")) {
      banner("MNDe init --apply");
      renderDiscovery(discovery);
      line("");
      const result = apply(ctx);
      if (result.applied.length === 0) {
        line("Nothing to apply. No changes were written.");
        return;
      }
      for (const entry of result.applied) {
        line(`BACKUP CREATED: ${entry.backupPath}`);
        line(`  for: ${entry.configPath} (${entry.clientName})`);
        line(`  protected servers: ${entry.servers.join(", ")}`);
      }
      line("");
      if (result.draftPath) line(`Policy draft written (NOT active, review required): ${result.draftPath}`);
      line("");
      line("Done. MNDe now sits in front of the wired MCP servers.");
      line("Restart your MCP client(s) to pick up the change.");
      line("Undo any time with:  mnde uninstall");
      return;
    }

    // init  and  init --dry-run  both make NO changes.
    banner(has("--dry-run") ? "MNDe init --dry-run" : "MNDe init");
    renderDiscovery(discovery);
    line("");
    renderPlan(plan);

    if (has("--dry-run")) {
      const draft = buildDraft(discovery, ctx);
      line(`Policy draft preview: ${draft.servers.length} server(s), default decision ${draft.default_decision} (review required).`);
      line("");
      banner("NO CHANGES WRITTEN");
      line("This was a dry run. Re-run with --apply to make these changes (backups are created first).");
    } else {
      line("");
      line("No changes were made. Next:");
      line("  mnde init --dry-run    see the exact plan");
      line("  mnde init --apply      apply it (backups created first)");
    }
    return;
  }

  if (command === "uninstall") {
    banner("MNDe uninstall");
    const result = uninstall(ctx);
    if (result.restored.length === 0) {
      line("Nothing to restore. No MNDe wiring is recorded.");
    } else {
      for (const entry of result.restored) line(`RESTORED: ${entry.configPath} (${entry.clientName})`);
      line("");
      line("Original configurations restored from backups. Restart your MCP client(s).");
    }
    if (result.missing.length > 0) {
      line("");
      for (const entry of result.missing) line(`! backup missing for ${entry.configPath}; left unchanged`);
    }
    return;
  }

  if (command === "decide") {
    // Run a request + policy through the deterministic policy engine and emit a
    // signed receipt on the shared authority chain. The decision logic is the
    // authority layer; this command only produces and verifies its receipt.
    banner("MNDe decide");
    const requestPath = flagValue("--request");
    const policyPath = flagValue("--policy");
    const authoritiesPath = flagValue("--authorities");
    const outPath = flagValue("--out");
    if (!requestPath || !policyPath) {
      line("Usage: mnde decide --request <request.json> --policy <policy.json> [--authorities <auth.json>] [--out <receipt.json>]");
      process.exitCode = 1;
      return;
    }
    const trustAnchorsPath = flagValue("--trust-anchors");
    const approvalsPath = flagValue("--approvals");
    const approvalAnchorsPath = flagValue("--approval-trust-anchors");
    const request = JSON.parse(readFileSync(requestPath, "utf8"));
    const policy = JSON.parse(readFileSync(policyPath, "utf8"));
    const authorities = authoritiesPath ? JSON.parse(readFileSync(authoritiesPath, "utf8")) : [];
    const trustAnchors = trustAnchorsPath ? JSON.parse(readFileSync(trustAnchorsPath, "utf8")) : undefined;
    const approvals = approvalsPath ? JSON.parse(readFileSync(approvalsPath, "utf8")) : undefined;
    const approvalTrustAnchors = approvalAnchorsPath ? JSON.parse(readFileSync(approvalAnchorsPath, "utf8")) : undefined;
    if (!approvalTrustAnchors && policyDeclaresApprovalRequired(policy)) {
      // Same refusal as the sidecar's configuration load (UC-002): without approval
      // trust anchors the engine would skip `approval_required` and ALLOW unapproved.
      line("REFUSED: the policy declares approval_required but no --approval-trust-anchors were given,");
      line("so approvals cannot be verified and the gate would silently do nothing.");
      line("Error: ERR_PE_APPROVAL_REQUIRED_WITHOUT_TRUST_ANCHORS");
      process.exitCode = 1;
      return;
    }
    const receipt = buildPolicyReceipt(request, policy, { authorities, trustAnchors, approvals, approvalTrustAnchors });
    const verified = (await verifyPolicyReceipt(receipt, { trustAnchors, approvalTrustAnchors })).verified;
    line(`Decision:    ${receipt.decision_output.decision}`);
    line(`Reason:      ${receipt.decision_output.reason_code}`);
    line(`Receipt:     ${verified ? "VERIFIED (offline)" : "NOT VERIFIED"}`);
    if (outPath) {
      writeFileSync(outPath, `${JSON.stringify(receipt, null, 2)}\n`, "utf8");
      line(`RECEIPT WRITTEN: ${outPath}`);
    } else {
      line("");
      line(JSON.stringify(receipt, null, 2));
    }
    return;
  }

  if (command === "status") {
    banner("MNDe status");
    const identity = getReleaseIdentity();
    line(`Release:              ${identity.product} ${identity.version ?? "unknown"} (${identity.commit_short ?? identity.source})`);
    line("");
    const s = status(ctx);
    line("Protected");
    if (s.protected.length === 0) {
      line("  (nothing wired — run `mnde init --dry-run`)");
    } else {
      for (const p of s.protected) {
        line(`  ${p.client}: ${p.servers.join(", ")}`);
        line(`    ${p.configPath}  (applied ${p.appliedAt})`);
      }
    }
    line("");
    line(`Policy:               draft ${s.policy.draftPresent ? "present" : "absent"} (drafts are never enforced)`);
    line(`Authority (local):    ${s.authority.ready ? "READY" : `not configured${s.authority.reason ? ` (${s.authority.reason})` : ""}`}`);
    line(`Receipt verification: ${s.receiptVerification === null ? "no sample found" : s.receiptVerification ? "VERIFIED (sample receipt)" : "FAILED"}`);
    return;
  }

  line("MNDe onboarding CLI");
  line("");
  line("Usage:");
  line("  mnde version           show installed release identity (add --json for machine output)");
  line("  mnde init              discovery + recommendations (no changes)");
  line("  mnde init --dry-run    full wiring plan (no changes)");
  line("  mnde init --apply      apply approved wiring (backups created first)");
  line("  mnde uninstall         restore original configurations from backups");
  line("  mnde status            show protected clients/servers and authority status");
  line("  mnde decide            evaluate a request+policy and emit a signed receipt");
  line("                         (--request <f> --policy <f> [--authorities <f>] [--out <f>])");
  process.exitCode = command ? 1 : 0;
}

main().catch((error) => {
  process.stderr.write(`mnde: ${error?.message ?? String(error)}\n`);
  process.exit(1);
});
