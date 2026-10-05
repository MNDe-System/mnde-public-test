// Onboarding orchestrator.
//
// Glues the discovery, wiring, and policy-drafting layers into the operations
// the CLI exposes. It reads authority STATE for `status` (keys/manifest present,
// a sample receipt verifies) but never makes or influences an authority decision.
// The authority layer does not import anything here.

import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { buildContext } from "./context.mjs";
import { runDiscovery } from "../discovery/index.mjs";
import { buildWiringPlan, applyPlan, uninstall as wiringUninstall, readManifest } from "../wiring/index.mjs";
import { draftPolicy } from "../policy-drafting/index.mjs";

// Read-only authority state for `status` only.
import { loadAuthorityBundle } from "../../shared/authority-manifest.mjs";
import { verifyReceiptFile, verificationPassed } from "../../tools/verify-receipt.mjs";

export { buildContext };

export function discover(ctx) {
  return runDiscovery(ctx);
}

export function planDeployment(ctx) {
  const discovery = runDiscovery(ctx);
  return { discovery, plan: buildWiringPlan(discovery, ctx) };
}

function serversFromDiscovery(discovery) {
  const servers = [];
  for (const client of discovery.clients) {
    for (const server of client.servers) {
      servers.push({ name: server.name, client: client.id });
    }
  }
  return servers;
}

export function buildDraft(discovery, ctx) {
  return draftPolicy(serversFromDiscovery(discovery), { now: ctx.now() });
}

export function apply(ctx) {
  const { discovery, plan } = planDeployment(ctx);
  const result = applyPlan(plan, ctx);
  let draftPath = null;
  if (result.applied.length > 0) {
    const draft = buildDraft(discovery, ctx);
    draftPath = join(ctx.cwd, "policy.draft.json");
    writeFileSync(draftPath, `${JSON.stringify(draft, null, 2)}\n`, "utf8");
  }
  return { discovery, plan, applied: result.applied, draftPath };
}

export function uninstall(ctx) {
  return wiringUninstall(ctx);
}

export function status(ctx) {
  const manifest = readManifest(ctx);

  let authorityReady = false;
  let authorityReason = null;
  try {
    const bundle = loadAuthorityBundle(ctx.repoRoot, { kind: "local" });
    authorityReady = bundle.ok;
    authorityReason = bundle.ok ? null : bundle.reason;
  } catch (error) {
    authorityReason = error?.message ?? String(error);
  }

  let receiptVerified = null;
  const sample = join(ctx.repoRoot, "examples", "receipts", "valid-receipt.json");
  if (existsSync(sample)) {
    try {
      receiptVerified = verificationPassed(verifyReceiptFile(sample));
    } catch {
      receiptVerified = false;
    }
  }

  return {
    protected: manifest.entries.map((e) => ({
      client: e.clientName ?? e.clientId,
      configPath: e.configPath,
      servers: e.servers,
      appliedAt: e.appliedAt
    })),
    policy: {
      draftPresent: existsSync(join(ctx.cwd, "policy.draft.json")),
      enforcedNote: "MNDe enforces only explicit, versioned policy in the authority layer. The draft is not enforced."
    },
    authority: { ready: authorityReady, reason: authorityReason },
    receiptVerification: receiptVerified
  };
}
