// Optional policy-engine-mode reviewer kit.
//
//   npm run reviewer-kit:pe
//
// Runs the live sidecar with MNDE_DECISION_ENGINE=policy-engine and confirms an
// ALLOW and a REFUSE produce policy-engine receipts that verify offline through
// the unified verifier. The default `npm run reviewer-kit` is unchanged.

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { verifyAnyReceiptFile } from "../tools/verify.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const samplePolicy = join(repoRoot, "examples", "policy-engine", "sample-policy-no-approval.json");

function peReq(tool) {
  return {
    schema_version: "1.0", request_id: `req-${tool}`, timestamp: new Date().toISOString(),
    principal: { id: "reviewer" }, agent: { id: "reviewer" }, tool: { tool_name: tool },
    parameters: {}, environment: {}, context: {}
  };
}
async function decide(url, body) {
  return (await fetch(`${url}/v1/decisions`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) })).json();
}
async function verifyFile(receipt) {
  const f = join(mkdtempSync(join(tmpdir(), "mnde-rkpe-")), "r.json");
  writeFileSync(f, JSON.stringify(receipt));
  return (await verifyAnyReceiptFile(f)).verified;
}

async function main() {
  console.log("MNDe Reviewer Kit — policy-engine mode\n");
  let pass = true;
  const sidecar = await startMndeSidecar({ url: "http://127.0.0.1:8787", env: { MNDE_DECISION_ENGINE: "policy-engine", MNDE_PE_POLICY: samplePolicy } });
  try {
    const allow = await decide(sidecar.url, peReq("read_status"));
    const allowVerified = allow.receipt && await verifyFile(allow.receipt);
    console.log(`ALLOW: decision=${allow.decision} engine=${allow.decision_engine} receipt=${allowVerified ? "VERIFIED" : "NOT VERIFIED"}`);
    pass = pass && allow.decision === "ALLOW" && allow.decision_engine === "policy-engine" && allowVerified;

    const refuse = await decide(sidecar.url, peReq("recursive_delete"));
    const refuseVerified = refuse.receipt && await verifyFile(refuse.receipt);
    console.log(`REFUSE: decision=${refuse.decision} reason=${refuse.reason_code} receipt=${refuseVerified ? "VERIFIED" : "NOT VERIFIED"}`);
    pass = pass && refuse.decision === "REFUSE" && refuseVerified;
  } finally {
    await sidecar.stop();
  }
  console.log(`\nFINAL VERDICT: ${pass ? "PASS" : "FAIL"}`);
  if (!pass) process.exit(1);
}

main().catch((error) => {
  console.error(error);
  console.log("\nFINAL VERDICT: FAIL");
  process.exit(1);
});
