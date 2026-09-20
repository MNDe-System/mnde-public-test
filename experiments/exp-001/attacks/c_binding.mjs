// Conjunct C — Structural binding of a declared action to its authorization.
//
// Property: a receipt authorizing declared action A(params, id, subject) must NOT
// authorize any structurally different declared action. We capture ONE genuine
// ALLOW receipt from the real sidecar (C001), then present that SAME receipt —
// without obtaining a new one — against mutated requests, and require the
// executor's strict gate to REFUSE and never call run().
//
// The presentation is done with a stand-in decision endpoint that returns the
// captured receipt verbatim. This models an adversary who has a valid receipt
// for action A and tries to ride it into action B. MNDe source is unmodified;
// the executor + receipt + verifier are the real ones.

import http from "node:http";
import { createMndeExecutor } from "../../../executor/index.mjs";
import { startMndeSidecar } from "../../../executor/sidecar-harness.mjs";
import { freePort, receiptsDir, record, writeEvidence } from "../harness/common.mjs";

const SUBJECT = "EXP001-SUBJECT-A";
const results = [];

// A tiny endpoint that answers /v1/decisions with a fixed body (the captured
// receipt), regardless of the request. Everything else 404s.
function replayServer(fixedBody) {
  const server = http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/v1/decisions") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(fixedBody));
      });
    } else {
      res.writeHead(404); res.end();
    }
  });
  return server;
}

async function listen(server, port) {
  await new Promise((done) => server.listen(port, "127.0.0.1", done));
}
async function close(server) { await new Promise((done) => server.close(done)); }

async function main() {
  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  const sc = await startMndeSidecar({ url, testerId: SUBJECT });
  let captured = null;
  const C001_ID = `EXP-C001-${Date.now()}`;
  const AUTH_ACTION = "github.merge";
  const AUTH_PARAMS = { repository: "mnde-exp-001", pull_request: 17, source_commit: "abc123", target_ref: "refs/heads/main", operation: "merge" };

  try {
    // ── C001 control: obtain one genuine ALLOW receipt, run() executes once ──
    const mnde = createMndeExecutor({ sidecarUrl: url, receiptsDir, testerId: SUBJECT });
    let ran = 0;
    const c001 = await mnde.execute({
      action: AUTH_ACTION, input: AUTH_PARAMS, executionId: C001_ID,
      run: async () => { ran += 1; return "MERGED"; }
    });
    const control_ok = c001.decision === "ALLOW" && c001.executed === true && c001.verified === true && ran === 1;
    results.push(record("C001", "C-binding", control_ok ? "PASS" : "FAIL",
      "ALLOW + executed once + verified", { decision: c001.decision, executed: c001.executed, verified: c001.verified, ran, reason: c001.reason }));
    captured = c001.receipt;
    if (!captured) throw new Error("no receipt captured from C001; cannot run substitution matrix");
  } finally {
    await sc.stop();
  }

  // The sidecar is now STOPPED. Every mutation below is served the captured
  // receipt by the replay endpoint — no fresh authorization is ever issued.
  const mockPort = await freePort();
  const mockUrl = `http://127.0.0.1:${mockPort}`;
  const server = replayServer({ decision: "ALLOW", reason_code: "OK_ALLOW", receipt: captured });
  await listen(server, mockPort);

  try {
    // Helper: attempt a mutated execution against the replayed receipt.
    async function attempt(id, label, { action = AUTH_ACTION, input = AUTH_PARAMS, executionId = C001_ID, expectedSubjectId } = {}) {
      const mnde = createMndeExecutor({ sidecarUrl: mockUrl, receiptsDir, testerId: SUBJECT, expectedSubjectId });
      let ran = 0;
      const r = await mnde.execute({ action, input, executionId, run: async () => { ran += 1; return "SIDE-EFFECT"; } });
      // For a mutation, the ONLY safe outcome is REFUSE with run() never called.
      const safe = r.decision === "REFUSE" && r.executed === false && ran === 0;
      results.push(record(id, "C-binding", safe ? "PASS" : "FAIL",
        "REFUSE, run() not called", { decision: r.decision, executed: r.executed, ran, reason: r.reason, failClosed: r.failClosed }, { label }));
      return r;
    }

    // T005 operation / action substitution.
    await attempt("T005", "action substitution (merge→force_push)", { action: "github.force_push" });
    // T001 target ref mutation (param change).
    await attempt("T001", "target ref mutation (main→production)", { input: { ...AUTH_PARAMS, target_ref: "refs/heads/production" } });
    // T002 source commit mutation.
    await attempt("T002", "source commit mutation (abc123→def456)", { input: { ...AUTH_PARAMS, source_commit: "def456" } });
    // T003 pull request mutation.
    await attempt("T003", "pull request mutation (17→18)", { input: { ...AUTH_PARAMS, pull_request: 18 } });
    // T004 repository mutation.
    await attempt("T004", "repository mutation", { input: { ...AUTH_PARAMS, repository: "another-repo" } });
    // T006/T-id: replay the receipt onto a DIFFERENT call (new execution id).
    await attempt("Tid", "execution-id substitution (receipt reused for a new call)", { executionId: `DIFFERENT-${Date.now()}` });
    // T007 subject binding: executor expects subject B, receipt names subject A.
    await attempt("T007", "subject mismatch (expected B, receipt A)", { expectedSubjectId: "EXP001-SUBJECT-B" });

    // T009-executor: IDENTICAL replay (same id/action/params) through the gate.
    // The executor has no cross-call consumption memory, so this is expected to
    // ALLOW again — freshness/single-use is the SIDECAR's responsibility (see
    // conjunct D). We record the OBSERVED behavior honestly as a characterization
    // (not a pass/fail of C): it shows the executor gate is a binding check, not a
    // consumption ledger.
    {
      const mnde = createMndeExecutor({ sidecarUrl: mockUrl, receiptsDir, testerId: SUBJECT });
      let ran = 0;
      const r = await mnde.execute({ action: AUTH_ACTION, input: AUTH_PARAMS, executionId: C001_ID, run: async () => { ran += 1; return "REPLAYED"; } });
      const allowed = r.decision === "ALLOW" && ran === 1;
      results.push(record("T009-exec", "C-binding", "INCONCLUSIVE",
        "characterize executor replay of identical request",
        { decision: r.decision, executed: r.executed, ran },
        { label: "identical-request replay at executor gate", interpretation: allowed
          ? "Executor re-authorizes an identical declared request when re-presented the same receipt+id; it is a per-call binding check, NOT a single-use ledger. Consumption must be enforced by the sidecar (conjunct D)."
          : "Executor refused identical replay." }));
    }
  } finally {
    await close(server);
  }

  const summary = {
    conjunct: "C-binding",
    total: results.length,
    fail: results.filter((r) => r.verdict === "FAIL").length,
    inconclusive: results.filter((r) => r.verdict === "INCONCLUSIVE").length,
    results
  };
  writeEvidence("C_binding.json", summary);
  for (const r of results) console.log(`  [${r.verdict}] ${r.id} ${r.detail.label ?? ""} — ${r.observed.reason ?? r.observed.decision}`);
  console.log(`C-binding: ${summary.total - summary.fail - summary.inconclusive}/${summary.total} PASS, ${summary.fail} FAIL, ${summary.inconclusive} INCONCLUSIVE`);
  return summary;
}

export default await main();
