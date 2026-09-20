// Conjunct D — Freshness / replay / restart / rollback.
//
// These operate INSIDE MNDe's own authority state (the execution-id dedup store),
// so their results are findings ABOUT MNDe, not about GitHub.
//
// Forbidden transition:  Consumed(n) → Unused(n).
// We drive the real sidecar over HTTP with a fixed execution id and observe
// whether a second submission of the same id is refused — across same-process
// replay, process restart, a rolled-back store, and the default (no store).

import { existsSync, readdirSync, rmSync, statSync } from "node:fs";
import { startMndeSidecar } from "../../../executor/sidecar-harness.mjs";
import { reviewerRequest } from "../../../scripts/reviewer-request.mjs";
import { freePort, tmpDir, record, writeEvidence } from "../harness/common.mjs";

const results = [];

async function decide(url, execId) {
  const body = reviewerRequest({ requestId: execId, tool: "github.merge", testerId: "EXP001-D", installationId: "EXP001-INSTALL" });
  const res = await fetch(`${url}/v1/decisions`, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body)
  });
  const json = await res.json().catch(() => ({}));
  return { decision: json.decision ?? null, reason: json.reason_code ?? json.reason ?? null };
}

function storeFiles(dir) {
  try { return existsSync(dir) ? readdirSync(dir) : []; } catch { return []; }
}

async function boot(cacheDir) {
  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  const env = cacheDir ? { MNDE_EXEC_ID_CACHE: cacheDir } : {};
  const sc = await startMndeSidecar({ url, testerId: "EXP001-D", env });
  return { url, sc };
}

async function main() {
  // ── D1: durable dedup ON, same process — second submission refused ──────────
  {
    const cache = tmpDir("d1-cache");
    const { url, sc } = await boot(cache);
    let d1a, d1b, files;
    try {
      const ID = `D1-${Date.now()}`;
      d1a = await decide(url, ID);
      d1b = await decide(url, ID);
      files = storeFiles(cache);
    } finally { await sc.stop(); }
    const ok = d1a.decision === "ALLOW" && d1b.decision === "REFUSE";
    results.push(record("D1", "D-freshness", ok ? "PASS" : "FAIL",
      "first ALLOW, replay REFUSE (consumed)", { first: d1a, replay: d1b, storeFiles: files }));
  }

  // ── D2: durable dedup survives process RESTART (same cache dir) ─────────────
  {
    const cache = tmpDir("d2-cache");
    const ID = `D2-${Date.now()}`;
    let first, afterRestart;
    let b1 = await boot(cache);
    try { first = await decide(b1.url, ID); } finally { await b1.sc.stop(); }
    let b2 = await boot(cache);        // restart, same store
    try { afterRestart = await decide(b2.url, ID); } finally { await b2.sc.stop(); }
    const ok = first.decision === "ALLOW" && afterRestart.decision === "REFUSE";
    results.push(record("D2", "D-freshness", ok ? "PASS" : "FAIL",
      "consumed id still REFUSED after restart", { first, afterRestart }));
  }

  // ── D3: ROLLBACK of the store reopens a consumed id (monotonicity broken) ────
  // Simulate restoring MNDe's durable state from a backup taken BEFORE the id was
  // consumed: delete the id's reservation file, then restart and resubmit.
  {
    const cache = tmpDir("d3-cache");
    const ID = `D3-${Date.now()}`;
    let consumed, afterRollback, before, after;
    let b1 = await boot(cache);
    try {
      consumed = await decide(b1.url, ID);         // ALLOW → id reserved on disk
      before = storeFiles(cache);
    } finally { await b1.sc.stop(); }
    // Roll the store back to its pre-consumption state (remove the reservation).
    for (const f of storeFiles(cache)) {
      if (f.includes(ID)) rmSync(`${cache}/${f}`, { force: true });
    }
    after = storeFiles(cache);
    let b2 = await boot(cache);
    try { afterRollback = await decide(b2.url, ID); } finally { await b2.sc.stop(); }
    // If the rolled-back id is ALLOWED again, Consumed→Unused occurred: FAIL.
    const rolledBackToUnused = consumed.decision === "ALLOW" && afterRollback.decision === "ALLOW";
    results.push(record("D3", "D-freshness", rolledBackToUnused ? "FAIL" : "PASS",
      "rolled-back consumed id must NOT re-authorize",
      { consumed, afterRollback, storeBefore: before, storeAfterRollback: after },
      { note: "Freshness state lives entirely in the local FS store; a rollback of that store reverts Consumed→Unused. No out-of-rollback-domain anchor exists." }));
  }

  // ── D4: DEFAULT (no MNDE_EXEC_ID_CACHE) — replay across restart succeeds ─────
  {
    const ID = `D4-${Date.now()}`;
    let first, afterRestart;
    let b1 = await boot(null);
    try { first = await decide(b1.url, ID); } finally { await b1.sc.stop(); }
    let b2 = await boot(null);
    try { afterRestart = await decide(b2.url, ID); } finally { await b2.sc.stop(); }
    // Default posture: no durable store. A replay after restart is ALLOWED again.
    const replayAllowed = first.decision === "ALLOW" && afterRestart.decision === "ALLOW";
    results.push(record("D4", "D-freshness", replayAllowed ? "FAIL" : "PASS",
      "default posture must not allow replay across restart",
      { first, afterRestart },
      { note: "MNDE_EXEC_ID_CACHE unset by default → only in-process dedup, which resets on restart. Durable single-use is opt-in, not the default." }));
  }

  // ── D5: DEFAULT, same process — in-process dedup still holds within a life ──
  {
    const ID = `D5-${Date.now()}`;
    const { url, sc } = await boot(null);
    let a, b;
    try { a = await decide(url, ID); b = await decide(url, ID); } finally { await sc.stop(); }
    const ok = a.decision === "ALLOW" && b.decision === "REFUSE";
    results.push(record("D5", "D-freshness", ok ? "PASS" : "INCONCLUSIVE",
      "same-process replay refused even without durable store", { first: a, replay: b }));
  }

  const summary = {
    conjunct: "D-freshness",
    total: results.length,
    fail: results.filter((r) => r.verdict === "FAIL").length,
    inconclusive: results.filter((r) => r.verdict === "INCONCLUSIVE").length,
    results
  };
  writeEvidence("D_freshness.json", summary);
  for (const r of results) console.log(`  [${r.verdict}] ${r.id} ${r.expected} — first=${JSON.stringify(r.observed.first ?? r.observed.consumed)} then=${JSON.stringify(r.observed.replay ?? r.observed.afterRestart ?? r.observed.afterRollback)}`);
  console.log(`D-freshness: ${summary.total - summary.fail - summary.inconclusive}/${summary.total} PASS, ${summary.fail} FAIL, ${summary.inconclusive} INCONCLUSIVE`);
  return summary;
}

export default await main();
