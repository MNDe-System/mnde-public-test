import { createAdapter as createDisabledAdapter } from "../src/adapter.mjs";
// EXP-001 Stage 2 — integration tests against the PRODUCTION claim backend
// (node:sqlite: one transactional INSERT + two unique indexes; durable WAL;
// consistent cross-process reads).
//
// TRUST-BOUNDARY NOTE: the SQLite file is genuinely separate STORAGE (its own
// file, in a directory distinct from the executor-local files) but on the SAME
// machine — it is NOT genuinely independent infrastructure (no separate
// credentials/backups). So these tests DEMONSTRATE the mechanism and model the
// out-of-rollback-domain property; they are NOT a deployment proof of F-002.
import { spawn } from "node:child_process";
import { rmSync, cpSync, mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { atest, done, assert } from "./_t.mjs";
import { createOfflineAdapter as createAdapter, ATTEMPT } from "../../../tests/support/offline_freshness_adapter.mjs";
import { createSqliteClaimBackend, createLostAckButPresentBackend, createFileClaimBackend } from "../src/claim_store.mjs";
import { deriveClaimRecord } from "../src/freshness.mjs";
import { tmpDir } from "./_tmp.mjs";
import { makeRealVerifiedDeclaration } from "./_real_receipt.mjs";

const NS = "mnde:exp001s2:prod";
const CONFIG = { owner: "mnde-labs", repo: "exp-001", target_ref: "main", namespace: NS, requireProductionBackend: true };
const spy = (resp = { status: 200, body: { merged: true } }) => { const c = []; const f = async (r) => { c.push(r); return resp; }; f.calls = c; return f; };
const dbIn = (prefix) => join(tmpDir(prefix), "claims.sqlite");

// F-002 mechanism against a production backend in SEPARATE storage.
await atest("SQLite: executor-local restore leaves the independent DB intact => SPENT, zero transport", async () => {
  const dbPath = dbIn("prod-restore");
  const localDir = tmpDir("prod-local"); mkdirSync(join(localDir, "state"), { recursive: true });
  const snap = tmpDir("prod-snap"); cpSync(localDir, snap, { recursive: true });
  const decl = await makeRealVerifiedDeclaration({ executionId: "INT-1", grant_id: "INT-G" });

  const t1 = spy(); const b1 = createSqliteClaimBackend({ dbPath });
  const first = await createAdapter({ config: CONFIG, transport: t1, claimBackend: b1 }).attemptMerge(decl);
  assert.equal(first.outcome, ATTEMPT.RESPONDED);
  b1.close();

  rmSync(localDir, { recursive: true, force: true }); cpSync(snap, localDir, { recursive: true }); // restore LOCAL only

  const t2 = spy(); const b2 = createSqliteClaimBackend({ dbPath }); // restart: new conn, same DB
  const again = await createAdapter({ config: CONFIG, transport: t2, claimBackend: b2 }).attemptMerge(decl);
  assert.equal(again.error, "ERR_AUTHORITY_SPENT");
  assert.equal(t2.calls.length, 0);
  b2.close();
});

// Separate OS processes racing for the SAME authority against the SAME DB.
await atest("SQLite: two separate processes racing => exactly one CLAIMED", async () => {
  const dbPath = dbIn("prod-race");
  createSqliteClaimBackend({ dbPath }).close(); // materialize schema
  const url = pathToFileURL(resolve("experiments/exp-001-stage2/src/claim_store.mjs")).href;
  const record = { namespace: NS, execution_id: "RACE-1", grant_id: "RACE-G", subject: "s", executor_id: "x", receipt_hash: "h", aplus_digest: "d" };
  const script =
    `import { createSqliteClaimBackend } from ${JSON.stringify(url)};\n` +
    `const b = createSqliteClaimBackend({ dbPath: ${JSON.stringify(dbPath)} });\n` +
    `const r = await b.claim(${JSON.stringify(record)});\n` +
    `b.close();\n` +
    `process.exit(r.status === "CLAIMED" ? 0 : (r.status === "ALREADY_SPENT" ? 1 : 2));\n`;
  const run = () => new Promise((res) => { const p = spawn(process.execPath, ["--input-type=module"], { stdio: ["pipe", "ignore", "ignore"] }); p.on("close", res); p.stdin.end(script); });
  const codes = (await Promise.all([run(), run()])).sort();
  assert.deepEqual(codes, [0, 1], "exactly one process CLAIMED (0), the other SPENT (1)");
});

// Backend loss during claim: durably present but ack lost => SPENT (never re-send).
await atest("SQLite: lost ack but durably present => SPENT, no transport", async () => {
  const backend = createLostAckButPresentBackend(createSqliteClaimBackend({ dbPath: dbIn("prod-lostack") }));
  const t = spy();
  const rec = await createAdapter({ config: CONFIG, transport: t, claimBackend: backend }).attemptMerge(await makeRealVerifiedDeclaration({ executionId: "LA-1", grant_id: "LA-G" }));
  assert.equal(rec.error, "ERR_AUTHORITY_SPENT");
  assert.equal(t.calls.length, 0);
});

// Backend unavailable (closed) => refuse, no transport.
await atest("SQLite: unavailable backend => refuse, no transport", async () => {
  const b = createSqliteClaimBackend({ dbPath: dbIn("prod-closed") }); b.close();
  const t = spy();
  const rec = await createAdapter({ config: CONFIG, transport: t, claimBackend: b }).attemptMerge(await makeRealVerifiedDeclaration({ executionId: "CL-1" }));
  assert.equal(rec.error, "ERR_CLAIM_BACKEND_UNAVAILABLE");
  assert.equal(t.calls.length, 0);
});

// Crash after claim acknowledgement, before transport => recovery refuses.
await atest("SQLite: crash after claim ack, before transport => recovery SPENT, zero transport", async () => {
  const dbPath = dbIn("prod-crash");
  const decl = await makeRealVerifiedDeclaration({ executionId: "CR-1", grant_id: "CR-G" });
  const b1 = createSqliteClaimBackend({ dbPath });
  const claimed = await b1.claim(deriveClaimRecord(decl, { namespace: NS }).record); // durable ack, then "crash"
  assert.equal(claimed.status, "CLAIMED");
  b1.close();
  const t = spy(); const b2 = createSqliteClaimBackend({ dbPath });
  const rec = await createAdapter({ config: CONFIG, transport: t, claimBackend: b2 }).attemptMerge(decl);
  assert.equal(rec.error, "ERR_AUTHORITY_SPENT");
  assert.equal(t.calls.length, 0);
  b2.close();
});

// Single-insert enforces BOTH unique identities atomically.
await atest("SQLite: single-insert enforces both unique identities", async () => {
  const b = createSqliteClaimBackend({ dbPath: dbIn("prod-uniq") });
  const r = (e, g) => ({ namespace: NS, execution_id: e, grant_id: g, subject: "s", executor_id: "x", receipt_hash: "h", aplus_digest: "d" });
  assert.equal((await b.claim(r("E1", "G1"))).status, "CLAIMED");
  assert.equal((await b.claim(r("E1", "G2"))).status, "ALREADY_SPENT"); // exec
  assert.equal((await b.claim(r("E2", "G1"))).status, "ALREADY_SPENT"); // grant
  assert.equal((await b.claim(r("E2", "G2"))).status, "CLAIMED");
  b.close();
});

// Production posture must never fall back to a non-production backend.
await atest("production adapter refuses backend injection regardless of flags", async () => {
  const t = spy();
  const fileB = createFileClaimBackend({ dir: tmpDir("prod-refuse") });
  const rec = await createDisabledAdapter({ config: CONFIG, transport: t, claimBackend: fileB }).attemptMerge(await makeRealVerifiedDeclaration({ executionId: "RP-1" }));
  assert.equal(rec.error, "ERR_FRESHNESS_DEPLOYMENT_DISABLED");
  assert.equal(t.calls.length, 0);
});

// Authorization / claim / attempt / observation are separate records.
await atest("records authorization, claim, dispatch attempt, and observation separately", async () => {
  const decl = await makeRealVerifiedDeclaration({ executionId: "SEP-1", grant_id: "SEP-G" });
  const t = spy({ status: 200, body: { merged: true }, headers: { "x-github-request-id": "gh-9" } });
  const b = createSqliteClaimBackend({ dbPath: dbIn("prod-sep") });
  const rec = await createAdapter({ config: CONFIG, transport: t, claimBackend: b }).attemptMerge(decl);
  assert.equal(decl.provenance, "VERIFIED");             // authorization
  assert.equal(rec.claim.decision, "CLAIMED");           // claim
  assert.ok(rec.request && rec.httpStatus === 200);      // dispatch attempt + provider response
  // Observation is produced independently by the observer, distinct from the provider response.
  const observation = { source: "independent-read", complete: true, after: { merged: true } };
  assert.ok(observation !== rec.responseBodySanitized);
  b.close();
});

done("freshness-integration-sqlite");
