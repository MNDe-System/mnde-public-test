// MNDe Executor — enforcement tests.
//
//   npm run test:executor
//
// Proves the product claim: if a tool is wrapped with MNDe, there is no code
// path where REFUSE (or any fail-closed condition) executes the function.

import assert from "node:assert/strict";
import http from "node:http";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";

import { createMndeExecutor } from "../executor/index.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import { verificationPassed, verifyReceiptFile } from "../tools/verify-receipt.mjs";

// Dedicated port: 8787 is the sidecar's real default, so a developer's live
// sidecar may legitimately own it while tests run.
const SIDECAR_URL = "http://127.0.0.1:8805";
const RECEIPTS_DIR = "./mnde-receipts/executor-tests";

rmSync(RECEIPTS_DIR, { recursive: true, force: true });

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

async function main() {
  console.log("MNDe Executor — enforcement tests\n");

  const sidecar = await startMndeSidecar({ url: SIDECAR_URL, testerId: "EXEC-TEST-001" });
  const mnde = createMndeExecutor({ sidecarUrl: SIDECAR_URL, receiptsDir: RECEIPTS_DIR });
  let allowReceiptPath = null;

  try {
    await test("1. ALLOW runs the function", async () => {
      let ran = false;
      const r = await mnde.execute({ action: "read_status", input: {}, run: async () => { ran = true; return "ok"; } });
      assert.equal(r.decision, "ALLOW");
      assert.equal(r.executed, true);
      assert.equal(ran, true);
      assert.equal(r.result, "ok");
      assert.ok(r.receiptPath && existsSync(r.receiptPath), "ALLOW must store a receipt");
      allowReceiptPath = r.receiptPath;
    });

    await test("2. REFUSE does not run the function", async () => {
      let ran = false;
      const r = await mnde.execute({
        action: "delete_backups",
        input: { path: "backups/", script: "rm -rf backups/" },
        run: async () => { ran = true; return "deleted"; }
      });
      assert.equal(r.decision, "REFUSE");
      assert.equal(r.executed, false);
      assert.equal(ran, false, "the wrapped function must NOT run on REFUSE");
      assert.equal(r.result, undefined);
    });

    await test("3. A throwing function does not erase the receipt", async () => {
      const r = await mnde.execute({ action: "read_status", input: {}, run: async () => { throw new Error("boom"); } });
      assert.equal(r.decision, "ALLOW");
      assert.equal(r.executed, true);
      assert.match(String(r.error), /boom/);
      assert.ok(r.receiptPath && existsSync(r.receiptPath), "receipt must survive a throwing run()");
    });

    await test("6. Receipt verifies offline", async () => {
      assert.ok(allowReceiptPath, "need an ALLOW receipt from test 1");
      assert.equal(verificationPassed(verifyReceiptFile(allowReceiptPath)), true);
    });

    await test("7. Duplicate execution_id refuses the second run", async () => {
      const id = `exec-dup-${Date.now()}`;
      let ranA = false;
      let ranB = false;
      const a = await mnde.execute({ action: "read_status", input: {}, executionId: id, run: async () => { ranA = true; return "a"; } });
      const b = await mnde.execute({ action: "read_status", input: {}, executionId: id, run: async () => { ranB = true; return "b"; } });
      assert.equal(a.decision, "ALLOW");
      assert.equal(ranA, true);
      assert.equal(b.decision, "REFUSE");
      assert.equal(b.executed, false);
      assert.equal(ranB, false, "the second run of a consumed execution_id must NOT execute");
      assert.equal(b.reason, "ERR_EXECUTION_ID_REPLAYED");
    });
  } finally {
    await sidecar.stop();
  }

  await test("4. Missing sidecar fails closed", async () => {
    const offline = createMndeExecutor({ sidecarUrl: "http://127.0.0.1:8799", receiptsDir: RECEIPTS_DIR, timeoutMs: 1500 });
    let ran = false;
    const r = await offline.execute({ action: "read_status", input: {}, run: async () => { ran = true; } });
    assert.equal(r.decision, "REFUSE");
    assert.equal(r.executed, false);
    assert.equal(ran, false, "a missing sidecar must NOT execute the function");
    assert.equal(r.failClosed, true);
  });

  await test("5. Malformed decision fails closed", async () => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ decision: "MAYBE", reason_code: "garbage" }));
    });
    await new Promise((done) => server.listen(8798, "127.0.0.1", done));
    try {
      const bad = createMndeExecutor({ sidecarUrl: "http://127.0.0.1:8798", receiptsDir: RECEIPTS_DIR, timeoutMs: 1500 });
      let ran = false;
      const r = await bad.execute({ action: "read_status", input: {}, run: async () => { ran = true; } });
      assert.equal(r.decision, "REFUSE");
      assert.equal(r.executed, false);
      assert.equal(ran, false, "a malformed decision must NOT execute the function");
      assert.equal(r.failClosed, true);
    } finally {
      await new Promise((done) => server.close(done));
    }
  });

  await test("9. Hostile execution IDs cannot escape the receipt directory", async () => {
    const root = mkdtempSync(join(tmpdir(), "mnde-executor-path-"));
    const receiptsDir = join(root, "receipts");
    const outsideVictim = join(root, "victim.json");
    try {
      const offline = createMndeExecutor({ sidecarUrl: "http://127.0.0.1:8799", receiptsDir, timeoutMs: 250 });
      let ran = false;
      const r = await offline.execute({
        action: "read_status",
        input: {},
        executionId: "/../../victim",
        run: async () => { ran = true; }
      });
      const rel = relative(resolve(receiptsDir), resolve(r.receiptPath));
      assert.equal(ran, false);
      assert.equal(r.decision, "REFUSE");
      assert.ok(rel && !rel.startsWith("..") && !isAbsolute(rel), `receipt escaped: ${r.receiptPath}`);
      assert.match(r.receiptPath, /failclosed-[0-9a-f]{64}\.json$/);
      assert.equal(existsSync(outsideVictim), false, "hostile ID must not create or overwrite an outside JSON file");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  await test('8. Direct (unwrapped) execution is NOT protected — documented bypass', async () => {
    // The ONLY way to bypass MNDe is to call the raw function directly, never
    // through mnde.execute()/wrapTool(). When you do, no decision is asked and
    // no receipt exists. This test documents that bypass so it is impossible to
    // claim by accident: protection comes from wrapping, not from importing.
    let ran = false;
    const deleteBackups = async () => { ran = true; return "deleted"; };

    await deleteBackups(); // <-- NOT PROTECTED. Never do this with a risky action.

    assert.equal(ran, true, "a raw call runs with no MNDe decision");
    assert.equal(typeof deleteBackups.mndeProtected, "undefined", "a raw function carries no MNDe protection marker");
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL executor enforcement tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS executor enforcement tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
