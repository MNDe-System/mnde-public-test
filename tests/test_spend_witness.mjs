// Spend witness protocol (mnde.spend-witness.v1): first-writer-wins consumption, signed and
// nonce-bound responses, fail-closed client, and a log that refuses to load if tampered with.
//
//   npm run test:spend-witness
//
// The server logic and the client are the production code, joined in-process (no TLS), so the
// signatures, the hash chain and the uniqueness rules are real. Network behaviour (timeouts, drops,
// forged or replayed responses) is injected by wrapping the transport.

import assert from "node:assert/strict";
import { appendFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { signResponse, WITNESS_DECISION, parseWitnessConfig } from "../src/freshness/spend_witness.mjs";
import { openWitnessLog } from "../deployment/witness/witness-server.mjs";
import { newWitnessKey, startInProcessWitness } from "./support/witness_fixtures.mjs";

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  [PASS] ${name}`); }
  catch (error) { failed += 1; console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.stack : String(error)}`); }
}
const A = { executor_id: "exec-A", namespace: "ns-1" };
const B = { executor_id: "exec-B", namespace: "ns-1" };
const rec = (n, over = {}) => ({ namespace: "ns-1", grant_id: `grant-${n}`, execution_id: `exec-${n}`, executor_id: "exec-A", receipt_hash: "r".repeat(64), aplus_digest: "a".repeat(64), ...over });
const tmp = () => mkdtempSync(join(tmpdir(), "mnde-witness-test-"));
const dirs = [];
const world = (opts = {}) => { const w = startInProcessWitness({ identities: [A, B, { executor_id: "exec-C", namespace: "ns-2" }], ...opts }); dirs.push(w.dataDir); return w; };

console.log("── first writer wins ──");

await test("the first consume is CONSUMED with a chained entry; the same grant or execution id is CONFLICT", async () => {
  const w = world(); const c = w.client(A);
  const first = await c.consume(rec(1));
  assert.equal(first.decision, WITNESS_DECISION.CONSUMED);
  assert.equal(first.witness.n, 1);
  assert.match(first.witness.entry_digest, /^[0-9a-f]{64}$/);
  assert.equal((await c.consume(rec(1))).decision, WITNESS_DECISION.CONFLICT, "the identical request is not idempotent: a second consume never yields authority");
  assert.equal((await c.consume(rec(2, { grant_id: "grant-1" }))).decision, WITNESS_DECISION.CONFLICT, "a new execution id on a spent grant");
  assert.equal((await c.consume(rec(1, { grant_id: "grant-other" }))).decision, WITNESS_DECISION.CONFLICT, "a spent execution id under a new grant");
  const second = await c.consume(rec(3));
  assert.equal(second.witness.n, 2);
  assert.equal(w.log.head().n, 2);
  w.close();
});

await test("100 concurrent consumes of one authorization produce exactly one CONSUMED", async () => {
  const w = world(); const c = w.client(A);
  const results = await Promise.all(Array.from({ length: 100 }, () => c.consume(rec(7))));
  assert.equal(results.filter((r) => r.decision === WITNESS_DECISION.CONSUMED).length, 1);
  assert.equal(results.filter((r) => r.decision === WITNESS_DECISION.CONFLICT).length, 99);
  assert.equal(w.log.head().n, 1);
  w.close();
});

await test("two executors (two clients, no shared state but the witness) cannot both spend one grant", async () => {
  const w = world(); const a = w.client(A); const b = w.client(B);
  const [x, y] = await Promise.all([a.consume(rec(9)), b.consume(rec(9, { executor_id: "exec-B" }))]);
  assert.deepEqual([x.decision, y.decision].sort(), [WITNESS_DECISION.CONFLICT, WITNESS_DECISION.CONSUMED]);
  w.close();
});

await test("namespaces are independent: a grant spent in one is not spent in another", async () => {
  const w = world();
  assert.equal((await w.client(A).consume(rec(5))).decision, WITNESS_DECISION.CONSUMED);
  assert.equal((await w.client({ executor_id: "exec-C", namespace: "ns-2" }).consume(rec(5, { namespace: "ns-2", executor_id: "exec-C" }))).decision, WITNESS_DECISION.CONSUMED);
  w.close();
});

await test("executor identity substitution is refused and consumes nothing", async () => {
  const w = world(); const a = w.client(A);
  const asB = await a.consume(rec(11, { executor_id: "exec-B" }));
  assert.notEqual(asB.decision, WITNESS_DECISION.CONSUMED);
  const wrongNs = await a.consume(rec(12, { namespace: "ns-2" }));
  assert.notEqual(wrongNs.decision, WITNESS_DECISION.CONSUMED);
  assert.equal(w.log.head().n, 0, "a refused request must not touch the log");
  w.close();
});

console.log("\n── durability and restart ──");

await test("a restarted witness (same data directory) still knows every spend and keeps the chain", async () => {
  const dataDir = tmp(); dirs.push(dataDir); const key = newWitnessKey();
  const w1 = startInProcessWitness({ dataDir, key, identities: [A] });
  const one = await w1.client(A).consume(rec(1));
  w1.close();
  const w2 = startInProcessWitness({ dataDir, key, identities: [A] });
  assert.equal((await w2.client(A).consume(rec(1))).decision, WITNESS_DECISION.CONFLICT);
  const two = await w2.client(A).consume(rec(2));
  assert.equal(two.witness.n, 2);
  assert.notEqual(two.witness.entry_digest, one.witness.entry_digest);
  w2.close();
});

await test("the witness refuses to start on a tampered, torn or duplicated log", async () => {
  const dataDir = tmp(); dirs.push(dataDir); const key = newWitnessKey();
  const w = startInProcessWitness({ dataDir, key, identities: [A] });
  await w.client(A).consume(rec(1)); await w.client(A).consume(rec(2));
  w.close();
  const path = join(dataDir, "spend-log.jsonl");
  const good = readFileSync(path, "utf8");
  writeFileSync(path, good.replace("grant-1", "grant-X"));
  assert.throws(() => openWitnessLog(dataDir), /ERR_WITNESS_LOG_CORRUPT/, "an edited entry breaks its digest");
  writeFileSync(path, good.split("\n").filter(Boolean).slice(1).join("\n") + "\n");
  assert.throws(() => openWitnessLog(dataDir), /ERR_WITNESS_LOG_CORRUPT/, "a deleted first entry breaks the chain");
  writeFileSync(path, good + good.split("\n")[0]);
  assert.throws(() => openWitnessLog(dataDir), /ERR_WITNESS_LOG_CORRUPT/, "a torn final line");
  writeFileSync(path, good + good.split("\n")[0] + "\n");
  assert.throws(() => openWitnessLog(dataDir), /ERR_WITNESS_LOG_CORRUPT/, "a replayed entry");
  writeFileSync(path, good);
  openWitnessLog(dataDir).close(); // the untouched log loads
});

await test("a second server cannot open a data directory that is locked", async () => {
  const w = world();
  assert.throws(() => openWitnessLog(w.dataDir), /ERR_WITNESS_LOCKED/);
  w.close();
});

console.log("\n── the client fails closed ──");

await test("forged, re-signed, wrong-key and tampered responses are UNKNOWN, never CONSUMED", async () => {
  const w = world();
  const tamper = (mutate) => (direct) => async (req) => {
    const out = await direct(req);
    const body = JSON.parse(out.text);
    mutate(body);
    return { status: out.status, text: JSON.stringify(body) };
  };
  for (const [name, mutate] of Object.entries({
    outcome_flipped: (b) => { b.outcome = b.outcome === "CONSUMED" ? "CONFLICT" : "CONSUMED"; },
    n_changed: (b) => { b.n = 99; },
    nonce_changed: (b) => { b.nonce = "f".repeat(32); },
    signature_removed: (b) => { delete b.signature; },
    signature_flipped: (b) => { b.signature = (b.signature[0] === "0" ? "1" : "0") + b.signature.slice(1); }
  })) {
    const r = await w.client(A, { wrap: tamper(mutate) }).consume(rec(20 + Object.keys({}).length + name.length));
    assert.equal(r.decision, WITNESS_DECISION.UNKNOWN, name);
  }
  w.close();
});

await test("a response signed by a different key, or naming an unpinned key id, is not trusted", async () => {
  const w = world(); const rogue = newWitnessKey("witness-key-1");      // same key id, different key
  const resign = (direct) => async (req) => {
    const out = await direct(req);
    const { signature: _s, ...body } = JSON.parse(out.text);
    return { status: out.status, text: JSON.stringify(await signResponse(body, rogue.private_pem)) };
  };
  assert.equal((await w.client(A, { wrap: resign }).consume(rec(30))).decision, WITNESS_DECISION.UNKNOWN);
  const rogue2 = newWitnessKey("unpinned-key");
  const resign2 = (direct) => async (req) => {
    const out = await direct(req);
    const { signature: _s, ...body } = JSON.parse(out.text);
    return { status: out.status, text: JSON.stringify(await signResponse({ ...body, key_id: "unpinned-key" }, rogue2.private_pem)) };
  };
  assert.equal((await w.client(A, { wrap: resign2 }).consume(rec(31))).decision, WITNESS_DECISION.UNKNOWN);
  w.close();
});

await test("a recorded CONSUMED response replayed for a different request is rejected", async () => {
  const w = world();
  let recorded = null;
  const record = (direct) => async (req) => { const out = await direct(req); if (req.method === "POST" && !recorded) recorded = out; return out; };
  assert.equal((await w.client(A, { wrap: record }).consume(rec(40))).decision, WITNESS_DECISION.CONSUMED);
  const replay = () => async () => recorded;
  const r = await w.client(A, { wrap: replay }).consume(rec(41));
  assert.equal(r.decision, WITNESS_DECISION.UNKNOWN, "the nonce, attempt id and identifiers no longer match");
  const sameIds = await w.client(A, { wrap: replay }).consume(rec(40));
  assert.equal(sameIds.decision, WITNESS_DECISION.UNKNOWN, "even the same identifiers fail on the fresh nonce");
  w.close();
});

await test("a stale response (issued long ago) is rejected", async () => {
  const w = world();
  const old = (direct) => async (req) => {
    const out = await direct(req);
    const { signature: _s, ...body } = JSON.parse(out.text);
    return { status: out.status, text: JSON.stringify(await signResponse({ ...body, issued_at: new Date(Date.now() - 3600_000).toISOString() }, w.key.private_pem)) };
  };
  assert.equal((await w.client(A, { wrap: old }).consume(rec(50))).decision, WITNESS_DECISION.UNKNOWN);
  w.close();
});

await test("unreachable, slow, dropped and garbage transports are UNKNOWN (consume) or UNAVAILABLE (preflight); nothing is retried", async () => {
  const w = world();
  let calls = 0;
  const modes = {
    refused: () => async () => { calls += 1; return { error: new Error("ECONNREFUSED") }; },
    timeout: () => async () => { calls += 1; return { error: new Error("timeout") }; },
    garbage: () => async () => { calls += 1; return { status: 201, text: "<html>" }; },
    http500: () => async () => { calls += 1; return { status: 500, text: "{}" }; }
  };
  for (const [name, wrap] of Object.entries(modes)) {
    const c = w.client(A, { wrap });
    calls = 0;
    assert.equal((await c.consume(rec(60))).decision, WITNESS_DECISION.UNKNOWN, name);
    assert.equal(calls, 1, `${name}: exactly one attempt`);
    assert.equal((await c.preflight({ namespace: "ns-1" })).decision, WITNESS_DECISION.UNAVAILABLE, name);
  }
  assert.equal(w.log.head().n, 0);
  w.close();
});

await test("a consume whose reply is lost after the witness recorded it stays spent and is UNKNOWN to the caller", async () => {
  const w = world();
  const lose = (direct) => async (req) => { await direct(req); return { error: new Error("connection reset after the witness committed") }; };
  assert.equal((await w.client(A, { wrap: lose }).consume(rec(70))).decision, WITNESS_DECISION.UNKNOWN);
  assert.equal(w.log.head().n, 1);
  assert.equal((await w.client(A).consume(rec(70))).decision, WITNESS_DECISION.CONFLICT, "the lost-ack authority is not re-spendable");
  const looked = await w.client(A).lookup({ namespace: "ns-1", grant_id: "grant-70", execution_id: "exec-70" });
  assert.equal(looked.decision, "FOUND", "an operator can reconcile with the witness");
  w.close();
});

await test("key rotation: both keys pinned accepts either; only the old key pinned rejects the new", async () => {
  const w = world(); const oldKey = w.key; const newKey = newWitnessKey("witness-key-2");
  const both = w.client(A, { configExtra: { witness_keys: [{ key_id: oldKey.key_id, public_key: oldKey.public_key }, { key_id: newKey.key_id, public_key: newKey.public_key }] } });
  assert.equal((await both.consume(rec(80))).decision, WITNESS_DECISION.CONSUMED);
  // The witness now signs with the new key.
  const w2 = startInProcessWitness({ dataDir: tmp(), key: newKey, identities: [A] }); dirs.push(w2.dataDir);
  const oldOnly = w2.client(A, { configExtra: { witness_keys: [{ key_id: oldKey.key_id, public_key: oldKey.public_key }] } });
  assert.equal((await oldOnly.consume(rec(81))).decision, WITNESS_DECISION.UNKNOWN);
  const rotated = w2.client(A, { configExtra: { witness_keys: [{ key_id: oldKey.key_id, public_key: oldKey.public_key }, { key_id: newKey.key_id, public_key: newKey.public_key }] } });
  assert.equal((await rotated.consume(rec(82))).decision, WITNESS_DECISION.CONSUMED);
  w.close(); w2.close();
});

await test("preflight returns the signed head and refuses a head for the wrong namespace or witness", async () => {
  const w = world(); const c = w.client(A);
  await c.consume(rec(90));
  const head = await c.preflight({ namespace: "ns-1" });
  assert.equal(head.decision, "OK");
  assert.equal(head.head.n, 1);
  assert.equal((await c.preflight({ namespace: "ns-2" })).decision, WITNESS_DECISION.UNAVAILABLE, "a token bound to ns-1 cannot read ns-2");
  const otherWitness = w.client(A, { configExtra: { witness_id: "some-other-witness" } });
  assert.equal((await otherWitness.preflight({ namespace: "ns-1" })).decision, WITNESS_DECISION.UNAVAILABLE);
  w.close();
});

console.log("\n── configuration ──");

await test("configuration is exact: unknown keys, plain http, paths with query, no pinned key and relative paths are refused", () => {
  const good = { url: "https://w.example", witness_id: "w", caFile: "/ca.pem", tokenFile: "/t", witness_keys: [{ key_id: "k", public_key: "p" }] };
  parseWitnessConfig(good);
  for (const bad of [
    { ...good, extra: 1 }, { ...good, url: "http://w.example" }, { ...good, url: "https://w.example/path" }, { ...good, url: "https://u:p@w.example" },
    { ...good, witness_keys: [] }, { ...good, witness_keys: [{ key_id: "k", public_key: "p", extra: 1 }] }, { ...good, caFile: "ca.pem" },
    { ...good, witness_keys: [{ key_id: "k", public_key: "p" }, { key_id: "k", public_key: "q" }] }, { ...good, timeoutMs: 1 }
  ]) assert.throws(() => parseWitnessConfig(bad), /ERR_WITNESS_CONFIG/);
});

for (const d of dirs) { try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
console.log(`\n${failed === 0 ? "PASS" : "FAIL"} spend witness (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
