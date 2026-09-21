#!/usr/bin/env node
// Deployment proof for the durable single-use claim store.
//
//   MNDE_CLAIM_CONFIG=/abs/path/claim-config.json \
//     node ./deployment/freshness/claim-store-proof.mjs
//
// This is NOT part of `npm test` and must never be added to it. It needs a
// provisioned PostgreSQL primary and the `pg` driver, neither of which exists in
// CI, and it writes rows that are by design impossible to delete. Run it once
// against a freshly provisioned claim database, before that database is used for
// anything, and keep the output.
//
// WHAT IT IS FOR. src/freshness/postgres_claim.mjs and postgres.sql beside this
// file carry the whole of MNDe's answer to F-001: a verified receipt is a
// signature, and a signature can be presented twice, so authority has to be spent
// somewhere that cannot be rewound. Everything about that answer was, until this
// harness, unexecuted code and unapplied SQL. This runs the adapter UNMODIFIED
// against a real server and checks the two claims the design actually rests on:
//
//   1. an authority can be spent exactly once, including under concurrency
//   2. the executor login cannot roll the claim store back
//
// The second is deliberately the weaker claim, and the wording matters. It is
// "the executor cannot", not "nobody can": whoever owns the database can still
// restore a backup. Keeping restore and admin authority outside the automated
// system is a deployment requirement, not something this proof establishes.
//
// IT DISPATCHES NOTHING. There is no effect here to protect. A passing run does
// not close F-001 and does not enable execution; see docs/F001-CLAIM-STORE-PROOF.md
// for what remains.

import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";

import { openExecutorClaimBackend } from "../../src/freshness/postgres_claim.mjs";

const configPath = process.env.MNDE_CLAIM_CONFIG;
if (!configPath) {
  console.error("MNDE_CLAIM_CONFIG is not set. See docs/F001-CLAIM-STORE-PROOF.md for provisioning.");
  process.exit(2);
}
const config = JSON.parse(readFileSync(configPath, "utf8"));
const NAMESPACE = config.namespace;

// Optional. A shell command that restarts the database server with -m immediate,
// used by the durability case. Left unset, that one case is reported as SKIP
// rather than quietly passing.
const RESTART_COMMAND = process.env.MNDE_CLAIM_PROOF_RESTART_COMMAND ?? null;

let passed = 0;
let failed = 0;
let skipped = 0;
async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    if (error?.skip === true) {
      skipped += 1;
      console.log(`  [SKIP] ${name}: ${error.message}`);
      return;
    }
    failed += 1;
    console.log(`  [FAIL] ${name}: ${error?.message ?? error}`);
  }
}
function skip(message) {
  const error = new Error(message);
  error.skip = true;
  throw error;
}

let counter = 0;
function unique(prefix) {
  counter += 1;
  return `${prefix}-${process.pid}-${Date.now()}-${counter}`;
}

function record(overrides = {}) {
  return {
    namespace: NAMESPACE,
    execution_id: unique("exec"),
    grant_id: unique("grant"),
    subject: "proof-subject",
    executor_id: "mnde:proof:executor:01",
    receipt_hash: `sha256:${"a".repeat(64)}`,
    aplus_digest: `sha256:${"b".repeat(64)}`,
    ...overrides
  };
}

// A direct client as the SAME restricted login, to test what that login is able
// to do — which is a different question from what the adapter chooses to ask for.
// A client-side check is not a security boundary, so the boundary is tested
// where it has to hold.
let pg;
async function asExecutor(sql, params = []) {
  pg ??= (await import("pg")).default;
  const client = new pg.Client({
    host: config.host,
    port: config.port,
    database: config.database,
    user: config.user,
    password: readFileSync(config.passwordFile, "utf8").trim(),
    ssl: { ca: readFileSync(config.caFile, "utf8"), rejectUnauthorized: true }
  });
  await client.connect();
  try {
    return await client.query(sql, params);
  } finally {
    await client.end().catch(() => {});
  }
}

// Asserts the statement is refused by the SERVER for an authorization reason.
// Matching the message matters: a connection failure would otherwise read as a
// successful refusal and every case in this section would pass for free.
async function denied(name, sql) {
  await test(name, async () => {
    await assert.rejects(
      () => asExecutor(sql),
      (error) => {
        assert.match(
          String(error?.message),
          /permission denied|must be owner/i,
          `expected an authorization refusal, got: ${error?.message}`
        );
        return true;
      }
    );
  });
}

async function main() {
  console.log("F-001 durable single-use claim store — deployment proof");
  console.log(`  database: ${config.user}@${config.host}:${config.port}/${config.database}`);
  console.log(`  namespace: ${NAMESPACE}\n`);

  console.log("── the adapter reaches a durable primary ──");
  const backend = await openExecutorClaimBackend();

  await test("connects over verified TLS and agrees with the server about the namespace", async () => {
    const health = await backend.health();
    assert.equal(health.ok, true, "health() must confirm the server-side bound namespace");
  });

  console.log("\n── an authority is spent exactly once ──");

  await test("a fresh authority is CLAIMED and the acknowledgement echoes the record exactly", async () => {
    const claim = record();
    const result = await backend.claim(claim);
    assert.equal(result.status, "CLAIMED");
    // An ack that does not echo the record is a status flag, not authority.
    assert.deepEqual(result.record, claim);
  });

  await test("replaying the same execution_id is ALREADY_SPENT", async () => {
    const claim = record();
    assert.equal((await backend.claim(claim)).status, "CLAIMED");
    const replay = await backend.claim(claim);
    assert.equal(replay.status, "ALREADY_SPENT");
    assert.deepEqual(replay.prior, claim);
  });

  await test("a NEW execution_id reusing a spent grant_id is ALREADY_SPENT", async () => {
    // This is the replay that matters, and it is the one F-001 names. A receipt
    // can be presented again under a fresh execution id; the grant is what
    // carries the authority, so the grant has to be what gets spent.
    const first = record();
    assert.equal((await backend.claim(first)).status, "CLAIMED");
    const replay = record({ grant_id: first.grant_id });
    assert.notEqual(replay.execution_id, first.execution_id);
    const result = await backend.claim(replay);
    assert.equal(result.status, "ALREADY_SPENT", "a reused grant must not produce a second claim");
    assert.equal(result.prior.execution_id, first.execution_id);
  });

  await test("lookup finds a spent claim and returns the original record", async () => {
    const claim = record();
    await backend.claim(claim);
    const found = await backend.lookup(claim);
    assert.equal(found.found, true);
    assert.deepEqual(found.record, claim);
  });

  await test("lookup of an unspent authority reports not-found, never permission", async () => {
    const found = await backend.lookup(record());
    assert.equal(found.found, false);
    assert.equal(found.record, undefined);
  });

  console.log("\n── under concurrency ──");

  for (const workers of [2, 8, 32]) {
    await test(`${workers} concurrent claims of one grant produce exactly 1 CLAIMED`, async () => {
      const grantId = unique("grant-race");
      const attempts = Array.from({ length: workers }, () => record({ grant_id: grantId }));
      const results = await Promise.all(
        attempts.map((claim) => backend.claim(claim).catch(() => ({ status: "THREW" })))
      );
      const claimed = results.filter((result) => result.status === "CLAIMED");
      const spent = results.filter((result) => result.status === "ALREADY_SPENT");
      const threw = results.filter((result) => result.status === "THREW");
      assert.equal(
        claimed.length, 1,
        `expected exactly 1 CLAIMED, got ${claimed.length} (spent ${spent.length}, threw ${threw.length})`
      );
      // A throw is a SAFE outcome: claimAuthority turns it into UNKNOWN and sends
      // nothing. What it must never be is a second claim.
      assert.equal(claimed.length + spent.length + threw.length, workers);
    });
  }

  await test("16 concurrent claims of one execution_id produce exactly 1 CLAIMED", async () => {
    const executionId = unique("exec-race");
    const attempts = Array.from({ length: 16 }, () => record({ execution_id: executionId }));
    const results = await Promise.all(
      attempts.map((claim) => backend.claim(claim).catch(() => ({ status: "THREW" })))
    );
    assert.equal(results.filter((result) => result.status === "CLAIMED").length, 1);
  });

  console.log("\n── the executor login cannot roll the store back ──");

  await denied("cannot DELETE a claim", "DELETE FROM mnde_claim.claims");
  await denied("cannot UPDATE a claim", "UPDATE mnde_claim.claims SET record = '{}'::jsonb");
  await denied("cannot TRUNCATE the claims table", "TRUNCATE mnde_claim.claims");
  await denied(
    "cannot INSERT directly, bypassing first_claim",
    "INSERT INTO mnde_claim.claims(namespace,execution_id,grant_id,record) VALUES ('x','y','z','{}'::jsonb)"
  );
  await denied("cannot SELECT the claims table directly", "SELECT * FROM mnde_claim.claims");
  await denied("cannot DROP the schema", "DROP SCHEMA mnde_claim CASCADE");
  await denied("cannot rebind its own namespace", "UPDATE mnde_claim.executor_namespaces SET namespace = 'other'");
  await denied(
    "cannot grant itself a second namespace",
    "INSERT INTO mnde_claim.executor_namespaces VALUES (current_user, 'other')"
  );

  await test("the server refuses a foreign namespace even when asked directly", async () => {
    await assert.rejects(
      () => asExecutor("SELECT * FROM mnde_claim.first_claim($1::jsonb)", [JSON.stringify(record({ namespace: "not-my-namespace" }))]),
      (error) => { assert.match(error.message, /wrong namespace/); return true; }
    );
  });

  await test("the adapter refuses a foreign namespace before it reaches the server", async () => {
    await assert.rejects(() => backend.claim(record({ namespace: "not-my-namespace" })), /ERR_CLAIM_IDENTITY/);
  });

  await test("the adapter refuses a record with extra or missing fields", async () => {
    const extra = record();
    extra.unexpected = "x";
    await assert.rejects(() => backend.claim(extra), /ERR_CLAIM_IDENTITY/);
    const missing = record();
    delete missing.subject;
    await assert.rejects(() => backend.claim(missing), /ERR_CLAIM_IDENTITY/);
  });

  console.log("\n── durability ──");

  await test("a claim survives an immediate server restart", async () => {
    if (!RESTART_COMMAND) {
      skip("set MNDE_CLAIM_PROOF_RESTART_COMMAND to a command that restarts the server with -m immediate");
    }
    // An acknowledgement that does not survive a crash is not a claim. `-m
    // immediate` skips the shutdown checkpoint, so recovery has to replay WAL.
    // This is weaker than real power loss — it does not exercise a lying disk
    // cache — and should not be described as more than it is.
    const claim = record();
    assert.equal((await backend.claim(claim)).status, "CLAIMED");
    execSync(RESTART_COMMAND, { stdio: "ignore" });
    await new Promise((done) => setTimeout(done, 3000));
    const after = await backend.claim(claim);
    assert.equal(after.status, "ALREADY_SPENT", "the claim did not survive an immediate restart");
  });

  const total = passed + failed;
  console.log(`\n${failed === 0 ? "PASS" : "FAIL"} F-001 claim store deployment proof (${passed}/${total}${skipped ? `, ${skipped} skipped` : ""})`);
  process.exit(failed === 0 ? 0 : 1);
}

await main();
