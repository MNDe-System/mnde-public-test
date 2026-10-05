import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { generateKeyPair, sign } from "../src/crypto/provider.mjs";
import { openHubState } from "../src/hub/state.mjs";
import { openHubPairing } from "../src/hub/pairing.mjs";
import { challengeMessage, rawPublicKey } from "../src/hub/pairing-protocol.mjs";

const folders = [];
afterEach(() => { for (const folder of folders.splice(0)) rmSync(folder, { recursive: true, force: true }); });
function setup(hubId = "hub-test-one") {
  const dir = mkdtempSync(join(tmpdir(), "mnde-pairing-")); folders.push(dir);
  let clock = Date.parse("2026-10-04T12:00:00.000Z");
  const storage = openHubState(dir);
  const pairing = openHubPairing({ hubId, storage, now: () => clock });
  return { dir, storage, pairing, advance: ms => { clock += ms; }, now: () => clock };
}
function pc(id = "a".repeat(16)) {
  const keys = generateKeyPair();
  return { keys, input: { clientId: `pc-${id}`, clientName: "CODY-PC", publicKey: rawPublicKey(keys.publicPem), protocolVersion: 1 } };
}
async function authenticate(pairing, person) {
  const challenge = pairing.createChallenge({ clientId: person.input.clientId });
  assert.equal(challenge.code, 200);
  const signature = Buffer.from(await sign(challengeMessage({ ...challenge.value, clientId: person.input.clientId }), person.keys.privatePem), "hex").toString("base64url");
  return { challenge, signature, verified: await pairing.verify({ clientId: person.input.clientId,
    challengeId: challenge.value.challengeId, signature }) };
}

test("a physical decision alone persists a client; polling cannot approve", () => {
  const f = setup(), person = pc();
  const created = f.pairing.createRequest(person.input, "lan-a");
  assert.equal(created.code, 201);
  assert.equal(f.pairing.status(created.value.pairingRequestId).value.status, "PENDING");
  assert.equal(f.pairing.pendingForPhysical()[0].actionType, "pairing.client");
  assert.equal(f.pairing.pendingForPhysical()[0].clientName, "CODY-PC");
  assert.equal(f.pairing.resolvePhysical(created.value.pairingRequestId, "APPROVED"), true);
  assert.equal(f.pairing.resolvePhysical(created.value.pairingRequestId, "REFUSED"), false);
  assert.equal(f.pairing.status(created.value.pairingRequestId).value.status, "APPROVED");
  assert.equal(f.pairing.listClients().length, 1);
  assert.equal(JSON.parse(readFileSync(join(f.dir, "paired-clients.json"))).clients[0].hubId, "hub-test-one");
  assert.equal(openHubPairing({ hubId: "hub-test-one", storage: openHubState(f.dir) }).listClients().length, 1);
});

test("invalid request fields, duplicates, pending limit and rate limits fail closed", () => {
  const f = setup(), first = pc();
  for (const invalid of [
    { ...first.input, clientId: "bad" }, { ...first.input, publicKey: "bad" },
    { ...first.input, protocolVersion: 2 }, { ...first.input, clientName: "bad\nname" },
    { ...first.input, extra: 1 }
  ]) assert.equal(f.pairing.createRequest(invalid).code, 400);
  assert.equal(f.pairing.createRequest(first.input, "a").code, 201);
  assert.equal(f.pairing.createRequest(first.input, "a").code, 409);
  for (let i = 1; i < 5; i++) assert.equal(f.pairing.createRequest(pc(String(i).repeat(16)).input, `source-${i}`).code, 201);
  assert.equal(f.pairing.createRequest(pc("f".repeat(16)).input, "other").error, "ERR_PAIRING_PENDING_LIMIT");
  f.advance(180_001);
  assert.equal(f.pairing.pendingForPhysical().length, 0);
  assert.equal(f.pairing.createRequest(first.input, "new-source").code, 201);
});

test("refusal, expiration and wrong physical request never trust the client", () => {
  const f = setup(), person = pc();
  const first = f.pairing.createRequest(person.input).value.pairingRequestId;
  assert.equal(f.pairing.resolvePhysical("pair-AAAAAAAAAAAAAAAAAAAAAA", "APPROVED"), false);
  assert.equal(f.pairing.resolvePhysical(first, "REFUSED"), true);
  assert.equal(f.pairing.status(first).value.status, "REFUSED");
  assert.equal(f.pairing.listClients().length, 0);
  const second = f.pairing.createRequest(person.input).value.pairingRequestId;
  f.advance(180_001);
  assert.equal(f.pairing.status(second).value.status, "EXPIRED");
  assert.equal(f.pairing.resolvePhysical(second, "APPROVED"), false);
  assert.equal(f.pairing.listClients().length, 0);
});

test("signed challenge binds Hub and client, expires, and is single use", async () => {
  const f = setup(), person = pc();
  const id = f.pairing.createRequest(person.input).value.pairingRequestId;
  f.pairing.resolvePhysical(id, "APPROVED");
  let auth = await authenticate(f.pairing, person);
  assert.equal(auth.verified.code, 200);
  assert.match(auth.verified.value.sessionToken, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(f.pairing.status(id).value.status, "COMPLETED");
  assert.equal(f.pairing.session(auth.verified.value.sessionToken).hubId, "hub-test-one");
  assert.equal((await f.pairing.verify({ clientId: person.input.clientId,
    challengeId: auth.challenge.value.challengeId, signature: auth.signature })).code, 401);
  const wrong = pc("b".repeat(16));
  const challenge = f.pairing.createChallenge({ clientId: person.input.clientId }).value;
  const badSignature = Buffer.from(await sign(challengeMessage({ ...challenge, clientId: person.input.clientId }), wrong.keys.privatePem), "hex").toString("base64url");
  assert.equal((await f.pairing.verify({ clientId: person.input.clientId, challengeId: challenge.challengeId, signature: badSignature })).code, 401);
  assert.equal((await f.pairing.verify({ clientId: person.input.clientId, challengeId: challenge.challengeId, signature: auth.signature })).code, 401);
  const expiring = f.pairing.createChallenge({ clientId: person.input.clientId }).value;
  f.advance(60_001);
  assert.equal((await f.pairing.verify({ clientId: person.input.clientId, challengeId: expiring.challengeId, signature: auth.signature })).code, 401);
  auth = await authenticate(f.pairing, person);
  f.advance(300_001);
  assert.equal(f.pairing.session(auth.verified.value.sessionToken), null);
});

test("revocation invalidates challenges and sessions, and multiple clients are distinct", async () => {
  const f = setup(), a = pc(), b = pc("b".repeat(16));
  for (const p of [a, b]) f.pairing.resolvePhysical(f.pairing.createRequest(p.input).value.pairingRequestId, "APPROVED");
  const auth = await authenticate(f.pairing, a);
  const pendingChallenge = f.pairing.createChallenge({ clientId: a.input.clientId }).value;
  assert.equal(f.pairing.revoke(a.input.clientId), true);
  assert.equal(f.pairing.session(auth.verified.value.sessionToken), null);
  assert.equal(f.pairing.createChallenge({ clientId: a.input.clientId }).code, 401);
  assert.equal((await f.pairing.verify({ clientId: a.input.clientId, challengeId: pendingChallenge.challengeId, signature: auth.signature })).code, 401);
  assert.equal((await authenticate(f.pairing, b)).verified.code, 200);
  assert.equal(f.pairing.listClients().find(c => c.clientId === a.input.clientId).revoked, true);
});

test("Hub B cannot load Hub A client records", () => {
  const f = setup(), person = pc();
  f.pairing.resolvePhysical(f.pairing.createRequest(person.input).value.pairingRequestId, "APPROVED");
  assert.throws(() => openHubPairing({ hubId: "hub-test-two", storage: f.storage }), /ERR_PAIRING_STORE/);
});

test("a signature for Hub A cannot complete Hub B's challenge", async () => {
  const a = setup("hub-test-one"), b = setup("hub-test-two"), person = pc();
  for (const f of [a, b]) f.pairing.resolvePhysical(f.pairing.createRequest(person.input).value.pairingRequestId, "APPROVED");
  const challengeA = a.pairing.createChallenge({ clientId: person.input.clientId }).value;
  const challengeB = b.pairing.createChallenge({ clientId: person.input.clientId }).value;
  const signature = Buffer.from(await sign(challengeMessage({ ...challengeA, clientId: person.input.clientId }), person.keys.privatePem), "hex").toString("base64url");
  assert.equal((await b.pairing.verify({ clientId: person.input.clientId,
    challengeId: challengeB.challengeId, signature })).code, 401);
});

test("challenge creation is rate limited for a paired client", () => {
  const f = setup(), person = pc();
  f.pairing.resolvePhysical(f.pairing.createRequest(person.input).value.pairingRequestId, "APPROVED");
  for (let i = 0; i < 15; i++) assert.equal(f.pairing.createChallenge({ clientId: person.input.clientId }).code, 200);
  assert.equal(f.pairing.createChallenge({ clientId: person.input.clientId }).code, 429);
});
