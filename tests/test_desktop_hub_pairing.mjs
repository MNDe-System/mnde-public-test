import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { DesktopClientIdentity, windowsDpapiStore } from "../src/desktop/windows-client-identity.mjs";
import { HubTrustStore } from "../src/desktop/hub-trust-store.mjs";
import { HubPairingClient } from "../src/desktop/hub-pairing-client.mjs";
import { openHubPairing } from "../src/hub/pairing.mjs";

const folders = [];
afterEach(() => { for (const folder of folders.splice(0)) rmSync(folder, { recursive: true, force: true }); });
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
function folder() { const value = mkdtempSync(join(tmpdir(), "mnde-desktop-pair-")); folders.push(value); return value; }
const fakeStore = Object.freeze({ protect: async value => Buffer.from(value.toString("base64")),
  unprotect: async value => Buffer.from(value.toString(), "base64") });

test("Windows client identity persists with encrypted private material", async () => {
  if (process.platform !== "win32") return;
  const dir = folder(), path = join(dir, "client-identity.json");
  const identity = new DesktopClientIdentity({ path, secureStore: windowsDpapiStore, name: "CODY-PC" });
  const first = await identity.publicIdentity();
  assert.match(first.clientId, /^pc-[0-9a-f]{16}$/);
  assert.equal(first.clientName, "CODY-PC");
  assert.equal(JSON.parse(readFileSync(path)).publicKey, first.publicKey);
  const encrypted = readFileSync(join(dir, "client-private-key.dpapi"));
  assert.equal(encrypted.includes(Buffer.from("PRIVATE KEY")), false);
  assert.deepEqual(await new DesktopClientIdentity({ path, secureStore: windowsDpapiStore }).publicIdentity(), first);
});

test("partial identity fails closed without generating a replacement key", async () => {
  const dir = folder(), path = join(dir, "client-identity.json");
  const identity = new DesktopClientIdentity({ path, secureStore: fakeStore, name: "PC" });
  const first = await identity.publicIdentity();
  rmSync(join(dir, "client-private-key.dpapi"));
  await assert.rejects(new DesktopClientIdentity({ path, secureStore: fakeStore }).publicIdentity(), /ERR_CLIENT_IDENTITY_PARTIAL/);
  assert.equal(JSON.parse(readFileSync(path)).clientId, first.clientId);
});

test("desktop stores two Hub relationships separately and never treats discovery as trust", async () => {
  const dir = folder(), trust = new HubTrustStore(join(dir, "paired-hubs.json"));
  const candidate = { name: "Hub A", hubId: "hub-alpha", ip: "192.168.1.2", port: 8790, status: "UNVERIFIED" };
  const discovery = { snapshot: () => ({ status: "UNVERIFIED", candidates: [candidate] }) };
  const client = new HubPairingClient({ discovery, trust, identity: new DesktopClientIdentity({ path: join(dir, "identity.json"), secureStore: fakeStore }) });
  assert.equal(client.snapshot().status, "UNPAIRED");
  assert.equal(client.snapshot().connectedHubId, null);
  const at = new Date().toISOString();
  trust.save({ hubId: "hub-alpha", lastKnownIp: "192.168.1.2", port: 8790, pairedAt: at });
  trust.save({ hubId: "hub-beta", lastKnownIp: "192.168.1.3", port: 8790, pairedAt: at });
  assert.deepEqual(trust.list().map(h => h.hubId), ["hub-alpha", "hub-beta"]);
  assert.equal(client.snapshot().connectedHubId, null);
});

test("a Hub with a pinned signing key cannot reconnect using plain identity", async () => {
  const dir = folder(), trust = new HubTrustStore(join(dir, "paired-hubs.json"));
  trust.save({ hubId: "hub-alpha", lastKnownIp: "192.168.1.2", port: 8790,
    pairedAt: new Date().toISOString(), identityPublicKey: "A".repeat(43) });
  let authCalls = 0;
  const fetchImpl = async target => {
    if (new URL(target).pathname === "/v1/auth/challenge") authCalls++;
    return new Response(JSON.stringify({ product: "MNDe Hub", protocolVersion: 1,
      hubId: "hub-alpha", status: "ready" }));
  };
  const client = new HubPairingClient({ discovery: { snapshot: () => ({ status: "OFFLINE", candidates: [] }) },
    trust, fetchImpl, identity: new DesktopClientIdentity({ path: join(dir, "identity.json"), secureStore: fakeStore }) });
  client.running = true;
  await client.tick();
  assert.equal(client.snapshot().connectedHubId, null);
  assert.equal(authCalls, 0);
});

test("desktop waits for physical approval, authenticates, and reconnects at a new IP", async () => {
  const dir = folder(), identity = new DesktopClientIdentity({ path: join(dir, "identity.json"), secureStore: fakeStore, name: "PC" });
  const trust = new HubTrustStore(join(dir, "paired-hubs.json"));
  let ip = "192.168.1.2";
  const candidate = () => ({ name: "Hub A", hubId: "hub-alpha", ip, port: 8790, status: "UNVERIFIED" });
  const discovery = { snapshot: () => ({ status: "UNVERIFIED", candidates: [candidate()] }) };
  const data = { version: 1, clients: [] };
  const storage = { readPairingClients: () => data,
    savePairingClients: value => { data.clients = value.clients; } };
  const hub = openHubPairing({ hubId: "hub-alpha", storage });
  const requests = [], events = [];
  const fetchImpl = async (target, options) => {
    const parsed = new URL(target), body = options.body ? JSON.parse(options.body) : undefined;
    requests.push({ target, body });
    let result;
    if (parsed.pathname === "/v1/pairing/requests" && options.method === "POST") result = hub.createRequest(body);
    else if (parsed.pathname.startsWith("/v1/pairing/requests/")) result = hub.status(parsed.pathname.split("/").at(-1));
    else if (parsed.pathname === "/v1/auth/challenge") result = hub.createChallenge(body);
    else if (parsed.pathname === "/v1/auth/verify") result = await hub.verify(body);
    else if (parsed.pathname === "/v1/auth/session") {
      const session = hub.session(options.headers.authorization?.slice(7));
      result = session ? { code: 200, value: { ok: true, ...session } } : { code: 401 };
    } else if (parsed.pathname === "/v1/hub/identity") result = { code: 200,
      value: { product: "MNDe Hub", protocolVersion: 1, hubId: "hub-alpha", status: "ready" } };
    else result = { code: 404 };
    return new Response(JSON.stringify(result.value ?? { ok: false }), { status: result.code });
  };
  const client = new HubPairingClient({ discovery, identity, trust, fetchImpl, pollMs: 5,
    monitorMs: 100000, log: (event, fields) => events.push({ event, ...fields }) });
  client.start();
  try {
    const started = await client.startPairing("hub-alpha", ip);
    assert.equal(client.snapshot().status, "WAITING_FOR_APPROVAL");
    assert.equal(client.snapshot().clientId, (await identity.publicIdentity()).clientId);
    assert.equal(trust.list().length, 0);
    assert.equal(hub.resolvePhysical(started.pairingRequestId, "APPROVED"), true);
    for (let i = 0; i < 30 && client.snapshot().status !== "PAIRED"; i++) await wait(10);
    assert.equal(client.snapshot().status, "PAIRED");
    for (const event of ["hub.pairing.post_started", "hub.pairing.post_http", "hub.pairing.request_created",
      "hub.pairing.polling_started", "hub.pairing.status", "hub.pairing.approved",
      "hub.auth.challenge_created", "hub.auth.verify_result"]) assert(events.some(e => e.event === event));
    assert.equal(events.find(e => e.event === "hub.pairing.post_http").httpStatus, 201);
    assert.equal(events.some(e => JSON.stringify(e).includes("sessionToken") || JSON.stringify(e).includes("signature")), false);
    assert.equal(trust.get("hub-alpha").lastKnownIp, ip);
    assert.equal(requests.some(r => r.body?.privateKey), false);
    client.connected = null;
    ip = "192.168.1.22";
    await client.tick();
    assert.equal(client.snapshot().connectedHubId, "hub-alpha");
    assert.equal(trust.get("hub-alpha").lastKnownIp, ip);
    assert.equal(hub.revoke((await identity.publicIdentity()).clientId), true);
    client.connected.checkedAtMs -= 11_000;
    await client.tick();
    assert.equal(client.snapshot().connectedHubId, null);
  } finally { client.stop(); }
});

test("pairing POST failure retains exact Hub status and reason without polling", async () => {
  for (const status of [200, 400]) {
    const dir = folder(), events = [], requests = [];
    const candidate = { hubId: "hub-alpha", ip: "192.168.1.2", port: 8790, status: "UNVERIFIED" };
    const fetchImpl = async (target, options) => {
      const path = new URL(target).pathname;
      requests.push({ path, method: options.method });
      return path === "/v1/hub/identity"
        ? new Response(JSON.stringify({ product: "MNDe Hub", protocolVersion: 1, hubId: "hub-alpha", status: "ready" }))
        : new Response(JSON.stringify(status === 400 ? { ok: false, reason_code: "ERR_PAIRING_INPUT" }
          : { ok: true, pairingRequestId: "pair-AAAAAAAAAAAAAAAAAAAAAA", status: "PENDING", expiresAt: new Date(Date.now() + 180000).toISOString() }),
        { status });
    };
    const client = new HubPairingClient({ discovery: { snapshot: () => ({ candidates: [candidate] }) },
      identity: new DesktopClientIdentity({ path: join(dir, "identity.json"), secureStore: fakeStore }),
      trust: new HubTrustStore(join(dir, "trust.json")), fetchImpl,
      log: (event, fields) => events.push({ event, ...fields }) });
    await assert.rejects(client.startPairing("hub-alpha", candidate.ip));
    assert.equal(client.snapshot().status, "PAIRING_FAILED");
    assert.equal(client.snapshot().hubHttpStatus, status);
    assert.equal(client.snapshot().reasonCode, status === 400 ? "ERR_PAIRING_INPUT" : "ERR_HUB_RESPONSE");
    assert.equal(requests.filter(r => r.path === "/v1/pairing/requests" && r.method === "POST").length, 1);
    assert.equal(requests.some(r => r.path.startsWith("/v1/pairing/requests/") && r.method === "GET"), false);
    assert.equal(events.find(e => e.event === "hub.pairing.post_http").httpStatus, status);
  }
});

test("waiting appears only after HTTP 201 PENDING", async () => {
  const dir = folder(), candidate = { hubId: "hub-alpha", ip: "192.168.1.2", port: 8790, status: "UNVERIFIED" };
  let releasePost;
  const postResponse = new Promise(resolve => { releasePost = resolve; });
  const fetchImpl = async target => new URL(target).pathname === "/v1/hub/identity"
    ? new Response(JSON.stringify({ product: "MNDe Hub", protocolVersion: 1, hubId: "hub-alpha", status: "ready" }))
    : postResponse;
  const client = new HubPairingClient({ discovery: { snapshot: () => ({ candidates: [candidate] }) },
    identity: new DesktopClientIdentity({ path: join(dir, "identity.json"), secureStore: fakeStore }),
    trust: new HubTrustStore(join(dir, "trust.json")), fetchImpl });
  const starting = client.startPairing("hub-alpha", candidate.ip);
  await wait(20);
  assert.equal(client.snapshot().status, "PAIRING");
  releasePost(new Response(JSON.stringify({ ok: true, pairingRequestId: "pair-AAAAAAAAAAAAAAAAAAAAAA",
    status: "PENDING", expiresAt: new Date(Date.now() + 180000).toISOString() }), { status: 201 }));
  await starting;
  assert.equal(client.snapshot().status, "WAITING_FOR_APPROVAL");
});

test("pairing poll surfaces a Hub reason code and stops", async () => {
  const dir = folder(), candidate = { hubId: "hub-alpha", ip: "192.168.1.2", port: 8790, status: "UNVERIFIED" };
  let polls = 0;
  const fetchImpl = async (target, options) => {
    const path = new URL(target).pathname;
    if (path === "/v1/hub/identity") return new Response(JSON.stringify({ product: "MNDe Hub",
      protocolVersion: 1, hubId: "hub-alpha", status: "ready" }));
    if (path === "/v1/pairing/requests" && options.method === "POST") return new Response(JSON.stringify({ ok: true,
      pairingRequestId: "pair-AAAAAAAAAAAAAAAAAAAAAA", status: "PENDING",
      expiresAt: new Date(Date.now() + 180000).toISOString() }), { status: 201 });
    polls++;
    return new Response(JSON.stringify({ ok: false, reason_code: "ERR_PAIRING_NOT_FOUND" }), { status: 404 });
  };
  const client = new HubPairingClient({ discovery: { snapshot: () => ({ candidates: [candidate] }) },
    identity: new DesktopClientIdentity({ path: join(dir, "identity.json"), secureStore: fakeStore }),
    trust: new HubTrustStore(join(dir, "trust.json")), fetchImpl, pollMs: 5, monitorMs: 100000 });
  client.start();
  try {
    await client.startPairing("hub-alpha", candidate.ip);
    for (let i = 0; i < 20 && client.snapshot().status !== "PAIRING_FAILED"; i++) await wait(10);
    assert.equal(client.snapshot().status, "PAIRING_FAILED");
    assert.equal(client.snapshot().reasonCode, "ERR_PAIRING_NOT_FOUND");
    assert.equal(client.snapshot().hubHttpStatus, 404);
    await wait(20);
    assert.equal(polls, 1);
  } finally { client.stop(); }
});
