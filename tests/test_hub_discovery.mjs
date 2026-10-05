import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import { HubDiscoveryService, normalizeMdnsService, validateIdentity,
  verifyHubIdentity, loadPairing, savePairing, privateIp } from "../src/desktop/hub-discovery.mjs";

const folders = [];
const services = [];
afterEach(() => {
  for (const service of services.splice(0)) service.stopDiscovery();
  for (const folder of folders.splice(0)) rmSync(folder, { recursive: true, force: true });
});
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const advert = (ip = "192.168.1.25", name = "Kitchen Hub") => ({
  name, host: "mnde-hub.local", type: "mnde-hub", protocol: "tcp",
  fqdn: `${name}._mnde-hub._tcp.local`, port: 8790, addresses: [ip], txt: {}
});
const identity = (hubId = "hub-kitchen") => ({
  product: "MNDe Hub", protocolVersion: 1, hubId, version: "1.0.0", status: "ready"
});
const pairing = (ip = "192.168.1.25") => ({
  hubId: "hub-kitchen", lastKnownHost: "mnde-hub.local", lastKnownIp: ip,
  port: 8790, protocolVersion: 1, lastSuccessfulConnection: "2026-10-01T00:00:00.000Z"
});

test("Tailscale IPv4 addresses are eligible Hub endpoints", () => {
  assert.equal(privateIp("100.76.54.120"), true);
  assert.equal(privateIp("100.64.0.1"), true);
  assert.equal(privateIp("100.127.255.254"), true);
  assert.equal(privateIp("100.63.255.255"), false);
  assert.equal(privateIp("100.128.0.1"), false);
});

function fixture({ health = { ok: true }, id = identity(), proof = false,
  routes = {}, saved = null, discoveryWindowMs = 20, manualIp = null } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "mnde-hub-discovery-")); folders.push(dir);
  const path = join(dir, "paired.json");
  if (saved) savePairing(path, saved);
  const browser = new EventEmitter(); let stopped = false, destroyed = false, updates = 0;
  browser.stop = () => { stopped = true; };
  browser.update = () => { updates++; };
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    const ip = new URL(url).hostname;
    const pathname = new URL(url).pathname;
    const override = routes[`${ip}${pathname}`] ?? routes[pathname];
    if (override instanceof Error) throw override;
    if (typeof override === "function") return override(options, url);
    const value = override === undefined ? (pathname === "/healthz" ? health : id) : override;
    return value instanceof Response ? value : new Response(JSON.stringify(value), {
      status: value === null ? 404 : 200,
      headers: { "content-type": "application/json" }
    });
  };
  const service = new HubDiscoveryService({ fetchImpl, pairingFile: path,
    bonjourFactory: () => ({ find: () => browser, destroy: () => { destroyed = true; } }),
    proofVerifier: async () => proof, probeTimeoutMs: 25, monitorMs: 100000,
    discoveryWindowMs, manualIp });
  services.push(service);
  return { service, browser, calls, path, state: () => ({ stopped, destroyed, updates }) };
}

test("configured Tailscale IP is probed without multicast discovery", async () => {
  const f = fixture({ manualIp: "100.76.54.120" });
  f.service.startDiscovery();
  await sleep(20);
  assert.equal(f.service.snapshot().candidates[0]?.ip, "100.76.54.120");
  assert.equal(f.service.snapshot().candidates[0]?.method, "manual");
  assert(f.calls.some(c => c.url.startsWith("http://100.76.54.120:8790/healthz")));
});

test("mDNS candidate found stays unverified without identity proof", async () => {
  const f = fixture(), events = []; f.service.log = event => events.push(event);
  f.service.startDiscovery(); f.browser.emit("up", advert());
  await sleep(20);
  assert.equal(f.service.snapshot().status, "UNVERIFIED");
  assert.equal(f.service.snapshot().candidates[0].hubId, "hub-kitchen");
  assert.equal(f.service.snapshot().connectedHubId, null);
  assert(f.calls.some(c => new URL(c.url).pathname === "/v1/hub/identity"));
  for (const event of ["hub.discovery.mdns_discovered", "hub.discovery.health_succeeded",
    "hub.discovery.identity_received"]) assert(events.includes(event));
});

test("no Hub found becomes offline without blocking startup", async () => {
  const f = fixture({ discoveryWindowMs: 5 }); f.service.startDiscovery();
  assert.equal(f.service.snapshot().message, "Searching for MNDe Hub…");
  await sleep(15);
  assert.equal(f.service.snapshot().status, "OFFLINE");
});

test("malformed advertisements, public addresses and bad TXT are ignored", () => {
  assert.equal(normalizeMdnsService({ ...advert(), port: 8787 }), null);
  assert.equal(normalizeMdnsService({ ...advert(), addresses: ["8.8.8.8"] }), null);
  assert.equal(normalizeMdnsService({ ...advert(), fqdn: "Other._http._tcp.local" }), null);
  assert.equal(normalizeMdnsService({ ...advert(), txt: { protocol: "2" } }), null);
  assert.equal(normalizeMdnsService({ ...advert(), txt: { product: "Other" } }), null);
  assert.equal(normalizeMdnsService(advert()).addresses[0], "192.168.1.25");
});

test("health timeout cannot leave a candidate connected", async () => {
  const f = fixture({ routes: { "/healthz": options => new Promise((_, reject) =>
    options.signal.addEventListener("abort", () => reject(new Error("timeout")), { once: true })) } });
  f.service.startDiscovery(); f.browser.emit("up", advert());
  await sleep(50);
  assert.equal(f.service.snapshot().candidates.length, 0);
});

test("wrong service on saved address is discarded", async () => {
  const f = fixture({ saved: pairing(), id: null }); f.service.startDiscovery();
  await sleep(20);
  assert.equal(f.service.snapshot().connectedHubId, null);
  assert.equal(f.service.snapshot().candidates.length, 0);
});

test("valid identity schema is accepted; malformed and unsupported versions are refused", () => {
  assert.deepEqual(validateIdentity(identity()), identity());
  assert.deepEqual(validateIdentity({ product: "MNDe Hub", protocolVersion: 1,
    hubId: "hub-kitchen", status: "ready" }), { ...identity(), version: null });
  assert.equal(validateIdentity({ ...identity(), hubId: "bad" }), null);
  assert.equal(validateIdentity({ ...identity(), protocolVersion: 2 }), null);
  assert.equal(validateIdentity({ ...identity(), product: "Other" }), null);
});

test("signed challenge proof enables explicit pairing and rejects a different key", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const rawKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const publicKeyText = rawKey.toString("base64url");
  const signedResponse = challenge => {
    const fields = { challenge, ...identity() };
    return { ...identity(), challenge, publicKey: publicKeyText,
      signature: sign(null, Buffer.from(JSON.stringify(fields)), privateKey).toString("base64url") };
  };
  assert.equal(await verifyHubIdentity(signedResponse("abc"), "different"), null);
  const f = fixture({ routes: { "/v1/hub/identity": (_options, url) =>
    new Response(JSON.stringify(signedResponse(new URL(url).searchParams.get("challenge")))) } });
  // Exercise the production verifier instead of the fixture's injected boolean.
  f.service.proofVerifier = verifyHubIdentity;
  f.service.startDiscovery(); f.browser.emit("up", advert()); await sleep(20);
  const candidate = f.service.snapshot().candidates[0];
  assert.equal(candidate.status, "PAIRING_REQUIRED");
  assert.equal(f.service.pairHub("hub-kitchen", "wrong"), false);
  assert.equal(f.service.pairHub("hub-kitchen", candidate.fingerprint), true);
  assert.equal(f.service.snapshot().status, "CONNECTED");
  assert.equal(loadPairing(f.path).identityPublicKey, publicKeyText);
  f.service.disconnectHub(); await f.service.trySavedHub();
  assert.equal(f.service.snapshot().status, "CONNECTED");
});

test("malformed identity response is an error, not trusted", async () => {
  const f = fixture({ id: { product: "MNDe Hub", protocolVersion: 1 } });
  f.service.startDiscovery(); f.browser.emit("up", advert()); await sleep(20);
  assert.equal(f.service.snapshot().status, "ERROR");
  assert.equal(f.service.snapshot().connectedHubId, null);
});

test("invalid identity JSON is an error, not trusted", async () => {
  const f = fixture({ routes: { "/v1/hub/identity": new Response("{broken", { status: 200 }) } });
  f.service.startDiscovery(); f.browser.emit("up", advert()); await sleep(20);
  assert.equal(f.service.snapshot().status, "ERROR");
});

test("unsupported protocol response is an error", async () => {
  const f = fixture({ id: { ...identity(), protocolVersion: 2 } });
  f.service.startDiscovery(); f.browser.emit("up", advert()); await sleep(20);
  assert.equal(f.service.snapshot().candidates[0].status, "ERROR");
});

test("missing identity endpoint remains unverified", async () => {
  const f = fixture({ id: null });
  f.service.startDiscovery(); f.browser.emit("up", advert()); await sleep(20);
  assert.equal(f.service.snapshot().status, "UNVERIFIED");
  assert.equal(f.service.snapshot().candidates[0].hubId, null);
});

test("saved trusted Hub reconnects after proof verification", async () => {
  const f = fixture({ saved: pairing(), proof: true }); f.service.startDiscovery(); await sleep(20);
  assert.equal(f.service.snapshot().status, "CONNECTED");
  assert.equal(f.service.snapshot().connectedHubId, "hub-kitchen");
  assert.equal(loadPairing(f.path).lastKnownIp, "192.168.1.25");
});

test("same Hub at new IP updates transport address after proof", async () => {
  const f = fixture({ saved: pairing("192.168.1.99"), proof: true,
    routes: { "192.168.1.99/healthz": new Error("old address offline") } });
  f.service.startDiscovery(); f.browser.emit("up", advert("192.168.1.25")); await sleep(20);
  assert.equal(f.service.snapshot().connectedHubId, "hub-kitchen");
  assert.equal(loadPairing(f.path).lastKnownIp, "192.168.1.25");
});

test("different Hub at saved IP cannot replace the pairing", async () => {
  const f = fixture({ saved: pairing(), proof: true, id: identity("hub-stranger") });
  f.service.startDiscovery(); await sleep(20);
  assert.equal(f.service.snapshot().connectedHubId, null);
  assert.equal(loadPairing(f.path).hubId, "hub-kitchen");
});

test("multiple unpaired Hubs are exposed without arbitrary selection", async () => {
  const f = fixture({ id: null }); f.service.startDiscovery();
  f.browser.emit("up", advert("192.168.1.25", "Kitchen Hub"));
  f.browser.emit("up", advert("192.168.1.26", "Office Hub")); await sleep(20);
  assert.equal(f.service.snapshot().candidates.length, 2);
  assert.equal(f.service.snapshot().message, "Multiple MNDe Hubs found");
  assert.equal(f.service.snapshot().connectedHubId, null);
});

test("connected Hub goes offline and comes back online", async () => {
  let online = true;
  const f = fixture({ saved: pairing(), proof: true,
    routes: { "/healthz": () => online ? new Response('{"ok":true}') : Promise.reject(new Error("offline")) } });
  f.service.startDiscovery(); await sleep(20);
  assert.equal(f.service.snapshot().status, "CONNECTED");
  online = false; await f.service.monitorConnection();
  assert.equal(f.service.snapshot().status, "OFFLINE");
  await sleep(5); online = true; await f.service.trySavedHub();
  assert.equal(f.service.snapshot().status, "CONNECTED");
});

test("duplicate mDNS events do not issue simultaneous probes", async () => {
  let resolveHealth;
  const healthPromise = new Promise(resolve => { resolveHealth = resolve; });
  const f = fixture({ routes: { "/healthz": () => healthPromise } });
  f.service.startDiscovery(); f.browser.emit("up", advert()); f.browser.emit("up", advert());
  await sleep(5);
  assert.equal(f.calls.filter(c => c.url.endsWith("/healthz")).length, 1);
  resolveHealth(new Response('{"ok":true}')); await sleep(15);
});

test("stopping discovery closes mDNS and aborts probes", async () => {
  let aborted = false;
  const f = fixture({ routes: { "/healthz": options => new Promise((_, reject) =>
    options.signal.addEventListener("abort", () => { aborted = true; reject(new Error("stopped")); }, { once: true })) } });
  f.service.startDiscovery(); f.browser.emit("up", advert()); await sleep(5);
  f.service.stopDiscovery(); await sleep(5);
  assert.deepEqual({ stopped: f.state().stopped, destroyed: f.state().destroyed, aborted },
    { stopped: true, destroyed: true, aborted: true });
});
