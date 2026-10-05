import { Bonjour } from "bonjour-service";
import { readFileSync, mkdirSync, writeFileSync, renameSync } from "node:fs";
import { isIP } from "node:net";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { randomBytes, sha256, verify } from "../crypto/provider.mjs";

export const HUB_SERVICE = "_mnde-hub._tcp.local";
export const HUB_PORT = 8790;
const ID = /^hub-[a-zA-Z0-9][a-zA-Z0-9_-]{2,127}$/;
const MAX_CANDIDATES = 32;
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");

export function privateIp(value) {
  if (typeof value !== "string" || isIP(value) === 0) return false;
  if (isIP(value) === 6) {
    const first = Number.parseInt(value.split(":")[0] || "0", 16);
    return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80;
  }
  const p = value.split(".").map(Number);
  return p[0] === 10 || (p[0] === 100 && p[1] >= 64 && p[1] <= 127)
    || (p[0] === 172 && p[1] >= 16 && p[1] <= 31)
    || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254);
}

function safeHost(value) {
  return typeof value === "string" && value.length <= 253
    && /^[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.local\.?$/.test(value);
}

function safeText(value, max = 128) {
  return typeof value === "string" && value.length > 0 && value.length <= max && !/[\x00-\x1f\x7f]/.test(value);
}

function txtValue(value) {
  if (Buffer.isBuffer(value)) return value.toString("utf8");
  return value;
}

export function normalizeMdnsService(service) {
  if (!service || service.type !== "mnde-hub" || service.protocol !== "tcp"
    || typeof service.fqdn !== "string"
    || !service.fqdn.toLowerCase().endsWith(`.${HUB_SERVICE}`)
    || !safeText(service.name) || !safeHost(service.host)
    || service.port !== HUB_PORT || !Array.isArray(service.addresses)) return null;
  const txt = service.txt && typeof service.txt === "object" && !Array.isArray(service.txt) ? service.txt : {};
  const protocol = txtValue(txt.protocol), product = txtValue(txt.product), api = txtValue(txt.api);
  if ((protocol !== undefined && protocol !== "1")
    || (product !== undefined && product !== "MNDe-Hub")
    || (api !== undefined && api !== "/v1")) return null;
  const addresses = [...new Set(service.addresses.filter(privateIp))].slice(0, 8);
  if (!addresses.length) return null;
  return { name: service.name, host: service.host, addresses, port: HUB_PORT,
    method: "mdns", txt: { ...(protocol !== undefined ? { protocol } : {}),
      ...(product !== undefined ? { product } : {}), ...(api !== undefined ? { api } : {}) } };
}

export function validateIdentity(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || value.product !== "MNDe Hub" || value.protocolVersion !== 1
    || typeof value.hubId !== "string" || !ID.test(value.hubId)
    || (value.version !== undefined && (typeof value.version !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/.test(value.version)))
    || typeof value.status !== "string" || !/^[a-z][a-z0-9_-]{0,31}$/.test(value.status)) return null;
  return { product: value.product, protocolVersion: 1, hubId: value.hubId,
    version: value.version ?? null, status: value.status };
}

// Proof is deliberately separate from the schema check. The currently deployed
// Pi identity endpoint has a Hub ID but no signed challenge response.
export async function verifyHubIdentity(value, challenge) {
  const identity = validateIdentity(value);
  if (!identity || value.challenge !== challenge
    || typeof value.publicKey !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.publicKey)
    || typeof value.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(value.signature)) return null;
  try {
    const rawKey = Buffer.from(value.publicKey, "base64url");
    const signature = Buffer.from(value.signature, "base64url");
    if (rawKey.length !== 32 || signature.length !== 64
      || rawKey.toString("base64url") !== value.publicKey
      || signature.toString("base64url") !== value.signature) return null;
    const der = Buffer.concat([ED25519_SPKI, rawKey]);
    const pem = `-----BEGIN PUBLIC KEY-----\n${der.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----\n`;
    const message = Buffer.from(JSON.stringify({ challenge, ...identity }), "utf8");
    if (!await verify(message, signature.toString("hex"), pem)) return null;
    return { publicKey: value.publicKey, fingerprint: sha256(rawKey) };
  } catch { return null; }
}

export function pairingPath(env = process.env) {
  return join(env.LOCALAPPDATA || join(homedir(), "AppData", "Local"), "MNDe", "hub-pairing.json");
}

export function loadPairing(path) {
  try {
    const p = JSON.parse(readFileSync(path, "utf8"));
    if (!p || !ID.test(p.hubId) || p.protocolVersion !== 1 || p.port !== HUB_PORT
      || !privateIp(p.lastKnownIp) || (p.lastKnownHost !== null && !safeHost(p.lastKnownHost))
      || typeof p.lastSuccessfulConnection !== "string"
      || !Number.isFinite(Date.parse(p.lastSuccessfulConnection))
      || (p.identityPublicKey != null && !/^[A-Za-z0-9_-]{43}$/.test(p.identityPublicKey))) return null;
    return { hubId: p.hubId, lastKnownHost: p.lastKnownHost, lastKnownIp: p.lastKnownIp,
      port: HUB_PORT, protocolVersion: 1, lastSuccessfulConnection: p.lastSuccessfulConnection,
      identityPublicKey: typeof p.identityPublicKey === "string" && /^[A-Za-z0-9_-]{43}$/.test(p.identityPublicKey)
        ? p.identityPublicKey : null };
  } catch { return null; }
}

export function savePairing(path, pairing) {
  const validated = loadPairingShape(pairing);
  if (!validated) throw new Error("Invalid Hub pairing metadata");
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temp = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  writeFileSync(temp, `${JSON.stringify(validated)}\n`, { flag: "wx", mode: 0o600 });
  renameSync(temp, path);
}

function loadPairingShape(p) {
  if (!p || !ID.test(p.hubId) || p.protocolVersion !== 1 || p.port !== HUB_PORT
    || !privateIp(p.lastKnownIp) || (p.lastKnownHost !== null && !safeHost(p.lastKnownHost))
    || typeof p.lastSuccessfulConnection !== "string"
    || !Number.isFinite(Date.parse(p.lastSuccessfulConnection))
    || (p.identityPublicKey != null && !/^[A-Za-z0-9_-]{43}$/.test(p.identityPublicKey))) return null;
  return { hubId: p.hubId, lastKnownHost: p.lastKnownHost, lastKnownIp: p.lastKnownIp,
    port: HUB_PORT, protocolVersion: 1, lastSuccessfulConnection: p.lastSuccessfulConnection,
    identityPublicKey: p.identityPublicKey ?? null };
}

async function readSmallJson(response) {
  const reader = response.body?.getReader();
  if (!reader) throw new Error("empty response");
  const parts = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 4096) throw new Error("response too large");
      parts.push(value);
    }
  } finally { reader.cancel().catch(() => {}); }
  return JSON.parse(Buffer.concat(parts).toString("utf8"));
}

function endpoint(ip, port, path) {
  return `http://${isIP(ip) === 6 ? `[${ip}]` : ip}:${port}${path}`;
}

export class HubDiscoveryService {
  constructor({ fetchImpl = fetch, bonjourFactory = () => new Bonjour({}, () => {}),
    pairingFile = pairingPath(), proofVerifier = verifyHubIdentity,
    log = () => {}, probeTimeoutMs = 900, monitorMs = 5000, discoveryWindowMs = 5000,
    manualIp = process.env.MNDE_HUB_IP || null } = {}) {
    if (manualIp !== null && !privateIp(manualIp)) throw new Error("MNDE_HUB_IP must be a private or Tailscale IP address");
    this.fetch = fetchImpl; this.bonjourFactory = bonjourFactory; this.pairingFile = pairingFile;
    this.proofVerifier = proofVerifier; this.log = log; this.probeTimeoutMs = probeTimeoutMs;
    this.monitorMs = monitorMs; this.discoveryWindowMs = discoveryWindowMs; this.manualIp = manualIp;
    this.running = false; this.generation = 0; this.candidates = new Map(); this.inflight = new Set();
    this.pairing = null; this.connected = null; this.status = "DISCOVERED"; this.message = "Searching for MNDe Hub…";
    this.everConnected = false;
  }

  snapshot() {
    return { status: this.status, message: this.message,
      pairedHubId: this.pairing?.hubId ?? null,
      connectedHubId: this.connected?.hubId ?? null,
      candidates: [...this.candidates.values()].map(c => ({ ...c })) };
  }

  startDiscovery() {
    if (this.running) return;
    this.running = true; const generation = ++this.generation;
    this.pairing = loadPairing(this.pairingFile);
    this.status = "DISCOVERED"; this.message = "Searching for MNDe Hub…";
    this.log("hub.discovery.started");
    if (this.pairing) void this.trySavedHub(generation);
    if (this.manualIp) void this.tryConfiguredHub(generation);
    this.discoverMdns(generation);
    this.windowTimer = setTimeout(() => {
      if (this.running && generation === this.generation && !this.candidates.size && !this.connected) {
        this.status = "OFFLINE"; this.message = "Hub offline";
      }
    }, this.discoveryWindowMs);
    this.monitorTimer = setInterval(() => void this.monitorConnection(), this.monitorMs);
  }

  stopDiscovery() {
    if (!this.running) return;
    this.running = false; ++this.generation;
    clearTimeout(this.windowTimer); clearInterval(this.monitorTimer);
    try { this.browser?.stop(); } catch { /* best effort */ }
    try { this.bonjour?.destroy(); } catch { /* best effort */ }
    this.browser = null; this.bonjour = null;
    for (const controller of this.inflight) controller.abort();
    this.inflight.clear(); this.connected = null;
    this.log("hub.discovery.stopped");
  }

  discoverMdns(generation = this.generation) {
    try {
      this.bonjour = this.bonjourFactory();
      this.browser = this.bonjour.find({ type: "mnde-hub", protocol: "tcp" });
      this.browser.on("up", service => {
        if (!this.running || generation !== this.generation) return;
        const candidate = normalizeMdnsService(service);
        if (candidate) {
          this.log("hub.discovery.mdns_discovered");
          void this.probeCandidate(candidate, generation);
        }
      });
      this.browser.on("down", service => {
        const candidate = normalizeMdnsService(service);
        if (candidate) this.markDown(candidate);
      });
    } catch {
      try { this.bonjour?.destroy(); } catch { /* best effort */ }
      this.bonjour = null; this.browser = null;
      this.log("hub.discovery.mdns_unavailable");
    }
  }

  async trySavedHub(generation = this.generation) {
    if (!this.pairing) return;
    await this.probeCandidate({ name: this.pairing.lastKnownHost || this.pairing.hubId,
      host: this.pairing.lastKnownHost, addresses: [this.pairing.lastKnownIp],
      port: this.pairing.port, method: "saved", txt: {} }, generation);
  }

  async tryConfiguredHub(generation = this.generation) {
    if (!this.manualIp) return;
    await this.probeCandidate({ name: "Configured MNDe Hub", host: null,
      addresses: [this.manualIp], port: HUB_PORT, method: "manual", txt: {} }, generation);
  }

  async request(ip, path) {
    const controller = new AbortController(); this.inflight.add(controller);
    const timeout = setTimeout(() => controller.abort(), this.probeTimeoutMs);
    try {
      const response = await this.fetch(endpoint(ip, HUB_PORT, path), {
        method: "GET", headers: { accept: "application/json" },
        redirect: "error", cache: "no-store", signal: controller.signal
      });
      let body = null, malformed = false;
      if (response.ok) {
        try { body = await readSmallJson(response); }
        catch { malformed = true; }
      }
      return { status: response.status, ok: response.ok, body, malformed };
    } finally { clearTimeout(timeout); this.inflight.delete(controller); }
  }

  async probeCandidate(candidate, generation = this.generation) {
    if (!this.running || generation !== this.generation || this.candidates.size >= MAX_CANDIDATES) return;
    const ip = candidate.addresses.find(privateIp);
    if (!ip) return;
    const key = `${candidate.method}:${ip}`;
    if (this.pending?.has(key)) return;
    if (this.connected?.ip === ip && candidate.method === this.connected.method) return;
    if ([...this.candidates.values()].some(c => c.ip === ip && c.method === candidate.method
      && Date.now() - Date.parse(c.lastSeen) < 10_000)) return;
    this.pending ||= new Set(); this.pending.add(key);
    try {
      this.log("hub.discovery.candidate");
      const health = await this.request(ip, "/healthz");
      if (!health.ok || health.body?.ok !== true) throw new Error("health");
      this.log("hub.discovery.health_succeeded");
      if (!this.running || generation !== this.generation) return;
      const record = { name: candidate.name, host: candidate.host, ip, port: HUB_PORT,
        method: candidate.method, status: "UNVERIFIED", hubId: null, protocolVersion: null,
        version: null, lastSeen: new Date().toISOString() };
      const challenge = randomBytes(16).toString("base64url");
      let identityResponse;
      try { identityResponse = await this.request(ip, `/v1/hub/identity?challenge=${challenge}`); }
      catch { identityResponse = null; }
      if (identityResponse?.status === 200) {
        this.log("hub.discovery.identity_received");
        const identity = validateIdentity(identityResponse.body);
        if (!identity) {
          record.status = "ERROR";
          this.log("hub.discovery.identity_invalid");
        } else {
          record.hubId = identity.hubId; record.protocolVersion = identity.protocolVersion;
          record.version = identity.version;
          this.log("hub.discovery.identified");
          const proof = await Promise.resolve(this.proofVerifier(identityResponse.body, challenge, record)).catch(() => null);
          if (proof === true || proof?.publicKey) {
            record.identityPublicKey = proof?.publicKey || null;
            record.fingerprint = proof?.fingerprint || null;
            record.status = this.pairing?.hubId === identity.hubId
              && (proof === true || this.pairing.identityPublicKey === proof.publicKey)
              ? "TRUSTED" : "PAIRING_REQUIRED";
          }
        }
      } else if (identityResponse && identityResponse.status !== 404 && identityResponse.status !== 501) {
        this.log("hub.discovery.identity_unavailable");
      }
      if (candidate.method !== "mdns" && !record.hubId) return;
      if (candidate.method === "saved" && record.hubId !== this.pairing?.hubId) {
        this.log("hub.discovery.saved_identity_mismatch"); return;
      }
      if (!this.running || generation !== this.generation) return;
      // One entry per claimed identity, but only a proof-verified identity can
      // replace an existing trusted connection or update its saved address.
      const recordKey = record.status === "TRUSTED" || record.status === "PAIRING_REQUIRED"
        ? record.hubId : key;
      this.candidates.set(recordKey, record);
      if (record.status === "TRUSTED") this.connectHub(record);
      else this.recomputeStatus();
    } catch { this.log("hub.discovery.probe_failed"); }
    finally { this.pending.delete(key); }
  }

  connectHub(record) {
    if (record.status !== "TRUSTED" || !this.pairing || record.hubId !== this.pairing.hubId) return;
    const moved = this.pairing.lastKnownIp !== record.ip;
    const reconnected = this.everConnected;
    this.connected = { ...record, status: "CONNECTED" };
    this.everConnected = true;
    this.candidates.set(record.hubId, this.connected);
    this.status = "CONNECTED"; this.message = "Connected";
    this.pairing = { hubId: record.hubId, lastKnownHost: record.host,
      lastKnownIp: record.ip, port: HUB_PORT, protocolVersion: 1,
      lastSuccessfulConnection: new Date().toISOString(),
      identityPublicKey: record.identityPublicKey || this.pairing.identityPublicKey || null };
    try { savePairing(this.pairingFile, this.pairing); } catch { this.log("hub.discovery.save_failed"); }
    this.log(moved ? "hub.discovery.address_changed" : reconnected ? "hub.discovery.reconnected" : "hub.discovery.connected");
  }

  disconnectHub() {
    if (!this.connected) return;
    for (const [key, candidate] of this.candidates) {
      if (candidate.ip === this.connected.ip && candidate.hubId === this.connected.hubId)
        this.candidates.delete(key);
    }
    this.connected = null; this.status = "OFFLINE"; this.message = "Reconnecting…";
    this.log("hub.discovery.disconnected");
  }

  pairHub(hubId, fingerprint) {
    const record = [...this.candidates.values()].find(c => c.hubId === hubId && c.status === "PAIRING_REQUIRED");
    if (!record?.identityPublicKey || record.fingerprint !== fingerprint) return false;
    const pairing = { hubId, lastKnownHost: record.host, lastKnownIp: record.ip,
      port: HUB_PORT, protocolVersion: 1, lastSuccessfulConnection: new Date().toISOString(),
      identityPublicKey: record.identityPublicKey };
    savePairing(this.pairingFile, pairing);
    this.pairing = pairing;
    record.status = "TRUSTED";
    this.connectHub(record);
    return true;
  }

  markDown(candidate) {
    if (!this.running) return;
    for (const [key, record] of this.candidates) {
      if (record.method === "mdns" && candidate.addresses.includes(record.ip)) {
        this.candidates.delete(key);
        if (this.connected?.ip === record.ip) this.disconnectHub();
      }
    }
    this.recomputeStatus();
  }

  recomputeStatus() {
    if (this.connected) return;
    const records = [...this.candidates.values()];
    if (records.length > 1 && !this.pairing) {
      this.status = "DISCOVERED"; this.message = "Multiple MNDe Hubs found";
    } else if (records.some(r => r.status === "PAIRING_REQUIRED")) {
      this.status = "PAIRING_REQUIRED"; this.message = "Pairing required";
    } else if (records.some(r => r.status === "ERROR")) {
      this.status = "ERROR"; this.message = "Hub identity could not be verified";
    } else if (records.length) {
      this.status = "UNVERIFIED"; this.message = "MNDe Hub found — identity unverified";
    } else if (this.pairing) {
      this.status = "OFFLINE"; this.message = "Hub offline";
    }
  }

  async monitorConnection() {
    if (!this.running) return;
    if (!this.connected) {
      if (this.pairing) void this.trySavedHub();
      if (this.manualIp) void this.tryConfiguredHub();
      this.browser?.update();
      return;
    }
    const ip = this.connected.ip;
    try {
      const health = await this.request(ip, "/healthz");
      if (!health.ok || health.body?.ok !== true) throw new Error("offline");
      const challenge = randomBytes(16).toString("base64url");
      const identity = await this.request(ip, `/v1/hub/identity?challenge=${challenge}`);
      const parsed = identity.ok ? validateIdentity(identity.body) : null;
      if (!parsed || parsed.hubId !== this.pairing.hubId
        || !identityProofMatches(await Promise.resolve(this.proofVerifier(identity.body, challenge, this.connected)).catch(() => null), this.pairing)) throw new Error("identity");
      this.connected.lastSeen = new Date().toISOString();
      this.candidates.set(this.connected.hubId, { ...this.connected });
    } catch {
      this.disconnectHub();
      await this.trySavedHub();
      this.browser?.update();
    }
  }
}

function identityProofMatches(proof, pairing) {
  return proof === true || Boolean(proof?.publicKey && pairing.identityPublicKey === proof.publicKey);
}
