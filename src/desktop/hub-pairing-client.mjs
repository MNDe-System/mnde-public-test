import { isIP } from "node:net";
import { privateIp, validateIdentity, verifyHubIdentity } from "./hub-discovery.mjs";
import { DesktopClientIdentity } from "./windows-client-identity.mjs";
import { HubTrustStore } from "./hub-trust-store.mjs";
import { HUB_ID, PAIR_ID } from "../hub/pairing-protocol.mjs";
import { randomBytes } from "../crypto/provider.mjs";

const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const url = (ip, path) => `http://${isIP(ip) === 6 ? `[${ip}]` : ip}:8790${path}`;

export class HubPairingClient {
  constructor({ discovery, identity = new DesktopClientIdentity(), trust = new HubTrustStore(),
    fetchImpl = fetch, pollMs = 1500, monitorMs = 2000, clock = () => Date.now(), log = () => {} } = {}) {
    this.discovery = discovery; this.identity = identity; this.trust = trust; this.fetch = fetchImpl;
    this.pollMs = pollMs; this.monitorMs = monitorMs; this.clock = clock; this.log = log;
    this.flow = null; this.connected = null; this.lastAttempt = new Map(); this.running = false;
  }
  emit(event, fields = {}) { try { this.log(event, fields); } catch { /* diagnostics are non-authoritative */ } }
  start() {
    if (this.running) return;
    this.running = true;
    void this.identity.loadOrCreate().catch(() => { this.identityError = true; });
    this.timer = setInterval(() => void this.tick(), this.monitorMs);
    void this.tick();
  }
  stop() { this.running = false; clearInterval(this.timer); this.connected = null; }
  candidates() {
    return this.discovery?.snapshot().candidates.filter(c => c.hubId && c.status !== "ERROR") ?? [];
  }
  snapshot() {
    const found = this.candidates();
    if (this.identityError) return { status: "ERROR", message: "Windows client identity unavailable",
      pairedHubIds: [], connectedHubId: null, pairingRequestId: null, candidates: found.map(c => ({ ...c, status: "ERROR" })) };
    let hubs;
    try { hubs = this.trust.list(); }
    catch { return { status: "ERROR", message: "Hub trust store unavailable", pairedHubIds: [],
      connectedHubId: null, pairingRequestId: null, candidates: found.map(c => ({ ...c, status: "ERROR" })) }; }
    const flow = this.flow;
    const candidates = found.map(c => ({ ...c,
      status: this.connected?.hubId === c.hubId && this.connected.ip === c.ip
        && this.connected.expiresAtMs > this.clock() ? "CONNECTED"
        : hubs.some(h => h.hubId === c.hubId) ? "AUTHENTICATING" : "UNPAIRED" }));
    let status = "SEARCHING", message = "Searching for MNDe Hub…";
    if (flow && ["PAIRING", "WAITING_FOR_APPROVAL", "PAIRING_APPROVED", "PAIRED", "PAIRING_REFUSED",
      "PAIRING_EXPIRED", "PAIRING_FAILED", "AUTHENTICATING", "AUTHENTICATION_FAILED"].includes(flow.status)) {
      status = flow.status;
      message = ({ PAIRING: "Pairing...", WAITING_FOR_APPROVAL: "Waiting for physical approval on MNDe Hub",
        PAIRING_APPROVED: "Paired", PAIRED: "Paired", PAIRING_REFUSED: "Pairing refused",
        PAIRING_EXPIRED: "Pairing expired", PAIRING_FAILED: "Pairing failed",
        AUTHENTICATING: "Authenticating", AUTHENTICATION_FAILED: "Pairing failed" })[status];
    } else if (this.connected && this.connected.expiresAtMs > this.clock()) {
      status = "CONNECTED"; message = "Connected";
    } else if (candidates.some(c => c.status === "AUTHENTICATING")) {
      status = "AUTHENTICATING"; message = "Authenticating with MNDe Hub…";
    } else if (candidates.length) {
      status = "UNPAIRED"; message = candidates.length > 1 ? "MNDe Hubs found" : "MNDe Hub found — unpaired";
    } else if (hubs.length || this.discovery?.snapshot().status === "OFFLINE") {
      status = "OFFLINE"; message = "Hub offline";
    }
    return { status, message, pairedHubIds: hubs.map(h => h.hubId),
      clientId: this.identity.cached?.clientId ?? null,
      clientName: this.identity.cached?.clientName ?? null,
      connectedHubId: this.connected?.expiresAtMs > this.clock() ? this.connected.hubId : null,
      pairingRequestId: flow?.id ?? null, reasonCode: flow?.reasonCode ?? null,
      hubHttpStatus: flow?.httpStatus ?? null,
      candidates };
  }
  async request(ip, path, input, token, expectedStatus = null) {
    if (!privateIp(ip) || !path.startsWith("/v1/")) throw new Error("ERR_HUB_ENDPOINT");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    try {
      const response = await this.fetch(url(ip, path), { method: input === undefined ? "GET" : "POST",
        headers: { accept: "application/json", ...(input === undefined ? {} : { "content-type": "application/json" }),
          ...(token ? { authorization: `Bearer ${token}` } : {}) },
        ...(input === undefined ? {} : { body: JSON.stringify(input) }),
        redirect: "error", cache: "no-store", signal: controller.signal });
      if (path === "/v1/pairing/requests" && input !== undefined) {
        if (this.flow?.status === "PAIRING") this.flow.httpStatus = response.status;
        this.emit("hub.pairing.post_http", { httpStatus: response.status });
      }
      const parts = []; let size = 0;
      for await (const part of response.body) {
        size += part.length;
        if (size > 4096) throw new Error("ERR_HUB_RESPONSE_SIZE");
        parts.push(part);
      }
      let parsed;
      try { parsed = JSON.parse(Buffer.concat(parts).toString("utf8")); }
      catch {
        const error = new Error("ERR_HUB_RESPONSE_JSON");
        error.reasonCode = "ERR_HUB_RESPONSE_JSON"; error.httpStatus = response.status;
        throw error;
      }
      if (!response.ok || (expectedStatus !== null && response.status !== expectedStatus)) {
        const reasonCode = typeof parsed?.reason_code === "string"
          && /^[A-Za-z0-9_.-]{1,128}$/.test(parsed.reason_code)
          ? parsed.reason_code : "ERR_HUB_RESPONSE";
        const error = new Error(reasonCode);
        error.reasonCode = reasonCode; error.httpStatus = response.status;
        throw error;
      }
      return parsed;
    } finally { clearTimeout(timer); }
  }
  async identify(hubId, ip, identityPublicKey = null) {
    const nonce = randomBytes(16).toString("base64url");
    const response = await this.request(ip, `/v1/hub/identity?challenge=${nonce}`);
    const identity = validateIdentity(response);
    if (!identity || identity.hubId !== hubId) throw new Error("ERR_HUB_IDENTITY");
    if (identityPublicKey) {
      const proof = await verifyHubIdentity(response, nonce);
      if (!proof || proof.publicKey !== identityPublicKey) throw new Error("ERR_HUB_IDENTITY_PROOF");
    }
    return identity;
  }
  async startPairing(hubId, ip, fingerprint = null) {
    if (this.flow && ["PAIRING", "WAITING_FOR_APPROVAL", "PAIRING_APPROVED", "AUTHENTICATING"].includes(this.flow.status))
      throw new Error("ERR_PAIRING_IN_PROGRESS");
    const candidate = this.candidates().find(c => c.hubId === hubId && c.ip === ip);
    if (!candidate || !HUB_ID.test(hubId) || this.trust.get(hubId)) throw new Error("ERR_PAIRING_CANDIDATE");
    if (candidate.identityPublicKey && candidate.fingerprint !== fingerprint) throw new Error("ERR_PAIRING_FINGERPRINT");
    const flow = { hubId, ip, status: "PAIRING", id: null, reasonCode: null, httpStatus: null,
      identityPublicKey: candidate.identityPublicKey ?? null };
    this.flow = flow;
    try {
      await this.identify(hubId, ip, candidate.identityPublicKey ?? null);
      const client = await this.identity.publicIdentity();
      this.emit("hub.pairing.post_started", { hubId, clientId: client.clientId });
      const response = await this.request(ip, "/v1/pairing/requests", { clientId: client.clientId,
        clientName: client.clientName, publicKey: client.publicKey, protocolVersion: 1 }, undefined, 201);
      if (response.ok !== true || !PAIR_ID.test(response.pairingRequestId) || response.status !== "PENDING"
        || !Number.isFinite(Date.parse(response.expiresAt))) throw new Error("ERR_PAIRING_RESPONSE");
      flow.id = response.pairingRequestId;
      flow.status = "WAITING_FOR_APPROVAL";
      this.emit("hub.pairing.request_created", { pairingRequestId: flow.id });
      this.emit("hub.pairing.polling_started", { pairingRequestId: flow.id });
      void this.#poll(flow, this.clock() + 185_000);
      return { ok: true, pairingRequestId: flow.id, status: flow.status, expiresAt: response.expiresAt };
    } catch (error) {
      flow.status = "PAIRING_FAILED";
      flow.reasonCode = error.reasonCode ?? (error.message?.startsWith("ERR_") ? error.message : "ERR_PAIRING_NETWORK");
      flow.httpStatus = error.httpStatus ?? flow.httpStatus;
      this.emit("hub.pairing.failed", { httpStatus: flow.httpStatus, reasonCode: flow.reasonCode });
      throw error;
    }
  }
  async #poll(flow, expiresAtMs) {
    while (this.running && this.flow === flow && this.clock() < expiresAtMs) {
      await wait(this.pollMs);
      if (!this.running || this.flow !== flow) return;
      try {
        const result = await this.request(flow.ip, `/v1/pairing/requests/${flow.id}`, undefined, undefined, 200);
        if (result.ok !== true) throw new Error("ERR_PAIRING_STATUS");
        this.emit("hub.pairing.status", { pairingRequestId: flow.id, status: result.status });
        if (result.status === "PENDING") continue;
        if (result.status === "REFUSED") {
          flow.status = "PAIRING_REFUSED"; this.emit("hub.pairing.refused", { pairingRequestId: flow.id }); return;
        }
        if (result.status === "EXPIRED") {
          flow.status = "PAIRING_EXPIRED"; this.emit("hub.pairing.expired", { pairingRequestId: flow.id }); return;
        }
        if (result.status !== "APPROVED" && result.status !== "COMPLETED") throw new Error("ERR_PAIRING_STATUS");
        flow.status = "PAIRING_APPROVED";
        this.emit("hub.pairing.approved", { pairingRequestId: flow.id });
        flow.status = "AUTHENTICATING";
        await this.identify(flow.hubId, flow.ip, flow.identityPublicKey);
        await this.authenticate(flow.hubId, flow.ip);
        this.trust.save({ hubId: flow.hubId, lastKnownIp: flow.ip, port: 8790,
          pairedAt: new Date(this.clock()).toISOString(), lastAuthenticatedAt: new Date(this.clock()).toISOString(),
          identityPublicKey: flow.identityPublicKey });
        flow.status = "PAIRED";
        return;
      } catch (error) {
        if (flow.status === "AUTHENTICATING") {
          if (this.connected?.hubId === flow.hubId && this.connected?.ip === flow.ip) this.connected = null;
          flow.status = "AUTHENTICATION_FAILED";
          flow.reasonCode = error.reasonCode ?? (error.message?.startsWith("ERR_") ? error.message : "ERR_AUTH_NETWORK");
          flow.httpStatus = error.httpStatus ?? null;
          return;
        }
        if (error.httpStatus !== undefined || ["ERR_PAIRING_STATUS", "ERR_HUB_RESPONSE_SIZE"].includes(error.message)) {
          flow.status = "PAIRING_FAILED";
          flow.reasonCode = error.reasonCode ?? error.message;
          flow.httpStatus = error.httpStatus ?? null;
          this.emit("hub.pairing.failed", { pairingRequestId: flow.id,
            httpStatus: flow.httpStatus, reasonCode: flow.reasonCode });
          return;
        }
        this.emit("hub.pairing.poll_error", { pairingRequestId: flow.id,
          httpStatus: error.httpStatus ?? null, reasonCode: error.reasonCode ?? null });
        // A transient failed status poll is retried until the request expires.
      }
    }
    if (this.running && this.flow === flow && flow.status === "WAITING_FOR_APPROVAL") {
      flow.status = "PAIRING_EXPIRED";
      this.emit("hub.pairing.expired", { pairingRequestId: flow.id });
    }
  }
  async authenticate(hubId, ip) {
    try {
      const client = await this.identity.publicIdentity();
      const challenge = await this.request(ip, "/v1/auth/challenge", { clientId: client.clientId }, undefined, 200);
      if (challenge.hubId !== hubId || !/^challenge-[A-Za-z0-9_-]{22}$/.test(challenge.challengeId)
        || !/^[A-Za-z0-9_-]{43}$/.test(challenge.nonce)
        || !Number.isFinite(Date.parse(challenge.expiresAt))) throw new Error("ERR_AUTH_CHALLENGE");
      this.emit("hub.auth.challenge_created", { hubId, clientId: client.clientId, challengeId: challenge.challengeId });
      const signature = await this.identity.signChallenge(challenge);
      const result = await this.request(ip, "/v1/auth/verify", { clientId: client.clientId,
        challengeId: challenge.challengeId, signature }, undefined, 200);
      if (result.ok !== true || !/^[A-Za-z0-9_-]{43}$/.test(result.sessionToken)
        || !Number.isFinite(Date.parse(result.expiresAt))) throw new Error("ERR_AUTH_SESSION");
      const check = await this.request(ip, "/v1/auth/session", undefined, result.sessionToken, 200);
      if (check.ok !== true || check.hubId !== hubId || check.clientId !== client.clientId) throw new Error("ERR_AUTH_SESSION");
      this.connected = { hubId, ip, expiresAtMs: this.clock() + 240_000,
        checkedAtMs: this.clock(), token: result.sessionToken };
      this.emit("hub.auth.verify_result", { hubId, clientId: client.clientId, ok: true });
      return true;
    } catch (error) {
      this.emit("hub.auth.verify_result", { hubId, ok: false,
        httpStatus: error.httpStatus ?? null, reasonCode: error.reasonCode ?? null });
      throw error;
    }
  }
  async tick() {
    if (!this.running || this.tickBusy) return;
    this.tickBusy = true;
    try {
      const saved = this.trust.list();
      if (this.connected && this.connected.expiresAtMs > this.clock() + 30_000) {
        if (this.connected.checkedAtMs + 10_000 > this.clock()) return;
        try {
          const check = await this.request(this.connected.ip, "/v1/auth/session", undefined, this.connected.token);
          if (check.ok === true && check.hubId === this.connected.hubId) {
            this.connected.checkedAtMs = this.clock();
            return;
          }
        } catch { /* revoked, offline, or moved */ }
        this.connected = null;
      }
      for (const hub of saved) {
        const candidates = this.candidates().filter(c => c.hubId === hub.hubId);
        const addresses = [...new Set([...candidates.map(c => c.ip), hub.lastKnownIp])];
        for (const ip of addresses) {
          const key = `${hub.hubId}:${ip}`;
          if ((this.lastAttempt.get(key) ?? 0) + 10_000 > this.clock()) continue;
          this.lastAttempt.set(key, this.clock());
          try {
            await this.identify(hub.hubId, ip, hub.identityPublicKey);
            await this.authenticate(hub.hubId, ip);
            this.trust.save({ ...hub, lastKnownIp: ip, lastAuthenticatedAt: new Date(this.clock()).toISOString() });
            return;
          } catch {
            if (this.connected?.hubId === hub.hubId && this.connected?.ip === ip) this.connected = null;
          }
        }
      }
      if (this.connected?.expiresAtMs <= this.clock()) this.connected = null;
    } catch { this.connected = null; }
    finally { this.tickBusy = false; }
  }
}
