// Pairing is a separate trust domain. No method here grants execution authority.
import { randomBytes } from "../crypto/provider.mjs";
import { CHALLENGE_ID, CLIENT_ID, HUB_ID, PAIR_ID, publicKeyPem, randomTag, verifyChallenge } from "./pairing-protocol.mjs";

const REQUEST_TTL = 3 * 60_000;
const CHALLENGE_TTL = 60_000;
const SESSION_TTL = 5 * 60_000;
const TERMINAL_TTL = 5 * 60_000;
const exact = (value, keys) => value && typeof value === "object" && !Array.isArray(value)
  && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
const clientNameValid = value => typeof value === "string" && value.length >= 1 && value.length <= 64
  && !/[\x00-\x1f\x7f]/.test(value) && value.trim() === value;
const iso = value => new Date(value).toISOString();

function validateStore(value, hubId) {
  if (!exact(value, ["version", "clients"]) || value.version !== 1 || !Array.isArray(value.clients)
    || value.clients.length > 256) throw new Error("ERR_PAIRING_STORE");
  const ids = new Set();
  for (const client of value.clients) {
    if (!exact(client, ["hubId", "clientId", "clientName", "publicKey", "pairedAt", "revoked", "credentialVersion"])
      || client.hubId !== hubId || !CLIENT_ID.test(client.clientId) || ids.has(client.clientId)
      || !clientNameValid(client.clientName) || !publicKeyPem(client.publicKey)
      || !Number.isFinite(Date.parse(client.pairedAt)) || typeof client.revoked !== "boolean"
      || !Number.isSafeInteger(client.credentialVersion) || client.credentialVersion < 1) throw new Error("ERR_PAIRING_STORE");
    ids.add(client.clientId);
  }
  return value;
}

export function openHubPairing({ hubId, storage, now = () => Date.now() }) {
  if (!HUB_ID.test(hubId) || !storage?.readPairingClients || !storage?.savePairingClients) throw new Error("ERR_PAIRING_CONFIG");
  let saved = validateStore(storage.readPairingClients(), hubId);
  const requests = new Map(), challenges = new Map(), sessions = new Map(), limits = new Map();
  const clients = () => saved.clients;
  const client = id => clients().find(c => c.clientId === id && !c.revoked);
  function persist(next) { storage.savePairingClients(next); saved = next; }
  function sweep() {
    const t = now();
    for (const [id, request] of requests) {
      if (request.status === "PENDING" && request.expiresAtMs <= t) {
        request.status = "EXPIRED"; request.terminalAt = t;
      }
      if (request.terminalAt && request.terminalAt + TERMINAL_TTL <= t) requests.delete(id);
    }
    for (const [id, challenge] of challenges) if (challenge.expiresAtMs <= t) challenges.delete(id);
    for (const [id, session] of sessions) if (session.expiresAtMs <= t) sessions.delete(id);
    for (const [key, bucket] of limits) if (bucket.resetAt <= t) limits.delete(key);
  }
  function limited(kind, source, max) {
    const key = `${kind}:${source}`;
    const t = now(), bucket = limits.get(key);
    if (!bucket || bucket.resetAt <= t) { limits.set(key, { count: 1, resetAt: t + 60_000 }); return false; }
    bucket.count++;
    return bucket.count > max;
  }
  function createRequest(input, source = "unknown") {
    sweep();
    if (!exact(input, ["clientId", "clientName", "publicKey", "protocolVersion"])
      || !CLIENT_ID.test(input.clientId) || !clientNameValid(input.clientName)
      || !publicKeyPem(input.publicKey) || input.protocolVersion !== 1) return { code: 400, error: "ERR_PAIRING_INPUT" };
    if (limited("pair", source, 5) || limited("pair-client", input.clientId, 5)) return { code: 429, error: "ERR_PAIRING_RATE_LIMIT" };
    if (client(input.clientId)) return { code: 409, error: "ERR_PAIRING_ALREADY_PAIRED" };
    if ([...requests.values()].some(r => r.status === "PENDING" && r.clientId === input.clientId))
      return { code: 409, error: "ERR_PAIRING_DUPLICATE" };
    if (requests.size >= 128) return { code: 429, error: "ERR_PAIRING_RECORD_LIMIT" };
    if ([...requests.values()].filter(r => r.status === "PENDING").length >= 5)
      return { code: 429, error: "ERR_PAIRING_PENDING_LIMIT" };
    const id = randomTag("pair"), expiresAtMs = now() + REQUEST_TTL;
    requests.set(id, { id, ...input, status: "PENDING", expiresAtMs, terminalAt: null });
    return { code: 201, value: { ok: true, pairingRequestId: id, status: "PENDING", expiresAt: iso(expiresAtMs) } };
  }
  function status(id) {
    sweep();
    if (!PAIR_ID.test(id) || !requests.has(id)) return { code: 404, error: "ERR_PAIRING_NOT_FOUND" };
    return { code: 200, value: { ok: true, status: requests.get(id).status } };
  }
  function pendingForPhysical() {
    sweep();
    return [...requests.values()].filter(r => r.status === "PENDING").map(r => Object.freeze({
      actionType: "pairing.client", pairingRequestId: r.id, clientId: r.clientId,
      clientName: r.clientName, expiresAt: iso(r.expiresAtMs)
    }));
  }
  function resolvePhysical(id, decision) {
    sweep();
    const request = requests.get(id);
    if (!request || request.status !== "PENDING" || !["APPROVED", "REFUSED"].includes(decision)) return false;
    if (decision === "APPROVED") {
      const previous = clients().find(c => c.clientId === request.clientId);
      if (previous && !previous.revoked) return false;
      const record = { hubId, clientId: request.clientId, clientName: request.clientName,
        publicKey: request.publicKey, pairedAt: iso(now()), revoked: false,
        credentialVersion: (previous?.credentialVersion ?? 0) + 1 };
      persist({ version: 1, clients: [...clients().filter(c => c.clientId !== request.clientId), record] });
    }
    request.status = decision; request.terminalAt = now();
    return true;
  }
  function createChallenge(input, source = "unknown") {
    sweep();
    if (!exact(input, ["clientId"]) || !CLIENT_ID.test(input.clientId)) return { code: 400, error: "ERR_AUTH_INPUT" };
    if (limited("auth", source, 15) || limited("auth-client", input.clientId, 15)) return { code: 429, error: "ERR_AUTH_RATE_LIMIT" };
    const found = client(input.clientId);
    if (!found) return { code: 401, error: "ERR_AUTH_CLIENT" };
    if (challenges.size >= 256) return { code: 429, error: "ERR_AUTH_CHALLENGE_LIMIT" };
    const challengeId = randomTag("challenge"), nonce = randomBytes(32).toString("base64url"), expiresAtMs = now() + CHALLENGE_TTL;
    challenges.set(challengeId, { hubId, clientId: found.clientId, credentialVersion: found.credentialVersion,
      challengeId, nonce, expiresAt: iso(expiresAtMs), expiresAtMs });
    return { code: 200, value: { challengeId, nonce, expiresAt: iso(expiresAtMs), hubId } };
  }
  async function verify(input) {
    sweep();
    if (!exact(input, ["clientId", "challengeId", "signature"])
      || !CLIENT_ID.test(input.clientId) || !CHALLENGE_ID.test(input.challengeId)) return { code: 400, error: "ERR_AUTH_INPUT" };
    const challenge = challenges.get(input.challengeId);
    if (!challenge || challenge.clientId !== input.clientId) return { code: 401, error: "ERR_AUTH_CHALLENGE" };
    challenges.delete(input.challengeId); // Consume on first attempt, including a bad signature.
    const found = client(input.clientId);
    if (!found || found.credentialVersion !== challenge.credentialVersion
      || !await verifyChallenge(challenge, input.signature, found.publicKey)) return { code: 401, error: "ERR_AUTH_SIGNATURE" };
    if (sessions.size >= 512) return { code: 429, error: "ERR_AUTH_SESSION_LIMIT" };
    const sessionToken = randomBytes(32).toString("base64url"), expiresAtMs = now() + SESSION_TTL;
    sessions.set(sessionToken, { clientId: found.clientId, credentialVersion: found.credentialVersion, expiresAtMs });
    for (const request of requests.values()) if (request.clientId === found.clientId && request.status === "APPROVED") {
      request.status = "COMPLETED"; request.terminalAt = now();
    }
    return { code: 200, value: { ok: true, sessionToken, expiresAt: iso(expiresAtMs) } };
  }
  function session(token) {
    sweep();
    const value = sessions.get(token), found = value && client(value.clientId);
    if (!found || found.credentialVersion !== value.credentialVersion) return null;
    return { clientId: value.clientId, hubId, expiresAt: iso(value.expiresAtMs) };
  }
  function revoke(clientId) {
    if (!CLIENT_ID.test(clientId)) return false;
    const found = client(clientId);
    if (!found) return false;
    persist({ version: 1, clients: clients().map(c => c.clientId === clientId ? { ...c, revoked: true } : c) });
    for (const [id, challenge] of challenges) if (challenge.clientId === clientId) challenges.delete(id);
    for (const [token, value] of sessions) if (value.clientId === clientId) sessions.delete(token);
    return true;
  }
  return Object.freeze({ hubId, createRequest, status, pendingForPhysical, resolvePhysical,
    createChallenge, verify, session, revoke, listClients: () => clients().map(({ publicKey, ...record }) => record) });
}
