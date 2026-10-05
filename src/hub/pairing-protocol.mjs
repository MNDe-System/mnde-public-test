import { randomBytes, verify } from "../crypto/provider.mjs";

export const HUB_ID = /^hub-[A-Za-z0-9][A-Za-z0-9_-]{2,127}$/;
export const CLIENT_ID = /^pc-[0-9a-f]{16,32}$/;
export const PAIR_ID = /^pair-[A-Za-z0-9_-]{22}$/;
export const CHALLENGE_ID = /^challenge-[A-Za-z0-9_-]{22}$/;
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");

export function randomTag(prefix) { return `${prefix}-${randomBytes(16).toString("base64url")}`; }

export function publicKeyPem(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value)) return null;
  const raw = Buffer.from(value, "base64url");
  if (raw.length !== 32 || raw.toString("base64url") !== value) return null;
  const der = Buffer.concat([ED25519_SPKI, raw]);
  return `-----BEGIN PUBLIC KEY-----\n${der.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----\n`;
}

export function rawPublicKey(pem) {
  const body = pem.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s/g, "");
  const der = Buffer.from(body, "base64");
  if (der.length !== 44 || !der.subarray(0, 12).equals(ED25519_SPKI)) throw new Error("ERR_PAIRING_KEY");
  return der.subarray(12).toString("base64url");
}

export function challengeMessage({ hubId, clientId, challengeId, nonce, expiresAt }) {
  return Buffer.from(JSON.stringify({ purpose: "mnde.hub.client-auth.v1", hubId, clientId,
    challengeId, nonce, expiresAt }), "utf8");
}

export async function verifyChallenge(challenge, signature, publicKey) {
  if (typeof signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(signature)) return false;
  const raw = Buffer.from(signature, "base64url");
  const pem = publicKeyPem(publicKey);
  return Boolean(pem && raw.length === 64 && raw.toString("base64url") === signature
    && await verify(challengeMessage(challenge), raw.toString("hex"), pem));
}
