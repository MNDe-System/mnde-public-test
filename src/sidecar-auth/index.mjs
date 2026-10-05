// Sidecar caller authentication (opt-in).
//
// Default mode is "off" (unauthenticated, legacy-compatible). In "bearer" mode
// the sidecar requires `Authorization: Bearer <token>` and validates the token
// against config/env only. The caller identity is derived from the configured
// token label — NEVER from the request body. Tokens and identities are config;
// they are never written into receipts.

import { readFileSync } from "node:fs";

import { constantTimeEqual } from "../crypto/provider.mjs";

const FAILED_AUTH_THRESHOLD = 5;
const FAILED_AUTH_WINDOW_MS = 60_000;
const failedAuthBySource = new Map();

// Load auth config from env. Fails closed (ok:false) if bearer mode is enabled
// but no usable tokens are configured.
export function loadAuthConfig(env) {
  const mode = env.MNDE_SIDECAR_AUTH === "bearer" ? "bearer" : "off";
  if (mode === "off") return { ok: true, mode: "off", tokens: new Map() };

  let raw = env.MNDE_SIDECAR_AUTH_TOKENS;
  if (!raw && env.MNDE_SIDECAR_AUTH_TOKENS_FILE) {
    try {
      raw = readFileSync(env.MNDE_SIDECAR_AUTH_TOKENS_FILE, "utf8");
    } catch (error) {
      return { ok: false, mode: "bearer", reason: `auth token file load failed: ${error?.message ?? String(error)}` };
    }
  }
  if (!raw) return { ok: false, mode: "bearer", reason: "MNDE_SIDECAR_AUTH=bearer requires MNDE_SIDECAR_AUTH_TOKENS or MNDE_SIDECAR_AUTH_TOKENS_FILE" };

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, mode: "bearer", reason: "auth tokens must be a JSON object { token: caller_id }" };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, mode: "bearer", reason: "auth tokens must be a JSON object { token: caller_id }" };
  }

  const tokens = new Map();
  for (const [token, label] of Object.entries(parsed)) {
    if (typeof token === "string" && token.length > 0 && typeof label === "string" && label.length > 0) {
      tokens.set(token, { id: label, label });
    }
  }
  if (tokens.size === 0) return { ok: false, mode: "bearer", reason: "no valid auth tokens configured" };
  return { ok: true, mode: "bearer", tokens };
}

// Constant-time lookup: compare the candidate against every configured token so
// validity does not leak through timing.
function matchToken(tokens, candidate) {
  const candidateBuffer = Buffer.from(candidate, "utf8");
  let matched = null;
  for (const [token, identity] of tokens) {
    const tokenBuffer = Buffer.from(token, "utf8");
    if (constantTimeEqual(tokenBuffer, candidateBuffer)) {
      matched = identity;
    }
  }
  return matched;
}

// Returns { ok, caller } on success or { ok:false, reason } on failure. The
// caller-facing reason is uniform (no missing-vs-wrong oracle) at the sidecar.
export function authenticate(headers, authConfig) {
  const header = headers?.authorization ?? headers?.Authorization;
  const value = Array.isArray(header) ? header[0] : header;
  if (typeof value !== "string") return { ok: false, reason: "missing" };
  const match = /^Bearer\s+(.+)$/i.exec(value.trim());
  if (!match) return { ok: false, reason: "malformed" };
  const token = match[1].trim();
  if (!token) return { ok: false, reason: "malformed" };
  const identity = matchToken(authConfig.tokens, token);
  if (!identity) return { ok: false, reason: "invalid_token" };
  return { ok: true, caller: { id: identity.id, label: identity.label } };
}

function recentFailures(source, now) {
  const cutoff = now - FAILED_AUTH_WINDOW_MS;
  const attempts = (failedAuthBySource.get(source) ?? []).filter((at) => at > cutoff);
  if (attempts.length > 0) failedAuthBySource.set(source, attempts);
  else failedAuthBySource.delete(source);
  return attempts;
}

export function authSourceForRequest(req) {
  return req?.socket?.remoteAddress || "unknown";
}

export function isAuthThrottled(source, now = Date.now()) {
  return recentFailures(source, now).length >= FAILED_AUTH_THRESHOLD;
}

export function recordAuthFailure(source, now = Date.now()) {
  const attempts = recentFailures(source, now);
  attempts.push(now);
  failedAuthBySource.set(source, attempts);
  return attempts.length >= FAILED_AUTH_THRESHOLD;
}

export function clearAuthFailures(source) {
  failedAuthBySource.delete(source);
}
