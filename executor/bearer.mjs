// Outbound bearer token for sidecar decision calls.
//
// Token handling is isolated here so it lives in exactly one place. The token is
// sent only as an Authorization header on the request to /v1/decisions. It is
// never logged, never stored in receipts, and never included in error output.

export function resolveBearerToken(explicit) {
  const token = explicit ?? process.env.MNDE_SIDECAR_BEARER_TOKEN ?? null;
  return typeof token === "string" && token.length > 0 ? token : null;
}

export function bearerAuthHeader(token) {
  return token ? { authorization: `Bearer ${token}` } : {};
}
