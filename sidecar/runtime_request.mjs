export const ERR_UNAUTHORIZED_ORIGIN = "ERR_UNAUTHORIZED_ORIGIN";

export function allowedCorsOrigins(env = process.env) {
  const raw = env.MNDE_ALLOWED_ORIGINS ?? "";
  return new Set(raw.split(/[\s,]+/).map((origin) => origin.trim()).filter(Boolean));
}

export function isAllowedCorsOrigin(origin) {
  return origin === undefined || origin === null || origin === "" || allowedCorsOrigins().has(origin);
}

export function corsHeadersForOrigin(origin) {
  if (!origin || !allowedCorsOrigins().has(origin)) return {};
  return {
    "access-control-allow-origin": origin,
    "vary": "Origin"
  };
}

export function createRuntimeInput(request, policy) {
  const sanitizedRequest = { ...request };
  delete sanitizedRequest.policy_document;
  return {
    ...sanitizedRequest,
    policy_document: policy
  };
}
