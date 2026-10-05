export const ERR_SIDECAR_SATURATED = "ERR_SIDECAR_SATURATED";
export const ERR_L0_TRANSPORT_SHED = "ERR_L0_TRANSPORT_SHED";

export const DEFAULT_HTTP_LIMITS = {
  max_active_requests: 96,
  max_active_sockets: 128,
  max_request_body_bytes: 1_048_576,
  request_timeout_ms: 10_000,
  keep_alive_timeout_ms: 1_000,
  headers_timeout_ms: 2_000,
  max_requests_per_socket: 100
};

export const DEFAULT_L0_LIMITS = {
  enable: true,
  max_connections: 64,
  hybrid_503_connections: 72,
  backlog: 128,
  keepalive_timeout_ms: 250,
  headers_timeout_ms: 750,
  shed_mode: "503"
};

const ENV_TO_KEY = {
  MNDE_HTTP_MAX_ACTIVE_REQUESTS: "max_active_requests",
  MNDE_HTTP_MAX_ACTIVE_SOCKETS: "max_active_sockets",
  MNDE_HTTP_MAX_REQUEST_BODY_BYTES: "max_request_body_bytes",
  MNDE_HTTP_REQUEST_TIMEOUT_MS: "request_timeout_ms",
  MNDE_HTTP_KEEP_ALIVE_TIMEOUT_MS: "keep_alive_timeout_ms",
  MNDE_HTTP_HEADERS_TIMEOUT_MS: "headers_timeout_ms",
  MNDE_HTTP_MAX_REQUESTS_PER_SOCKET: "max_requests_per_socket"
};

const L0_ENV_TO_KEY = {
  MNDE_L0_MAX_CONNECTIONS: "max_connections",
  MNDE_L0_HYBRID_503_CONNECTIONS: "hybrid_503_connections",
  MNDE_L0_BACKLOG: "backlog",
  MNDE_L0_KEEPALIVE_TIMEOUT_MS: "keepalive_timeout_ms",
  MNDE_L0_HEADERS_TIMEOUT_MS: "headers_timeout_ms"
};

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function parseLimit(env, name, fallback) {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!positiveInteger(parsed)) throw new Error(`ERR_HTTP_LIMIT_CONFIG: ${name} must be a positive safe integer`);
  return parsed;
}

export function parseHttpLimitConfig(env = process.env) {
  const config = {};
  for (const [envName, key] of Object.entries(ENV_TO_KEY)) {
    config[key] = parseLimit(env, envName, DEFAULT_HTTP_LIMITS[key]);
  }
  return config;
}

export function parseL0LimitConfig(env = process.env) {
  const config = {
    enable: env.MNDE_L0_ENABLE === undefined ? DEFAULT_L0_LIMITS.enable : env.MNDE_L0_ENABLE === "1",
    shed_mode: env.MNDE_L0_SHED_MODE ?? DEFAULT_L0_LIMITS.shed_mode
  };
  if (!new Set(["destroy", "503", "hybrid"]).has(config.shed_mode)) {
    throw new Error("ERR_L0_LIMIT_CONFIG: MNDE_L0_SHED_MODE must be destroy, 503, or hybrid");
  }
  for (const [envName, key] of Object.entries(L0_ENV_TO_KEY)) {
    config[key] = parseLimit(env, envName, DEFAULT_L0_LIMITS[key]);
  }
  if (config.hybrid_503_connections < config.max_connections) {
    throw new Error("ERR_L0_LIMIT_CONFIG: MNDE_L0_HYBRID_503_CONNECTIONS must be >= MNDE_L0_MAX_CONNECTIONS");
  }
  return config;
}

export function createAdmissionController(config = {}) {
  const limits = {
    max_active_requests: config.max_active_requests ?? DEFAULT_HTTP_LIMITS.max_active_requests,
    max_active_sockets: config.max_active_sockets ?? DEFAULT_HTTP_LIMITS.max_active_sockets,
    max_requests_per_socket: config.max_requests_per_socket ?? DEFAULT_HTTP_LIMITS.max_requests_per_socket
  };
  for (const [key, value] of Object.entries(limits)) {
    if (!positiveInteger(value)) throw new Error(`ERR_HTTP_LIMIT_CONFIG: ${key} must be a positive safe integer`);
  }

  let activeRequests = 0;
  let activeSockets = 0;
  let refusedByAdmission = 0;
  const socketRequests = new WeakMap();

  return {
    tryAcquireRequest() {
      const started = performance.now();
      if (activeRequests >= limits.max_active_requests) {
        refusedByAdmission += 1;
        return {
          ok: false,
          reason_code: ERR_SIDECAR_SATURATED,
          admission_wait_ms: Math.max(0, Math.round(performance.now() - started))
        };
      }
      activeRequests += 1;
      let released = false;
      return {
        ok: true,
        admission_wait_ms: Math.max(0, Math.round(performance.now() - started)),
        release() {
          if (released) return;
          released = true;
          activeRequests = Math.max(0, activeRequests - 1);
        }
      };
    },

    tryAcquireSocket() {
      if (activeSockets >= limits.max_active_sockets) {
        refusedByAdmission += 1;
        return { ok: false, reason_code: ERR_SIDECAR_SATURATED };
      }
      activeSockets += 1;
      let released = false;
      return {
        ok: true,
        release() {
          if (released) return;
          released = true;
          activeSockets = Math.max(0, activeSockets - 1);
        }
      };
    },

    noteSocketRequest(socket) {
      const next = (socketRequests.get(socket) ?? 0) + 1;
      socketRequests.set(socket, next);
      if (next > limits.max_requests_per_socket) {
        refusedByAdmission += 1;
        return { ok: false, reason_code: ERR_SIDECAR_SATURATED };
      }
      return { ok: true };
    },

    recordAdmissionRefusal() {
      refusedByAdmission += 1;
    },

    snapshot() {
      return {
        active_requests: activeRequests,
        active_sockets: activeSockets,
        refused_by_admission_total: refusedByAdmission
      };
    },

    limits() {
      return { ...limits };
    }
  };
}
