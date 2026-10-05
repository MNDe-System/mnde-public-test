export const ERR_SOCKET_REGISTRY_CONFIG = "ERR_SOCKET_REGISTRY_CONFIG";

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

export function validateSocketRegistryConfig(config = {}) {
  const idle_timeout_ms = config.idle_timeout_ms ?? 1_000;
  const eviction_interval_ms = config.eviction_interval_ms ?? 250;
  const shutdown_grace_ms = config.shutdown_grace_ms ?? 500;
  if (!positiveInteger(idle_timeout_ms)) throw new Error(`${ERR_SOCKET_REGISTRY_CONFIG}: idle_timeout_ms must be positive`);
  if (!positiveInteger(eviction_interval_ms)) throw new Error(`${ERR_SOCKET_REGISTRY_CONFIG}: eviction_interval_ms must be positive`);
  if (!positiveInteger(shutdown_grace_ms)) throw new Error(`${ERR_SOCKET_REGISTRY_CONFIG}: shutdown_grace_ms must be positive`);
  return { idle_timeout_ms, eviction_interval_ms, shutdown_grace_ms };
}

export class SocketRegistry {
  #config;
  #sockets = new Map();
  #timer = null;
  #nextId = 1;
  #metrics = {
    opened: 0,
    closed: 0,
    destroyed: 0,
    idle_destroyed: 0,
    shutdown_destroyed: 0,
    errors: 0,
    max_open: 0
  };

  constructor(config = {}) {
    this.#config = validateSocketRegistryConfig(config);
  }

  start() {
    if (this.#timer) return;
    this.#timer = setInterval(() => this.destroyIdle(), this.#config.eviction_interval_ms);
    this.#timer.unref?.();
  }

  stop() {
    if (!this.#timer) return;
    clearInterval(this.#timer);
    this.#timer = null;
  }

  track(socket) {
    const id = this.#nextId;
    this.#nextId += 1;
    const now = performance.now();
    const state = {
      id,
      socket,
      opened_at_ms: now,
      last_active_at_ms: now,
      first_byte_at_ms: 0,
      close_at_ms: 0,
      requests: 0,
      destroyed: false
    };
    this.#sockets.set(socket, state);
    this.#metrics.opened += 1;
    this.#metrics.max_open = Math.max(this.#metrics.max_open, this.#sockets.size);

    socket.setNoDelay?.(true);
    socket.on("close", () => {
      if (this.#sockets.delete(socket)) this.#metrics.closed += 1;
      state.close_at_ms = performance.now();
    });
    socket.on("error", () => {
      this.#metrics.errors += 1;
    });
    socket.prependListener("data", () => {
      this.markActive(socket);
      if (state.first_byte_at_ms === 0) state.first_byte_at_ms = performance.now();
    });
    return state;
  }

  state(socket) {
    return this.#sockets.get(socket) ?? null;
  }

  markRequest(socket) {
    const state = this.#sockets.get(socket);
    if (!state) return null;
    state.requests += 1;
    state.last_active_at_ms = performance.now();
    return state;
  }

  markActive(socket) {
    const state = this.#sockets.get(socket);
    if (state) state.last_active_at_ms = performance.now();
    return state;
  }

  destroy(socket, reason = "destroyed") {
    const state = this.#sockets.get(socket);
    if (state && !state.destroyed) {
      state.destroyed = true;
      this.#metrics.destroyed += 1;
      if (reason === "idle") this.#metrics.idle_destroyed += 1;
      if (reason === "shutdown") this.#metrics.shutdown_destroyed += 1;
    }
    socket.destroy?.();
  }

  destroyIdle(now = performance.now()) {
    for (const state of this.#sockets.values()) {
      if (now - state.last_active_at_ms > this.#config.idle_timeout_ms) {
        this.destroy(state.socket, "idle");
      }
    }
  }

  async shutdown() {
    this.stop();
    for (const state of this.#sockets.values()) this.destroy(state.socket, "shutdown");
    const deadline = Date.now() + this.#config.shutdown_grace_ms;
    while (this.#sockets.size > 0 && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    for (const state of this.#sockets.values()) this.destroy(state.socket, "shutdown");
  }

  metrics() {
    const now = performance.now();
    let idle = 0;
    for (const state of this.#sockets.values()) {
      if (now - state.last_active_at_ms > this.#config.idle_timeout_ms) idle += 1;
    }
    return {
      ...this.#metrics,
      open: this.#sockets.size,
      idle,
      idle_timeout_ms: this.#config.idle_timeout_ms
    };
  }
}
