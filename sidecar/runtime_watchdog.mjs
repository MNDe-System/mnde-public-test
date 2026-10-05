export const ERR_RUNTIME_WATCHDOG_CONFIG = "ERR_RUNTIME_WATCHDOG_CONFIG";
export const ERR_RUNTIME_DEGRADED = "ERR_RUNTIME_DEGRADED";
export const ERR_RUNTIME_FATAL = "ERR_RUNTIME_FATAL";

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

export function validateWatchdogConfig(config = {}) {
  const interval_ms = config.interval_ms ?? 250;
  const max_event_loop_lag_ms = config.max_event_loop_lag_ms ?? 250;
  const fatal_event_loop_lag_ms = config.fatal_event_loop_lag_ms ?? 2_000;
  const max_open_sockets = config.max_open_sockets ?? 256;
  const fatal_open_sockets = config.fatal_open_sockets ?? 1_024;
  if (!positiveInteger(interval_ms)) throw new Error(`${ERR_RUNTIME_WATCHDOG_CONFIG}: interval_ms must be positive`);
  if (!positiveInteger(max_event_loop_lag_ms)) throw new Error(`${ERR_RUNTIME_WATCHDOG_CONFIG}: max_event_loop_lag_ms must be positive`);
  if (!positiveInteger(fatal_event_loop_lag_ms)) throw new Error(`${ERR_RUNTIME_WATCHDOG_CONFIG}: fatal_event_loop_lag_ms must be positive`);
  if (!positiveInteger(max_open_sockets)) throw new Error(`${ERR_RUNTIME_WATCHDOG_CONFIG}: max_open_sockets must be positive`);
  if (!positiveInteger(fatal_open_sockets)) throw new Error(`${ERR_RUNTIME_WATCHDOG_CONFIG}: fatal_open_sockets must be positive`);
  return { interval_ms, max_event_loop_lag_ms, fatal_event_loop_lag_ms, max_open_sockets, fatal_open_sockets };
}

export class RuntimeWatchdog {
  #config;
  #snapshotProvider;
  #timer = null;
  #expectedNextTick = 0;
  #state = {
    started_at_ms: performance.now(),
    last_heartbeat_ms: performance.now(),
    last_watchdog_ms: 0,
    event_loop_lag_ms: 0,
    degraded: false,
    degraded_reason: null,
    fatal: false,
    fatal_reason: null,
    interventions: 0,
    degraded_transitions: 0,
    fatal_transitions: 0,
    endpoint_responsiveness_ms: 0
  };

  constructor(config = {}, snapshotProvider = () => ({})) {
    this.#config = validateWatchdogConfig(config);
    this.#snapshotProvider = snapshotProvider;
  }

  start() {
    if (this.#timer) return;
    this.#expectedNextTick = performance.now() + this.#config.interval_ms;
    this.#timer = setInterval(() => this.#tick(), this.#config.interval_ms);
    this.#timer.unref?.();
  }

  stop() {
    if (!this.#timer) return;
    clearInterval(this.#timer);
    this.#timer = null;
  }

  heartbeat(label = "heartbeat") {
    this.#state.last_heartbeat_ms = performance.now();
    if (label === "healthz") this.#state.endpoint_responsiveness_ms = this.#state.last_heartbeat_ms;
  }

  markIntervention() {
    this.#state.interventions += 1;
  }

  setDegraded(reason) {
    if (!this.#state.degraded || this.#state.degraded_reason !== reason) {
      this.#state.degraded_transitions += 1;
    }
    this.#state.degraded = true;
    this.#state.degraded_reason = reason;
  }

  clearDegraded() {
    this.#state.degraded = false;
    this.#state.degraded_reason = null;
  }

  setFatal(reason) {
    if (!this.#state.fatal || this.#state.fatal_reason !== reason) {
      this.#state.fatal_transitions += 1;
    }
    this.#state.fatal = true;
    this.#state.fatal_reason = reason;
    this.setDegraded(reason);
  }

  canAcceptDecisions() {
    return !this.#state.degraded && !this.#state.fatal;
  }

  snapshot() {
    return {
      started_at_ms: Math.max(0, Math.round(this.#state.started_at_ms)),
      last_heartbeat_ms: Math.max(0, Math.round(this.#state.last_heartbeat_ms)),
      last_watchdog_ms: Math.max(0, Math.round(this.#state.last_watchdog_ms)),
      event_loop_lag_ms: Math.max(0, Math.round(this.#state.event_loop_lag_ms)),
      degraded: this.#state.degraded,
      degraded_reason: this.#state.degraded_reason,
      fatal: this.#state.fatal,
      fatal_reason: this.#state.fatal_reason,
      interventions: this.#state.interventions,
      degraded_transitions: this.#state.degraded_transitions,
      fatal_transitions: this.#state.fatal_transitions,
      endpoint_responsiveness_ms: Math.max(0, Math.round(this.#state.endpoint_responsiveness_ms)),
      uptime_ms: Math.max(0, Math.round(performance.now() - this.#state.started_at_ms))
    };
  }

  #tick() {
    const now = performance.now();
    const lag = Math.max(0, Math.round(now - this.#expectedNextTick));
    this.#expectedNextTick = now + this.#config.interval_ms;
    this.#state.last_watchdog_ms = now;
    this.#state.event_loop_lag_ms = lag;
    const snapshot = this.#snapshotProvider() ?? {};

    if (lag >= this.#config.fatal_event_loop_lag_ms) {
      this.setFatal("ERR_EVENT_LOOP_FATAL");
    } else if (snapshot.open_sockets >= this.#config.fatal_open_sockets) {
      this.setFatal("ERR_SOCKET_ACCUMULATION_FATAL");
    } else if (lag >= this.#config.max_event_loop_lag_ms) {
      this.setDegraded("ERR_EVENT_LOOP_LAG");
    } else if (snapshot.open_sockets >= this.#config.max_open_sockets) {
      this.setDegraded("ERR_SOCKET_ACCUMULATION");
    } else if (!snapshot.receipt_fail_closed) {
      this.clearDegraded();
    }
  }
}
