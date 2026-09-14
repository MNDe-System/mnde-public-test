// Graceful shutdown lifecycle for the MNDe sidecar.
//
// The orchestration this owns is small but easy to get wrong, so it lives here
// as a pure, dependency-injected helper that the sidecar wires real resources
// into (and that tests drive with fakes). It guarantees four properties the
// runtime cares about:
//
//   1. Idempotent — repeated SIGINT/SIGTERM (or repeated `stop`) share ONE
//      shutdown; they never start concurrent cleanup passes.
//   2. Drain-first — `onBegin()` runs synchronously at the very first call so the
//      caller can flip its draining flag (readiness → not-ready, new decisions
//      refused) before any awaiting happens.
//   3. One deadline over the WHOLE sequence — a stalled request, receipt flush,
//      or worker termination cannot wedge the process open. `Promise.race` does
//      NOT cancel the losing work, so the deadline path itself calls `exit`.
//   4. Honest exit code — 0 only after every phase reports success. A phase that
//      returns { ok:false } (e.g. receipt persistence that finished fail-closed)
//      or the deadline both take the forced-cleanup path and exit non-zero.
//
// Nothing here touches decision hashes, canonicalization, signing, receipt
// bytes, or the verifier. It only sequences teardown of already-produced work.

export const SHUTDOWN_DEADLINE_FALLBACK_MS = 5_000;
export const ERR_SHUTDOWN_CONFIG = "ERR_SHUTDOWN_CONFIG";
export const ERR_SIDECAR_SHUTDOWN_DEADLINE = "ERR_SIDECAR_SHUTDOWN_DEADLINE";
export const ERR_SIDECAR_SHUTDOWN_PERSISTENCE = "ERR_SIDECAR_SHUTDOWN_PERSISTENCE";
export const ERR_SIDECAR_SHUTDOWN_FAILED = "ERR_SIDECAR_SHUTDOWN_FAILED";

function positiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

// Consistent with sidecar/http_admission.mjs parseLimit: an explicitly-set but
// invalid value is a hard config error (fail fast at startup), while unset/empty
// falls back to the documented default.
export function parseShutdownDeadlineMs(env = process.env, fallback = SHUTDOWN_DEADLINE_FALLBACK_MS) {
  const raw = env.MNDE_SHUTDOWN_DEADLINE_MS;
  if (raw === undefined || raw === "") return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!positiveSafeInteger(parsed)) {
    throw new Error(`${ERR_SHUTDOWN_CONFIG}: MNDE_SHUTDOWN_DEADLINE_MS must be a positive safe integer`);
  }
  return parsed;
}

// Resolves once getInflight() reports no active application work, or once the
// shared signal is aborted (the overall deadline fired). Timers are ref'd so the
// event loop stays alive while we legitimately wait for in-flight requests; the
// outer deadline is what bounds the wait.
export function waitForQuiescence(getInflight, signal, { intervalMs = 5, setTimer = setTimeout } = {}) {
  return new Promise((resolve) => {
    const check = () => {
      if (signal.aborted || getInflight() <= 0) {
        resolve();
        return;
      }
      setTimer(check, intervalMs);
    };
    check();
  });
}

// phases: ordered [{ name, run: (signal) => void | { ok, reason } | Promise<...> }].
//   A phase resolving normally (or to { ok:true }) advances the sequence.
//   A phase resolving to { ok:false, reason } stops the sequence fail-closed.
// onBegin: synchronous, runs once at the first shutdown() call (set draining
//   flag, stop accepting new connections). Must not throw meaningfully; wrapped.
// onForcedCleanup: synchronous best-effort teardown on the failure/deadline
//   path. MUST NOT await — it runs when we are already over budget.
export function createGracefulShutdown({
  deadlineMs,
  phases,
  onBegin = () => {},
  onForcedCleanup = () => {},
  now = () => Date.now(),
  setTimer = (fn, ms) => setTimeout(fn, ms),
  clearTimer = (timer) => clearTimeout(timer),
  exit = (code) => process.exit(code),
  log = (line) => process.stderr.write(`${line}\n`)
}) {
  if (!positiveSafeInteger(deadlineMs)) {
    throw new Error(`${ERR_SHUTDOWN_CONFIG}: deadlineMs must be a positive safe integer`);
  }
  if (!Array.isArray(phases) || phases.length === 0) {
    throw new Error(`${ERR_SHUTDOWN_CONFIG}: at least one phase is required`);
  }

  let started = false;
  let inFlight = null;
  const signal = { aborted: false };

  function settleOnce() {
    let settled = false;
    let deadlineTimer = null;
    return {
      finish(code, reasonCode, detail) {
        if (settled) return;
        settled = true;
        signal.aborted = true;
        if (deadlineTimer !== null) clearTimer(deadlineTimer);
        if (code !== 0) {
          log(`${reasonCode}: shutdown did not complete cleanly${detail ? ` — ${detail}` : ""}; forcing teardown`);
          try {
            onForcedCleanup();
          } catch (error) {
            log(`${ERR_SIDECAR_SHUTDOWN_FAILED}: forced cleanup error — ${(error && error.message) || error}`);
          }
        }
        exit(code);
      },
      armDeadline(finish) {
        deadlineTimer = setTimer(
          () => finish(1, ERR_SIDECAR_SHUTDOWN_DEADLINE, `deadline ${deadlineMs}ms exceeded`),
          deadlineMs
        );
      }
    };
  }

  async function execute() {
    const startedAt = now();
    const gate = settleOnce();
    const finish = gate.finish.bind(gate);
    gate.armDeadline(finish);
    try {
      for (const phase of phases) {
        if (signal.aborted) return; // deadline already fired
        const result = await phase.run(signal);
        if (signal.aborted) return; // deadline fired while this phase was awaiting
        if (result && result.ok === false) {
          const reasonCode = phase.name === "drain-receipts"
            ? ERR_SIDECAR_SHUTDOWN_PERSISTENCE
            : ERR_SIDECAR_SHUTDOWN_FAILED;
          finish(1, reasonCode, `${phase.name}${result.reason ? `: ${result.reason}` : ""}`);
          return;
        }
      }
      log(`mnde.sidecar.shutdown ok in ${Math.max(0, now() - startedAt)}ms`);
      finish(0);
    } catch (error) {
      finish(1, ERR_SIDECAR_SHUTDOWN_FAILED, (error && error.message) || String(error));
    }
  }

  function shutdown() {
    if (started) return inFlight;
    started = true;
    try {
      onBegin();
    } catch (error) {
      log(`${ERR_SIDECAR_SHUTDOWN_FAILED}: begin-drain error — ${(error && error.message) || error}`);
    }
    inFlight = execute();
    return inFlight;
  }

  return {
    shutdown,
    isShuttingDown: () => started,
    // Exposed for tests; the sidecar keeps its own module-level draining flag set
    // by onBegin so request/readiness code paths need no import-time coupling.
    _signal: signal
  };
}
