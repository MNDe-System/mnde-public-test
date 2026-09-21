// Test-only worker for the SQLite claim backend's STARTUP path.
//
// The factory is synchronous: once it is called this process's event loop is
// blocked until it returns or throws. That is precisely why the competing lock
// has to be owned by the parent — only an independent OS process can release it
// while this one is inside SQLite. The worker therefore does one thing: it opens
// the REAL factory on command and reports what happened, with monotonic timings.
//
// It speaks over the IPC channel only. Nothing here reimplements the factory's
// pragma sequence; importing the real one is the point of the regression test.

import { createRequire } from "node:module";

import { createSqliteClaimBackend } from "../../experiments/exp-001-stage2/src/claim_store.mjs";

// Same lazy-require convention as claim_store.mjs, so this file does not make
// node:sqlite a load-time requirement of the module graph.
const require_ = createRequire(import.meta.url);

const nowMs = () => Number(process.hrtime.bigint() / 1000000n);

function send(message) {
  if (typeof process.send !== "function") throw new Error("E_NO_IPC_CHANNEL");
  process.send({ ...message, at: nowMs() });
}

function describeError(error) {
  return {
    code: error?.code ?? null,
    errcode: typeof error?.errcode === "number" ? error.errcode : null,
    // SQLite reports extended result codes; the low byte is the primary code.
    errcodeBase: typeof error?.errcode === "number" ? error.errcode & 0xff : null,
    errstr: error?.errstr ?? null,
    message: String(error?.message ?? error),
    stack: error?.stack ?? null
  };
}

let backend = null;

// Narrowly scoped, test-only instrumentation. Observing the factory's own
// cleanup while this process is still alive is the only way to tell cleanup
// from process exit, which would release the handle regardless.
//   "observe" — count real close() calls and let them through.
//   "throw"   — call the real close(), then throw a sentinel, so the test can
//               prove the factory still propagates the ORIGINAL failure.
function runWithCloseProbe(mode, run) {
  if (!mode) return run({ closes: 0 });
  const DatabaseSync = require_("node:sqlite").DatabaseSync;
  const original = DatabaseSync.prototype.close;
  const state = { closes: 0 };
  DatabaseSync.prototype.close = function probedClose(...args) {
    state.closes += 1;
    const result = original.apply(this, args);
    if (mode === "throw") throw new Error("E_PROBE_CLOSE_SENTINEL");
    return result;
  };
  try {
    return run(state);
  } finally {
    DatabaseSync.prototype.close = original;
  }
}

function handleOpen({ dbPath, probeClose }) {
  if (typeof dbPath !== "string" || dbPath.length === 0) throw new Error("E_MALFORMED_COMMAND: open needs dbPath");
  if (probeClose !== undefined && probeClose !== "observe" && probeClose !== "throw") {
    throw new Error(`E_MALFORMED_COMMAND: unknown probeClose ${JSON.stringify(probeClose)}`);
  }
  // Sent before the blocking call, so the parent knows the factory is about to
  // run. It is evidence of intent, not proof the OS has scheduled SQLite yet —
  // the test asserts on the measured wait, not on this message alone.
  send({ type: "opening" });
  const started = nowMs();
  runWithCloseProbe(probeClose, (state) => {
    try {
      backend = createSqliteClaimBackend({ dbPath });
      send({ type: "opened", durationMs: nowMs() - started, closes: state.closes, kind: backend.kind, production: backend.production });
    } catch (error) {
      backend = null;
      send({ type: "open-error", durationMs: nowMs() - started, closes: state.closes, ...describeError(error) });
    }
  });
}

async function handleClaim({ record }) {
  if (!backend) throw new Error("E_NO_BACKEND: claim before a successful open");
  const result = await backend.claim(record);
  send({ type: "claimed", status: result?.status ?? null, collided_on: result?.collided_on ?? null });
}

function handleClose() {
  if (backend) backend.close();
  backend = null;
  send({ type: "closed" });
}

process.on("message", (message) => {
  Promise.resolve()
    .then(() => {
      if (!message || typeof message !== "object" || typeof message.cmd !== "string") {
        throw new Error(`E_MALFORMED_COMMAND: ${JSON.stringify(message)}`);
      }
      switch (message.cmd) {
        case "open": return handleOpen(message);
        case "claim": return handleClaim(message);
        case "close": return handleClose();
        case "exit": return process.exit(0);
        default: throw new Error(`E_MALFORMED_COMMAND: unknown cmd ${JSON.stringify(message.cmd)}`);
      }
    })
    .catch((error) => { send({ type: "worker-error", ...describeError(error) }); });
});

send({ type: "ready" });
