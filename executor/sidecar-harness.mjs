// Test/demo harness: start and stop a real MNDe sidecar.
//
// This is NOT part of the @mnde/executor public API. In real usage the sidecar
// runs as its own long-lived process and your code just points the executor at
// its URL. The harness exists so `npm run executor-demo`, `npm run test:executor`,
// and the examples are one-command runnable against a genuine sidecar + real
// signed receipts.

import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { bootstrapReceiptKeys } from "../scripts/bootstrap_dev_receipt_keys.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataRoot = process.env.MNDE_HOME ? resolve(process.env.MNDE_HOME) : repoRoot;

export async function startMndeSidecar({
  url = "http://127.0.0.1:8787",
  testerId = "EXEC-DEMO-001",
  installationId = "EXEC-INSTALL-001",
  env: extraEnv = {}
} = {}) {
  // Fresh-clone safe: generate local receipt signing keys + signed local authority
  // if they don't exist yet (idempotent). Without this the sidecar refuses to boot.
  bootstrapReceiptKeys({ repoRoot: dataRoot });

  const logsRoot = join(dataRoot, "mnde-receipts", "_sidecar-logs");
  mkdirSync(logsRoot, { recursive: true });

  // Per-start nonce echoed back by /readyz. Readiness only counts when the
  // responder proves it is the child we just spawned — otherwise an unrelated
  // process already bound to the port (e.g. a dev sidecar on the default 8787)
  // would silently become the system under test.
  const instanceId = globalThis.crypto.randomUUID();

  const env = {
    ...process.env,
    MNDE_RECEIPT_LOG: join(logsRoot, "sidecar-receipts.jsonl"),
    MNDE_AUTH_AUDIT_LOG: join(logsRoot, "auth-audit.jsonl"),
    MNDE_RECEIPT_HMAC_SECRET: "demo-legacy-signature-key-000000000001",
    MNDE_RECEIPT_HMAC_KEY_ID: "demo-legacy-signature-key",
    MNDE_INLINE_REFUSAL_RECEIPTS: "1", // return REFUSE receipts inline so the wrapper can store + verify them
    MNDE_RECEIPT_DURABILITY_MODE: "strict_audit",
    MNDE_WORKER_POOL_SIZE: "1",
    MNDE_WORKER_QUEUE_MAX_DEPTH: "16",
    MNDE_TESTER_ID: testerId,
    MNDE_INSTALLATION_ID: installationId,
    // v1 makes policy-engine the sidecar default. These harness-based demos/tests
    // exercise the legacy GPU pipeline, so pin the legacy compatibility engine
    // explicitly unless an ambient or caller value selects a different engine.
    MNDE_DECISION_ENGINE: process.env.MNDE_DECISION_ENGINE ?? "legacy",
    MNDE_HARNESS_INSTANCE_ID: instanceId,
    // Bind where the caller said it would poll. Without this, a url on a
    // non-default port silently spawns a sidecar on 8787 and polls the wrong one.
    MNDE_BIND_PORT: new URL(url).port || "8787",
    // F1: the runtime refuses to start without an explicit MNDE_PROFILE. This is
    // the test/demo harness — choose local explicitly; callers that need the
    // production gate pass MNDE_PROFILE via extraEnv, which overrides just below.
    MNDE_PROFILE: process.env.MNDE_PROFILE ?? "local",
    // Caller overrides last (e.g. MNDE_PROFILE, MNDE_DECISION_ENGINE, MNDE_PE_POLICY, MNDE_BIND_PORT).
    ...extraEnv
  };

  const child = spawn(process.execPath, ["mnde-local-sidecar.mjs"], {
    cwd: repoRoot,
    env,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true
  });

  let stdout = "";
  let stderr = "";
  child.stdout?.on("data", (chunk) => {
    stdout += chunk.toString();
  });
  child.stderr?.on("data", (chunk) => {
    stderr += chunk.toString();
  });

  await waitReady(url, child, () => stderr, instanceId);

  return {
    url,
    getStdout() {
      return stdout;
    },
    getStderr() {
      return stderr;
    },
    async stop() {
      if (child.exitCode !== null) return;
      child.kill();
      await new Promise((done) => {
        const timeout = setTimeout(() => {
          try {
            child.kill("SIGKILL");
          } catch {
            /* already gone */
          }
          done();
        }, 3000);
        child.once("exit", () => {
          clearTimeout(timeout);
          done();
        });
      });
    }
  };
}

async function waitReady(url, child, getStderr, instanceId) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`MNDe sidecar exited early (code ${child.exitCode}):\n${getStderr()}`);
    }
    try {
      const response = await fetch(`${url}/readyz`);
      const body = await response.json();
      if (body?.ok === true) {
        if (body.harness_instance_id !== instanceId) {
          // A responder that does not echo our nonce is NOT the child we
          // spawned. Fail closed instead of running the tests against it.
          try {
            child.kill();
          } catch {
            /* already gone */
          }
          throw new Error(
            `Another process is already serving ${url} (readyz answered without this harness's instance id). ` +
              `Stop the process bound to that port, or point the harness at a free port via MNDE_BIND_PORT + url.`
          );
        }
        return;
      }
    } catch (error) {
      if (error instanceof Error && /already serving/.test(error.message)) throw error;
      /* not up yet */
    }
    await new Promise((done) => setTimeout(done, 200));
  }
  throw new Error(`MNDe sidecar readiness timed out:\n${getStderr()}`);
}
