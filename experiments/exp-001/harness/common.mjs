// EXP-001 Stage 1 harness — shared helpers.
//
// Stage 1 tests MNDe exactly as it exists at the pinned commit. It adds NO
// GitHub machinery and modifies NO MNDe source. Every helper here only boots the
// real sidecar, drives the real executor, and uses MNDe's own crypto/canonical
// modules. Evidence is written verbatim; nothing is normalized to look better.

import { createServer } from "node:net";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const expRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const evidenceDir = join(expRoot, "evidence");
export const receiptsDir = join(expRoot, "receipts");
mkdirSync(evidenceDir, { recursive: true });
mkdirSync(receiptsDir, { recursive: true });

export async function freePort() {
  const server = createServer();
  await new Promise((done, reject) => server.once("error", reject).listen(0, "127.0.0.1", done));
  const port = server.address().port;
  await new Promise((done) => server.close(done));
  return port;
}

export function tmpDir(prefix) {
  return mkdtempSync(join(tmpdir(), `exp001-${prefix}-`));
}

export function writeEvidence(name, value) {
  const p = join(evidenceDir, name);
  writeFileSync(p, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  return p;
}

// A three-state result record. INCONCLUSIVE is never silently promoted to PASS.
export function record(id, conjunct, verdict, expected, observed, detail = {}) {
  if (!["PASS", "FAIL", "INCONCLUSIVE"].includes(verdict)) {
    throw new Error(`invalid verdict ${verdict} for ${id}`);
  }
  return { id, conjunct, verdict, expected, observed, detail, at: new Date().toISOString() };
}
