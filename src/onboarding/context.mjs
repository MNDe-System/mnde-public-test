// Onboarding context.
//
// Everything in the onboarding/discovery/wiring/policy-drafting layers takes an
// explicit context so it can be driven against fixtures with no access to the
// real system. The CLI builds a real context from the process; tests build one
// pointed at temp directories. This layer NEVER makes authority decisions.

import os from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const moduleDir = dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO_ROOT = resolve(moduleDir, "..", "..");

export function buildContext(overrides = {}) {
  const env = overrides.env ?? process.env;
  const platform = overrides.platform ?? process.platform;
  const homedir = overrides.homedir ?? os.homedir();
  const cwd = overrides.cwd ?? process.cwd();
  const repoRoot = overrides.repoRoot ?? DEFAULT_REPO_ROOT;
  const stateDir = overrides.stateDir ?? env.MNDE_STATE_DIR ?? join(homedir, ".mnde");
  const sidecarUrl = overrides.sidecarUrl ?? env.MNDE_SIDECAR_URL ?? "http://127.0.0.1:8787";
  const now = overrides.now ?? (() => new Date().toISOString());
  return { env, platform, homedir, cwd, repoRoot, stateDir, sidecarUrl, now };
}
