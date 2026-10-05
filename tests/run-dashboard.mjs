import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const dataRoot = mkdtempSync(join(tmpdir(), "mnde-app-dashboard-test-"));
try {
  const result = spawnSync(process.execPath, [fileURLToPath(new URL("./test_dashboard.mjs", import.meta.url))], {
    env: { ...process.env, MNDE_HOME: dataRoot }, stdio: "inherit"
  });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
} finally {
  rmSync(dataRoot, { recursive: true, force: true });
}
