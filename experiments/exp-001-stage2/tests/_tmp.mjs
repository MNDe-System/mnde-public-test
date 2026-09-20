// Per-test OS temp directory (outside the repository).
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export function tmpDir(prefix = "t") {
  return mkdtempSync(join(tmpdir(), `exp001s2-${prefix}-`));
}
