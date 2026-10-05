import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const work = mkdtempSync(join(tmpdir(), "mnde-app-built-"));
const app = join(work, "app");
const home = join(work, "data");
cpSync(join(root, "dist"), app, { recursive: true });
mkdirSync(home);
const installed = process.platform === "win32"
  ? spawnSync(process.env.ComSpec || "cmd.exe", ["/d", "/s", "/c", "npm ci --omit=dev"],
    { cwd: app, encoding: "utf8" })
  : spawnSync("npm", ["ci", "--omit=dev"], { cwd: app, encoding: "utf8" });
assert.equal(installed.status, 0, `Clean bundle install failed: ${installed.stderr}`);
const port = 18000 + Math.floor(Math.random() * 30000);
const child = spawn(process.execPath, ["scripts/start-app.mjs"], {
  cwd: app,
  env: { ...process.env, MNDE_HOME: home, MNDE_BIND_PORT: String(port),
    MNDE_HUB_DISCOVERY: "0", MNDE_FELINE: "0" },
  stdio: ["pipe", "pipe", "pipe"]
});
let output = "";
child.stdout.on("data", chunk => { output += chunk; });
child.stderr.on("data", chunk => { output += chunk; });
try {
  let ready = false;
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline && child.exitCode === null) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/readyz`, { signal: AbortSignal.timeout(1000) });
      if ((await response.json()).ok === true) { ready = true; break; }
    } catch { /* still starting */ }
    await new Promise(done => setTimeout(done, 200));
  }
  assert(ready, `Built app did not become ready: ${output.slice(-2000)}`);
  const page = await fetch(`http://127.0.0.1:${port}/`);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /MNDe Hub/);
  console.log("Built app launch and dashboard smoke: PASS");
} finally {
  if (child.exitCode === null) {
    child.stdin.write("stop\n");
    await Promise.race([
      new Promise(done => child.once("exit", done)),
      new Promise(done => setTimeout(done, 6000))
    ]);
    if (child.exitCode === null) child.kill();
  }
  rmSync(work, { recursive: true, force: true });
}
