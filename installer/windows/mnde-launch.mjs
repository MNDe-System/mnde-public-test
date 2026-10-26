#!/usr/bin/env node
// One-click launcher for the MNDe dashboard (the Windows "MNDe" desktop shortcut
// runs this; it works the same on any OS).
//
//   - sidecar already answering /readyz  -> just open the dashboard
//   - otherwise start the EXISTING scripts/start-sidecar.mjs (detached, hidden),
//     wait for /readyz, then open the dashboard
//
// It adds no server, UI, or trust path: it only starts the same process
// `npm run sidecar` starts, bound to 127.0.0.1, and opens the page that sidecar
// already serves. Paths come from this file's location, never from the working
// directory, so it is safe to launch from anywhere.

import { spawn, spawnSync } from "node:child_process";
import { closeSync, mkdirSync, openSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const HOST = "127.0.0.1";
const PORT = Number.parseInt(process.env.MNDE_BIND_PORT ?? "8787", 10);
const URL_BASE = `http://${HOST}:${PORT}/`;
const READY_TIMEOUT_MS = Number.parseInt(process.env.MNDE_LAUNCH_TIMEOUT_MS ?? "40000", 10);
const dataRoot = process.env.MNDE_HOME ? resolve(process.env.MNDE_HOME) : repoRoot;
const logsDir = join(resolve(process.env.MNDE_RECEIPTS_DIR ?? join(dataRoot, "mnde-receipts")), "_sidecar-logs");
const logPath = join(logsDir, "launcher-sidecar.log");
const lockPath = join(logsDir, "launcher.lock");
const LOCK_STALE_MS = 60_000;

function fail(message) {
  process.stderr.write(`MNDe: ${message}\n`);
  if (process.platform === "win32" && process.env.MNDE_LAUNCH_NO_DIALOG !== "1") {
    const text = `${message}\n\nLog: ${logPath}`.replace(/'/g, "''");
    spawnSync(
      "powershell.exe",
      ["-NoProfile", "-Command", `Add-Type -AssemblyName PresentationFramework; [void][System.Windows.MessageBox]::Show('${text}','MNDe')`],
      { windowsHide: true, stdio: "ignore" }
    );
  }
  process.exit(1);
}

async function isReady() {
  try {
    const response = await fetch(`${URL_BASE}readyz`, { signal: AbortSignal.timeout(1500) });
    return (await response.json())?.ok === true;
  } catch {
    return false;
  }
}

// Exclusive-create lock so two quick double-clicks do not both start a sidecar.
// Stale after 60s. The port bind is the real guard; this only avoids a noisy loser.
function takeLock() {
  try {
    writeFileSync(lockPath, String(process.pid), { flag: "wx" });
    return true;
  } catch {
    try {
      if (Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS) {
        rmSync(lockPath, { force: true });
        writeFileSync(lockPath, String(process.pid), { flag: "wx" });
        return true;
      }
    } catch {
      /* lost the race */
    }
    return false;
  }
}

function openBrowser(url) {
  if (process.env.MNDE_LAUNCH_NO_BROWSER === "1") return;
  const [cmd, args] =
    process.platform === "win32" ? ["rundll32.exe", ["url.dll,FileProtocolHandler", url]]
    : process.platform === "darwin" ? ["open", [url]]
    : ["xdg-open", [url]];
  const child = spawn(cmd, args, { detached: true, stdio: "ignore", windowsHide: true });
  child.on("error", () => {});
  child.unref();
}

function startSidecar() {
  const fd = openSync(logPath, "a");
  const child = spawn(process.execPath, [join(repoRoot, "scripts", "start-sidecar.mjs")], {
    cwd: repoRoot,
    detached: true,
    windowsHide: true,
    stdio: ["ignore", fd, fd]
  });
  child.on("error", () => {});
  child.unref();
  closeSync(fd);
  return child;
}

const MIN_NODE = Number.parseInt(process.env.MNDE_LAUNCH_MIN_NODE ?? "24", 10); // package.json engines.node
if (Number.parseInt(process.versions.node, 10) < MIN_NODE) fail(`Node.js ${MIN_NODE} or later is required (found ${process.versions.node}).`);
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) fail(`Invalid MNDE_BIND_PORT: ${process.env.MNDE_BIND_PORT}`);

if (await isReady()) {
  openBrowser(URL_BASE);
  process.stdout.write(`MNDe sidecar already running — opened ${URL_BASE}\n`);
  process.exit(0);
}

mkdirSync(logsDir, { recursive: true });
let child = null;
const ownsLock = takeLock();
if (ownsLock) child = startSidecar();
let childExited = false;
child?.on("exit", () => { childExited = true; });

const deadline = Date.now() + READY_TIMEOUT_MS;
let ready = false;
while (Date.now() < deadline) {
  if (await isReady()) { ready = true; break; }
  // We started it and it died (bad key, port held by something else, ...): stop waiting.
  if (childExited && !(await isReady())) break;
  await new Promise((done) => setTimeout(done, 300));
}
if (ownsLock) rmSync(lockPath, { force: true });

if (!ready) fail(`The sidecar did not become ready at ${URL_BASE}readyz. See the log for details.`);
openBrowser(URL_BASE);
process.stdout.write(`MNDe sidecar ready — opened ${URL_BASE}\n`);
process.exit(0);
