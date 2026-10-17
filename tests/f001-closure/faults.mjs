// TEST SUPPORT ONLY — preload for the F-001 closure harness
// (`node --import tests/f001-closure/faults.mjs bin/mnde-git-push.mjs ...`).
//
// Selected by MNDE_F001_FAULT. Every fault but one is a REAL process death:
// SIGKILL delivered to this process at an exact boundary, so no finally block,
// no flush and no exit handler runs. The single exception is `sql-lost-ack`, which
// is labelled as a simulated network fault in the evidence, not a crash.
//
//   sql-before-claim       die before first_claim is sent
//   sql-before-commit      die with the claim transaction open, COMMIT not sent
//   sql-during-commit      send COMMIT and die without reading the reply
//   sql-after-commit       die after the server acknowledged COMMIT
//   sql-lost-ack           (simulated) COMMIT acknowledged, reply reported as lost
//   fs-before-ledger       die before the executor-local ledger entry is created
//   fs-before-start-record die after the ledger entry, before the start record
//   fs-after-start-record  die after the start record and its directory are fsynced
//   exec-before-push       die immediately before `git push` is spawned
//   fs-evidence-before-rename  die with the signed evidence fsynced as *.tmp only
//   fs-evidence-after-rename   die after the rename, before the directory fsync
//   stdout-before-response die after evidence is durable, before the caller hears
//
// The pg-level faults work by redirecting the adapter's dynamic `import("pg")` to
// ./pg_wrapper.mjs, which wraps the real driver; the adapter itself is unmodified.

import fs from "node:fs";
import cp from "node:child_process";
import { registerHooks, syncBuiltinESMExports } from "node:module";

const fault = process.env.MNDE_F001_FAULT ?? "";
const log = (line) => { try { if (process.env.MNDE_F001_LOG) fs.appendFileSync(process.env.MNDE_F001_LOG, `${line}\n`); } catch { /* best effort */ } };
export const die = (where) => { log(`SIGKILL@${where}`); process.kill(process.pid, "SIGKILL"); };

if (fault.startsWith("sql-")) {
  const wrapper = new URL("./pg_wrapper.mjs", import.meta.url).href;
  registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier === "pg" && !String(context.parentURL ?? "").endsWith("pg_wrapper.mjs")) return { url: wrapper, shortCircuit: true };
      return nextResolve(specifier, context);
    }
  });
}

const originals = { openSync: fs.openSync, closeSync: fs.closeSync, fsyncSync: fs.fsyncSync, renameSync: fs.renameSync, execFile: cp.execFile };
let startFd = null;
let startClosed = false;

if (fault === "fs-before-ledger") {
  fs.openSync = (...a) => { if (/spent-ledger\/grant-.*\.json$/.test(String(a[0])) && a[1] === "wx") die(fault); return originals.openSync(...a); };
}
if (fault === "fs-before-start-record") {
  fs.openSync = (...a) => { if (String(a[0]).endsWith(".started.json") && a[1] === "wx") die(fault); return originals.openSync(...a); };
}
if (fault === "fs-after-start-record") {
  fs.openSync = (...a) => {
    const fd = originals.openSync(...a);
    if (String(a[0]).endsWith(".started.json") && a[1] === "wx") startFd = fd;
    return fd;
  };
  fs.closeSync = (fd) => { originals.closeSync(fd); if (fd === startFd) { startFd = null; startClosed = true; } };
  // The first fsync after the start file closed is its directory entry.
  fs.fsyncSync = (fd) => { originals.fsyncSync(fd); if (startClosed) die(fault); };
}
if (fault === "exec-before-push") {
  cp.execFile = (file, args, ...rest) => { if (Array.isArray(args) && args[0] === "push") die(fault); return originals.execFile(file, args, ...rest); };
}
if (fault === "fs-evidence-before-rename") {
  fs.renameSync = (from, to) => { if (String(from).endsWith(".signed.json.tmp")) die(fault); return originals.renameSync(from, to); };
}
if (fault === "fs-evidence-after-rename") {
  fs.renameSync = (from, to) => { originals.renameSync(from, to); if (String(from).endsWith(".signed.json.tmp")) die(fault); };
}
if (fault === "stdout-before-response") {
  const write = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk, ...rest) => { if (String(chunk).includes("mnde.git-push-cli-result")) die(fault); return write(chunk, ...rest); };
}
syncBuiltinESMExports();
