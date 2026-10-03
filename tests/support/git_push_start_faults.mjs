// TEST SUPPORT ONLY. Installed in an isolated CLI child after startup readiness.
// All operations are real except the selected deterministic persistence failure.
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";

export function installStartFault(mode, log) {
  const original = { open: fs.openSync, write: fs.writeFileSync, sync: fs.fsyncSync, close: fs.closeSync };
  let startFd = null;
  let directoryFd = null;
  let fileClosed = false;
  let directorySynced = false;
  const fail = (stage) => {
    log(`start-fault:${stage}`);
    throw Object.assign(new Error(`injected start ${stage} failure`), { code: "EIO" });
  };
  fs.openSync = (...args) => {
    const fd = original.open(...args);
    if (String(args[0]).endsWith(".started.json") && args[1] === "wx") {
      startFd = fd;
      log("start:create");
    } else if (fileClosed && !directorySynced && fs.fstatSync(fd).isDirectory()) directoryFd = fd;
    return fd;
  };
  fs.writeFileSync = (...args) => {
    if (startFd !== null && args[0] === startFd) {
      if (mode === "write") fail("write");
      const value = original.write(...args);
      log("start:write");
      return value;
    }
    return original.write(...args);
  };
  fs.fsyncSync = (fd) => {
    if (fd === startFd) {
      if (mode === "file-sync") fail("file-sync");
      original.sync(fd);
      log("start:file-sync");
    } else if (fd === directoryFd) {
      if (mode === "directory-sync") fail("directory-sync");
      original.sync(fd);
      directorySynced = true;
      log("start:directory-sync");
    } else original.sync(fd);
  };
  fs.closeSync = (fd) => {
    if (fd === startFd) {
      original.close(fd);
      startFd = null;
      fileClosed = true;
      // Model a close that reports failure after releasing the descriptor.
      if (mode === "close") fail("close");
      log("start:close");
    } else if (fd === directoryFd) {
      original.close(fd);
      directoryFd = null;
      if (directorySynced) {
        log("start:directory-close");
        if (mode === "kill-before-push") {
          // Parent observes the log and kills us after all durability calls,
          // while the real executor has not yet reached performPush().
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
        }
      }
    } else original.close(fd);
  };
  syncBuiltinESMExports();
}
