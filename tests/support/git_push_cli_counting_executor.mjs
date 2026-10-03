// TEST SUPPORT ONLY — see ./git_push_cli_counting_hooks.mjs.

import { appendFileSync } from "node:fs";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { installStartFault } from "./git_push_start_faults.mjs";

const realUrl = new URL(import.meta.url).searchParams.get("real");
if (!realUrl) throw new Error("counting executor loaded without the real module URL");
// The query keeps this import from being redirected back to this wrapper.
const real = await import(`${realUrl}?mnde-cli-probe=real`);

function log(event) {
  const path = process.env.MNDE_TEST_CLI_CALL_LOG;
  if (path) appendFileSync(path, `${event}\n`, "utf8");
}

export const OUTCOME = real.OUTCOME;
export const REQUEST_KEYS = real.REQUEST_KEYS;
export const EVIDENCE_SCHEMA = real.EVIDENCE_SCHEMA;

export function createGitPushExecutor(startup) {
  log("construct");
  if (process.env.MNDE_TEST_START_FAULT) installStartFault(process.env.MNDE_TEST_START_FAULT, log);
  // Faults exist only in this test preload, after identity readiness. Real git,
  // observation, claim ordering, settle() and CLI exit mapping remain in use.
  const fault = process.env.MNDE_TEST_EVIDENCE_FAULT;
  if (fault === "signer") {
    startup = { ...startup, executorSigner: { sign() { log("evidence-fault"); throw new Error("test signer unavailable"); } } };
  } else if (fault) {
    const original = { open: fs.openSync, write: fs.writeFileSync, sync: fs.fsyncSync, rename: fs.renameSync };
    const signedFds = new Set();
    let published = false;
    const fail = () => { log("evidence-fault"); throw Object.assign(new Error("injected evidence I/O failure"), { code: "EIO" }); };
    fs.openSync = (...args) => {
      const fd = original.open(...args);
      if (typeof args[0] === "string" && args[0].endsWith(".signed.json.tmp")) signedFds.add(fd);
      else signedFds.delete(fd);
      return fd;
    };
    fs.writeFileSync = (...args) => {
      if (fault === "write" && signedFds.has(args[0])) fail();
      return original.write(...args);
    };
    fs.fsyncSync = (fd) => {
      if ((fault === "file-sync" && signedFds.has(fd)) || (fault === "directory-sync" && published && fs.fstatSync(fd).isDirectory())) fail();
      return original.sync(fd);
    };
    fs.renameSync = (...args) => {
      if (String(args[1]).endsWith(".signed.json")) {
        if (fault === "rename") fail();
        const value = original.rename(...args);
        published = true;
        return value;
      }
      return original.rename(...args);
    };
    syncBuiltinESMExports();
  }
  const executor = real.createGitPushExecutor(startup);
  return Object.freeze({
    ...executor,
    async executeGitPush(request) {
      log("execute");
      return executor.executeGitPush(request);
    }
  });
}

export default createGitPushExecutor;
