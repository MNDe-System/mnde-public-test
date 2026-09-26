// TEST SUPPORT ONLY — see ./git_push_cli_counting_hooks.mjs.

import { appendFileSync } from "node:fs";

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
