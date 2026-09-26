// TEST SUPPORT ONLY — preload for tests/test_git_push_cli.mjs child processes:
//   node --import <this file> bin/mnde-git-push.mjs request.json
//
// Wraps the typed executor module the CLI imports so every construction and
// every executeGitPush() call is appended to MNDE_TEST_CLI_CALL_LOG. The suite
// counts those lines: one CLI invocation must construct the executor at most
// once and call executeGitPush() at most once, whatever the outcome. That is the
// guard against a retry, a "second opinion" call or a loop being added later.
//
// The wrapper imports the module the CLI actually resolved (source tree or the
// built dist/ tree alike), so the package test exercises the shipped files.

import { registerHooks } from "node:module";

const TARGET = "/src/effects/git-push/index.mjs";
const WRAPPER = new URL("./git_push_cli_counting_executor.mjs", import.meta.url).href;

registerHooks({
  resolve(specifier, context, nextResolve) {
    const resolved = nextResolve(specifier, context);
    if (resolved.url.startsWith("file:") && resolved.url.endsWith(TARGET)) {
      return { ...resolved, url: `${WRAPPER}?real=${encodeURIComponent(resolved.url)}`, shortCircuit: true };
    }
    return resolved;
  }
});
