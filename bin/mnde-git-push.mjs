#!/usr/bin/env node
// mnde-git-push — the supported production caller of the typed git.push executor.
//
//   mnde-git-push <request.json>
//
// A thin adapter and nothing more. It reads one request file, loads the
// executor's startup configuration from the deployment environment, constructs
// createGitPushExecutor() once, calls executeGitPush() once, and prints the
// executor's result as one line of JSON. Whether a push happens is decided
// entirely inside the executor: authorization, request binding, the durable
// single-use claim, the typed transport, the observed post-state and the signed
// evidence all live below this file, and this file reaches none of them directly.
//
// Its own process, not a subcommand of `mnde`, so the process that holds the
// executor's signing key loads only the executor and its startup loader, not the
// onboarding CLI's discovery and file-rewriting code.
//
// It never retries. A second executeGitPush() for the same authority is either
// refused by the claim or, after an ambiguous outcome, exactly the replay F-001
// is about. An operator who wants another attempt needs a fresh authorization.
//
// Exit codes (docs/GIT-PUSH-CLI.md):
//   0 EXECUTED                the remote was observed at the approved SHA
//   1 REFUSED                 nothing was sent
//   2 INDETERMINATE           sent; what the remote holds is unknown: a human reconciles
//   3 invalid input           usage, unreadable file, bad JSON, wrong fields
//   4 startup/config failure  the executor was not constructed
//   5 internal error          unexpected exception; if executor_invoked is true, reconcile
//   6 RECONCILED_NOT_APPLIED  sent, did not land, remote unchanged; authority spent

import { readFileSync } from "node:fs";

import { createGitPushExecutor, OUTCOME, REQUEST_KEYS } from "../src/effects/git-push/index.mjs";
import { loadGitPushStartup } from "../src/effects/git-push/startup.mjs";

const RESULT_SCHEMA = "mnde.git-push-cli-result.v1";

const EXIT = Object.freeze({
  EXECUTED: 0,
  REFUSED: 1,
  INDETERMINATE: 2,
  INVALID_INPUT: 3,
  STARTUP_FAILED: 4,
  INTERNAL_ERROR: 5,
  RECONCILED_NOT_APPLIED: 6
});

function emit(exitCode, body) {
  process.stdout.write(`${JSON.stringify({ schema: RESULT_SCHEMA, exit_code: exitCode, ...body })}\n`);
  process.exitCode = exitCode;
}

function failure(exitCode, outcome, reason_code, detail, extra = {}) {
  emit(exitCode, { outcome, ok: false, executed: false, reason_code, detail, ...extra });
}

function readRequest(args) {
  if (args.length !== 1 || args[0].length === 0 || args[0].startsWith("-")) {
    return { ok: false, reason_code: "ERR_GIT_PUSH_CLI_USAGE", detail: "usage: mnde-git-push <request.json>" };
  }
  let text;
  try {
    text = readFileSync(args[0], "utf8");
  } catch (error) {
    return { ok: false, reason_code: "ERR_GIT_PUSH_CLI_REQUEST_UNREADABLE", detail: `request file could not be read (${error?.code ?? "error"})` };
  }
  let request;
  try {
    request = JSON.parse(text);
  } catch {
    return { ok: false, reason_code: "ERR_GIT_PUSH_CLI_REQUEST_NOT_JSON", detail: "request file is not valid JSON" };
  }
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    return { ok: false, reason_code: "ERR_GIT_PUSH_CLI_REQUEST_FIELDS", detail: "request must be a JSON object" };
  }
  // The executor's own key list. Startup settings such as claimBackend or
  // executorSigner have no field here, so naming one is refused, never read.
  const keys = Object.keys(request).sort();
  if (keys.length !== REQUEST_KEYS.length || keys.some((key, index) => key !== REQUEST_KEYS[index])) {
    return { ok: false, reason_code: "ERR_GIT_PUSH_CLI_REQUEST_FIELDS", detail: `request fields [${keys.join(", ")}] are not exactly [${REQUEST_KEYS.join(", ")}]` };
  }
  return { ok: true, request };
}

function exitFor(result) {
  if (result?.outcome === OUTCOME.EXECUTED && result.ok === true && result.executed === true) return EXIT.EXECUTED;
  if (result?.outcome === OUTCOME.REFUSED) return EXIT.REFUSED;
  if (result?.outcome === OUTCOME.INDETERMINATE) return EXIT.INDETERMINATE;
  if (result?.outcome === OUTCOME.RECONCILED_NOT_APPLIED) return EXIT.RECONCILED_NOT_APPLIED;
  return EXIT.INTERNAL_ERROR;
}

// The executor's result, as the executor stated it. The local evidence record is
// not copied whole because it carries git's stderr, which can hold remote URLs
// and credential-helper output; it stays in the file at evidence_path.
function report(result) {
  const evidence = result.evidence ?? {};
  return {
    outcome: result.outcome ?? null,
    ok: result.ok === true,
    executed: result.executed ?? null,
    reason_code: result.reason_code ?? null,
    detail: result.detail ?? null,
    executor_invoked: true,
    effect_attempted: evidence.effect_attempted === true,
    execution_id: evidence.execution_id ?? null,
    grant_id: evidence.grant_id ?? null,
    executor_id: evidence.executor_id ?? null,
    authorized: evidence.authorized ?? null,
    observed: evidence.observed ?? null,
    claim: evidence.claim ?? null,
    evidence_path: result.evidencePath ?? null,
    signed_evidence_path: result.signedEvidencePath ?? null,
    signed_evidence: result.signedEvidence ?? null
  };
}

async function main() {
  const input = readRequest(process.argv.slice(2));
  if (!input.ok) return failure(EXIT.INVALID_INPUT, "INVALID_INPUT", input.reason_code, input.detail);

  let loaded;
  try {
    loaded = await loadGitPushStartup(process.env);
  } catch (error) {
    return failure(EXIT.STARTUP_FAILED, "STARTUP_FAILED", "ERR_GIT_PUSH_CLI_CONFIG", String(error?.message ?? error));
  }
  if (!loaded.ok) return failure(EXIT.STARTUP_FAILED, "STARTUP_FAILED", loaded.reason_code, loaded.detail);

  try {
    let executor;
    try {
      executor = createGitPushExecutor(loaded.startup);
    } catch (error) {
      return failure(EXIT.STARTUP_FAILED, "STARTUP_FAILED", error?.code ?? "ERR_GIT_PUSH_STARTUP_CONFIG", String(error?.message ?? error));
    }

    let result;
    try {
      result = await executor.executeGitPush(input.request);
    } catch (error) {
      // The executor normally returns every outcome. A throw here may have come
      // after the push began, so it is never reported as "nothing happened".
      return failure(EXIT.INTERNAL_ERROR, "INTERNAL_ERROR", "ERR_GIT_PUSH_CLI_INTERNAL", String(error?.message ?? error), {
        executed: null,
        executor_invoked: true,
        review_required: true
      });
    }
    return emit(exitFor(result), report(result));
  } finally {
    loaded.signer.destroy?.();
  }
}

main().catch((error) => {
  failure(EXIT.INTERNAL_ERROR, "INTERNAL_ERROR", "ERR_GIT_PUSH_CLI_INTERNAL", String(error?.message ?? error), { executed: null });
});
