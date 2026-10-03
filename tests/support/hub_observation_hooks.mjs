// Test-only observation of real executor/provider calls. No production seams.
import "./claim_backend_hooks.mjs";
import { registerHooks } from "node:module";

registerHooks({
  load(url, context, nextLoad) {
    const result = nextLoad(url, context);
    if (!url.endsWith("/src/effects/git-push/index.mjs") && !url.endsWith("/src/effects/git-push/credential-provider.mjs")) return result;
    let source = String(result.source);
    source = source.replace("async function executeGitPush(request = {}) {", "async function executeGitPush(request = {}) { if (globalThis.__hubObservation) globalThis.__hubObservation.executions++; ");
    source = source.replace("async function acquire({ repository, remoteUrl, executorId } = {}) {", "async function acquire({ repository, remoteUrl, executorId } = {}) { if (globalThis.__hubObservation) { globalThis.__hubObservation.acquisitions++; await globalThis.__hubObservation.beforeAcquire?.(); } ");
    return { ...result, source };
  }
});
