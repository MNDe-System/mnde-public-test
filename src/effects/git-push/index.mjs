// git.push — MNDe's first narrow typed production effect.
//
// ─────────────────────────────────────────────────────────────────────────────
// WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT
//
//   Not this:  execute(command, args)          — a process-execution capability
//   This:      executeGitPush({ repository, sourceCommit, targetRef,
//                               expectedOldSha, authorization })
//
// The second exposes one capability: move one branch on one remote from one
// exact SHA to one exact SHA, when a signed authorization said so and the
// authority has not been spent. Everything the subprocess receives is derived
// from signed fields. There is no callback, no command string, no caller-supplied
// flag and no caller-supplied refspec, which is why a subprocess is acceptable
// here and a generic one never would be.
//
// WHY THIS DOES NOT REOPEN F-001. The generic dispatch path in
// executor/index.mjs is still hard-closed and this file does not touch it. What
// makes this path safe is not that it is narrow — narrow would still be
// replayable — but that the authority is DURABLY SPENT before the network effect,
// in a store the executor cannot roll back. If the claim is anything other than
// CLAIMED, nothing is sent. That ordering is the whole of F-001's answer and it
// is the one thing in this file that must never be reordered.
//
// WHAT AN ALLOW STILL DOES NOT MEAN. A signed ALLOW receipt is evidence that
// policy approved a request. It is not permission to act and it never was. This
// effect refuses unless it ALSO has production trust posture, a matching executor
// identity, a local repository that agrees with the authorization, a remote
// observed to be in the exact approved pre-state, and a fresh durable claim.
//
// WHAT IS NOT YET TRUE. The execution evidence written here is UNSIGNED. It is a
// faithful record of what happened, but it is not offline-verifiable the way a
// decision receipt is, and it must not be described as one. Signing it needs the
// executor's receipt-signing key on the dispatch path, which is a separate change.
// ─────────────────────────────────────────────────────────────────────────────

import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { sha256 } from "../../crypto/provider.mjs";
import { evaluateExecutorPosture } from "../../executor-posture-preflight.mjs";
import { isProductionExecutionAuthority, verifyExecutionAuthority } from "../../execution-authority/index.mjs";
import { claimAuthority, deriveClaimRecord, DISPATCH } from "../../freshness/claim.mjs";
import { parseRuntimeProfile } from "../../../shared/runtime-profile.mjs";
import {
  bindRequestToAuthority,
  GIT_PUSH_ACTION,
  validateGitPushParameters
} from "./validate.mjs";
import {
  buildPushArgv,
  buildTransportEnv,
  isAncestor,
  performPush,
  readConfiguredRemoteUrl,
  readRemoteRef,
  resolveLocalCommit
} from "./transport.mjs";

export const EVIDENCE_SCHEMA = "mnde.execution-evidence.v1";

// Terminal outcomes. There are four because there are genuinely four things that
// can be true after a push is attempted, and collapsing the last two into
// "failed" is how a replay gets built later.
export const OUTCOME = Object.freeze({
  EXECUTED: "EXECUTED",                                 // observed post-state equals the approved SHA
  REFUSED: "REFUSED",                                   // nothing was sent
  RECONCILED_NOT_APPLIED: "RECONCILED_NOT_APPLIED",     // sent, did not land, remote read back cleanly
  INDETERMINATE: "INDETERMINATE"                        // outcome unknown; needs a human
});

export const ERR_PROFILE_NOT_PRODUCTION = "ERR_GIT_PUSH_PROFILE_NOT_PRODUCTION";
export const ERR_REMOTE_MISMATCH = "ERR_GIT_PUSH_REMOTE_MISMATCH";
export const ERR_REMOTE_MOVED = "ERR_GIT_PUSH_REMOTE_MOVED";
export const ERR_NOT_FAST_FORWARD = "ERR_GIT_PUSH_NOT_FAST_FORWARD";
export const ERR_AUTHORITY_ALREADY_SPENT = "ERR_GIT_PUSH_AUTHORITY_ALREADY_SPENT";
export const ERR_CLAIM_NOT_ESTABLISHED = "ERR_GIT_PUSH_CLAIM_NOT_ESTABLISHED";
export const ERR_POSTSTATE_MISMATCH = "ERR_GIT_PUSH_POSTSTATE_MISMATCH";
export const ERR_STARTUP_CONFIG = "ERR_GIT_PUSH_STARTUP_CONFIG";

const DEFAULT_TIMEOUT_MS = 30_000;

function nonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

// The caller speaks camelCase; the signed parameters are snake_case. One fixed
// mapping, written out rather than computed, so that a renamed field is a
// compile-time-visible change instead of a silently unbound one.
//
// The key set is exact. Dropping an unrecognized field would let a caller write
// `force: true` and be quietly ignored, which reads to them as a request that
// was honoured. There is no field here that is safe to ignore, so none is.
const REQUEST_KEYS = Object.freeze([
  "authorization", "expectedOldSha", "remote", "remoteUrl", "repository", "sourceCommit", "targetRef"
]);

function normalizeRequest(request) {
  const keys = Object.keys(request).sort();
  if (keys.length !== REQUEST_KEYS.length || keys.some((key, index) => key !== REQUEST_KEYS[index])) {
    return { ok: false, detail: `request fields [${keys.join(", ")}] are not exactly [${[...REQUEST_KEYS].join(", ")}]` };
  }
  return {
    ok: true,
    normalized: {
      expected_old_sha: request.expectedOldSha,
      remote: request.remote,
      remote_url: request.remoteUrl,
      repository: request.repository,
      source_commit: request.sourceCommit,
      target_ref: request.targetRef
    }
  };
}

// What actually happened, decided from the remote rather than from the exit code.
//
// Kept pure and exported because the hardest case to produce on demand is also
// the one that matters most: a transport that neither succeeded nor cleanly
// failed. Every branch below is reachable in a test without having to arrange a
// real network partition.
//
// The rule in one line: the remote is the authority. A push that exited non-zero
// but left the ref at the approved SHA DID happen, and a push that exited zero
// but did not move the ref did not.
export function decidePushOutcome({ pushed, after, approvedSourceCommit, approvedOldSha, targetRef }) {
  // The remote could not be read back. The effect may or may not have landed and
  // nothing here is allowed to guess. The authority stays spent either way.
  if (!after?.ok) {
    return Object.freeze({
      outcome: OUTCOME.INDETERMINATE,
      executed: null,
      reason_code: after?.reason ?? ERR_POSTSTATE_MISMATCH,
      detail: after?.detail ?? "the remote could not be read back after the push"
    });
  }

  if (after.sha === approvedSourceCommit) {
    return Object.freeze({ outcome: OUTCOME.EXECUTED, executed: true, reason_code: null, detail: null });
  }

  if (after.sha === approvedOldSha) {
    // The remote is untouched, so the push demonstrably did not land. No retry:
    // the authority is spent and a fresh authorization is required.
    return Object.freeze({
      outcome: OUTCOME.RECONCILED_NOT_APPLIED,
      executed: false,
      reason_code: pushed?.reason ?? ERR_POSTSTATE_MISMATCH,
      detail: "the push did not land and the remote is unchanged; the authority is spent and must not be reused"
    });
  }

  // A third SHA: something else moved the ref, or the push landed and was then
  // overwritten. Neither "succeeded" nor "did not happen" is true, so neither is
  // claimed.
  return Object.freeze({
    outcome: OUTCOME.INDETERMINATE,
    executed: null,
    reason_code: ERR_POSTSTATE_MISMATCH,
    detail: `${targetRef} is at ${after.sha}, which is neither the approved source ${approvedSourceCommit} nor the approved pre-state ${approvedOldSha}`
  });
}

// Trusted startup configuration. This is the executor process's own wiring, set
// by the operator who deployed it. It is NOT reachable from a request, and
// nothing an agent sends can add to it or change it.
export function createGitPushExecutor(startup = {}) {
  const {
    repoPath,
    namespace,
    authorityBundle,
    authorityBundlePath,
    trustedRootFingerprint,
    environmentId,
    expectedExecutorId,
    allowedSchemes,
    transportEnv = {},
    evidenceDir,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    // The durable claim backend. The trusted startup owns this choice: a caller
    // cannot supply one, and there is no code path that constructs a backend
    // from a request. Production deployments pass the adapter returned by
    // src/freshness/postgres_claim.mjs, whose single-use property is proven in
    // docs/F001-CLAIM-STORE-PROOF.md. Whatever is passed, its `kind` is recorded
    // in the evidence, so a non-durable backend is visible in the audit record
    // rather than indistinguishable from the real one.
    claimBackend = null,
    env = process.env
  } = startup;

  for (const [name, value] of [["repoPath", repoPath], ["namespace", namespace], ["evidenceDir", evidenceDir]]) {
    if (!nonEmptyString(value)) {
      throw Object.assign(new Error(`${ERR_STARTUP_CONFIG}: ${name} is required`), { code: ERR_STARTUP_CONFIG });
    }
  }

  const transport = buildTransportEnv(transportEnv);
  if (!transport.ok) {
    throw Object.assign(new Error(`${transport.reason}: ${transport.detail}`), { code: transport.reason });
  }

  const context = Object.freeze({
    repoPath: resolve(repoPath),
    env: transport.env,
    cwd: resolve(repoPath),
    timeoutMs
  });

  function writeEvidence(evidence) {
    const body = JSON.stringify(evidence, null, 2);
    try {
      mkdirSync(evidenceDir, { recursive: true });
      const path = join(evidenceDir, `git-push-${evidence.execution_id ?? "unidentified"}-${evidence.recorded_at.replace(/[:.]/g, "-")}.json`);
      writeFileSync(path, `${body}\n`, "utf8");
      return path;
    } catch {
      // Evidence that cannot be written must not silently turn into evidence
      // that was never produced, but it also must not mask the outcome.
      return null;
    }
  }

  function refuse(reason, detail, partial = {}) {
    const evidence = {
      schema: EVIDENCE_SCHEMA,
      outcome: OUTCOME.REFUSED,
      action: GIT_PUSH_ACTION,
      reason_code: reason,
      detail: detail ?? null,
      effect_attempted: false,
      recorded_at: new Date().toISOString(),
      ...partial
    };
    const evidencePath = writeEvidence(evidence);
    return Object.freeze({
      ok: false,
      outcome: OUTCOME.REFUSED,
      executed: false,
      reason_code: reason,
      detail: detail ?? null,
      evidence: Object.freeze(evidence),
      evidencePath
    });
  }

  async function executeGitPush(request = {}) {
    if (!request || typeof request !== "object" || Array.isArray(request)) {
      return refuse(ERR_STARTUP_CONFIG, "request must be an object");
    }

    // ── 1. Production trust posture ──────────────────────────────────────────
    // A production effect requires a production deployment. Outside it, this
    // refuses rather than degrading, because the trust anchors that make the
    // authorization meaningful are exactly what is missing.
    const profile = parseRuntimeProfile(env.MNDE_PROFILE);
    if (!profile.ok || profile.profile !== "production") {
      return refuse(ERR_PROFILE_NOT_PRODUCTION,
        `a protected git.push requires MNDE_PROFILE=production; got ${profile.ok ? profile.profile : profile.reason_code}`);
    }
    const posture = evaluateExecutorPosture({
      verifyAuthorityBundlePath: authorityBundlePath,
      verifyAuthorityBundleLoaded: authorityBundle !== undefined && authorityBundle !== null,
      verifyTrustedRootFingerprint: trustedRootFingerprint,
      verifyEnvironmentId: environmentId,
      verifyExpectedExecutorId: expectedExecutorId,
      verifyRequireExecutor: true,
      repoRoot: context.repoPath
    });
    if (!posture.ok) {
      const first = posture.violations[0];
      return refuse(first.reason_code, first.detail);
    }

    // ── 2. The authorization is authentic, executor-bound and current ────────
    const authority = await verifyExecutionAuthority(request.authorization, {
      authorityBundle,
      trustedRootFingerprint,
      environmentId,
      expectedExecutorId,
      namespace
    });
    if (!authority.ok || !isProductionExecutionAuthority(authority)) {
      return refuse(authority.reason ?? "ERR_RECEIPT_UNVERIFIED", authority.detail ?? null);
    }

    const identity = {
      execution_id: authority.execution_id,
      grant_id: authority.grant_id,
      subject: authority.subject,
      executor_id: authority.executor_id,
      authority_digest: authority.authority_digest,
      receipt_hash: authority.receipt_hash,
      policy: authority.policy
    };

    // ── 3. It authorizes THIS action ─────────────────────────────────────────
    if (authority.action !== GIT_PUSH_ACTION) {
      return refuse("ERR_GIT_PUSH_ACTION_MISMATCH", `authorization is for '${authority.action}', not '${GIT_PUSH_ACTION}'`, identity);
    }

    // ── 4. The signed parameters are a push MNDe is willing to build ─────────
    const validated = validateGitPushParameters(authority.parameters, { allowedSchemes });
    if (!validated.ok) return refuse(validated.reason, validated.detail, identity);
    const p = validated.parameters;

    // ── 5. The caller asked for exactly what was authorized ──────────────────
    const shaped = normalizeRequest(request);
    if (!shaped.ok) return refuse("ERR_GIT_PUSH_REQUEST_BINDING", shaped.detail, identity);
    const bound = bindRequestToAuthority(shaped.normalized, p);
    if (!bound.ok) return refuse(bound.reason, bound.detail, identity);

    const authorized = Object.freeze({
      repository: p.repository,
      remote: p.remote,
      remote_url: p.remote_url,
      source_commit: p.source_commit,
      target_ref: p.target_ref,
      expected_old_sha: p.expected_old_sha
    });

    // ── 6. The repository we are standing in is the one that was authorized ──
    const configuredRemote = await readConfiguredRemoteUrl(p.remote, context);
    if (!configuredRemote.ok) return refuse(configuredRemote.reason, configuredRemote.detail, { ...identity, authorized });
    if (configuredRemote.url !== p.remote_url) {
      return refuse(ERR_REMOTE_MISMATCH,
        `local remote '${p.remote}' points at '${configuredRemote.url}', not the authorized '${p.remote_url}'`,
        { ...identity, authorized });
    }

    // ── 7 & 8. Both approved SHAs exist locally and are commits ──────────────
    for (const sha of [p.source_commit, p.expected_old_sha]) {
      const local = await resolveLocalCommit(sha, context);
      if (!local.ok) return refuse(local.reason, local.detail, { ...identity, authorized });
    }

    // ── 9. The remote is observed, independently, in the approved pre-state ──
    const before = await readRemoteRef(p.remote_url, p.target_ref, context);
    if (!before.ok) return refuse(before.reason, before.detail, { ...identity, authorized });
    if (before.sha !== p.expected_old_sha) {
      return refuse(ERR_REMOTE_MOVED,
        `${p.target_ref} is at ${before.sha}; the authorization approved a push from ${p.expected_old_sha}`,
        { ...identity, authorized, observed: { before: before.sha } });
    }

    // ── 10. The approved move is a fast-forward ──────────────────────────────
    // --force-with-lease alone would permit rewriting history that happened to
    // still be at the leased SHA. It is an exact-state guard, not a direction
    // guard, so the direction is checked here.
    const ancestry = await isAncestor(p.expected_old_sha, p.source_commit, context);
    if (!ancestry.ok) return refuse(ancestry.reason, ancestry.detail, { ...identity, authorized, observed: { before: before.sha } });
    if (ancestry.ancestor !== true) {
      return refuse(ERR_NOT_FAST_FORWARD,
        `${p.expected_old_sha} is not an ancestor of ${p.source_commit}; only fast-forward updates are authorized`,
        { ...identity, authorized, observed: { before: before.sha } });
    }

    // ── 11. Spend the authority, durably, BEFORE anything leaves the process ─
    // Everything above this line is a read. Everything below is irreversible.
    const derived = deriveClaimRecord(authority, { namespace });
    if (!derived.ok) return refuse(derived.reason, "the claim record could not be derived from the verified authority", { ...identity, authorized, observed: { before: before.sha } });

    const claim = await claimAuthority(claimBackend, derived.record);
    const claimMeta = {
      namespace,
      backend_kind: claimBackend?.kind ?? null,
      decision: claim.decision,
      note: claim.note ?? null
    };
    if (claim.decision === DISPATCH.SPENT) {
      // The one case the whole design exists for. A second presentation of the
      // same authority sends nothing, ever, whatever else is true.
      return refuse(ERR_AUTHORITY_ALREADY_SPENT,
        "this execution authority has already been spent; it cannot authorize a second push",
        { ...identity, authorized, observed: { before: before.sha }, claim: claimMeta });
    }
    if (claim.decision !== DISPATCH.CLAIMED) {
      // NO_BACKEND, BACKEND_UNAVAILABLE and UNKNOWN all land here and all send
      // nothing. UNKNOWN in particular must never be retried: the claim may have
      // landed, and a retry would be exactly the replay F-001 names.
      return refuse(ERR_CLAIM_NOT_ESTABLISHED,
        `the durable single-use claim was not established (${claim.decision}); nothing was sent`,
        { ...identity, authorized, observed: { before: before.sha }, claim: claimMeta });
    }

    // ── 12. THE EFFECT ───────────────────────────────────────────────────────
    const argv = buildPushArgv({
      remoteUrl: p.remote_url,
      sourceCommit: p.source_commit,
      targetRef: p.target_ref,
      expectedOldSha: p.expected_old_sha
    });
    const pushed = await performPush(argv, context);

    // ── 13. Believe the remote, not the exit code ────────────────────────────
    // Exit 0 is the subprocess's opinion. The effect is what the remote says it
    // is, so it is read back independently and that observation is what the
    // evidence records.
    const after = await readRemoteRef(p.remote_url, p.target_ref, context);

    const base = {
      schema: EVIDENCE_SCHEMA,
      action: GIT_PUSH_ACTION,
      ...identity,
      authorized,
      claim: { ...claimMeta, record_digest: sha256(JSON.stringify(derived.record)) },
      transport: {
        executable: "git",
        argv,
        shell: false,
        exit_code: pushed.exit_code ?? null,
        stderr: (pushed.stderr ?? "").slice(0, 4096)
      },
      effect_attempted: true,
      observed: { before: before.sha, after: after.ok ? after.sha : null },
      recorded_at: new Date().toISOString()
    };

    const verdict = decidePushOutcome({
      pushed,
      after,
      approvedSourceCommit: p.source_commit,
      approvedOldSha: p.expected_old_sha,
      targetRef: p.target_ref
    });
    const evidence = { ...base, outcome: verdict.outcome, reason_code: verdict.reason_code, detail: verdict.detail };
    const evidencePath = writeEvidence(evidence);
    return Object.freeze({
      ok: verdict.outcome === OUTCOME.EXECUTED,
      outcome: verdict.outcome,
      executed: verdict.executed,
      reason_code: verdict.reason_code,
      detail: verdict.detail,
      evidence: Object.freeze(evidence),
      evidencePath
    });
  }

  return Object.freeze({ executeGitPush, action: GIT_PUSH_ACTION });
}

export default createGitPushExecutor;
