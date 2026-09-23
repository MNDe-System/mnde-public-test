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
// EXECUTION EVIDENCE IS SIGNED, AND IT IS NOT A RECEIPT. Every outcome that
// names a verified authorization is recorded as a signed, offline-verifiable
// record of what the executor OBSERVED — see ./evidence.mjs. It answers a
// different question from the authorization it descends from: not "was this
// authorized?" but "what actually happened?". The two carry different schema
// strings and neither is accepted where the other is required.
//
// WHAT IS STILL NOT TRUE. Refusals that occur BEFORE an authorization verifies
// have no execution id or approved effect to bind to, so they are recorded
// locally and unsigned. The local record also keeps fields the signed one
// deliberately omits, notably git's stderr, which can carry remote URLs and
// credential-helper chatter and so stays out of the portable record.
// ─────────────────────────────────────────────────────────────────────────────

import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readdirSync, readFileSync, writeFileSync, writeSync } from "node:fs";
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
import { buildExecutionEvidenceBody, signExecutionEvidence } from "./evidence.mjs";
import {
  buildPushArgv,
  buildTransportEnv,
  createStagingRepository,
  isAncestor,
  performPush,
  readConfiguredRemoteUrl,
  readRemoteRef,
  removeStagingRepository,
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
export const ERR_EXECUTION_START_NOT_RECORDED = "ERR_GIT_PUSH_EXECUTION_START_NOT_RECORDED";

export const EXECUTION_START_SCHEMA = "mnde.git-push-execution-start.v1";

const DEFAULT_TIMEOUT_MS = 30_000;

function startRecordName(executionId) {
  return `git-push-${executionId}.started.json`;
}

// Recovery view: what does THIS executor's evidence directory say happened to one
// execution? Read-only; it never re-spends, retries or clears anything.
//
//   NOT_STARTED   no durable start record: no push was begun for this execution.
//                 If the claim store shows the authority spent, it was consumed
//                 without an effect and needs a fresh authorization.
//   EXECUTED / RECONCILED_NOT_APPLIED / INDETERMINATE
//                 the recorded post-transport outcome.
//   INDETERMINATE a start was recorded but no outcome ever was (the process died
//                 between starting the push and recording what the remote said):
//                 whether the ref moved is unknown, so a human reconciles it
//                 against the remote. Never promoted to success, never retried.
export function classifyGitPushExecution({ evidenceDir, executionId } = {}) {
  if (!nonEmptyString(evidenceDir) || !nonEmptyString(executionId)) {
    return Object.freeze({ condition: "UNKNOWN_REQUEST", review_required: true });
  }
  const started = existsSync(join(evidenceDir, startRecordName(executionId)));
  let outcome = null;
  let names = [];
  try { names = readdirSync(evidenceDir); } catch { names = []; }
  for (const name of names) {
    if (!name.startsWith(`git-push-${executionId}-`) || !name.endsWith(".json") || name.endsWith(".signed.json")) continue;
    let record;
    try { record = JSON.parse(readFileSync(join(evidenceDir, name), "utf8")); } catch { continue; }
    if (record?.execution_id !== executionId || record.effect_attempted !== true) continue;
    outcome = record.outcome;
  }
  if (outcome) {
    return Object.freeze({ condition: outcome, started, review_required: outcome === OUTCOME.INDETERMINATE, retry_permitted: false });
  }
  if (started) {
    return Object.freeze({ condition: OUTCOME.INDETERMINATE, started, review_required: true, retry_permitted: false,
      detail: "an execution start was recorded but no outcome was: reconcile against the remote" });
  }
  return Object.freeze({ condition: "NOT_STARTED", started, review_required: false, retry_permitted: false });
}

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
    // The executor's own signing identity, and a signer that keeps the private
    // key to itself. Both are required: this effect exists to produce evidence
    // of what it did, and evidence nobody signed is a log entry. There is no
    // configuration in which the push runs and the evidence goes unsigned.
    executorIdentity = null,
    executorSigner = null,
    env = process.env
  } = startup;

  for (const [name, value] of [["repoPath", repoPath], ["namespace", namespace], ["evidenceDir", evidenceDir]]) {
    if (!nonEmptyString(value)) {
      throw Object.assign(new Error(`${ERR_STARTUP_CONFIG}: ${name} is required`), { code: ERR_STARTUP_CONFIG });
    }
  }

  if (!executorIdentity || typeof executorIdentity !== "object" || typeof executorSigner?.sign !== "function") {
    throw Object.assign(
      new Error(`${ERR_STARTUP_CONFIG}: executorIdentity and executorSigner are required so execution evidence can be signed`),
      { code: ERR_STARTUP_CONFIG }
    );
  }
  for (const field of ["executor_id", "key_id", "credential_id", "environment_id", "credential"]) {
    if (executorIdentity[field] === undefined || executorIdentity[field] === null) {
      throw Object.assign(new Error(`${ERR_STARTUP_CONFIG}: executorIdentity.${field} is required`), { code: ERR_STARTUP_CONFIG });
    }
  }
  // A signing identity that does not match the executor this deployment claims
  // to be would sign truthfully and still attest to the wrong process.
  if (nonEmptyString(expectedExecutorId) && executorIdentity.executor_id !== expectedExecutorId) {
    throw Object.assign(
      new Error(`${ERR_STARTUP_CONFIG}: executorIdentity.executor_id does not match expectedExecutorId`),
      { code: ERR_STARTUP_CONFIG }
    );
  }
  if (nonEmptyString(environmentId) && executorIdentity.environment_id !== environmentId) {
    throw Object.assign(
      new Error(`${ERR_STARTUP_CONFIG}: executorIdentity.environment_id does not match environmentId`),
      { code: ERR_STARTUP_CONFIG }
    );
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

  // Sign the portable record of what happened.
  //
  // Signed evidence descends from an authorization, so it can only be produced
  // once one has verified: before that there is no execution id, no grant id
  // and no approved effect to bind to, and signing a record of "a malformed
  // request arrived" would bind nothing worth verifying. Those early refusals
  // still write the local unsigned record; they simply have no portable form.
  // Everything from the action check onward — every refusal that names a real
  // authorization, and every post-transport outcome — is signed.
  async function signEvidence(evidence) {
    if (!evidence.authorized || !nonEmptyString(evidence.execution_id)) {
      return { envelope: null, reason: "no verified authorization to bind evidence to" };
    }
    const built = buildExecutionEvidenceBody({
      execution_id: evidence.execution_id,
      grant_id: evidence.grant_id,
      authorization_receipt_hash: evidence.receipt_hash ?? null,
      authority_digest: evidence.authority_digest ?? null,
      executor_id: evidence.executor_id,
      environment_id: executorIdentity.environment_id,
      key_id: executorIdentity.key_id,
      credential_id: executorIdentity.credential_id,
      authority_bundle_fingerprint: trustedRootFingerprint ?? null,
      repository: evidence.authorized.repository,
      remote: evidence.authorized.remote,
      remote_url: evidence.authorized.remote_url,
      target_ref: evidence.authorized.target_ref,
      expected_old_sha: evidence.authorized.expected_old_sha,
      approved_new_sha: evidence.authorized.source_commit,
      observed_before_sha: evidence.observed?.before ?? null,
      observed_after_sha: evidence.observed?.after ?? null,
      claim: {
        decision: evidence.claim?.decision ?? null,
        namespace: evidence.claim?.namespace ?? null,
        record_digest: evidence.claim?.record_digest ?? null
      },
      effect_attempted: evidence.effect_attempted === true,
      outcome: evidence.outcome,
      reason_code: evidence.reason_code ?? null,
      recorded_at: evidence.recorded_at
    });
    if (!built.ok) return { envelope: null, reason: built.detail ?? built.reason_code };

    const signed = await signExecutionEvidence(built.body, { identity: executorIdentity, signer: executorSigner });
    if (!signed.ok) return { envelope: null, reason: signed.detail ?? signed.reason_code };
    return { envelope: signed.envelope, reason: null };
  }

  // Write the signed envelope beside the local record. A failure to persist it
  // is reported rather than swallowed: evidence that was not stored must not
  // look like evidence that was.
  function writeSignedEvidence(envelope, executionId, recordedAt) {
    if (!envelope) return null;
    try {
      mkdirSync(evidenceDir, { recursive: true });
      const path = join(evidenceDir, `git-push-${executionId}-${recordedAt.replace(/[:.]/g, "-")}.signed.json`);
      writeFileSync(path, `${JSON.stringify(envelope, null, 2)}\n`, "utf8");
      return path;
    } catch {
      return null;
    }
  }

  // One file per execution id, created exclusively and fsynced. It records only
  // that an attempt began and what it was bound to; the outcome, when there is
  // one, lives in the ordinary evidence record.
  function recordExecutionStart({ execution_id, grant_id, executor_id, authorized, namespace: ns }) {
    if (!nonEmptyString(execution_id)) return { ok: false, detail: "no execution id" };
    let fd = null;
    try {
      mkdirSync(evidenceDir, { recursive: true });
      const path = join(evidenceDir, startRecordName(execution_id));
      fd = openSync(path, "wx");
      writeSync(fd, `${JSON.stringify({
        schema: EXECUTION_START_SCHEMA,
        execution_id,
        grant_id: grant_id ?? null,
        executor_id: executor_id ?? null,
        namespace: ns,
        authorized,
        started_at: new Date().toISOString()
      }, null, 2)}\n`);
      fsyncSync(fd);
      return { ok: true, path };
    } catch (error) {
      return { ok: false, detail: String(error?.code ?? error?.message ?? error) };
    } finally {
      if (fd !== null) { try { closeSync(fd); } catch { /* already closed */ } }
    }
  }

  async function settle(evidence, result) {
    const { envelope, reason } = await signEvidence(evidence);
    const local = { ...evidence, evidence_signed: envelope !== null, evidence_unsigned_reason: reason };
    const evidencePath = writeEvidence(local);
    const signedEvidencePath = writeSignedEvidence(envelope, local.execution_id ?? "unidentified", local.recorded_at);
    return Object.freeze({
      ...result,
      evidence: Object.freeze(local),
      evidencePath,
      signedEvidence: envelope,
      signedEvidencePath
    });
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
    return settle(evidence, {
      ok: false,
      outcome: OUTCOME.REFUSED,
      executed: false,
      reason_code: reason,
      detail: detail ?? null
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

    // ── 6b. Leave the local repository ───────────────────────────────────────
    // Everything from here on — the commit checks, both remote reads and the push
    // itself — runs in an executor-owned staging repository that reads the local
    // repository's objects but never its configuration. See
    // createStagingRepository in ./transport.mjs for the attacks this closes.
    const staging = await createStagingRepository(context.repoPath, context);
    if (!staging.ok) return refuse(staging.reason, staging.detail, { ...identity, authorized });
    try {
      return await effectFromStaging(staging.context, { authority, identity, authorized, p });
    } finally {
      removeStagingRepository(staging);
    }
  }

  async function effectFromStaging(stage, { authority, identity, authorized, p }) {
    // ── 7 & 8. Both approved SHAs exist locally and are commits ──────────────
    for (const sha of [p.source_commit, p.expected_old_sha]) {
      const local = await resolveLocalCommit(sha, stage);
      if (!local.ok) return refuse(local.reason, local.detail, { ...identity, authorized });
    }

    // ── 9. The remote is observed, independently, in the approved pre-state ──
    const before = await readRemoteRef(p.remote_url, p.target_ref, stage);
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
    const ancestry = await isAncestor(p.expected_old_sha, p.source_commit, stage);
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

    // ── 11b. Durably record that the effect is starting ──────────────────────
    // Claim-before-effect deliberately spends authority before the push, so a
    // crash here can leave "spent, never sent" or "sent, outcome never recorded".
    // Those need opposite handling and are indistinguishable unless the start is
    // written — and fsynced — before anything leaves the process. If it cannot
    // be, nothing is sent: an effect whose start cannot be recorded cannot later
    // be classified, and the authority is already spent either way.
    const started = recordExecutionStart({ ...identity, authorized, namespace });
    if (!started.ok) {
      return refuse(ERR_EXECUTION_START_NOT_RECORDED,
        `the execution start could not be durably recorded (${started.detail}); nothing was sent`,
        { ...identity, authorized, observed: { before: before.sha }, claim: claimMeta });
    }

    // ── 12. THE EFFECT ───────────────────────────────────────────────────────
    const argv = buildPushArgv({
      remoteUrl: p.remote_url,
      sourceCommit: p.source_commit,
      targetRef: p.target_ref,
      expectedOldSha: p.expected_old_sha
    });
    const pushed = await performPush(argv, stage);

    // ── 13. Believe the remote, not the exit code ────────────────────────────
    // Exit 0 is the subprocess's opinion. The effect is what the remote says it
    // is, so it is read back independently and that observation is what the
    // evidence records.
    const after = await readRemoteRef(p.remote_url, p.target_ref, stage);

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
    return settle(evidence, {
      ok: verdict.outcome === OUTCOME.EXECUTED,
      outcome: verdict.outcome,
      executed: verdict.executed,
      reason_code: verdict.reason_code,
      detail: verdict.detail
    });
  }

  return Object.freeze({ executeGitPush, action: GIT_PUSH_ACTION });
}

export default createGitPushExecutor;
