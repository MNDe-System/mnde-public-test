// Signed execution evidence for the git.push typed effect.
//
//   npm run test:git-push-execution-evidence
//
// WHAT THIS SUITE IS ABOUT. Not "was the push authorized" — that is the
// authorization's job and the git.push suite's subject. This is about the
// separate question of what the executor OBSERVED, and whether that observation
// survives being carried away from the machine that made it.
//
// So almost every case below does the same thing: take a real signed record,
// change exactly one field, and require verification to refuse. A record whose
// fields can be edited without breaking verification is not evidence, it is a
// suggestion.
//
// WHAT IS REAL HERE. Real git repositories over file://, real pushes, real
// executor-bound authorizations through the production verifier, and real
// ED25519 signatures chained to a root-signed executor credential. The claim
// backend is in-memory, for the reasons the git.push suite states.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { createGitPushExecutor, OUTCOME } from "../src/effects/git-push/index.mjs";
import {
  buildExecutionEvidenceBody,
  EVIDENCE_ERRORS,
  EVIDENCE_OUTCOME,
  EXECUTION_EVIDENCE_ENVELOPE_SCHEMA,
  EXECUTION_EVIDENCE_SCHEMA,
  signExecutionEvidence,
  verifyExecutionEvidence
} from "../src/effects/git-push/evidence.mjs";
import {
  ENVIRONMENT_ID,
  EXECUTOR_ID,
  gitPushAuthorization,
  inMemoryClaimBackend,
  makeRepositories,
  productionTrust,
  pushParameters,
  readJson
} from "./support/git_push_fixtures.mjs";

const NAMESPACE = "mnde-git-push-evidence-namespace";

let passed = 0;
let failed = 0;

const pendingCleanup = [];
function cleanUp() {
  while (pendingCleanup.length) {
    const dir = pendingCleanup.pop();
    try { rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }); } catch { /* best effort */ }
  }
}

async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    cleanUp();
  }
}

async function withProfile(value, fn) {
  const had = Object.hasOwn(process.env, "MNDE_PROFILE");
  const previous = process.env.MNDE_PROFILE;
  if (value === undefined) delete process.env.MNDE_PROFILE;
  else process.env.MNDE_PROFILE = value;
  try {
    return await fn();
  } finally {
    if (had) process.env.MNDE_PROFILE = previous;
    else delete process.env.MNDE_PROFILE;
  }
}

// Deep clone that keeps the envelope editable, so a case can change one field.
function mutate(envelope, path, value) {
  const copy = structuredClone(envelope);
  const parts = path.split(".");
  let node = copy;
  for (const part of parts.slice(0, -1)) node = node[part];
  node[parts.at(-1)] = value;
  return copy;
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "mnde-git-push-evidence-"));
  const trust = await productionTrust(dir);
  const otherTrust = await productionTrust(dir, { authorityId: "mnde-evidence-other-authority" });

  // Verification inputs a relying party would hold: the published bundle and the
  // root fingerprint obtained out of band. Nothing else.
  const verifyWith = (envelope, overrides = {}) =>
    verifyExecutionEvidence(envelope, {
      authorityBundle: trust.bundle,
      trustedRootFingerprint: trust.fingerprint,
      now: "2026-06-15T00:00:00.000Z",
      ...overrides
    });

  let caseIndex = 0;
  function fixture(startupOverrides = {}, backendOptions = {}) {
    caseIndex += 1;
    const caseDir = join(dir, `case-${caseIndex}`);
    pendingCleanup.push(caseDir);
    const repos = makeRepositories(caseDir);
    const backend = inMemoryClaimBackend({ namespace: NAMESPACE, ...backendOptions });
    const executor = createGitPushExecutor({
      repoPath: repos.localPath,
      namespace: NAMESPACE,
      authorityBundle: trust.bundle,
      authorityBundlePath: trust.bundlePath,
      trustedRootFingerprint: trust.fingerprint,
      environmentId: ENVIRONMENT_ID,
      expectedExecutorId: EXECUTOR_ID,
      allowedSchemes: ["file"],
      evidenceDir: join(caseDir, "evidence"),
      claimBackend: backend,
      executorIdentity: trust.executor.identity,
      executorSigner: trust.executor.signer,
      ...startupOverrides
    });
    return { repos, backend, executor, caseDir };
  }

  function requestFor(parameters, authorization, overrides = {}) {
    return {
      repository: parameters.repository,
      remote: parameters.remote,
      remoteUrl: parameters.remote_url,
      sourceCommit: parameters.source_commit,
      targetRef: parameters.target_ref,
      expectedOldSha: parameters.expected_old_sha,
      authorization,
      ...overrides
    };
  }

  // One successful push, reused by the tamper cases below.
  async function executedRun(overrides = {}) {
    const { repos, executor, backend } = fixture(overrides);
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    const result = await withProfile("production", () =>
      executor.executeGitPush(requestFor(parameters, authorization)));
    return { repos, executor, backend, parameters, authorization, result };
  }

  console.log("── 1. a real push produces signed evidence of what was observed ──");

  await test("a successful exact push produces EXECUTED evidence whose observed SHA is the approved SHA", async () => {
    const { repos, result } = await executedRun();
    assert.equal(result.outcome, OUTCOME.EXECUTED, `expected EXECUTED, got ${result.outcome} (${result.reason_code}: ${result.detail})`);
    const envelope = result.signedEvidence;
    assert.ok(envelope, "a successful push must produce signed evidence");
    assert.equal(envelope.schema_version, EXECUTION_EVIDENCE_ENVELOPE_SCHEMA);
    assert.equal(envelope.evidence.schema_version, EXECUTION_EVIDENCE_SCHEMA);
    assert.equal(envelope.evidence.outcome, EVIDENCE_OUTCOME.EXECUTED);
    assert.equal(envelope.evidence.approved_new_sha, repos.commits[1]);
    assert.equal(envelope.evidence.observed_after_sha, repos.commits[1],
      "EXECUTED evidence must record the ref as read back, not as hoped for");
    assert.equal(envelope.evidence.observed_before_sha, repos.commits[0]);
    assert.equal(envelope.evidence.effect_attempted, true);
  });

  await test("the evidence signature verifies against the published bundle and pinned root", async () => {
    const { result } = await executedRun();
    const verdict = await verifyWith(result.signedEvidence);
    assert.equal(verdict.ok, true, `verification failed: ${verdict.reason_code} ${verdict.detail ?? ""}`);
    assert.equal(verdict.executed, true);
    assert.equal(verdict.executor_id, EXECUTOR_ID);
  });

  await test("the evidence binds the authorization it descends from", async () => {
    const { result } = await executedRun();
    const e = result.signedEvidence.evidence;
    for (const field of ["execution_id", "grant_id", "authorization_receipt_hash", "authority_digest"]) {
      assert.ok(typeof e[field] === "string" && e[field].length > 0, `${field} must be bound into the evidence`);
    }
    assert.equal(e.claim.decision, "CLAIMED", "the evidence must record that the single-use authority was consumed");
    assert.equal(e.action, "git.push");
  });

  await test("the signed evidence carries no transport stderr and no key material", async () => {
    const { result } = await executedRun();
    const serialized = JSON.stringify(result.signedEvidence.evidence);
    assert.ok(!serialized.includes("PRIVATE KEY"), "evidence must never carry key material");
    assert.equal("transport" in result.signedEvidence.evidence, false,
      "git stderr stays in the local record and out of the portable one");
    // The local record still has it, so operators lose nothing.
    assert.ok(readJson(result.evidencePath).transport, "the local record should still carry the transport detail");
  });

  console.log("\n── 2. changing any bound field breaks verification ──");

  // Fields whose mutation must break the signature. Each is a value a forger
  // would want to change: which repository, which branch, which commit, whose
  // authorization, which grant.
  const signatureBoundFields = [
    ["evidence.repository", "file:/tmp/some-other-repository"],
    ["evidence.remote", "not-origin"],
    ["evidence.remote_url", "file:/tmp/elsewhere.git"],
    ["evidence.target_ref", "refs/heads/production"],
    ["evidence.expected_old_sha", "b".repeat(40)],
    ["evidence.execution_id", "exec-someone-elses"],
    ["evidence.grant_id", "grant-someone-elses"],
    ["evidence.authorization_receipt_hash", "c".repeat(64)],
    ["evidence.authority_digest", "d".repeat(64)],
    ["evidence.claim.decision", "SPENT"],
    ["evidence.claim.record_digest", "e".repeat(64)],
    ["evidence.reason_code", "SOMETHING_ELSE"],
    ["evidence.recorded_at", "2030-01-01T00:00:00.000Z"],
    ["evidence.authority_bundle_fingerprint", "f".repeat(64)]
  ];

  for (const [path, value] of signatureBoundFields) {
    await test(`changing ${path.replace("evidence.", "")} invalidates verification`, async () => {
      const { result } = await executedRun();
      const tampered = mutate(result.signedEvidence, path, value);
      const verdict = await verifyWith(tampered);
      assert.equal(verdict.ok, false, `${path} was mutated and verification still passed`);
      assert.equal(verdict.reason_code, EVIDENCE_ERRORS.SIGNATURE_INVALID,
        `expected a signature failure for ${path}, got ${verdict.reason_code}`);
    });
  }

  await test("changing the observed final SHA alone is refused as incoherent", async () => {
    const { result } = await executedRun();
    const tampered = mutate(result.signedEvidence, "evidence.observed_after_sha", "a".repeat(40));
    const verdict = await verifyWith(tampered);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.INCOHERENT,
      "EXECUTED whose observed SHA is not the approved SHA must be refused before any signature check");
  });

  await test("changing the approved new SHA alone is refused as incoherent", async () => {
    const { result } = await executedRun();
    const tampered = mutate(result.signedEvidence, "evidence.approved_new_sha", "a".repeat(40));
    const verdict = await verifyWith(tampered);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.INCOHERENT);
  });

  await test("rewriting BOTH SHAs to stay self-consistent still fails on the signature", async () => {
    // The sharpest version of the tamper test: the forged record is internally
    // coherent, so only the signature can catch it. If this passes, the
    // coherence rule is doing all the work and the signature none.
    const { result } = await executedRun();
    const forged = "a".repeat(40);
    let tampered = mutate(result.signedEvidence, "evidence.approved_new_sha", forged);
    tampered = mutate(tampered, "evidence.observed_after_sha", forged);
    const verdict = await verifyWith(tampered);
    assert.equal(verdict.ok, false, "a self-consistent forgery must still be caught by the signature");
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.SIGNATURE_INVALID);
  });

  console.log("\n── 3. the evidence cannot be re-attributed to another executor ──");

  await test("changing the executor id invalidates verification", async () => {
    const { result } = await executedRun();
    const tampered = mutate(result.signedEvidence, "evidence.executor_id", "mnde:test:prod:executor:attacker:99");
    const verdict = await verifyWith(tampered);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.CREDENTIAL_INVALID,
      "the credential is checked against the executor the body names");
  });

  await test("changing the key id invalidates verification", async () => {
    const { result } = await executedRun();
    const tampered = mutate(result.signedEvidence, "evidence.key_id", "some-other-key");
    const verdict = await verifyWith(tampered);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.IDENTITY_MISMATCH);
  });

  await test("changing the credential id invalidates verification", async () => {
    const { result } = await executedRun();
    const tampered = mutate(result.signedEvidence, "evidence.credential_id", "some-other-credential");
    const verdict = await verifyWith(tampered);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.IDENTITY_MISMATCH);
  });

  await test("a verifier pinning a different executor refuses valid evidence", async () => {
    const { result } = await executedRun();
    const verdict = await verifyWith(result.signedEvidence, { expectedExecutorId: "mnde:test:prod:executor:other:02" });
    assert.equal(verdict.ok, false);
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.IDENTITY_MISMATCH);
  });

  await test("evidence signed under one authority does not verify under another", async () => {
    const { result } = await executedRun();
    const verdict = await verifyExecutionEvidence(result.signedEvidence, {
      authorityBundle: otherTrust.bundle,
      trustedRootFingerprint: otherTrust.fingerprint,
      now: "2026-06-15T00:00:00.000Z"
    });
    assert.equal(verdict.ok, false, "a different trust root must not accept this evidence");
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.CREDENTIAL_INVALID);
  });

  await test("a substituted credential does not let a foreign key sign evidence", async () => {
    const { result } = await executedRun();
    const tampered = structuredClone(result.signedEvidence);
    tampered.credential = structuredClone(otherTrust.executor.identity.credential);
    const verdict = await verifyWith(tampered);
    assert.equal(verdict.ok, false);
    assert.ok(
      [EVIDENCE_ERRORS.CREDENTIAL_INVALID, EVIDENCE_ERRORS.IDENTITY_MISMATCH].includes(verdict.reason_code),
      `expected the swapped credential to be rejected, got ${verdict.reason_code}`
    );
  });

  console.log("\n── 4. malformed evidence fails closed ──");

  const malformed = [
    ["a null envelope", null],
    ["a string", "not-an-envelope"],
    ["an array", []],
    ["an envelope with no signature", { schema_version: EXECUTION_EVIDENCE_ENVELOPE_SCHEMA, evidence: {}, credential: {} }]
  ];

  for (const [label, value] of malformed) {
    await test(`${label} is refused rather than throwing`, async () => {
      const verdict = await verifyWith(value);
      assert.equal(verdict.ok, false);
      assert.ok(typeof verdict.reason_code === "string" && verdict.reason_code.length > 0);
    });
  }

  await test("an unknown envelope schema is refused", async () => {
    const { result } = await executedRun();
    const tampered = mutate(result.signedEvidence, "schema_version", "mnde.something-else.v9");
    const verdict = await verifyWith(tampered);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.SCHEMA);
  });

  await test("a smuggled extra field is refused rather than ignored", async () => {
    const { result } = await executedRun();
    const tampered = structuredClone(result.signedEvidence);
    tampered.evidence.also_allowed = true;
    const verdict = await verifyWith(tampered);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.INVALID);
  });

  await test("a missing bound field is refused rather than defaulted", async () => {
    const { result } = await executedRun();
    const tampered = structuredClone(result.signedEvidence);
    delete tampered.evidence.target_ref;
    const verdict = await verifyWith(tampered);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.INVALID);
  });

  await test("evidence for another action is refused by this verifier", async () => {
    const { result } = await executedRun();
    const tampered = mutate(result.signedEvidence, "evidence.action", "github.merge_pull_request");
    const verdict = await verifyWith(tampered);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.INVALID);
  });

  console.log("\n── 5. a refusal can never be dressed up as an execution ──");

  await test("a body claiming EXECUTED without a matching observation cannot even be built", async () => {
    const built = buildExecutionEvidenceBody({
      execution_id: "exec-1", grant_id: "grant-1",
      executor_id: EXECUTOR_ID, environment_id: ENVIRONMENT_ID,
      key_id: "k", credential_id: "c",
      repository: "file:/tmp/r", remote: "origin", remote_url: "file:/tmp/r.git",
      target_ref: "refs/heads/main",
      expected_old_sha: "a".repeat(40),
      approved_new_sha: "b".repeat(40),
      observed_before_sha: "a".repeat(40),
      observed_after_sha: "a".repeat(40), // the ref never moved
      effect_attempted: true,
      outcome: EVIDENCE_OUTCOME.EXECUTED,
      recorded_at: "2026-06-14T00:00:00.000Z"
    });
    assert.equal(built.ok, false, "EXECUTED must be unbuildable when the remote did not reach the approved SHA");
    assert.equal(built.reason_code, EVIDENCE_ERRORS.INCOHERENT);
  });

  await test("a body claiming EXECUTED with no attempt cannot be built", async () => {
    const built = buildExecutionEvidenceBody({
      execution_id: "exec-1", grant_id: "grant-1",
      executor_id: EXECUTOR_ID, environment_id: ENVIRONMENT_ID,
      key_id: "k", credential_id: "c",
      repository: "file:/tmp/r", remote: "origin", remote_url: "file:/tmp/r.git",
      target_ref: "refs/heads/main",
      expected_old_sha: "a".repeat(40),
      approved_new_sha: "b".repeat(40),
      observed_after_sha: "b".repeat(40),
      effect_attempted: false,
      outcome: EVIDENCE_OUTCOME.EXECUTED,
      recorded_at: "2026-06-14T00:00:00.000Z"
    });
    assert.equal(built.ok, false);
    assert.equal(built.reason_code, EVIDENCE_ERRORS.INCOHERENT);
  });

  await test("a REFUSED body that claims the effect was attempted cannot be built", async () => {
    const built = buildExecutionEvidenceBody({
      execution_id: "exec-1", grant_id: "grant-1",
      executor_id: EXECUTOR_ID, environment_id: ENVIRONMENT_ID,
      key_id: "k", credential_id: "c",
      repository: "file:/tmp/r", remote: "origin", remote_url: "file:/tmp/r.git",
      target_ref: "refs/heads/main",
      expected_old_sha: "a".repeat(40),
      approved_new_sha: "b".repeat(40),
      effect_attempted: true,
      outcome: EVIDENCE_OUTCOME.REFUSED,
      recorded_at: "2026-06-14T00:00:00.000Z"
    });
    assert.equal(built.ok, false);
    assert.equal(built.reason_code, EVIDENCE_ERRORS.INCOHERENT);
  });

  await test("flipping a signed REFUSED record to EXECUTED is caught", async () => {
    // Start from a real refusal, then forge the outcome.
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    repos.setRemoteTo(repos.commits[2]); // the remote is no longer at the approved pre-state
    const result = await withProfile("production", () =>
      executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.outcome, OUTCOME.REFUSED);
    assert.ok(result.signedEvidence, "a refusal after a verified authorization must still be signed");

    const forged = mutate(result.signedEvidence, "evidence.outcome", EVIDENCE_OUTCOME.EXECUTED);
    const verdict = await verifyWith(forged);
    assert.equal(verdict.ok, false, "a refusal must never verify as an execution");
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.INCOHERENT);
  });

  await test("a precondition refusal produces signed REFUSED evidence that verifies", async () => {
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    repos.setRemoteTo(repos.commits[2]);
    const result = await withProfile("production", () =>
      executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.outcome, OUTCOME.REFUSED);
    const verdict = await verifyWith(result.signedEvidence);
    assert.equal(verdict.ok, true, `refusal evidence failed to verify: ${verdict.reason_code} ${verdict.detail ?? ""}`);
    assert.equal(verdict.executed, false);
    assert.equal(verdict.evidence.effect_attempted, false);
    assert.equal(verdict.evidence.outcome, EVIDENCE_OUTCOME.REFUSED);
  });

  console.log("\n── 6. replay and ambiguity ──");

  await test("a second attempt on the same authorization is refused, and says so in signed evidence", async () => {
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    const first = await withProfile("production", () =>
      executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(first.outcome, OUTCOME.EXECUTED);

    // Put the remote back so a second push would otherwise be possible.
    repos.setRemoteTo(repos.commits[0]);
    const second = await withProfile("production", () =>
      executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(second.outcome, OUTCOME.REFUSED);
    assert.equal(repos.remoteSha(), repos.commits[0], "the replay must not have moved the remote");

    const verdict = await verifyWith(second.signedEvidence);
    assert.equal(verdict.ok, true, `replay refusal evidence failed to verify: ${verdict.reason_code}`);
    assert.equal(verdict.executed, false);
    assert.equal(verdict.evidence.claim.decision, "SPENT",
      "the evidence must record that the authority was already spent");
  });

  await test("the two runs produce two distinct, separately verifiable records", async () => {
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    const first = await withProfile("production", () =>
      executor.executeGitPush(requestFor(parameters, authorization)));
    repos.setRemoteTo(repos.commits[0]);
    const second = await withProfile("production", () =>
      executor.executeGitPush(requestFor(parameters, authorization)));

    assert.notEqual(first.signedEvidencePath, second.signedEvidencePath,
      "each attempt must leave its own record rather than overwriting the last");
    for (const one of [first, second]) {
      const verdict = await verifyWith(one.signedEvidence);
      assert.equal(verdict.ok, true);
    }
    assert.equal((await verifyWith(first.signedEvidence)).executed, true);
    assert.equal((await verifyWith(second.signedEvidence)).executed, false);
  });

  await test("an ambiguous transport outcome never verifies as EXECUTED", async () => {
    // decidePushOutcome is what classifies a push whose exit status is not
    // trustworthy. Whatever it returns, evidence may only say EXECUTED when the
    // ref was read back at the approved SHA, so this asserts on the record.
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    const result = await withProfile("production", () =>
      executor.executeGitPush(requestFor(parameters, authorization)));

    // Forge the record into the shape an "it probably worked" reading would
    // produce: effect attempted, no observation.
    const forged = mutate(
      mutate(result.signedEvidence, "evidence.observed_after_sha", null),
      "evidence.outcome",
      EVIDENCE_OUTCOME.EXECUTED
    );
    const verdict = await verifyWith(forged);
    assert.equal(verdict.ok, false, "an unobserved final state must never read as EXECUTED");
    assert.equal(verdict.reason_code, EVIDENCE_ERRORS.INCOHERENT);
  });

  console.log("\n── 7. the record outlives the process that made it ──");

  await test("the signed envelope is written to disk and verifies when read back", async () => {
    const { result } = await executedRun();
    assert.ok(result.signedEvidencePath, "the signed envelope must be persisted, not only returned");
    const fromDisk = readJson(result.signedEvidencePath);
    const verdict = await verifyWith(fromDisk);
    assert.equal(verdict.ok, true, `the stored envelope failed to verify: ${verdict.reason_code}`);
    assert.equal(verdict.executed, true);
    assert.deepEqual(fromDisk, JSON.parse(JSON.stringify(result.signedEvidence)),
      "what was written must be exactly what was signed");
  });

  await test("verification needs only the envelope, the bundle and the pinned root", async () => {
    // Nothing from the executor's own filesystem, and no clock it was not given.
    const { result } = await executedRun();
    const carried = JSON.parse(JSON.stringify(result.signedEvidence));
    const verdict = await verifyExecutionEvidence(carried, {
      authorityBundle: JSON.parse(JSON.stringify(trust.bundle)),
      trustedRootFingerprint: trust.fingerprint,
      now: "2026-06-15T00:00:00.000Z"
    });
    assert.equal(verdict.ok, true, `offline verification failed: ${verdict.reason_code} ${verdict.detail ?? ""}`);
    assert.equal(typeof verdict.evidence_digest, "string");
  });

  console.log("\n── 8. the executor refuses to run without a way to sign ──");

  await test("constructing the executor without a signer throws", async () => {
    caseIndex += 1;
    const caseDir = join(dir, `case-${caseIndex}`);
    pendingCleanup.push(caseDir);
    const repos = makeRepositories(caseDir);
    assert.throws(() => createGitPushExecutor({
      repoPath: repos.localPath,
      namespace: NAMESPACE,
      authorityBundle: trust.bundle,
      trustedRootFingerprint: trust.fingerprint,
      environmentId: ENVIRONMENT_ID,
      expectedExecutorId: EXECUTOR_ID,
      evidenceDir: join(caseDir, "evidence"),
      claimBackend: inMemoryClaimBackend({ namespace: NAMESPACE })
    }), /executorIdentity and executorSigner are required/);
  });

  await test("a signing identity that is not this executor is refused at startup", async () => {
    caseIndex += 1;
    const caseDir = join(dir, `case-${caseIndex}`);
    pendingCleanup.push(caseDir);
    const repos = makeRepositories(caseDir);
    assert.throws(() => createGitPushExecutor({
      repoPath: repos.localPath,
      namespace: NAMESPACE,
      authorityBundle: trust.bundle,
      trustedRootFingerprint: trust.fingerprint,
      environmentId: ENVIRONMENT_ID,
      expectedExecutorId: "mnde:test:prod:executor:someone-else:01",
      evidenceDir: join(caseDir, "evidence"),
      claimBackend: inMemoryClaimBackend({ namespace: NAMESPACE }),
      executorIdentity: trust.executor.identity,
      executorSigner: trust.executor.signer
    }), /does not match expectedExecutorId/);
  });

  await test("signing refuses when the body names a different executor than the signer", async () => {
    const built = buildExecutionEvidenceBody({
      execution_id: "exec-1", grant_id: "grant-1",
      executor_id: "mnde:test:prod:executor:someone-else:01",
      environment_id: ENVIRONMENT_ID,
      key_id: trust.executor.identity.key_id,
      credential_id: trust.executor.identity.credential_id,
      repository: "file:/tmp/r", remote: "origin", remote_url: "file:/tmp/r.git",
      target_ref: "refs/heads/main",
      expected_old_sha: "a".repeat(40),
      approved_new_sha: "b".repeat(40),
      effect_attempted: false,
      outcome: EVIDENCE_OUTCOME.REFUSED,
      recorded_at: "2026-06-14T00:00:00.000Z"
    });
    assert.equal(built.ok, true, built.detail);
    const signed = await signExecutionEvidence(built.body, {
      identity: trust.executor.identity,
      signer: trust.executor.signer
    });
    assert.equal(signed.ok, false);
    assert.equal(signed.reason_code, EVIDENCE_ERRORS.IDENTITY_MISMATCH);
  });

  await test("a signer that throws produces no envelope and no false success", async () => {
    const built = buildExecutionEvidenceBody({
      execution_id: "exec-1", grant_id: "grant-1",
      executor_id: trust.executor.identity.executor_id,
      environment_id: ENVIRONMENT_ID,
      key_id: trust.executor.identity.key_id,
      credential_id: trust.executor.identity.credential_id,
      repository: "file:/tmp/r", remote: "origin", remote_url: "file:/tmp/r.git",
      target_ref: "refs/heads/main",
      expected_old_sha: "a".repeat(40),
      approved_new_sha: "b".repeat(40),
      effect_attempted: false,
      outcome: EVIDENCE_OUTCOME.REFUSED,
      recorded_at: "2026-06-14T00:00:00.000Z"
    });
    assert.equal(built.ok, true, built.detail);
    const signed = await signExecutionEvidence(built.body, {
      identity: trust.executor.identity,
      signer: { sign: () => { throw new Error("hsm unavailable"); } }
    });
    assert.equal(signed.ok, false);
    assert.equal(signed.reason_code, EVIDENCE_ERRORS.SIGNING_FAILED);
  });

  rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });

  console.log(`\n${failed === 0 ? "PASS" : "FAIL"} git.push execution evidence (${passed}/${passed + failed})`);
  if (failed > 0) process.exitCode = 1;
}

await main();
