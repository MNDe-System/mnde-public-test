// Signed execution evidence v2 (mnde.git-push-execution-evidence.v2) and its compatibility with v1.
//
//   npm run test:git-push-evidence-v2
//
// v2 adds three fields to v1 — the execution-start record reference, the credential the push used
// (kind, access, scope, GitHub App id, installation id; never token material) and the spend-witness
// entry — and signs a domain-separated input. These tests check that: the real executor emits it;
// historical v1 evidence still verifies under its original rules; and every way of altering or
// forging the new fields, or confusing the two versions, is rejected by the offline verifier.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { canonicalizeJson } from "../shared/json.ts";
import {
  buildExecutionEvidenceBody, buildExecutionEvidenceBodyV2, EVIDENCE_V2_DOMAIN, EXECUTION_EVIDENCE_SCHEMA, EXECUTION_EVIDENCE_SCHEMA_V2,
  signExecutionEvidence, verifyExecutionEvidence
} from "../src/effects/git-push/evidence.mjs";
import { createGitPushExecutor, OUTCOME } from "../src/effects/git-push/index.mjs";
import { verifyExecutionAuthority } from "../src/execution-authority/index.mjs";
import { installClaimBackend } from "./support/claim_backend_double.mjs";
import { installWitnessClient } from "./support/witness_double.mjs";
import { startInProcessWitness } from "./support/witness_fixtures.mjs";
import {
  ENVIRONMENT_ID, EXECUTOR_ID, gitPushAuthorization, inMemoryClaimBackend, makeRepositories, productionTrust, pushParameters
} from "./support/git_push_fixtures.mjs";

const NAMESPACE = "mnde-git-push-evidence-v2-namespace";
let passed = 0, failed = 0;
const closers = [];
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  [PASS] ${name}`); }
  catch (error) { failed += 1; console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.stack : String(error)}`); }
  finally { installWitnessClient(undefined); while (closers.length) { try { closers.pop()(); } catch { /* already closed */ } } }
}

const dir = mkdtempSync(join(tmpdir(), "mnde-evidence-v2-"));
process.env.MNDE_PROFILE = "production";
const trust = await productionTrust(dir);
const verifyOptions = { authorityBundle: trust.bundle, trustedRootFingerprint: trust.fingerprint, expectedExecutorId: EXECUTOR_ID, expectedEnvironmentId: ENVIRONMENT_ID };
const verify = (envelope) => verifyExecutionEvidence(envelope, verifyOptions);
const sha256hex = (text) => createHash("sha256").update(text).digest("hex");

let caseIndex = 0;
async function executed({ withWitness = false } = {}) {
  caseIndex += 1;
  const caseDir = join(dir, `case-${caseIndex}`);
  const repos = makeRepositories(caseDir);
  process.env.MNDE_GIT_CREDENTIAL_CONFIG = repos.credentialConfigPath;
  const identity = { executor_id: EXECUTOR_ID, namespace: NAMESPACE };
  const witness = withWitness ? startInProcessWitness({ identities: [identity], dataDir: join(caseDir, "witness") }) : null;
  if (witness) closers.push(() => witness.close());
  installClaimBackend(inMemoryClaimBackend({ namespace: NAMESPACE }));
  installWitnessClient(withWitness ? witness.client(identity) : null);
  const evidenceDir = join(caseDir, "evidence");
  const executor = createGitPushExecutor({
    repoPath: repos.localPath, namespace: NAMESPACE, authorityBundle: trust.bundle, authorityBundlePath: trust.bundlePath,
    trustedRootFingerprint: trust.fingerprint, environmentId: ENVIRONMENT_ID, expectedExecutorId: EXECUTOR_ID,
    allowedSchemes: ["file"], evidenceDir, executorIdentity: trust.executor.identity, executorSigner: trust.executor.signer
  });
  const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
  const authorization = await gitPushAuthorization(trust, parameters);
  const result = await executor.executeGitPush({ repository: parameters.repository, remote: parameters.remote, remoteUrl: parameters.remote_url,
    sourceCommit: parameters.source_commit, targetRef: parameters.target_ref, expectedOldSha: parameters.expected_old_sha, authorization });
  return { result, evidenceDir, witness, authorization };
}

// A body the executor key genuinely signs, for cases the verifier must reject by its OWN checks rather than by a bad signature.
async function signedBy(body, domain = true) {
  const text = domain && body.schema_version === EXECUTION_EVIDENCE_SCHEMA_V2 ? `${EVIDENCE_V2_DOMAIN}${canonicalizeJson(body)}` : canonicalizeJson(body);
  const value = await trust.executor.signer.sign(text);
  return { schema_version: "mnde.git-push-execution-evidence-envelope.v1", evidence: body, credential: structuredClone(trust.executor.identity.credential),
    signature: { algorithm: "ED25519", key_id: trust.executor.identity.key_id, value } };
}
const clone = (v) => structuredClone(v);

console.log("── the real executor emits v2 ──");

await test("executor evidence is v2, verifies offline, and references the exact start record by digest", async () => {
  const { result, evidenceDir } = await executed();
  assert.equal(result.outcome, OUTCOME.EXECUTED, `${result.reason_code}: ${result.detail}`);
  const env = result.signedEvidence;
  assert.equal(env.evidence.schema_version, EXECUTION_EVIDENCE_SCHEMA_V2);
  const verdict = await verify(env);
  assert.equal(verdict.ok, true, JSON.stringify(verdict));
  assert.equal(verdict.evidence_version, 2);
  const startFile = readdirSync(evidenceDir).find((n) => n.endsWith(".started.json"));
  assert.equal(env.evidence.execution_start.record_sha256, sha256hex(readFileSync(join(evidenceDir, startFile), "utf8")), "the reference must be the digest of the file on disk");
  assert.equal(env.evidence.push_credential.kind, "none");
  assert.equal(env.evidence.push_credential.access, "static");
  assert.equal(env.evidence.push_credential.app_id, null);
  assert.equal(env.evidence.witness, null, "no witness was configured, and none is claimed");
  assert.ok(!JSON.stringify(env).match(/ghs_|BEGIN .*PRIVATE|Bearer /), "no token material in evidence");
});

await test("with a witness, the evidence carries the witness entry the witness itself recorded", async () => {
  const { result, witness } = await executed({ withWitness: true });
  assert.equal(result.outcome, OUTCOME.EXECUTED, `${result.reason_code}: ${result.detail}`);
  const w = result.signedEvidence.evidence.witness;
  assert.equal(w.n, 1);
  assert.equal(w.witness_id, "mnde-test-witness");
  assert.equal(w.entry_digest, witness.log.head().head_hash);
  assert.equal((await verify(result.signedEvidence)).ok, true);
});

console.log("\n── v1 compatibility ──");

await test("historical v1 evidence (built and signed with the v1 functions) still verifies unchanged", async () => {
  const { result } = await executed();
  const { evidence: v2 } = result.signedEvidence;
  const built = buildExecutionEvidenceBody({ ...v2, authorization_receipt_hash: v2.authorization_receipt_hash, claim: v2.claim });
  assert.equal(built.ok, true, JSON.stringify(built));
  assert.equal(built.body.schema_version, EXECUTION_EVIDENCE_SCHEMA);
  const signed = await signExecutionEvidence(built.body, { identity: trust.executor.identity, signer: trust.executor.signer });
  const verdict = await verify(signed.envelope);
  assert.equal(verdict.ok, true);
  assert.equal(verdict.evidence_version, 1);
});

await test("a v1 envelope carrying v2 fields, and a v2 envelope missing them, are refused", async () => {
  const { result } = await executed();
  const v2 = clone(result.signedEvidence.evidence);
  const downgraded = { ...v2, schema_version: EXECUTION_EVIDENCE_SCHEMA };
  assert.equal((await verify(await signedBy(downgraded))).ok, false, "v1 label with v2 fields");
  const { execution_start: _a, push_credential: _b, witness: _c, ...bare } = v2;
  assert.equal((await verify(await signedBy({ ...bare, schema_version: EXECUTION_EVIDENCE_SCHEMA_V2 }))).ok, false, "v2 label without v2 fields");
  assert.equal((await verify(await signedBy({ ...v2, schema_version: "mnde.git-push-execution-evidence.v3" }))).ok, false, "an unsupported version");
});

console.log("\n── v2 forgery and tampering ──");

await test("changing any v2 field, any identity or the action digest breaks the signature", async () => {
  const { result } = await executed({ withWitness: true });
  const good = result.signedEvidence;
  const mutations = {
    start_digest: (b) => { b.execution_start.record_sha256 = "0".repeat(64); },
    start_time: (b) => { b.execution_start.started_at = "2020-01-01T00:00:00.000Z"; },
    credential_kind: (b) => { b.push_credential.kind = "github-app"; },
    credential_access: (b) => { b.push_credential.access = "read"; },
    credential_scope: (b) => { b.push_credential.scope = "https:github.com/attacker/other"; },
    github_app_id: (b) => { b.push_credential.app_id = "424242"; b.push_credential.installation_id = "777"; },
    witness_entry: (b) => { b.witness.entry_digest = "f".repeat(64); },
    witness_sequence: (b) => { b.witness.n = 99; },
    witness_removed: (b) => { b.witness = null; },
    action_digest: (b) => { b.authority_digest = "e".repeat(64); },
    receipt_hash: (b) => { b.authorization_receipt_hash = "d".repeat(64); },
    executor: (b) => { b.executor_id = "mnde:attacker"; },
    outcome: (b) => { b.outcome = "REFUSED"; b.effect_attempted = false; },
    approved_sha: (b) => { b.approved_new_sha = "1".repeat(40); }
  };
  for (const [name, mutate] of Object.entries(mutations)) {
    const env = clone(good); mutate(env.evidence);
    assert.equal((await verify(env)).ok, false, `${name} was accepted`);
  }
});

await test("a body signed WITHOUT the v2 domain, or a v1 signature over a v2 body, does not verify", async () => {
  const { result } = await executed();
  const body = clone(result.signedEvidence.evidence);
  assert.equal((await verify(await signedBy(body, false))).ok, false, "v2 body signed with the v1 (undomained) input");
  assert.equal((await verify(await signedBy(body, true))).ok, true, "the same body signed with the v2 domain verifies (control)");
});

await test("a genuinely signed but incoherent or malformed v2 body is refused by the verifier's own checks", async () => {
  const { result } = await executed({ withWitness: true });
  const good = clone(result.signedEvidence.evidence);
  const bad = {
    effect_without_start: { ...good, execution_start: null },
    malformed_start_time: { ...good, execution_start: { ...good.execution_start, started_at: "not-a-time" } },
    short_digest: { ...good, execution_start: { ...good.execution_start, record_sha256: "abc" } },
    unknown_access: { ...good, push_credential: { ...good.push_credential, access: "admin" } },
    app_without_installation: { ...good, push_credential: { ...good.push_credential, app_id: "1", installation_id: null } },
    extra_credential_field: { ...good, push_credential: { ...good.push_credential, token: "ghs_x" } },
    witness_sequence_zero: { ...good, witness: { ...good.witness, n: 0 } },
    witness_extra_field: { ...good, witness: { ...good.witness, extra: true } },
    extra_top_level_field: { ...good, injected: true },
    executed_but_observed_differs: { ...good, observed_after_sha: "2".repeat(40) }
  };
  for (const [name, body] of Object.entries(bad)) assert.equal((await verify(await signedBy(body))).ok, false, `${name} was accepted`);
  assert.equal((await verify(await signedBy(good))).ok, true, "control");
});

await test("evidence signed by an untrusted issuer or checked against the wrong root is refused", async () => {
  const { result } = await executed();
  assert.equal((await verifyExecutionEvidence(result.signedEvidence, { ...verifyOptions, trustedRootFingerprint: "f".repeat(64) })).ok, false);
  assert.equal((await verifyExecutionEvidence(result.signedEvidence, { ...verifyOptions, expectedExecutorId: "mnde:someone:else" })).ok, false);
  const other = await productionTrust(dir, { authorityId: "mnde-git-push-other-authority" });
  assert.equal((await verifyExecutionEvidence(result.signedEvidence, { authorityBundle: other.bundle, trustedRootFingerprint: other.fingerprint })).ok, false);
});

await test("evidence is not authority: presented as an authorization it is refused", async () => {
  const { result } = await executed();
  const asAuthority = await verifyExecutionAuthority(result.signedEvidence, { authorityBundle: trust.bundle, trustedRootFingerprint: trust.fingerprint, environmentId: ENVIRONMENT_ID, expectedExecutorId: EXECUTOR_ID, namespace: NAMESPACE });
  assert.equal(asAuthority.ok, false);
});

await test("a signed refusal (the remote moved after approval) is v2, verifies, claims no effect and references no start record", async () => {
  caseIndex += 1;
  const caseDir = join(dir, `case-${caseIndex}`);
  const repos = makeRepositories(caseDir);
  process.env.MNDE_GIT_CREDENTIAL_CONFIG = repos.credentialConfigPath;
  installClaimBackend(inMemoryClaimBackend({ namespace: NAMESPACE })); installWitnessClient(null);
  const executor = createGitPushExecutor({ repoPath: repos.localPath, namespace: NAMESPACE, authorityBundle: trust.bundle, authorityBundlePath: trust.bundlePath,
    trustedRootFingerprint: trust.fingerprint, environmentId: ENVIRONMENT_ID, expectedExecutorId: EXECUTOR_ID, allowedSchemes: ["file"],
    evidenceDir: join(caseDir, "evidence"), executorIdentity: trust.executor.identity, executorSigner: trust.executor.signer });
  const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
  const authorization = await gitPushAuthorization(trust, parameters);
  repos.setRemoteTo(repos.commits[2]);                     // the ref moved after the approval was signed
  const result = await executor.executeGitPush({ repository: parameters.repository, remote: parameters.remote, remoteUrl: parameters.remote_url,
    sourceCommit: parameters.source_commit, targetRef: parameters.target_ref, expectedOldSha: parameters.expected_old_sha, authorization });
  assert.equal(result.outcome, OUTCOME.REFUSED);
  const env = result.signedEvidence;
  assert.ok(env, "this refusal names a verified authorization, so it must be signed");
  assert.equal((await verify(env)).ok, true);
  assert.equal(env.evidence.schema_version, EXECUTION_EVIDENCE_SCHEMA_V2);
  assert.equal(env.evidence.effect_attempted, false);
  assert.equal(env.evidence.execution_start, null, "nothing started, so nothing is referenced");
  assert.equal(env.evidence.observed_before_sha, repos.commits[2]);
});

rmSync(dir, { recursive: true, force: true });
console.log(`\n${failed === 0 ? "PASS" : "FAIL"} git.push evidence v2 (${passed}/${passed + failed})`);
process.exit(failed === 0 ? 0 : 1);
