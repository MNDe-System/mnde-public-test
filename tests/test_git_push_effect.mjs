// git.push — MNDe's first narrow typed production effect.
//
//   npm run test:git-push-effect
//
// WHAT IS REAL HERE. The repositories are real git repositories on disk and the
// pushes really happen, over file:// so the suite needs no network. The
// authorizations are real executor-bound mnde.signed-receipt.v2 envelopes that go
// through the production verifier — nothing in the verification path is stubbed.
//
// WHAT IS NOT. The durable claim backend is in-memory. It implements the same
// protocol and the same at-most-once semantics, so it exercises the ORDERING
// these tests are about: nothing is sent unless the claim came back CLAIMED, and
// a second presentation of the same authority is refused. It proves nothing about
// durability or non-rollback, which are established separately against a real
// PostgreSQL primary in docs/F001-CLAIM-STORE-PROOF.md at 22 of 22.
//
// THE ASSERTION THAT MATTERS MOST is not "the push worked". It is that on every
// refusal path the REMOTE IS UNCHANGED, which is why almost every case below
// reads the remote back rather than trusting the returned reason code.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  createGitPushExecutor,
  decidePushOutcome,
  ERR_AUTHORITY_ALREADY_SPENT,
  ERR_CLAIM_NOT_ESTABLISHED,
  ERR_NOT_FAST_FORWARD,
  ERR_POSTSTATE_MISMATCH,
  ERR_PROFILE_NOT_PRODUCTION,
  ERR_REMOTE_MISMATCH,
  ERR_REMOTE_MOVED,
  EVIDENCE_SCHEMA,
  OUTCOME
} from "../src/effects/git-push/index.mjs";
import { buildPushArgv, buildTransportEnv, ERR_TRANSPORT_ENV_NOT_ALLOWED } from "../src/effects/git-push/transport.mjs";
import { validateGitPushParameters } from "../src/effects/git-push/validate.mjs";
import { verifyExecutionAuthority } from "../src/execution-authority/index.mjs";
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

const NAMESPACE = "mnde-git-push-test-namespace";

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    failed += 1;
    console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.message : String(error)}`);
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

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "mnde-git-push-effect-"));
  const trust = await productionTrust(dir);
  const otherTrust = await productionTrust(dir, { authorityId: "mnde-git-push-other-authority" });

  let caseIndex = 0;
  // Each case gets its own pair of repositories and its own claim backend, so no
  // case can pass because a previous one left state behind.
  function fixture(startupOverrides = {}, backendOptions = {}) {
    caseIndex += 1;
    const caseDir = join(dir, `case-${caseIndex}`);
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
      ...startupOverrides
    });
    return { repos, backend, executor, caseDir };
  }

  // Turn signed parameters into the caller's camelCase request.
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

  console.log("── 1. a correct push succeeds, once ──");

  await test("a correct push moves the remote to exactly the approved SHA", async () => {
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    const result = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.outcome, OUTCOME.EXECUTED, `expected EXECUTED, got ${result.outcome} (${result.reason_code}: ${result.detail})`);
    assert.equal(result.executed, true);
    assert.equal(repos.remoteSha(), repos.commits[1], "the remote did not end at the approved source commit");
  });

  await test("the evidence records the observed post-state, the claim and the exact argv", async () => {
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    const result = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.outcome, OUTCOME.EXECUTED);
    const evidence = readJson(result.evidencePath);
    assert.equal(evidence.schema, EVIDENCE_SCHEMA);
    assert.equal(evidence.outcome, OUTCOME.EXECUTED);
    assert.equal(evidence.observed.before, repos.commits[0]);
    assert.equal(evidence.observed.after, repos.commits[1], "the evidence must record what the remote was read back as");
    assert.equal(evidence.claim.decision, "CLAIMED");
    // The backend is named in the evidence, so a non-durable one is visible in
    // the record rather than indistinguishable from the real adapter.
    assert.equal(evidence.claim.backend_kind, "test-in-memory");
    assert.equal(evidence.transport.shell, false);
    assert.deepEqual(evidence.transport.argv, [
      "push",
      "--no-verify",
      `--force-with-lease=refs/heads/main:${repos.commits[0]}`,
      "--",
      repos.remoteUrl,
      `${repos.commits[1]}:refs/heads/main`
    ]);
  });

  console.log("\n── 2. the same authorization cannot execute twice ──");

  await test("replaying an authorization that already pushed sends nothing", async () => {
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    const first = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(first.outcome, OUTCOME.EXECUTED);

    // Put the remote back, so that a second push WOULD be possible if the
    // authority were not spent. Without this the replay could be refused by the
    // lease rather than by the claim, and the test would prove the wrong thing.
    repos.setRemoteTo(repos.commits[0]);
    assert.equal(repos.remoteSha(), repos.commits[0]);

    const second = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(second.reason_code, ERR_AUTHORITY_ALREADY_SPENT, `expected the claim to refuse, got ${second.reason_code}`);
    assert.equal(second.outcome, OUTCOME.REFUSED);
    assert.equal(repos.remoteSha(), repos.commits[0], "the replay moved the remote; the authority was reused");
  });

  console.log("\n── 3-7. the request must be exactly what was authorized ──");

  for (const [label, overrides] of [
    ["repository", { repository: "file:/somewhere/else" }],
    ["remote", { remote: "upstream" }],
    ["source commit", null],
    ["target ref", { targetRef: "refs/heads/release" }],
    ["expected old SHA", null]
  ]) {
    await test(`a request with a different ${label} than the authorization refuses`, async () => {
      const { repos, executor } = fixture();
      const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
      const authorization = await gitPushAuthorization(trust, parameters);
      const substitution = overrides ?? (label === "source commit"
        ? { sourceCommit: repos.commits[2] }
        : { expectedOldSha: repos.commits[1] });
      const result = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization, substitution)));
      assert.equal(result.outcome, OUTCOME.REFUSED, `expected a refusal, got ${result.outcome}`);
      assert.equal(result.reason_code, "ERR_GIT_PUSH_REQUEST_BINDING", `expected the request binding to refuse, got ${result.reason_code}: ${result.detail}`);
      assert.equal(repos.remoteSha(), repos.commits[0], "the remote moved on a refused request");
    });
  }

  await test("an authorization whose signed remote is not the local repository's remote refuses", async () => {
    const { repos, executor } = fixture();
    // Sign a push whose remote_url is a DIFFERENT repository. The request matches
    // the authorization exactly, so only the local repository's own configuration
    // can catch it.
    const elsewhere = makeRepositories(join(dir, `elsewhere-${caseIndex}`));
    const parameters = pushParameters(elsewhere, { from: elsewhere.commits[0], to: elsewhere.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    const result = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.reason_code, ERR_REMOTE_MISMATCH, `expected a remote mismatch, got ${result.reason_code}: ${result.detail}`);
    assert.equal(elsewhere.remoteSha(), elsewhere.commits[0], "the other repository's remote moved");
    assert.equal(repos.remoteSha(), repos.commits[0]);
  });

  console.log("\n── 8. the remote must be in the approved pre-state ──");

  await test("a remote that moved after the authorization was signed refuses", async () => {
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    // Somebody else pushed in the meantime.
    repos.setRemoteTo(repos.commits[2]);
    const result = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.reason_code, ERR_REMOTE_MOVED, `expected the pre-state read to refuse, got ${result.reason_code}: ${result.detail}`);
    assert.equal(repos.remoteSha(), repos.commits[2], "the remote was overwritten despite having moved");
  });

  await test("a remote that moves between the pre-state read and the push is caught by the lease", async () => {
    // The claim backend moves the remote as a side effect, which is the only
    // deterministic way to open that window. The lease must refuse, and because
    // the ref is then at neither approved SHA the outcome is INDETERMINATE rather
    // than a silent failure — and the authority stays spent.
    let repos = null;
    const built = fixture({}, {
      onClaim: async () => { repos.setRemoteTo(repos.commits[2]); }
    });
    repos = built.repos;
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    const result = await withProfile("production", () => built.executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.outcome, OUTCOME.INDETERMINATE, `expected INDETERMINATE, got ${result.outcome} (${result.reason_code})`);
    assert.equal(result.executed, null, "an indeterminate outcome must not claim the effect either happened or did not");
    assert.equal(repos.remoteSha(), repos.commits[2], "the lease did not hold: the remote was overwritten");
    const evidence = readJson(result.evidencePath);
    assert.equal(evidence.observed.after, repos.commits[2]);
  });

  console.log("\n── 9. only a fast-forward is authorized ──");

  await test("a source commit that is not a descendant of the approved pre-state refuses", async () => {
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.divergent });
    // Put the remote at commit 1 and sign a push from commit 1 to the divergent
    // commit, which shares history with commit 0 but does not descend from 1.
    repos.setRemoteTo(repos.commits[1]);
    const rewriting = pushParameters(repos, { from: repos.commits[1], to: repos.divergent });
    const authorization = await gitPushAuthorization(trust, rewriting);
    const result = await withProfile("production", () => executor.executeGitPush(requestFor(rewriting, authorization)));
    assert.equal(result.reason_code, ERR_NOT_FAST_FORWARD, `expected the ancestry check to refuse, got ${result.reason_code}: ${result.detail}`);
    assert.equal(repos.remoteSha(), repos.commits[1], "history was rewritten");
    assert.ok(parameters.source_commit === repos.divergent);
  });

  console.log("\n── 10-12. trust, identity and posture ──");

  await test("an authorization bound to a different executor refuses", async () => {
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters, { executorId: "mnde:test:prod:executor:someone-else:01" });
    const result = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.outcome, OUTCOME.REFUSED);
    assert.notEqual(result.reason_code, null);
    assert.equal(repos.remoteSha(), repos.commits[0]);
  });

  await test("an authorization signed under a different trust root refuses", async () => {
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(otherTrust, parameters);
    const result = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.outcome, OUTCOME.REFUSED, `expected a refusal, got ${result.outcome}`);
    assert.equal(repos.remoteSha(), repos.commits[0], "a receipt from an unrelated authority moved the remote");
  });

  await test("an inner decision signed only by the authority shipped in the package refuses", async () => {
    // The outer envelope is production-signed and executor-bound; only the inner
    // policy decision falls back to the demo authority. This is the trust-mixing
    // shape #43 closed on the executor, checked here on the effect.
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters, { repoLocalInner: true });
    const result = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.outcome, OUTCOME.REFUSED, `expected a refusal, got ${result.outcome}`);
    assert.equal(repos.remoteSha(), repos.commits[0]);
  });

  await test("an authorization for a different action refuses", async () => {
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters, { action: "read_status" });
    const result = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.outcome, OUTCOME.REFUSED);
    assert.equal(repos.remoteSha(), repos.commits[0]);
  });

  await test("without MNDE_PROFILE=production nothing is attempted", async () => {
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    for (const profile of [undefined, "local", "PRODUCTIONN"]) {
      const result = await withProfile(profile, () => executor.executeGitPush(requestFor(parameters, authorization)));
      assert.equal(result.reason_code, ERR_PROFILE_NOT_PRODUCTION, `profile ${String(profile)} was not refused`);
      assert.equal(result.evidence.effect_attempted, false);
    }
    assert.equal(repos.remoteSha(), repos.commits[0]);
  });

  await test("missing production trust configuration refuses at the posture gate", async () => {
    const { repos, executor } = fixture({ trustedRootFingerprint: undefined });
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    const result = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.reason_code, "ERR_EXECUTOR_PRODUCTION_TRUST_ROOT_REQUIRED", `got ${result.reason_code}: ${result.detail}`);
    assert.equal(repos.remoteSha(), repos.commits[0]);
  });

  console.log("\n── 13-14. the claim is what stands between an authority and an effect ──");

  await test("a claim that cannot be established sends nothing", async () => {
    // Models a process that dies, or a store that is unreachable, BEFORE the
    // authority is spent. Nothing may be sent on anything but CLAIMED.
    for (const [label, options] of [
      ["an unhealthy backend", { healthy: false }],
      ["a backend whose claim submission fails", { throwOnClaim: true }]
    ]) {
      const { repos, executor } = fixture({}, options);
      const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
      const authorization = await gitPushAuthorization(trust, parameters);
      const result = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
      assert.equal(result.reason_code, ERR_CLAIM_NOT_ESTABLISHED, `${label}: got ${result.reason_code}`);
      assert.equal(result.evidence.effect_attempted, false, `${label}: the effect must not be attempted`);
      assert.equal(repos.remoteSha(), repos.commits[0], `${label}: the remote moved without a claim`);
    }
  });

  await test("with no claim backend at all, nothing is sent", async () => {
    const { repos, executor } = fixture({ claimBackend: null });
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    const result = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.reason_code, ERR_CLAIM_NOT_ESTABLISHED);
    assert.equal(repos.remoteSha(), repos.commits[0], "a missing claim store is not a reason to dispatch");
  });

  await test("an authority claimed by a run that then died is never re-spent", async () => {
    // The claim landed; the process died before it could dispatch. A new process
    // presenting the same authorization must refuse, not "finish the job" — the
    // safety property is at-most-once ATTEMPT, and that deliberately costs an
    // authority that may have produced no effect.
    const { repos, executor, backend } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    const authority = await verifyExecutionAuthority(authorization, {
      authorityBundle: trust.bundle,
      trustedRootFingerprint: trust.fingerprint,
      environmentId: ENVIRONMENT_ID,
      expectedExecutorId: EXECUTOR_ID,
      namespace: NAMESPACE
    });
    assert.equal(authority.ok, true, `could not derive the crashed run's claim: ${authority.reason}`);
    backend.spend({
      namespace: NAMESPACE,
      execution_id: authority.execution_id,
      grant_id: authority.grant_id,
      subject: authority.subject,
      executor_id: authority.executor_id,
      receipt_hash: authority.receipt_hash,
      aplus_digest: authority.authority_digest
    });

    const result = await withProfile("production", () => executor.executeGitPush(requestFor(parameters, authorization)));
    assert.equal(result.reason_code, ERR_AUTHORITY_ALREADY_SPENT, `got ${result.reason_code}: ${result.detail}`);
    assert.equal(result.evidence.effect_attempted, false);
    assert.equal(repos.remoteSha(), repos.commits[0]);
  });

  console.log("\n── 15-16. the remote is the authority on what happened ──");

  await test("an ambiguous transport failure is decided by reading the remote, not by retrying", () => {
    const approvedOldSha = "a".repeat(40);
    const approvedSourceCommit = "b".repeat(40);
    const ambiguous = { ok: false, indeterminate: true, reason: "ERR_GIT_TIMEOUT", exit_code: null };

    // It landed despite the ambiguity: the remote says so, so it executed.
    assert.equal(decidePushOutcome({
      pushed: ambiguous, after: { ok: true, sha: approvedSourceCommit }, approvedSourceCommit, approvedOldSha, targetRef: "refs/heads/main"
    }).outcome, OUTCOME.EXECUTED);

    // It did not land and the remote is untouched: reconciled, not applied, and
    // explicitly not a candidate for a second attempt.
    const notApplied = decidePushOutcome({
      pushed: ambiguous, after: { ok: true, sha: approvedOldSha }, approvedSourceCommit, approvedOldSha, targetRef: "refs/heads/main"
    });
    assert.equal(notApplied.outcome, OUTCOME.RECONCILED_NOT_APPLIED);
    assert.equal(notApplied.executed, false);
    assert.match(notApplied.detail, /must not be reused/);

    // The remote could not be read back at all: nobody knows, and it says so.
    assert.equal(decidePushOutcome({
      pushed: ambiguous, after: { ok: false, reason: "ERR_GIT_PUSH_REMOTE_READ_FAILED", detail: "x" }, approvedSourceCommit, approvedOldSha, targetRef: "refs/heads/main"
    }).outcome, OUTCOME.INDETERMINATE);
  });

  await test("an exit code of 0 is not accepted as proof that the ref moved", () => {
    const approvedOldSha = "a".repeat(40);
    const approvedSourceCommit = "b".repeat(40);
    const clean = { ok: true, exit_code: 0 };
    // Exit 0, but the ref is at a third SHA. Neither success nor no-op is true.
    const verdict = decidePushOutcome({
      pushed: clean, after: { ok: true, sha: "c".repeat(40) }, approvedSourceCommit, approvedOldSha, targetRef: "refs/heads/main"
    });
    assert.equal(verdict.outcome, OUTCOME.INDETERMINATE);
    assert.equal(verdict.reason_code, ERR_POSTSTATE_MISMATCH);
    assert.equal(verdict.executed, null);
  });

  console.log("\n── the argv and the environment ──");

  await test("the argv is the fixed shape and carries none of the forbidden flags", () => {
    const argv = buildPushArgv({
      remoteUrl: "https://example.invalid/owner/repo.git",
      sourceCommit: "b".repeat(40),
      targetRef: "refs/heads/main",
      expectedOldSha: "a".repeat(40)
    });
    assert.deepEqual(argv, [
      "push",
      "--no-verify",
      `--force-with-lease=refs/heads/main:${"a".repeat(40)}`,
      "--",
      "https://example.invalid/owner/repo.git",
      `${"b".repeat(40)}:refs/heads/main`
    ]);
    for (const forbidden of ["--force", "--mirror", "--all", "--delete", "--prune", "--receive-pack", "--exec", "-c"]) {
      assert.ok(!argv.includes(forbidden), `argv must never contain ${forbidden}`);
      assert.ok(!argv.some((a) => a !== "--force-with-lease=refs/heads/main:" + "a".repeat(40) && a.startsWith(`${forbidden}=`)), `argv must never contain ${forbidden}=`);
    }
  });

  await test("the transport environment is built from empty and refuses anything unlisted", () => {
    const built = buildTransportEnv({}, { platform: "linux" });
    assert.equal(built.ok, true);
    // Neutralized, so an operator's own git config cannot redirect the push.
    assert.equal(built.env.GIT_CONFIG_NOSYSTEM, "1");
    assert.equal(built.env.GIT_TERMINAL_PROMPT, "0");
    assert.ok(Object.hasOwn(built.env, "GIT_CONFIG_GLOBAL"));
    // Execution-affecting variables are absent because nothing is inherited.
    for (const absent of ["GIT_PROXY_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_DIR", "GIT_WORK_TREE", "LD_PRELOAD", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "http_proxy"]) {
      assert.ok(!Object.hasOwn(built.env, absent), `${absent} must not be present`);
    }
    for (const rejected of ["GIT_PROXY_COMMAND", "LD_PRELOAD", "GIT_DIR"]) {
      const result = buildTransportEnv({ [rejected]: "anything" }, { platform: "linux" });
      assert.equal(result.ok, false, `${rejected} was accepted`);
      assert.equal(result.reason, ERR_TRANSPORT_ENV_NOT_ALLOWED);
    }
    // The allowlisted ones are accepted, because the operator needs them.
    assert.equal(buildTransportEnv({ GIT_SSH_COMMAND: "ssh -i /k" }, { platform: "linux" }).ok, true);
  });

  console.log("\n── the bound fields are validated before anything is built ──");

  await test("abbreviated, option-like, malformed and credential-bearing fields all refuse", () => {
    const good = {
      repository: "https:example.invalid/owner/repo",
      remote: "origin",
      remote_url: "https://example.invalid/owner/repo.git",
      source_commit: "b".repeat(40),
      target_ref: "refs/heads/main",
      expected_old_sha: "a".repeat(40)
    };
    assert.equal(validateGitPushParameters(good).ok, true, JSON.stringify(validateGitPushParameters(good)));

    const cases = [
      ["an abbreviated source commit", { source_commit: "b".repeat(7) }, "ERR_GIT_PUSH_SHA_FORMAT"],
      ["an uppercase SHA", { source_commit: "B".repeat(40) }, "ERR_GIT_PUSH_SHA_FORMAT"],
      ["the null SHA as the pre-state", { expected_old_sha: "0".repeat(40) }, "ERR_GIT_PUSH_SHA_FORMAT"],
      ["an option-like remote", { remote: "--upload-pack=touch" }, "ERR_GIT_PUSH_OPTION_LIKE_VALUE"],
      ["an option-like ref", { target_ref: "--force" }, "ERR_GIT_PUSH_OPTION_LIKE_VALUE"],
      ["an unqualified branch name", { target_ref: "main" }, "ERR_GIT_PUSH_TARGET_REF_FORMAT"],
      ["a tag ref", { target_ref: "refs/tags/v1" }, "ERR_GIT_PUSH_TARGET_REF_FORMAT"],
      ["a ref containing ..", { target_ref: "refs/heads/a..b" }, "ERR_GIT_PUSH_TARGET_REF_FORMAT"],
      ["a ref containing @{", { target_ref: "refs/heads/a@{0}" }, "ERR_GIT_PUSH_TARGET_REF_FORMAT"],
      ["a command-executing transport", { remote_url: "ext::sh -c touch%20/tmp/pwned", repository: "x" }, "ERR_GIT_PUSH_REMOTE_URL_FORMAT"],
      ["credentials in the URL", { remote_url: "https://user:token@example.invalid/owner/repo.git" }, "ERR_GIT_PUSH_REMOTE_URL_CREDENTIALS"],
      ["a newline in the URL", { remote_url: "https://example.invalid/owner/repo.git\nfoo" }, "ERR_GIT_PUSH_REMOTE_URL_FORMAT"],
      ["a repository that disagrees with the URL", { repository: "https:example.invalid/someone/else" }, "ERR_GIT_PUSH_REPOSITORY_MISMATCH"],
      ["a push with nothing to do", { source_commit: "a".repeat(40) }, "ERR_GIT_PUSH_NO_OP"]
    ];
    for (const [label, overrides, expected] of cases) {
      const result = validateGitPushParameters({ ...good, ...overrides });
      assert.equal(result.ok, false, `${label} was accepted`);
      assert.equal(result.reason, expected, `${label}: expected ${expected}, got ${result.reason} (${result.detail})`);
    }

    // An extra or a missing parameter is refused rather than ignored: an ignored
    // parameter is a constraint the approver thought they had.
    assert.equal(validateGitPushParameters({ ...good, extra: "x" }).reason, "ERR_GIT_PUSH_PARAMETER_SHAPE");
    const { remote: _drop, ...missing } = good;
    assert.equal(validateGitPushParameters(missing).reason, "ERR_GIT_PUSH_PARAMETER_SHAPE");

    // The scheme allowlist is trusted config, and a scheme outside it refuses.
    assert.equal(validateGitPushParameters(good, { allowedSchemes: ["ssh"] }).reason, "ERR_GIT_PUSH_REMOTE_URL_SCHEME");
  });

  await test("a request carrying an extra field is refused", async () => {
    const { repos, executor } = fixture();
    const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
    const authorization = await gitPushAuthorization(trust, parameters);
    const result = await withProfile("production", () => executor.executeGitPush({
      ...requestFor(parameters, authorization),
      force: true
    }));
    assert.equal(result.reason_code, "ERR_GIT_PUSH_REQUEST_BINDING", `got ${result.reason_code}`);
    assert.equal(repos.remoteSha(), repos.commits[0]);
  });

  rmSync(dir, { recursive: true, force: true });

  const total = passed + failed;
  console.log(`\n${failed === 0 ? "PASS" : "FAIL"} git.push typed effect (${passed}/${total})`);
  process.exit(failed === 0 ? 0 : 1);
}

await main();
