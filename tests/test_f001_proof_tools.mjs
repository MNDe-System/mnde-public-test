// F-001 proof toolkit (scripts/f001): what the tools report must be true, and what
// they cannot know must be reported as unknown.
//
//   npm run test:f001-proof-tools
//
// The collector is exercised on a REAL executed push (real git over file://, real
// signatures chained to a root-signed executor credential), plus tampered copies.
// The claim store is the repo's in-memory test double, so nothing here is evidence
// of the independent-database requirement. That stays NOT_PROVIDED, and one case
// asserts that it does.
import assert from "node:assert/strict";
import { spawnSync, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createGitPushExecutor, OUTCOME } from "../src/effects/git-push/index.mjs";
import { scanEnvironment, interpretPermissions } from "../scripts/f001/check-agent-environment.mjs";
import { evaluateProofRefControls, evaluateProtectedBranch } from "../scripts/f001/check-repository-controls.mjs";
import { bindToPendingAction, crossCheckGithubActivity } from "../scripts/f001/collect-evidence.mjs";
import { isProofRef } from "../scripts/f001/prepare-pending-action.mjs";
import { ENVIRONMENT_ID, EXECUTOR_ID, gitPushAuthorization, inMemoryClaimBackend, makeRepositories, productionTrust, pushParameters } from "./support/git_push_fixtures.mjs";
import { installClaimBackend } from "./support/claim_backend_double.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tool = (name) => join(repoRoot, "scripts", "f001", name);
let passed = 0; let failed = 0;
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  [PASS] ${name}`); }
  catch (error) { failed += 1; console.log(`  [FAIL] ${name}: ${error.stack?.split("\n").slice(0, 3).join(" | ")}`); }
}

// ── pure: agent environment ─────────────────────────────────────────────────
await test("env scan: reports credential NAMES, never values", () => {
  const env = { GH_TOKEN: "ghp_THIS_VALUE_MUST_NEVER_APPEAR", PATH: "/usr/bin", AWS_SECRET_ACCESS_KEY: "s3cr3t-value", EMPTY_TOKEN: "" };
  const findings = scanEnvironment(env, () => false);
  const text = JSON.stringify(findings);
  assert.ok(!text.includes("THIS_VALUE_MUST_NEVER_APPEAR") && !text.includes("s3cr3t-value"));
  assert.deepEqual(findings.map((f) => f.name), ["AWS_SECRET_ACCESS_KEY", "GH_TOKEN"]);
  assert.equal(findings.find((f) => f.name === "GH_TOKEN").push_capable_by_name, true);
  assert.equal(findings.find((f) => f.name === "AWS_SECRET_ACCESS_KEY").push_capable_by_name, false);
});
await test("env scan: a clean environment has no findings; credential files count", () => {
  assert.deepEqual(scanEnvironment({ PATH: "/usr/bin", HOME: "/home/x" }, () => false), []);
  assert.deepEqual(scanEnvironment({}, (f) => f === ".git-credentials").map((f) => f.name), [".git-credentials"]);
});
await test("env scan: the real CLI exits non-zero when a push credential is present, and prints no value", () => {
  const r = spawnSync(process.execPath, [tool("check-agent-environment.mjs")], { encoding: "utf8", env: { PATH: process.env.PATH, HOME: mkdtempSync(join(tmpdir(), "f001-home-")), GH_TOKEN: "ghp_VALUE_NOT_TO_BE_PRINTED_123456" } });
  assert.equal(r.status, 1);
  assert.ok(!r.stdout.includes("VALUE_NOT_TO_BE_PRINTED"));
  assert.equal(JSON.parse(r.stdout).ok, false);
  const clean = spawnSync(process.execPath, [tool("check-agent-environment.mjs")], { encoding: "utf8", env: { PATH: process.env.PATH, HOME: mkdtempSync(join(tmpdir(), "f001-home-")) } });
  assert.equal(clean.status, 0, clean.stdout);
});
await test("permissions: unknown shapes are NOT_PROVIDED, never assumed safe", () => {
  assert.deepEqual(interpretPermissions(undefined), { push: "NOT_PROVIDED", admin: "NOT_PROVIDED" });
  assert.deepEqual(interpretPermissions({ pull: true }), { push: false, admin: false });
  assert.deepEqual(interpretPermissions({ push: true, admin: true }), { push: true, admin: true });
});

// ── pure: repository controls (shapes copied from the live rulesets) ─────────
const REF = "refs/heads/mnde-proof/physical-hub";
const APP = 5105189;
const ruleset = (over) => ({ name: "r", enforcement: "active", bypass_actors: [], conditions: { ref_name: { include: [REF], exclude: [] } }, rules: [], ...over });
const goodSet = () => [
  ruleset({ name: "App-only updates", rules: [{ type: "update" }], bypass_actors: [{ actor_id: APP, actor_type: "Integration", bypass_mode: "always" }] }),
  ruleset({ name: "safety", rules: [{ type: "deletion" }, { type: "non_fast_forward" }] }),
  ruleset({ name: "main", conditions: { ref_name: { include: ["~DEFAULT_BRANCH"], exclude: [] } }, rules: [{ type: "deletion" }, { type: "non_fast_forward" }, { type: "pull_request" }, { type: "required_status_checks" }] })
];
await test("controls: the configuration seen live is accepted", () => {
  assert.equal(evaluateProofRefControls(goodSet(), REF, APP).ok, true);
  assert.equal(evaluateProtectedBranch(goodSet()).ok, true);
});
await test("controls: each way of weakening the proof ref is rejected", () => {
  const without = (type) => goodSet().map((r) => ({ ...r, rules: r.rules.filter((x) => x.type !== type) }));
  for (const type of ["update", "deletion", "non_fast_forward"]) assert.equal(evaluateProofRefControls(without(type), REF, APP).ok, false, `missing ${type}`);
  assert.equal(evaluateProofRefControls(goodSet().map((r) => ({ ...r, enforcement: "evaluate" })), REF, APP).ok, false, "evaluate-only is not enforcement");
  assert.equal(evaluateProofRefControls(goodSet().map((r) => ({ ...r, enforcement: "disabled" })), REF, APP).ok, false);
  assert.equal(evaluateProofRefControls(goodSet(), REF, 999).ok, false, "wrong App id");
  const human = goodSet(); human[1].bypass_actors = [{ actor_id: 1, actor_type: "User", bypass_mode: "always" }];
  assert.equal(evaluateProofRefControls(human, REF, APP).ok, false, "a human bypass");
  const role = goodSet(); role[1].bypass_actors = [{ actor_id: 5, actor_type: "RepositoryRole", bypass_mode: "always" }];
  assert.equal(evaluateProofRefControls(role, REF, APP).ok, false, "a role bypass");
  const noBypass = goodSet(); noBypass[0].bypass_actors = [];
  assert.equal(evaluateProofRefControls(noBypass, REF, APP).ok, false, "nobody may update at all is not the App-only design");
  assert.equal(evaluateProofRefControls([], REF, APP).ok, false);
  assert.equal(evaluateProofRefControls(goodSet(), "refs/heads/other", APP).ok, false, "a ref no ruleset covers");
});
await test("controls: a default branch with any bypass actor, or no PR rule, is rejected", () => {
  const withBypass = goodSet(); withBypass[2].bypass_actors = [{ actor_id: 1, actor_type: "User", bypass_mode: "always" }];
  assert.equal(evaluateProtectedBranch(withBypass).ok, false);
  const noPr = goodSet(); noPr[2].rules = noPr[2].rules.filter((x) => x.type !== "pull_request");
  assert.equal(evaluateProtectedBranch(noPr).ok, false);
});
await test("pending: only refs/heads/mnde-proof/<name> are acceptable targets", () => {
  assert.equal(isProofRef(REF), true);
  for (const bad of ["refs/heads/main", "refs/heads/mnde-proof/", "refs/heads/mnde-proof/a/b", "refs/tags/mnde-proof/x", "refs/heads/x/mnde-proof/y", "mnde-proof/x", "refs/heads/mnde-proof/../main", "refs/heads/mnde-proof/a b"]) assert.equal(isProofRef(bad), false, bad);
});
await test("github activity cross-check: right actor, exactly one push, no force-push", () => {
  const evidence = { target_ref: REF, approved_new_sha: "b".repeat(40) };
  const push = { ref: REF, activity_type: "push", after: "b".repeat(40), before: "a".repeat(40), timestamp: "t", actor: { login: "app[bot]", type: "Bot" } };
  assert.deepEqual([crossCheckGithubActivity([push], evidence, "app[bot]").exactly_one_matching_push, crossCheckGithubActivity([push], evidence, "app[bot]").pushed_by_expected_actor], [true, true]);
  assert.equal(crossCheckGithubActivity([push], evidence, "someone-else").pushed_by_expected_actor, false);
  assert.equal(crossCheckGithubActivity([push, { ...push, activity_type: "force_push" }], evidence, "app[bot]").any_force_push, true);
  assert.equal(crossCheckGithubActivity([], evidence, "app[bot]").pushed_by_expected_actor, false);
  assert.equal(crossCheckGithubActivity(null, evidence, "app[bot]").checked, false);
});

// ── the collector on a REAL executed push ───────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), "f001-tools-"));
try {
  const trust = await productionTrust(dir);
  const caseDir = join(dir, "case"); mkdirSync(caseDir);
  const repos = makeRepositories(caseDir);
  const NAMESPACE = "f001-tools-namespace";
  installClaimBackend(inMemoryClaimBackend({ namespace: NAMESPACE }));
  process.env.MNDE_GIT_CREDENTIAL_CONFIG = repos.credentialConfigPath;
  const executor = createGitPushExecutor({
    repoPath: repos.localPath, namespace: NAMESPACE, authorityBundle: trust.bundle, authorityBundlePath: trust.bundlePath, trustedRootFingerprint: trust.fingerprint,
    environmentId: ENVIRONMENT_ID, expectedExecutorId: EXECUTOR_ID, allowedSchemes: ["file"], evidenceDir: join(caseDir, "evidence"),
    executorIdentity: trust.executor.identity, executorSigner: trust.executor.signer
  });
  const parameters = pushParameters(repos, { from: repos.commits[0], to: repos.commits[1] });
  const authorization = await gitPushAuthorization(trust, parameters);
  process.env.MNDE_PROFILE = "production";
  const result = await executor.executeGitPush({ repository: parameters.repository, remote: parameters.remote, remoteUrl: parameters.remote_url, sourceCommit: parameters.source_commit, targetRef: parameters.target_ref, expectedOldSha: parameters.expected_old_sha, authorization });
  delete process.env.MNDE_PROFILE;
  assert.equal(result.outcome, OUTCOME.EXECUTED, `fixture push did not execute: ${result.reason_code}`);

  const file = (name, value) => { const p = join(dir, name); writeFileSync(p, JSON.stringify(value)); return p; };
  const bundlePath = file("bundle.json", trust.bundle);
  const evidencePath = file("evidence.json", result.signedEvidence);
  const pending = { remote_url: parameters.remote_url, target_ref: parameters.target_ref, expected_old_sha: parameters.expected_old_sha, source_commit: parameters.source_commit };
  const baseArgs = [tool("collect-evidence.mjs"), "--authority-bundle", bundlePath, "--root-fingerprint", trust.fingerprint, "--expected-executor-id", EXECUTOR_ID, "--expected-environment-id", ENVIRONMENT_ID];
  const collect = (evidence, extra = []) => {
    const r = spawnSync(process.execPath, [...baseArgs, "--evidence", evidence, ...extra], { encoding: "utf8", cwd: repoRoot });
    return { status: r.status, report: JSON.parse(r.stdout) };
  };

  await test("collector: real signed evidence verifies offline and yields the identities and action binding", () => {
    const { report } = collect(evidencePath);
    const o = report.OBSERVED;
    assert.equal(o.offline_verification_of_signed_evidence.ok, true);
    assert.equal(o.identities.executor_id, EXECUTOR_ID);
    assert.equal(o.identities.environment_id, ENVIRONMENT_ID);
    assert.ok(o.identities.grant_id && o.identities.execution_id && o.identities.authorization_receipt_hash);
    assert.equal(o.action_binding.approved_new_sha, parameters.source_commit);
    assert.equal(o.action_binding.observed_after_sha, parameters.source_commit);
    assert.equal(o.outcome.outcome, "EXECUTED");
    assert.equal(o.claim_as_recorded_by_the_executor.decision, "CLAIMED");
  });
  await test("collector: with only the evidence it is NOT complete and says what is missing (claim system, start record, denial, activity)", () => {
    const { status, report } = collect(evidencePath);
    assert.equal(status, 1);
    assert.equal(report.complete, false);
    assert.equal(report.OBSERVED.claim_as_observed_by_the_independent_operator, "NOT_PROVIDED");
    assert.equal(report.OBSERVED.direct_push_denial, "NOT_PROVIDED");
    assert.equal(report.OBSERVED.github_side_record, "NOT_PROVIDED");
    for (const label of ["claim observation from the independent database operator", "durable execution-start record", "recorded direct-push denial", "GitHub ref activity"]) assert.ok(report.missing.includes(label), label);
    assert.ok(report.CANNOT_BE_COLLECTED_BY_THIS_TOOL.length >= 3);
  });
  await test("collector: binds the evidence to the action the approver was shown, and reports each mismatch", () => {
    const good = collect(evidencePath, ["--pending", file("pending-ok.json", pending)]).report.OBSERVED.action_binding.matches_what_the_approver_was_shown;
    assert.deepEqual([good.checked, good.matches, good.mismatches.length], [true, true, 0]);
    const bad = collect(evidencePath, ["--pending", file("pending-bad.json", { ...pending, target_ref: "refs/heads/mnde-proof/other", source_commit: "c".repeat(40) })]).report.OBSERVED.action_binding.matches_what_the_approver_was_shown;
    assert.equal(bad.matches, false);
    assert.deepEqual(bad.mismatches.map((m) => m.field).sort(), ["approved_new_sha", "target_ref"]);
  });
  await test("collector: tampered evidence fails verification and no field from it is reported as observed", () => {
    const tampered = structuredClone(result.signedEvidence);
    tampered.evidence.approved_new_sha = "d".repeat(40);
    tampered.evidence.observed_after_sha = "d".repeat(40);
    const { report } = collect(file("tampered.json", tampered));
    assert.equal(report.OBSERVED.offline_verification_of_signed_evidence.ok, false);
    assert.equal(report.OBSERVED.identities, "NOT_PROVIDED");
    assert.equal(report.OBSERVED.action_binding, "NOT_PROVIDED");
    assert.equal(report.complete, false);
  });
  await test("collector: evidence verified against the wrong pinned root fails", () => {
    const r = spawnSync(process.execPath, [...baseArgs.slice(0, 3), "--root-fingerprint", "0".repeat(64), "--evidence", evidencePath], { encoding: "utf8", cwd: repoRoot });
    assert.equal(JSON.parse(r.stdout).OBSERVED.offline_verification_of_signed_evidence.ok, false);
  });
  await test("collector: records the sha256 of every artifact it was given", () => {
    const { report } = collect(evidencePath, ["--pending", file("pending-ok2.json", pending)]);
    assert.equal(report.OBSERVED.artifacts.length, 3);
    assert.ok(report.OBSERVED.artifacts.every((a) => /^[0-9a-f]{64}$/.test(a.sha256)));
  });

  // ── prepare-pending-action, against a local bare repository ───────────────
  await test("prepare-pending-action: deterministic payload commit on the live tip; pushes nothing; refuses non-proof refs", () => {
    const bare = join(dir, "remote.git");
    const work = join(dir, "seed");
    mkdirSync(work);
    const g = (cwd, ...a) => execFileSync("git", a, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, GIT_AUTHOR_NAME: "s", GIT_AUTHOR_EMAIL: "s@x", GIT_COMMITTER_NAME: "s", GIT_COMMITTER_EMAIL: "s@x" } }).trim();
    g(dir, "init", "-q", "--bare", bare);
    g(work, "init", "-q"); writeFileSync(join(work, "a.txt"), "a\n"); g(work, "add", "."); g(work, "commit", "-q", "-m", "seed");
    g(work, "push", "-q", bare, "HEAD:refs/heads/mnde-proof/test");
    const url = `file://${bare}`;
    const before = g(dir, "ls-remote", url);
    const prepare = (name, ref = "refs/heads/mnde-proof/test") => {
      const r = spawnSync(process.execPath, [tool("prepare-pending-action.mjs"), "--remote-url", url, "--target-ref", ref, "--workdir", join(dir, name)], { encoding: "utf8" });
      return { status: r.status, out: JSON.parse(r.stdout) };
    };
    const a = prepare("w1"); const b = prepare("w2");
    assert.equal(a.status, 0, JSON.stringify(a.out));
    assert.equal(a.out.status, "PENDING_APPROVAL_NOT_EXECUTED");
    assert.equal(a.out.source_commit, b.out.source_commit, "the payload commit must be reproducible");
    assert.equal(a.out.expected_old_sha, g(dir, "ls-remote", url).split(/\s+/)[0]);
    assert.equal(g(join(dir, "w1"), "rev-parse", `${a.out.source_commit}^`), a.out.expected_old_sha, "payload commit is a direct descendant of the live tip");
    assert.equal(g(dir, "ls-remote", url), before, "preparing must not change the remote");
    const refused = prepare("w3", "refs/heads/main");
    assert.equal(refused.status, 2);
    assert.match(refused.out.error, /not a refs\/heads\/mnde-proof/);
    const missing = prepare("w4", "refs/heads/mnde-proof/does-not-exist");
    assert.equal(missing.status, 2);
    assert.match(missing.out.error, /already exist/);
  });
} finally { rmSync(dir, { recursive: true, force: true }); }

console.log("");
if (failed > 0) { console.log(`FAIL f001-proof-tools tests (${passed}/${passed + failed})`); process.exit(1); }
console.log(`PASS f001-proof-tools tests (${passed}/${passed + failed})`);
