#!/usr/bin/env node
// F-001 evidence inventory: collect what exists, verify what can be verified offline,
// and say plainly what is missing. It performs no push, claims nothing, writes
// nothing but its report, and reads only the files named on the command line.
//
//   node scripts/f001/collect-evidence.mjs \
//     --evidence <git-push-….signed.json> \
//     --authority-bundle <bundle.json> --root-fingerprint <hex> \
//     --expected-executor-id <id> --expected-environment-id <id> \
//     [--pending <pending-action.json>] [--started-marker <….started.json>] \
//     [--cli-result <mnde-git-push stdout json>] \
//     [--claim-observation <json from the independent database operator>] \
//     [--direct-push-denial <json recorded by the operator>] \
//     [--github-activity <ref activity JSON from GET /repos/{r}/activity?ref=…>] \
//     [--out <report.json>]
//
// Every section is either OBSERVED (read from a file and, where possible, verified
// here) or NOT_PROVIDED. Nothing is inferred into existence: a missing artifact
// leaves `complete` false and names itself in `missing`.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

import { verifyExecutionEvidence } from "../../src/effects/git-push/evidence.mjs";
import { NOT_PROVIDED, fileSha256, parseArgs } from "./lib.mjs";

const read = (path) => JSON.parse(readFileSync(path, "utf8"));

// Pure. Compare the signed evidence with the action the approver was shown.
export function bindToPendingAction(evidence, pending) {
  if (!pending) return { checked: false, reason: "no pending-action file provided" };
  const pairs = [
    ["remote_url", evidence.remote_url, pending.remote_url],
    ["target_ref", evidence.target_ref, pending.target_ref],
    ["expected_old_sha", evidence.expected_old_sha, pending.expected_old_sha],
    ["approved_new_sha", evidence.approved_new_sha, pending.source_commit]
  ];
  const mismatches = pairs.filter(([, a, b]) => a !== b).map(([field, signed, shown]) => ({ field, signed, shown }));
  return { checked: true, matches: mismatches.length === 0, mismatches };
}

// Pure. Did GitHub itself record the push to the ref, by whom, and to which SHA?
export function crossCheckGithubActivity(activity, evidence, expectedActorLogin) {
  if (!Array.isArray(activity)) return { checked: false, reason: "no GitHub activity file provided" };
  const pushes = activity.filter((a) => a.ref === evidence.target_ref && (a.activity_type === "push" || a.activity_type === "force_push") && a.after === evidence.approved_new_sha);
  const forced = pushes.filter((a) => a.activity_type === "force_push");
  return {
    checked: true,
    matching_pushes: pushes.map((a) => ({ at: a.timestamp, type: a.activity_type, actor: a.actor?.login, actor_type: a.actor?.type, before: a.before, after: a.after })),
    exactly_one_matching_push: pushes.length === 1,
    pushed_by_expected_actor: pushes.length > 0 && pushes.every((a) => a.actor?.login === expectedActorLogin),
    any_force_push: forced.length > 0
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2), {
    evidence: "value", "authority-bundle": "value", "root-fingerprint": "value", "expected-executor-id": "value", "expected-environment-id": "value",
    pending: "value", "started-marker": "value", "cli-result": "value", "claim-observation": "value", "direct-push-denial": "value",
    "github-activity": "value", "expected-pusher-login": "value", out: "value"
  });
  const missing = [];
  const artifacts = [];
  const track = (label, path) => { if (path && existsSync(path)) { artifacts.push({ label, path, sha256: fileSha256(path) }); return true; } missing.push(label); return false; };

  const have = {
    evidence: track("signed execution evidence", args.evidence),
    bundle: track("authority bundle", args["authority-bundle"]),
    pending: track("pending action (what the approver was shown)", args.pending),
    marker: track("durable execution-start record", args["started-marker"]),
    cli: track("executor CLI result", args["cli-result"]),
    claim: track("claim observation from the independent database operator", args["claim-observation"]),
    denial: track("recorded direct-push denial", args["direct-push-denial"]),
    activity: track("GitHub ref activity", args["github-activity"])
  };

  let verification = { performed: false, reason: "evidence or authority bundle not provided" };
  let envelope = null;
  if (have.evidence && have.bundle && args["root-fingerprint"]) {
    envelope = read(args.evidence);
    const verdict = await verifyExecutionEvidence(envelope, {
      authorityBundle: read(args["authority-bundle"]), trustedRootFingerprint: args["root-fingerprint"],
      expectedExecutorId: args["expected-executor-id"], expectedEnvironmentId: args["expected-environment-id"]
    });
    verification = { performed: true, ok: verdict.ok === true, reason_code: verdict.ok ? null : verdict.reason_code ?? null, detail: verdict.ok ? null : verdict.detail ?? null };
  }
  const ev = verification.ok ? envelope.evidence : null;

  let commit = NOT_PROVIDED;
  try { commit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(); } catch { /* not a checkout */ }

  const started = have.marker ? read(args["started-marker"]) : null;
  const claimObs = have.claim ? read(args["claim-observation"]) : null;
  const report = {
    tool: "collect-evidence",
    generated_at: new Date().toISOString(),
    OBSERVED: {
      commit_under_test: commit,
      environment: { node: process.version, platform: process.platform },
      offline_verification_of_signed_evidence: verification,
      identities: ev ? {
        executor_id: ev.executor_id, environment_id: ev.environment_id, key_id: ev.key_id, credential_id: ev.credential_id,
        grant_id: ev.grant_id, execution_id: ev.execution_id, authority_bundle_fingerprint: ev.authority_bundle_fingerprint,
        authorization_receipt_hash: ev.authorization_receipt_hash, authority_digest: ev.authority_digest
      } : NOT_PROVIDED,
      action_binding: ev ? {
        action: ev.action, repository: ev.repository, remote_url: ev.remote_url, target_ref: ev.target_ref,
        expected_old_sha: ev.expected_old_sha, approved_new_sha: ev.approved_new_sha,
        observed_before_sha: ev.observed_before_sha, observed_after_sha: ev.observed_after_sha,
        matches_what_the_approver_was_shown: bindToPendingAction(ev, have.pending ? read(args.pending) : null)
      } : NOT_PROVIDED,
      outcome: ev ? { outcome: ev.outcome, reason_code: ev.reason_code, effect_attempted: ev.effect_attempted, recorded_at: ev.recorded_at } : NOT_PROVIDED,
      claim_as_recorded_by_the_executor: ev ? ev.claim : NOT_PROVIDED,
      claim_as_observed_by_the_independent_operator: claimObs ?? NOT_PROVIDED,
      execution_start_record: started ? { present: true, name: args["started-marker"].split(/[\\/]/).pop() } : { present: false },
      github_side_record: have.activity && ev ? crossCheckGithubActivity(read(args["github-activity"]), ev, args["expected-pusher-login"]) : NOT_PROVIDED,
      direct_push_denial: have.denial ? read(args["direct-push-denial"]) : NOT_PROVIDED,
      artifacts
    },
    INFERRED: [
      "The signed evidence names the executor, grant, claim namespace and approved effect. It does not name the GitHub App or the installation (see docs/PRODUCTION-TRUST-BOUNDARY.md); that identity is only in the local execution record.",
      "A matching GitHub activity record plus verified evidence is consistent with the push having gone through the executor. It does not prove no other path exists."
    ],
    CANNOT_BE_COLLECTED_BY_THIS_TOOL: [
      "Whether the claim row exists in the independent database. Only the database operator can read it (see the protocol).",
      "Power-loss durability of the execution-start record or the claim store.",
      "That no other actor holds an equivalent push credential."
    ],
    missing,
    complete: missing.length === 0 && verification.ok === true
  };
  const text = `${JSON.stringify(report, null, 2)}\n`;
  if (args.out) writeFileSync(args.out, text);
  process.stdout.write(text);
  process.exit(report.complete ? 0 : 1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => { process.stdout.write(`${JSON.stringify({ complete: false, error: error.message })}\n`); process.exit(2); });
}
