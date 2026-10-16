#!/usr/bin/env node
// F-001 acceptance criterion 1: a direct, unauthorized push to the proof ref is denied.
//
//   node scripts/f001/check-repository-controls.mjs --repo <owner/repo> --ref <refs/heads/...> \
//        --expected-app-id <id> [--protected-branch <name>] [--token-env GH_TOKEN]
//
// Reads the repository's rulesets (GET only) and checks that, for the proof ref, only
// the named GitHub App can update it, nobody can delete or force-move it, and nobody
// else can bypass. It does NOT push anything. A configuration check shows the control
// is configured; it does not show a denied push. The denied push is a separate,
// operator-run step in docs/F001-PROOF-PROTOCOL.md.
import { fileURLToPath } from "node:url";

import { githubGet, parseArgs, report } from "./lib.mjs";

const REQUIRED_ON_PROOF_REF = ["update", "deletion", "non_fast_forward"];

// Pure. `rulesets` are full ruleset objects (with `rules`, `bypass_actors`,
// `conditions`, `enforcement`). Matches by the ref patterns the ruleset names.
export function evaluateProofRefControls(rulesets, ref, expectedAppId) {
  const applies = (ruleset) => ruleset.enforcement === "active"
    && (ruleset.conditions?.ref_name?.include ?? []).some((p) => p === ref || p === "~ALL")
    && !(ruleset.conditions?.ref_name?.exclude ?? []).includes(ref);
  const active = rulesets.filter(applies);
  const ruleTypes = new Set(active.flatMap((r) => (r.rules ?? []).map((rule) => rule.type)));
  const missing = REQUIRED_ON_PROOF_REF.filter((type) => !ruleTypes.has(type));
  const bypass = active.flatMap((r) => (r.bypass_actors ?? []).map((b) => ({ ruleset: r.name, actor_type: b.actor_type, actor_id: b.actor_id, bypass_mode: b.bypass_mode })));
  // Bypass belongs to the ruleset that restricts updates. The deletion / non-ff ruleset must have none.
  const unexpectedBypass = bypass.filter((b) => !(b.actor_type === "Integration" && String(b.actor_id) === String(expectedAppId)));
  const humanBypass = bypass.filter((b) => ["User", "Team", "RepositoryRole", "OrganizationAdmin"].includes(b.actor_type));
  return {
    rulesets_applying: active.map((r) => r.name),
    rule_types_applying: [...ruleTypes].sort(),
    missing_required_rule_types: missing,
    bypass_actors: bypass,
    unexpected_bypass_actors: unexpectedBypass,
    human_bypass_actors: humanBypass,
    ok: active.length > 0 && missing.length === 0 && unexpectedBypass.length === 0 && humanBypass.length === 0
      && bypass.some((b) => b.actor_type === "Integration" && String(b.actor_id) === String(expectedAppId))
  };
}

// Pure. The default branch must have no bypass actor at all.
export function evaluateProtectedBranch(rulesets) {
  const active = rulesets.filter((r) => r.enforcement === "active" && (r.conditions?.ref_name?.include ?? []).includes("~DEFAULT_BRANCH"));
  const types = new Set(active.flatMap((r) => (r.rules ?? []).map((rule) => rule.type)));
  const bypass = active.flatMap((r) => r.bypass_actors ?? []);
  return { rule_types_applying: [...types].sort(), bypass_actor_count: bypass.length, ok: types.has("pull_request") && types.has("non_fast_forward") && bypass.length === 0 };
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { repo: "value", ref: "value", "expected-app-id": "value", "token-env": "value" });
  if (!args.repo || !args.ref || !args["expected-app-id"]) throw new Error("--repo, --ref and --expected-app-id are required");
  const token = process.env[args["token-env"] ?? "GH_TOKEN"] ?? process.env.GITHUB_TOKEN;
  const list = await githubGet(`/repos/${args.repo}/rulesets`, token);
  if (list.status !== 200) throw new Error(`could not list rulesets (HTTP ${list.status})`);
  const full = [];
  for (const summary of list.body) {
    const detail = await githubGet(`/repos/${args.repo}/rulesets/${summary.id}`, token);
    if (detail.status !== 200) throw new Error(`could not read ruleset ${summary.id} (HTTP ${detail.status})`);
    full.push(detail.body);
  }
  const repo = await githubGet(`/repos/${args.repo}`, token);
  const proof = evaluateProofRefControls(full, args.ref, args["expected-app-id"]);
  const main = evaluateProtectedBranch(full);
  const callerCanAdminister = repo.body?.permissions?.admin === true;
  const out = report({
    tool: "check-repository-controls",
    ok: proof.ok && main.ok,
    observed: { repository: args.repo, proof_ref: args.ref, proof_ref_controls: proof, default_branch_controls: main, calling_token_has_admin: callerCanAdminister },
    inferred: [
      proof.ok ? "Per configuration, only the named App can advance the proof ref and no one can delete or force-move it." : "The proof ref is not configured as App-only."
    ],
    cannot_observe: [
      "A denied push. This is a configuration read; no push was attempted.",
      "Whether repository or organization administrators can edit or disable these rulesets. They can, so the control holds against non-admin identities only.",
      "Rulesets inherited from the organization, if the token cannot see them.",
      "Who holds the named App's private key."
    ]
  });
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
  process.exit(out.ok ? 0 : 1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => { process.stdout.write(`${JSON.stringify({ ok: false, error: error.message })}\n`); process.exit(2); });
}
