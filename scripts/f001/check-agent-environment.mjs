#!/usr/bin/env node
// F-001 acceptance criterion 2: the agent does not possess a production push credential.
//
//   node scripts/f001/check-agent-environment.mjs [--probe-github <owner/repo>]
//
// Run it AS the agent, in the agent's own environment. It lists credential-shaped
// environment variable NAMES and well-known credential files that exist, never their
// values. With --probe-github it also asks GitHub, with whatever token the agent
// holds, what that token may do to the repository (one GET, no writes).
//
// Exit 0 only if nothing push-capable was found. A non-zero exit is the expected
// result in any environment where the agent is also a developer. That is the point.
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { NOT_PROVIDED, githubGet, parseArgs, report } from "./lib.mjs";

const NAME_PATTERN = /(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|ASKPASS|API_KEY|APP_ID|INSTALLATION_ID|SSH_AUTH_SOCK)/i;
const KNOWN_GIT_TOKEN_NAMES = ["GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_PAT", "GIT_ASKPASS", "SSH_AUTH_SOCK"];
const CREDENTIAL_FILES = [".git-credentials", ".config/gh/hosts.yml", ".netrc", ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa"];

// Pure: given an environment object and a file-exists predicate, list findings.
export function scanEnvironment(env, fileExists) {
  const envFindings = Object.entries(env)
    .filter(([name, value]) => typeof value === "string" && value.length > 0 && (NAME_PATTERN.test(name) || KNOWN_GIT_TOKEN_NAMES.includes(name)))
    .map(([name]) => ({ kind: "environment_variable", name, push_capable_by_name: KNOWN_GIT_TOKEN_NAMES.includes(name) }))
    .sort((a, b) => a.name.localeCompare(b.name));
  const fileFindings = CREDENTIAL_FILES.filter((relative) => fileExists(relative)).map((relative) => ({ kind: "credential_file", name: relative, push_capable_by_name: true }));
  return [...envFindings, ...fileFindings];
}

// Pure: what GitHub said a token may do.
export function interpretPermissions(permissions) {
  if (!permissions || typeof permissions !== "object") return { push: NOT_PROVIDED, admin: NOT_PROVIDED };
  return { push: permissions.push === true, admin: permissions.admin === true };
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { "probe-github": "value" });
  const findings = scanEnvironment(process.env, (relative) => existsSync(join(homedir(), relative)));
  // Is a git credential helper configured? Presence only; the helper's output is never read.
  let helperConfigured = false;
  try { helperConfigured = /credential\s*\.?helper|\[credential/.test(readFileSync(join(homedir(), ".gitconfig"), "utf8")); } catch { /* no gitconfig */ }

  let probe = { performed: false };
  if (args["probe-github"]) {
    const token = process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN;
    if (!token) probe = { performed: true, result: "no GH_TOKEN/GITHUB_TOKEN to probe with" };
    else {
      const response = await githubGet(`/repos/${args["probe-github"]}`, token);
      probe = { performed: true, http_status: response.status, token_permissions_on_repository: interpretPermissions(response.body?.permissions) };
    }
  }

  const pushCapableToken = probe.token_permissions_on_repository?.push === true;
  const pushCapableByName = findings.some((f) => f.push_capable_by_name);
  const ok = !pushCapableByName && !pushCapableToken && !helperConfigured;
  const out = report({
    tool: "check-agent-environment",
    ok,
    observed: { credential_like_items: findings, git_credential_helper_configured: helperConfigured, github_probe: probe },
    inferred: pushCapableByName ? ["At least one item is named like a GitHub/git credential. Whether it is valid is not tested."] : [],
    cannot_observe: [
      "Credentials held outside this process's environment and home directory (other users, a keychain, a secrets agent, a network proxy that injects credentials).",
      "Whether a credential-shaped variable is actually valid. Only the optional GitHub probe tests one token, and only for the repository named."
    ]
  });
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
  process.exit(ok ? 0 : 1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => { process.stdout.write(`${JSON.stringify({ ok: false, error: error.message })}\n`); process.exit(2); });
}
