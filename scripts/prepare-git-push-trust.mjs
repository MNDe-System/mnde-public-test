#!/usr/bin/env node
// prepare-git-push-trust — generate the trust material one mnde-git-push
// deployment needs, outside the repository, and write the environment files
// that wire it up.
//
//   node scripts/prepare-git-push-trust.mjs \
//     --out <directory outside the repository> \
//     --authority-id <your-org>-prod \
//     --executor-id <your-org>:prod:executor:gitpush:01 \
//     [--environment prod] [--executor-ttl-hours 168]
//
// It adds no key handling of its own. It runs the two existing ceremonies:
//
//   1. scripts/init-production-authority.mjs  -> <out>/authority/
//      root key, receipt/ledger/activation keys, root-signed authority bundle.
//   2. scripts/trust-enroll-executor.mjs      -> <out>/executor/
//      a fresh executor key plus a root-signed credential for it.
//
// and then writes <out>/mnde-git-push.env.ps1 and <out>/mnde-git-push.env.sh,
// which set every variable mnde-git-push and scripts/authorize-git-push.mjs read.
// Values only the operator can supply (claim store, push credential, local
// repository) are left as clearly marked REPLACE_ME entries; mnde-git-push
// refuses to start while any of those files are missing.
//
// What happens to each file afterwards is described in
// docs/FIRST-PRODUCTION-GIT-PUSH.md. In short: the root key is needed once, for
// step 2, and should then be moved offline.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { isRepoContained } from "../src/authority-signing/repo-containment.mjs";
import { initProductionAuthority } from "./init-production-authority.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ENROLL = join(REPO_ROOT, "scripts", "trust-enroll-executor.mjs");

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--") || i + 1 >= argv.length) return null;
    args[token.slice(2)] = argv[(i += 1)];
  }
  return args;
}

function die(message, code = 1) {
  process.stderr.write(`prepare-git-push-trust: ${message}\n`);
  process.exit(code);
}

// Single quotes in PowerShell and POSIX sh both take the value literally; a
// quote inside a path is refused rather than escaped.
function quoted(value) {
  if (/['\r\n]/.test(value)) die(`refusing to write a value containing a quote or newline: ${value}`);
  return `'${value}'`;
}

export function envFileContents(vars, shell) {
  const lines = shell === "ps1"
    ? ["# mnde-git-push environment. Load with:  . .\\mnde-git-push.env.ps1", ""]
    : ["# mnde-git-push environment. Load with:  . ./mnde-git-push.env.sh", ""];
  for (const [name, value, note] of vars) {
    if (note) lines.push(`# ${note}`);
    lines.push(shell === "ps1" ? `$env:${name} = ${quoted(value)}` : `export ${name}=${quoted(value)}`);
  }
  return `${lines.join("\n")}\n`;
}

const KNOWN = new Set(["out", "authority-id", "executor-id", "environment", "executor-ttl-hours"]);
const USAGE = "usage: node scripts/prepare-git-push-trust.mjs --out <dir-outside-repo> --authority-id <id> --executor-id <id> [--environment prod] [--executor-ttl-hours 168]\n";

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args || Object.keys(args).some((key) => !KNOWN.has(key)) || !args.out || !args["authority-id"] || !args["executor-id"]) {
    process.stderr.write(USAGE);
    process.exit(2);
  }
  const out = resolve(args.out);
  const environment = args.environment ?? "prod";
  const executorId = args["executor-id"];
  const ttl = args["executor-ttl-hours"] ?? "168";
  if (isRepoContained(out, REPO_ROOT)) die("--out must be outside the repository", 2);
  if (/local|demo/i.test(executorId)) die("--executor-id must not contain 'local' or 'demo'", 2);
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(environment)) die("--environment must be 1-64 characters of [A-Za-z0-9._-]", 2);
  if (!/^[1-9][0-9]{0,4}$/.test(ttl)) die("--executor-ttl-hours must be a positive whole number", 2);
  if (existsSync(join(out, "mnde-git-push.env.ps1")) || existsSync(join(out, "mnde-git-push.env.sh"))) {
    die(`${out} already holds a prepared deployment; choose an empty directory`);
  }

  const authorityDir = join(out, "authority");
  const executorDir = join(out, "executor");

  // 1. Authority. Refuses to overwrite and to write inside the repository.
  const authority = await initProductionAuthority({ outDir: authorityDir, authorityId: args["authority-id"] });
  if (!authority.ok) die(`authority: ${authority.reason}`);

  // 2. Executor. The enrolment script is run as its own process so all of its
  // path checks (symlinks, junctions, repository containment) apply unchanged.
  const enrolled = spawnSync(process.execPath, [
    ENROLL,
    "--executor-id", executorId,
    "--environment", environment,
    "--bundle", authority.paths.bundle,
    "--root-key", authority.paths.rootPrivate,
    "--out-dir", executorDir,
    "--ttl-hours", ttl
  ], { encoding: "utf8", env: { ...process.env, MNDE_EXTERNAL_ROOT_SIGNER_CMD: "" } });
  if (enrolled.status !== 0) die(`executor enrolment failed: ${(enrolled.stderr || enrolled.stdout).trim()}`);
  let executor;
  try { executor = JSON.parse(enrolled.stdout); } catch { die("executor enrolment printed an unexpected summary"); }

  const bundle = JSON.parse(readFileSync(authority.paths.bundle, "utf8"));
  const replace = (what) => `REPLACE_ME: ${what}`;
  const vars = [
    ["MNDE_PROFILE", "production"],
    // What the executor trusts.
    ["MNDE_VERIFY_AUTHORITY_BUNDLE", authority.paths.bundle, "Trust: the published bundle and the root it must chain to."],
    ["MNDE_VERIFY_TRUSTED_ROOT_FINGERPRINT", authority.rootFingerprint],
    ["MNDE_VERIFY_ENVIRONMENT_ID", environment],
    ["MNDE_VERIFY_EXPECTED_EXECUTOR_ID", executorId],
    // Who the executor is.
    ["MNDE_EXECUTOR_ID", executorId, "Executor identity: signs execution evidence."],
    ["MNDE_EXECUTOR_PRIVATE_KEY", executor.private_key_path],
    ["MNDE_EXECUTOR_CREDENTIAL", executor.credential_path],
    ["MNDE_EXECUTOR_ENVIRONMENT", environment],
    // Approval side, read only by scripts/authorize-git-push.mjs.
    ["MNDE_AUTHORITY_BUNDLE", authority.paths.bundle, "Approval: the receipt key signs authorizations. Only authorize-git-push reads these two."],
    ["MNDE_RECEIPT_SIGNING_KEY", authority.paths.receiptPrivate],
    // Operator-supplied.
    ["MNDE_CLAIM_CONFIG", join(out, "claim-config.json"), "Claim store config; see the runbook. The file must exist."],
    ["MNDE_GIT_CREDENTIAL_CONFIG", join(out, "git-credential.json"), "Push credential config; see the runbook. The file must exist."],
    ["MNDE_GIT_PUSH_NAMESPACE", `${bundle.authority_id}-git-push`, "Must equal the namespace the claim-store login is bound to."],
    ["MNDE_GIT_PUSH_REPO_PATH", replace("absolute path of the local clone holding the commit to push")],
    ["MNDE_GIT_PUSH_EVIDENCE_DIR", join(out, "evidence")]
  ];
  writeFileSync(join(out, "mnde-git-push.env.ps1"), envFileContents(vars, "ps1"), { mode: 0o600, flag: "wx" });
  writeFileSync(join(out, "mnde-git-push.env.sh"), envFileContents(vars, "sh"), { mode: 0o600, flag: "wx" });

  process.stdout.write(`${JSON.stringify({
    authority_id: bundle.authority_id,
    root_fingerprint: authority.rootFingerprint,
    executor_id: executorId,
    executor_credential_expires_at: executor.expires_at,
    environment_id: environment,
    files: {
      root_private_key: authority.paths.rootPrivate,
      receipt_private_key: authority.paths.receiptPrivate,
      authority_bundle: authority.paths.bundle,
      executor_private_key: executor.private_key_path,
      executor_credential: executor.credential_path,
      env_powershell: join(out, "mnde-git-push.env.ps1"),
      env_sh: join(out, "mnde-git-push.env.sh")
    },
    next: "Move the root private key offline now; it is not needed to push. Then follow docs/FIRST-PRODUCTION-GIT-PUSH.md from step 3."
  }, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => die(error?.message ?? String(error)));
}
