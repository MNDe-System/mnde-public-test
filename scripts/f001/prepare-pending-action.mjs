#!/usr/bin/env node
// F-001 acceptance criterion 3/4: define the exact action that needs approval.
//
//   node scripts/f001/prepare-pending-action.mjs --remote-url <url> --target-ref <refs/heads/...> \
//        --workdir <empty dir> [--subject <approver id>]
//
// Reads the remote's current tip (git ls-remote, then a depth-1 fetch of that one
// ref into --workdir: read-only), builds ONE harmless payload commit on top of it
// with fixed author, committer, date and message so the SHA is reproducible, and
// prints the six values an approver must sign. It pushes nothing, creates no ref on
// the remote, and never signs. The output is a PENDING action, not a result.
import { execFileSync } from "node:child_process";
import { mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { fileSha256, parseArgs } from "./lib.mjs";

export const PAYLOAD_PATH = "proofs/f001-acceptance-payload.txt";
export const PAYLOAD_TEXT = "F-001 acceptance payload. Harmless: this file exists only to give the proof ref a descendant commit.\n";
const FIXED = {
  GIT_AUTHOR_NAME: "MNDe F-001 proof", GIT_AUTHOR_EMAIL: "f001-proof@mnde.invalid", GIT_AUTHOR_DATE: "2026-10-16T00:00:00Z",
  GIT_COMMITTER_NAME: "MNDe F-001 proof", GIT_COMMITTER_EMAIL: "f001-proof@mnde.invalid", GIT_COMMITTER_DATE: "2026-10-16T00:00:00Z"
};

const git = (cwd, args, env = {}) => execFileSync("git", args, { cwd, encoding: "utf8", env: { ...process.env, ...env, GIT_TERMINAL_PROMPT: "0" } }).trim();

// Pure: the refs a ref-pattern guard allows. The executor only moves existing refs/heads/<name>.
export function isProofRef(ref) {
  return /^refs\/heads\/mnde-proof\/[A-Za-z0-9._-]+$/.test(ref);
}

async function main() {
  const args = parseArgs(process.argv.slice(2), { "remote-url": "value", "target-ref": "value", workdir: "value", subject: "value" });
  if (!args["remote-url"] || !args["target-ref"] || !args.workdir) throw new Error("--remote-url, --target-ref and --workdir are required");
  if (!isProofRef(args["target-ref"])) throw new Error(`refusing: ${args["target-ref"]} is not a refs/heads/mnde-proof/<name> ref`);
  const workdir = resolve(args.workdir);
  mkdirSync(workdir, { recursive: true });
  if (readdirSync(workdir).length > 0) throw new Error("--workdir must be empty");

  const lsRemote = git(workdir, ["ls-remote", args["remote-url"], args["target-ref"]]);
  const expectedOld = lsRemote.split(/\s+/)[0];
  if (!/^[0-9a-f]{40}$/.test(expectedOld)) throw new Error(`could not read the remote tip of ${args["target-ref"]} (ref must already exist; the executor never creates one)`);

  git(workdir, ["init", "-q"]);
  git(workdir, ["fetch", "-q", "--depth=1", args["remote-url"], `${args["target-ref"]}:refs/remotes/origin/proof-tip`]);
  const tip = git(workdir, ["rev-parse", "refs/remotes/origin/proof-tip"]);
  if (tip !== expectedOld) throw new Error(`remote moved while preparing (ls-remote ${expectedOld}, fetched ${tip}); run again`);

  mkdirSync(join(workdir, "proofs"), { recursive: true });
  writeFileSync(join(workdir, PAYLOAD_PATH), PAYLOAD_TEXT);
  const blobSha = git(workdir, ["hash-object", "-w", PAYLOAD_PATH]);
  git(workdir, ["read-tree", tip]);
  git(workdir, ["update-index", "--add", "--cacheinfo", `100644,${blobSha},${PAYLOAD_PATH}`]);
  const tree = git(workdir, ["write-tree"]);
  const commit = git(workdir, ["commit-tree", tree, "-p", tip, "-m", "F-001 acceptance payload commit"], FIXED);
  git(workdir, ["update-ref", "refs/heads/f001-payload", commit]);

  const pending = {
    status: "PENDING_APPROVAL_NOT_EXECUTED",
    repository: args["remote-url"].replace(/\.git$/, ""),
    remote_url: args["remote-url"],
    target_ref: args["target-ref"],
    expected_old_sha: expectedOld,
    source_commit: commit,
    payload: { path: PAYLOAD_PATH, sha256: fileSha256(join(workdir, PAYLOAD_PATH)), git_blob: blobSha },
    local_clone_for_executor: workdir,
    approval_required_from: args.subject ?? "the repository operator who holds the approval (receipt-signing) key",
    approver_command: `node scripts/authorize-git-push.mjs --remote-url ${args["remote-url"]} --target-ref ${args["target-ref"]} --expected-old-sha ${expectedOld} --source-commit ${commit} --subject <approver> --out <request.json>`,
    note: "Nothing has been pushed. The executor needs the operator's trust material, a GitHub App credential and the independent claim store; none exist in this environment."
  };
  process.stdout.write(`${JSON.stringify(pending, null, 2)}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => { process.stdout.write(`${JSON.stringify({ status: "ERROR", error: error.message })}\n`); process.exit(2); });
}
