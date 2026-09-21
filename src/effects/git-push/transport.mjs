// git.push — the transport layer.
//
// THE DISTINCTION THIS FILE TURNS ON. A subprocess is not the security problem;
// a generic subprocess interface is. `execute(command, args)` hands a caller a
// process-execution capability. What is here is the opposite: a fixed executable,
// a fixed operation, an argv assembled entirely by MNDe from values that have
// already been validated, and an environment built from empty rather than
// inherited. A caller cannot add a flag, because there is nowhere to put one.
//
// WHY GIT AND NOT AN API. The contract MNDe needs is an atomic compare-and-swap
// on a ref: update it only if it is exactly the SHA that was approved. GitHub's
// REST ref-update endpoint takes no expected-old-SHA — it can refuse a
// non-fast-forward, which is a strictly weaker guarantee and would let a ref that
// moved forward under us be overwritten. The git wire protocol carries the old
// SHA in the update command itself, and `--force-with-lease=<ref>:<sha>` is how
// that is expressed. So the exact-state guard is the reason for the subprocess,
// not an accident of it.
//
// No shell anywhere: execFile with an argv array, never a command string, so
// there is no `sh -c`, no `cmd /c`, and nothing to quote wrongly.

import { execFile } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const ERR_GIT_UNAVAILABLE = "ERR_GIT_UNAVAILABLE";
export const ERR_GIT_TIMEOUT = "ERR_GIT_TIMEOUT";
export const ERR_LOCAL_COMMIT_MISSING = "ERR_GIT_PUSH_LOCAL_COMMIT_MISSING";
export const ERR_REMOTE_READ_FAILED = "ERR_GIT_PUSH_REMOTE_READ_FAILED";
export const ERR_REMOTE_REF_ABSENT = "ERR_GIT_PUSH_REMOTE_REF_ABSENT";
export const ERR_TRANSPORT_ENV_NOT_ALLOWED = "ERR_GIT_PUSH_TRANSPORT_ENV_NOT_ALLOWED";

// The only environment variables an operator may inject, and each is here for a
// stated reason. Everything else — credential helpers, proxy commands, hook
// paths, external diff drivers, loader overrides — is absent by construction
// because the environment is built from empty rather than filtered.
export const ALLOWED_TRANSPORT_ENV = Object.freeze({
  PATH: "git resolves its own helpers (git-remote-https, ssh) through PATH",
  HOME: "ssh reads the operator's known_hosts and key material from HOME; git config is separately neutralized",
  SSH_AUTH_SOCK: "ssh-agent socket, when the deployment authenticates with an agent rather than a key file",
  GIT_SSH_COMMAND: "explicit ssh invocation, when the deployment pins a key or a known-hosts file",
  GIT_SSL_CAINFO: "explicit CA bundle for https, when the deployment does not use the system store"
});

// A path that is deliberately never created. Git reads a configured-but-missing
// config file as empty, which is exactly what is wanted, and unlike the
// platform's null device it is an ordinary path on every OS — Git for Windows
// does not read \\.\nul as a config file.
const NO_CONFIG_FILE = join(tmpdir(), "mnde-git-push-no-config-this-file-is-never-created");

// Windows needs these for sockets, temporary files and executable resolution to
// work at all. They are platform plumbing, not policy, and none of them affects
// what git executes or where it pushes.
const WINDOWS_PLUMBING = ["SystemRoot", "SystemDrive", "TEMP", "TMP", "windir", "PATHEXT", "COMSPEC"];

// Build the subprocess environment from EMPTY. Nothing is inherited implicitly:
// if a variable is not named here, the subprocess does not see it.
//
// Two named exceptions, both plumbing rather than policy. PATH is inherited,
// because git resolves itself and its transport helpers through it and a
// hardcoded guess breaks every invocation on any non-standard install; it is on
// the operator allowlist so a deployment that wants to pin it can. On Windows a
// short list of platform variables is inherited too, without which sockets,
// temporary files and executable resolution do not work at all. Neither changes
// what git executes or where it pushes, and an attacker who can set PATH in the
// executor's own environment can already replace the executor.
export function buildTransportEnv(operatorEnv = {}, { platform = process.platform, inherit = process.env } = {}) {
  for (const key of Object.keys(operatorEnv)) {
    if (!Object.hasOwn(ALLOWED_TRANSPORT_ENV, key)) {
      return { ok: false, reason: ERR_TRANSPORT_ENV_NOT_ALLOWED, detail: `'${key}' is not an allowed transport environment variable; allowed: ${Object.keys(ALLOWED_TRANSPORT_ENV).join(", ")}` };
    }
    if (typeof operatorEnv[key] !== "string") {
      return { ok: false, reason: ERR_TRANSPORT_ENV_NOT_ALLOWED, detail: `'${key}' must be a string` };
    }
  }

  const env = {
    // No git config from anywhere but the repository itself. The global and
    // system files are pointed at the platform's null device, which git reads as
    // empty, so an operator's ~/.gitconfig cannot install an alias, a credential
    // helper, or a url.*.insteadOf rewrite that changes where this push lands.
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: NO_CONFIG_FILE,
    GIT_CONFIG_SYSTEM: NO_CONFIG_FILE,
    // Never block on a prompt. A hung push is a push whose outcome is unknown,
    // and unknown is the most expensive state this effect has.
    GIT_TERMINAL_PROMPT: "0",
    GIT_ASKPASS: "",
    SSH_ASKPASS: "",
    // Deterministic output, because ls-remote output is parsed.
    LC_ALL: "C",
    LANG: "C",
    // PATH is inherited unless the operator sets it. A hardcoded guess is worse
    // than inheriting: git resolves its own transport helpers through PATH, and
    // a wrong guess breaks every invocation on any non-standard install. It is
    // on the operator allowlist precisely so a deployment that wants to pin it
    // can.
    PATH: typeof inherit?.PATH === "string" && inherit.PATH ? inherit.PATH : (typeof inherit?.Path === "string" ? inherit.Path : "")
  };

  if (platform === "win32") {
    for (const key of WINDOWS_PLUMBING) {
      if (typeof inherit?.[key] === "string") env[key] = inherit[key];
    }
  }

  return { ok: true, env: Object.freeze({ ...env, ...operatorEnv }) };
}

function runGit(args, { env, cwd, timeoutMs }) {
  return new Promise((resolve) => {
    execFile("git", args, {
      cwd,
      env,
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024,
      windowsHide: true,
      shell: false,
      encoding: "utf8"
    }, (error, stdout, stderr) => {
      if (error) {
        resolve({
          ok: false,
          code: typeof error.code === "number" ? error.code : null,
          killed: error.killed === true || error.signal != null,
          timedOut: error.killed === true && error.signal === "SIGTERM",
          spawnFailed: error.code === "ENOENT",
          stdout: String(stdout ?? ""),
          stderr: String(stderr ?? ""),
          message: String(error.message ?? error)
        });
        return;
      }
      resolve({ ok: true, code: 0, stdout: String(stdout ?? ""), stderr: String(stderr ?? "") });
    });
  });
}

// Resolve a SHA locally and require it to be a commit object that is actually
// present. `--end-of-options` is belt to the braces of the option-like check in
// validate.mjs.
export async function resolveLocalCommit(sha, context) {
  const result = await runGit(["-C", context.repoPath, "rev-parse", "--verify", "--quiet", "--end-of-options", `${sha}^{commit}`], context);
  if (result.spawnFailed) return { ok: false, reason: ERR_GIT_UNAVAILABLE, detail: result.message };
  if (!result.ok) return { ok: false, reason: ERR_LOCAL_COMMIT_MISSING, detail: `${sha} is not a commit present in the local repository${result.stderr.trim() ? `: ${result.stderr.trim()}` : ""}` };
  const resolved = result.stdout.trim();
  if (resolved !== sha) return { ok: false, reason: ERR_LOCAL_COMMIT_MISSING, detail: `${sha} resolved to ${resolved || "nothing"}` };
  return { ok: true, sha: resolved };
}

// Is `ancestor` an ancestor of `descendant`? This is the fast-forward
// requirement. `--is-ancestor` exits 0 for yes and 1 for no, so a non-zero exit
// that is not 1 has to be treated as an error rather than as "no".
export async function isAncestor(ancestor, descendant, context) {
  const result = await runGit(["-C", context.repoPath, "merge-base", "--is-ancestor", "--end-of-options", ancestor, descendant], context);
  if (result.spawnFailed) return { ok: false, reason: ERR_GIT_UNAVAILABLE, detail: result.message };
  if (result.ok) return { ok: true, ancestor: true };
  if (result.code === 1) return { ok: true, ancestor: false };
  return { ok: false, reason: ERR_LOCAL_COMMIT_MISSING, detail: result.stderr.trim() || result.message };
}

// Read one ref from the remote, independently of anything the caller said and
// independently of the local repository's tracking refs. This is both the
// pre-transport expected-state read and the post-transport observation, and it
// is deliberately the same code for each so the two are comparable.
export async function readRemoteRef(remoteUrl, targetRef, context) {
  const result = await runGit(["ls-remote", "--exit-code", "--refs", "--", remoteUrl, targetRef], context);
  if (result.spawnFailed) return { ok: false, reason: ERR_GIT_UNAVAILABLE, detail: result.message };
  // ls-remote exits 2 when the ref simply is not there; that is an answer, not a
  // failure, but it is still a refusal for this effect because an absent ref has
  // no old SHA to lease against.
  if (!result.ok && result.code === 2) {
    return { ok: false, reason: ERR_REMOTE_REF_ABSENT, detail: `${targetRef} does not exist on the remote` };
  }
  if (!result.ok) {
    return { ok: false, reason: ERR_REMOTE_READ_FAILED, detail: result.stderr.trim() || result.message, timedOut: result.timedOut === true };
  }
  const lines = result.stdout.split("\n").map((line) => line.trim()).filter(Boolean);
  const matches = lines
    .map((line) => line.split(/\s+/))
    .filter((parts) => parts.length === 2 && parts[1] === targetRef);
  if (matches.length !== 1) {
    return { ok: false, reason: ERR_REMOTE_REF_ABSENT, detail: `expected exactly one ${targetRef} on the remote, got ${matches.length}` };
  }
  return { ok: true, sha: matches[0][0] };
}

// Read the URL the local repository has configured for the named remote, so that
// `remote` and `remote_url` in the authorization can be required to agree with
// the repository the executor is actually standing in.
export async function readConfiguredRemoteUrl(remoteName, context) {
  const result = await runGit(["-C", context.repoPath, "remote", "get-url", remoteName], context);
  if (result.spawnFailed) return { ok: false, reason: ERR_GIT_UNAVAILABLE, detail: result.message };
  if (!result.ok) {
    return {
      ok: false,
      reason: ERR_REMOTE_READ_FAILED,
      // git's own stderr, not a guess at what went wrong. Swallowing it turns
      // every distinct failure into the same unhelpful sentence.
      detail: `could not read the URL for remote '${remoteName}': ${result.stderr.trim() || result.message}`
    };
  }
  const url = result.stdout.trim();
  if (!url) return { ok: false, reason: ERR_REMOTE_READ_FAILED, detail: `remote '${remoteName}' has no URL` };
  return { ok: true, url };
}

// THE ARGV. Everything in it is either a literal MNDe wrote or a value that
// cleared validate.mjs. There is no caller-supplied refspec and no caller-
// supplied flag, and `--` ends option parsing before either operand.
//
//   git push --no-verify --force-with-lease=<ref>:<old> -- <url> <new>:<ref>
//
// `--no-verify` skips local pre-push hooks, which are operator-writable files
// that would otherwise run inside an authorized effect. The force-with-lease is
// the exact-state guard: the remote must still be at <old> at the moment the
// server processes the update, or it refuses. Note what is NOT here: no --force,
// no --mirror, no --all, no --delete, no --prune, no --receive-pack, no --exec,
// and no -c config override.
export function buildPushArgv({ remoteUrl, sourceCommit, targetRef, expectedOldSha }) {
  return Object.freeze([
    "push",
    "--no-verify",
    `--force-with-lease=${targetRef}:${expectedOldSha}`,
    "--",
    remoteUrl,
    `${sourceCommit}:${targetRef}`
  ]);
}

// Perform the push. Returns the raw outcome; deciding what it MEANS is the
// caller's job, because exit code 0 is not proof that the ref moved.
export async function performPush(argv, context) {
  const result = await runGit(argv, context);
  if (result.spawnFailed) return { ok: false, reason: ERR_GIT_UNAVAILABLE, detail: result.message, indeterminate: false };
  if (!result.ok) {
    return {
      ok: false,
      // A timeout or a kill leaves the outcome genuinely unknown: the update may
      // have reached the server. That is the reconciliation case, not a failure.
      indeterminate: result.timedOut === true || result.killed === true,
      reason: result.timedOut === true ? ERR_GIT_TIMEOUT : "ERR_GIT_PUSH_REJECTED",
      exit_code: result.code,
      stdout: result.stdout,
      stderr: result.stderr
    };
  }
  return { ok: true, exit_code: 0, stdout: result.stdout, stderr: result.stderr };
}
