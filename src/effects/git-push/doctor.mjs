// git.push — read-only readiness diagnosis for an operator.
//
// Answers one question: "if I ran mnde-git-push now, what would stop it?" It
// runs the SAME startup path the CLI and the Hub run, so it cannot drift from
// them: loadGitPushStartup() (trust files, trust root, executor identity),
// createGitPushExecutor() (push-credential configuration) and the executor's own
// readiness() (a read-only health query against the durable claim store).
//
// What it never does:
//   - call executeGitPush(), so it cannot push, claim, or write evidence;
//   - mint, read or print a push credential (the provider is constructed, not
//     asked for a token);
//   - write a file, start a process, or make an HTTP request of its own;
//   - print a value taken from the environment or a key file. Output carries
//     variable NAMES, executor and environment ids, a short root fingerprint,
//     expiry times, and the executor's own non-secret error text.
//
// Status vocabulary. A component is READY only when a test succeeded; the
// evidence line says which test. Anything doctor cannot test is NOT_VERIFIED,
// never READY. The verdict never says "protected" or "secure": at most it says
// the local checks passed, and lists what was not verified.

import { accessSync, constants, existsSync, statSync } from "node:fs";
import { delimiter, join } from "node:path";

import { createGitPushExecutor } from "./index.mjs";
import { loadGitPushStartup, REQUIRED_STARTUP_ENV } from "./startup.mjs";

export const DOCTOR_SCHEMA = "mnde.git-push-doctor.v1";
export const MIN_NODE_MAJOR = 24;
export const CREDENTIAL_EXPIRY_WARNING_MS = 48 * 60 * 60 * 1000;

export const STATUS = Object.freeze({
  READY: "READY",
  ATTENTION: "ATTENTION",
  FAILED: "FAILED",
  NOT_CONFIGURED: "NOT_CONFIGURED",
  NOT_VERIFIED: "NOT_VERIFIED",
  SKIPPED: "SKIPPED"
});

export const VERDICT = Object.freeze({
  NOT_READY: "NOT_READY",
  LOCAL_CHECKS_PASSED: "LOCAL_CHECKS_PASSED",
  LOCAL_CHECKS_PASSED_WITH_ATTENTION: "LOCAL_CHECKS_PASSED_WITH_ATTENTION"
});

const RUNBOOK = "docs/FIRST-PRODUCTION-GIT-PUSH.md";

// What to do about a startup failure, keyed by the reason code the loader or the
// executor reported. Unlisted codes fall back to the runbook.
const FIXES = Object.freeze({
  ERR_GIT_PUSH_DEMO_TRUST_MATERIAL: `Generate an independent authority with scripts/prepare-git-push-trust.mjs (${RUNBOOK}, step 1). The shipped demo authority can never anchor a real deployment.`,
  ERR_GIT_PUSH_TRUST_ROLE_REUSE: "Enrol a separate executor key with scripts/trust-enroll-executor.mjs. The executor key and the authority keys must be different keys.",
  ERR_GIT_PUSH_TRUST_FILE_INSECURE: "Fix the file as described: secret files owned by the executor's OS user and chmod 600; configuration files not writable by group or other; nothing inside the repository or the MNDe package.",
  ERR_EXECUTOR_CREDENTIAL_INVALID: `Re-enrol the executor to issue a fresh credential (${RUNBOOK}, step 1; scripts/trust-enroll-executor.mjs).`,
  ERR_EXECUTOR_IDENTITY_INCOMPLETE: `Load the environment file prepare-git-push-trust.mjs wrote (${RUNBOOK}, step 5).`,
  ERR_GIT_CREDENTIAL_CONFIG: `Check the push-credential configuration file against ${RUNBOOK}, step 2. Unrecognized fields are refused, not ignored.`,
  ERR_GIT_CREDENTIAL_FILE_INSECURE: "The push credential's key or token file must be owned by the executor's OS user, chmod 600, and outside the repository.",
  ERR_GIT_PUSH_STARTUP_CONFIG: `The executor refused its startup configuration. See ${RUNBOOK}.`
});

function check(id, component, status, evidence, extra = {}) {
  return Object.freeze({
    id,
    component,
    status,
    evidence,
    problem: extra.problem ?? null,
    fix: extra.fix ?? null
  });
}

// Executor error text is written to avoid secrets, but doctor is a diagnostic
// that people paste into issues, so it removes anything key-shaped and bounds
// the length rather than trusting that no later change leaks.
function scrub(text) {
  return String(text ?? "")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ")
    .replace(/-----BEGIN [A-Z ]+-----[\s\S]*?(-----END [A-Z ]+-----|$)/g, "[REDACTED KEY]")
    .replace(/\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, "[REDACTED TOKEN]")
    .slice(0, 400);
}

function fixFor(reasonCode, fallback) {
  return FIXES[reasonCode] ?? fallback ?? `See ${RUNBOOK}.`;
}

function findOnPath(names, env, platform) {
  const dirs = String(env.PATH ?? env.Path ?? "").split(delimiter).filter(Boolean);
  const exts = platform === "win32" ? ["", ".exe", ".cmd", ".bat"] : [""];
  for (const dir of dirs) {
    for (const name of names) {
      for (const ext of exts) {
        const candidate = join(dir, `${name}${ext}`);
        try {
          if (statSync(candidate).isFile()) return candidate;
        } catch { /* not here */ }
      }
    }
  }
  return null;
}

function dirCheck(id, component, path, { needsGit = false } = {}) {
  let stat;
  try { stat = statSync(path); } catch (error) {
    return { missing: true, check: check(id, component, STATUS.FAILED, `${path} cannot be read (${error?.code ?? "error"})`, {
      problem: `${component} does not exist or is not readable.`,
      fix: `Create it as described in ${RUNBOOK}, then re-run.`
    }) };
  }
  if (!stat.isDirectory()) {
    return { check: check(id, component, STATUS.FAILED, `${path} is not a directory`, { problem: `${component} must be a directory.`, fix: `Point the variable at a directory (${RUNBOOK}).` }) };
  }
  if (needsGit && !(existsSync(join(path, ".git")) || existsSync(join(path, "HEAD")))) {
    return { check: check(id, component, STATUS.FAILED, `${path} does not look like a Git repository (no .git or HEAD)`, {
      problem: "The staging repository is not a Git repository.",
      fix: `Clone the repository to this path first (${RUNBOOK}, step 4).`
    }) };
  }
  return { check: null, stat };
}

function daysAndHours(ms) {
  const hours = Math.floor(ms / 3_600_000);
  return hours >= 48 ? `${Math.floor(hours / 24)} days ${hours % 24} h` : `${hours} h`;
}

// Returns the report object. Never throws for an operator mistake: every
// problem becomes a check. It only reads `env` and the files `env` names.
export async function runGitPushDoctor(env = process.env, { now = Date.now(), platform = process.platform, nodeVersion = process.versions.node } = {}) {
  const checks = [];
  const push = (c) => { checks.push(c); return c; };

  // ── runtime ────────────────────────────────────────────────────────────────
  const major = Number.parseInt(String(nodeVersion).split(".")[0], 10);
  push(major >= MIN_NODE_MAJOR
    ? check("runtime.node", "Node.js", STATUS.READY, `Node.js ${nodeVersion} (>= ${MIN_NODE_MAJOR} required)`)
    : check("runtime.node", "Node.js", STATUS.FAILED, `Node.js ${nodeVersion}`, {
      problem: `MNDe requires Node.js ${MIN_NODE_MAJOR} or later.`,
      fix: `Install Node.js ${MIN_NODE_MAJOR}+ and re-run.`
    }));

  const gitPath = findOnPath(["git"], env, platform);
  push(gitPath
    ? check("runtime.git", "Git", STATUS.READY, "git executable found on PATH (located, not executed)")
    : check("runtime.git", "Git", STATUS.FAILED, "no git executable on PATH", { problem: "The executor pushes with Git.", fix: "Install Git and make sure it is on PATH." }));

  // ── configuration ──────────────────────────────────────────────────────────
  const missing = REQUIRED_STARTUP_ENV.filter((name) => typeof env[name] !== "string" || env[name].length === 0);
  if (missing.length > 0) {
    const none = missing.length === REQUIRED_STARTUP_ENV.length;
    push(check("config.environment", "Executor configuration", STATUS.NOT_CONFIGURED,
      none ? "none of the executor's required variables are set" : `${missing.length} of ${REQUIRED_STARTUP_ENV.length} required variables are not set: ${missing.join(", ")}`, {
        problem: none ? "This shell has no MNDe executor configuration." : "The executor's configuration is incomplete.",
        fix: none
          ? `New here? Follow ${RUNBOOK}: step 1 creates the trust material and an environment file; step 5 loads it into this shell.`
          : `Set the missing variables, or re-load the environment file from ${RUNBOOK}, step 5.`
      }));
    for (const [id, component] of [
      ["startup.trust", "Trust material and executor identity"],
      ["executor.credential_expiry", "Executor credential validity"],
      ["executor.construct", "Push-credential configuration"],
      ["claim.store", "Claim store (single-use enforcement)"],
      ["repo.path", "Staging repository"],
      ["evidence.dir", "Evidence directory"]
    ]) push(check(id, component, STATUS.SKIPPED, "not checked: the executor configuration is incomplete"));
  } else {
    push(check("config.environment", "Executor configuration", STATUS.READY, `all ${REQUIRED_STARTUP_ENV.length} required variables are set (values not shown)`));

    let loaded = null;
    try {
      loaded = await loadGitPushStartup(env);
    } catch (error) {
      loaded = { ok: false, reason_code: error?.code ?? "ERR_GIT_PUSH_CLI_CONFIG", detail: error?.message };
    }

    if (!loaded.ok) {
      push(check("startup.trust", "Trust material and executor identity", STATUS.FAILED,
        `${loaded.reason_code}: ${scrub(loaded.detail)}`, {
          problem: "The executor would refuse to start.",
          fix: fixFor(loaded.reason_code)
        }));
      for (const [id, component] of [
        ["executor.credential_expiry", "Executor credential validity"],
        ["executor.construct", "Push-credential configuration"],
        ["claim.store", "Claim store (single-use enforcement)"]
      ]) push(check(id, component, STATUS.SKIPPED, "not checked: trust material did not load"));
    } else {
      const { startup } = loaded;
      try {
        push(check("startup.trust", "Trust material and executor identity", STATUS.READY,
          `authority bundle verified; executor '${startup.executorIdentity.executor_id}' (environment '${startup.environmentId}') holds a root-signed credential and its private key matches; root ${String(startup.trustedRootFingerprint).slice(0, 16)}…; key roles are separate`));

        const expiresAt = Date.parse(startup.executorIdentity.credential?.expires_at);
        const remaining = expiresAt - now;
        push(Number.isFinite(remaining) && remaining > CREDENTIAL_EXPIRY_WARNING_MS
          ? check("executor.credential_expiry", "Executor credential validity", STATUS.READY, `valid until ${new Date(expiresAt).toISOString()} (${daysAndHours(remaining)} left)`)
          : check("executor.credential_expiry", "Executor credential validity", STATUS.ATTENTION,
            Number.isFinite(remaining) ? `valid until ${new Date(expiresAt).toISOString()} (${daysAndHours(Math.max(remaining, 0))} left)` : "expiry time unreadable", {
              problem: "The executor credential is close to expiry. When it lapses every push is refused until it is re-issued.",
              fix: `Re-enrol the executor to issue a new credential (${RUNBOOK}, step 1; scripts/trust-enroll-executor.mjs). Needs the offline root key.`
            }));

        // Constructing the executor validates the push-credential configuration
        // and its files. It does not ask the provider for a token.
        let executor = null;
        try {
          executor = createGitPushExecutor(startup);
          push(check("executor.construct", "Push-credential configuration", STATUS.READY,
            "executor constructed; credential configuration parsed and its files passed ownership/permission checks (no token requested)"));
        } catch (error) {
          push(check("executor.construct", "Push-credential configuration", STATUS.FAILED,
            `${error?.code ?? "ERROR"}: ${scrub(error?.message)}`, {
              problem: "The executor refused to construct, so no push could run.",
              fix: fixFor(error?.code)
            }));
        }

        if (!executor) {
          push(check("claim.store", "Claim store (single-use enforcement)", STATUS.SKIPPED, "not checked: the executor did not construct"));
        } else {
          // The executor's own readiness(): a read-only query that checks the
          // primary is reachable over verified TLS, durable (fsync on, not a
          // replica) and bound to this namespace. It writes no claim.
          let ready = false;
          try { ready = (await executor.readiness())?.ready === true; } catch { ready = false; }
          push(ready
            ? check("claim.store", "Claim store (single-use enforcement)", STATUS.READY,
              "read-only health query succeeded: primary reachable over verified TLS, durable, namespace bound (no claim written)")
            : check("claim.store", "Claim store (single-use enforcement)", STATUS.FAILED,
              "the executor's claim-store health query did not succeed (the adapter reports no further detail)", {
                problem: "Without a reachable durable claim store every push is refused (fail closed).",
                fix: `Check, in order: the claim configuration file's fields, that the 'pg' driver is installed in this runtime, that the database is reachable and the CA file matches its certificate, and that the login can read the claim schema (${RUNBOOK}, step 3).`
              }));
        }
      } finally {
        loaded.signer?.destroy?.();
      }
    }

    const repo = dirCheck("repo.path", "Staging repository", env.MNDE_GIT_PUSH_REPO_PATH, { needsGit: true });
    push(repo.check ?? check("repo.path", "Staging repository", STATUS.READY, `${env.MNDE_GIT_PUSH_REPO_PATH} is a Git repository`));

    const evidence = dirCheck("evidence.dir", "Evidence directory", env.MNDE_GIT_PUSH_EVIDENCE_DIR);
    if (evidence.check && evidence.missing) {
      push(check("evidence.dir", "Evidence directory", STATUS.ATTENTION,
        `${env.MNDE_GIT_PUSH_EVIDENCE_DIR} does not exist yet`, {
          problem: "The executor creates it on first use; if its parent is not writable the push completes without durable evidence.",
          fix: "Create it now, owned by the executor's OS user, outside the repository."
        }));
    } else if (evidence.check) {
      push(evidence.check);
    } else {
      let writable = true;
      try { accessSync(env.MNDE_GIT_PUSH_EVIDENCE_DIR, constants.W_OK); } catch { writable = false; }
      push(writable
        ? check("evidence.dir", "Evidence directory", STATUS.READY, `${env.MNDE_GIT_PUSH_EVIDENCE_DIR} exists and is writable by this user (nothing written)`)
        : check("evidence.dir", "Evidence directory", STATUS.FAILED, `${env.MNDE_GIT_PUSH_EVIDENCE_DIR} is not writable by this user`, {
          problem: "A push could change the remote and then fail to record signed evidence (exit code 7).",
          fix: "Make the directory writable by the executor's OS user."
        }));
    }
  }

  // ── what doctor cannot know ────────────────────────────────────────────────
  if (platform === "win32") {
    push(check("trust.file_permissions", "Trust-file permissions", STATUS.NOT_VERIFIED,
      "Node cannot read Windows ACLs, so ownership and access of the trust files were not checked", {
        problem: "On Windows the file ACL is the only control over who can replace a trust root or key.",
        fix: `Restrict the trust directory to your account (icacls, ${RUNBOOK}, step 1).`
      }));
  }
  push(check("credential.live", "Push credential at the provider", STATUS.NOT_VERIFIED,
    "doctor never requests a token, so it did not test that the credential can authenticate or that its scope is exactly one repository", {
      fix: `The first live proof is the real push to a throwaway branch (${RUNBOOK}, step 7). The executor refuses a token with any other scope.`
    }));
  push(check("enforcement.sole_credential", "No other route to the protected effect", STATUS.NOT_VERIFIED,
    "doctor cannot see which other credentials can push to the repository (your own account, deploy keys, other apps)", {
      problem: "MNDe constrains only pushes made through the executor. Any other valid credential bypasses it.",
      fix: "Restrict the repository so the executor's GitHub App is the only identity allowed to push the protected refs. See docs/PRODUCTION-TRUST-BOUNDARY.md."
    }));

  const failing = checks.filter((c) => c.status === STATUS.FAILED || c.status === STATUS.NOT_CONFIGURED);
  const attention = checks.filter((c) => c.status === STATUS.ATTENTION);
  const verdict = failing.length > 0
    ? VERDICT.NOT_READY
    : attention.length > 0 ? VERDICT.LOCAL_CHECKS_PASSED_WITH_ATTENTION : VERDICT.LOCAL_CHECKS_PASSED;

  return Object.freeze({
    schema: DOCTOR_SCHEMA,
    verdict,
    checks: Object.freeze(checks),
    not_verified: Object.freeze(checks.filter((c) => c.status === STATUS.NOT_VERIFIED).map((c) => c.id)),
    side_effects: Object.freeze({ push_attempted: false, claim_written: false, credential_requested: false, files_written: false })
  });
}

const LABEL_WIDTH = 15;

// Plain text for a terminal. Status is a word, never colour alone.
export function renderGitPushDoctor(report) {
  const lines = ["MNDe git.push doctor", ""];
  for (const c of report.checks) {
    lines.push(`${`[${c.status}]`.padEnd(LABEL_WIDTH)}${c.component}`);
    lines.push(`${" ".repeat(LABEL_WIDTH)}${c.evidence}`);
    if (c.problem) lines.push(`${" ".repeat(LABEL_WIDTH)}Problem: ${c.problem}`);
    if (c.fix) lines.push(`${" ".repeat(LABEL_WIDTH)}Fix:     ${c.fix}`);
  }
  lines.push("");
  if (report.verdict === VERDICT.NOT_READY) {
    lines.push("Result: NOT READY. Fix the items above marked FAILED or NOT_CONFIGURED; a push would be refused or would not start.");
  } else {
    lines.push(`Result: local checks passed${report.verdict === VERDICT.LOCAL_CHECKS_PASSED_WITH_ATTENTION ? ", with items needing attention" : ""}.`);
    lines.push("This is NOT a statement that your repository is protected. Items marked NOT_VERIFIED were not tested.");
  }
  lines.push("Nothing was pushed, no claim was written, no credential was requested, no file was written.");
  return `${lines.join("\n")}\n`;
}
