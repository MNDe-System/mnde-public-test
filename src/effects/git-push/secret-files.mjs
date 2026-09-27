// git.push — who can read, and who can rewrite, the executor's trust files.
//
// The executor takes all of its trust from files the deployment names: the
// authority bundle, the claim-store config, its own key and credential, and
// the push credential configuration and secret. Whoever can rewrite one of
// those decides what the executor trusts, so in production each is checked
// before it is used:
//
//   - an absolute path, outside the local repository (the agent writes there)
//     and outside the MNDe package;
//   - a regular file;
//   - owned by the executor's OS user (configuration may also be owned by
//     root), and not writable by group or other;
//   - secret material additionally: not a symbolic link, owned by the
//     executor's OS user, and not readable by group or other (0600).
//
// POSIX only. On Windows, access is governed by ACLs that Node cannot read, so
// the result says `checked: false` and the operator's ACL is the control.
// docs/PRODUCTION-TRUST-BOUNDARY.md says so rather than pretending otherwise.
//
// Symbolic links are refused for secrets, matching the executor key loader
// (src/custody/executor-identity.mjs). That excludes a Kubernetes secret
// volume mounted as a directory, whose entries are symlinks; mount the file
// with subPath, or copy it into place, instead.

import { lstatSync, statSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";

function nonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function isInside(root, candidate) {
  const rel = relative(resolve(root), resolve(candidate));
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

export function inspectSecretFile(path, { secret = true, forbiddenRoots = [], platform = process.platform, uid } = {}) {
  if (!nonEmptyString(path) || !isAbsolute(path)) {
    return { ok: false, detail: "must be an absolute path" };
  }
  for (const root of forbiddenRoots) {
    if (nonEmptyString(root) && isInside(root, path)) {
      return { ok: false, detail: "must not live inside the repository or the MNDe package" };
    }
  }
  let stat;
  try {
    stat = secret ? lstatSync(path) : statSync(path);
  } catch (error) {
    return { ok: false, missing: error?.code === "ENOENT", detail: `cannot be read (${error?.code ?? "error"})` };
  }
  if (stat.isSymbolicLink()) return { ok: false, detail: "must not be a symbolic link" };
  if (!stat.isFile()) return { ok: false, detail: "must be a regular file" };
  if (platform === "win32") return { ok: true, checked: false };
  const owner = uid ?? (typeof process.getuid === "function" ? process.getuid() : null);
  if (owner !== null && stat.uid !== owner && (secret || stat.uid !== 0)) {
    return { ok: false, detail: secret ? "must be owned by the executor's OS user" : "must be owned by the executor's OS user or root" };
  }
  const forbidden = secret ? 0o077 : 0o022;
  if ((stat.mode & forbidden) !== 0) {
    return { ok: false, detail: secret ? "must not be accessible to group or other (chmod 600)" : "must not be writable by group or other" };
  }
  return { ok: true, checked: true };
}
