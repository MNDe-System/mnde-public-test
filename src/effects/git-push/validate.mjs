// git.push — pure validation of the bound action fields.
//
// Everything in this file is a refusal rule. There are no side effects, no
// subprocess, and no network: it answers one question — do these fields describe
// a push MNDe is willing to construct an argv for?
//
// The rules exist because the argv is built from these values. A field that
// reaches the argv unvalidated is a command-injection surface even without a
// shell, because git itself takes options, and an option is just a string that
// starts with a dash. So: fixed key set, strict formats, no option-like values.

export const GIT_PUSH_ACTION = "git.push";

// Exactly these keys, no more and no fewer. A receipt carrying an extra
// parameter is refused rather than ignored, because an ignored parameter is a
// field the approver thought they were constraining and the executor did not.
export const GIT_PUSH_PARAMETER_KEYS = Object.freeze([
  "expected_old_sha",
  "remote",
  "remote_url",
  "repository",
  "source_commit",
  "target_ref"
]);

export const ERR_ACTION_MISMATCH = "ERR_GIT_PUSH_ACTION_MISMATCH";
export const ERR_PARAMETER_SHAPE = "ERR_GIT_PUSH_PARAMETER_SHAPE";
export const ERR_REQUEST_BINDING = "ERR_GIT_PUSH_REQUEST_BINDING";
export const ERR_OPTION_LIKE_VALUE = "ERR_GIT_PUSH_OPTION_LIKE_VALUE";
export const ERR_SHA_FORMAT = "ERR_GIT_PUSH_SHA_FORMAT";
export const ERR_TARGET_REF_FORMAT = "ERR_GIT_PUSH_TARGET_REF_FORMAT";
export const ERR_REMOTE_NAME_FORMAT = "ERR_GIT_PUSH_REMOTE_NAME_FORMAT";
export const ERR_REMOTE_URL_FORMAT = "ERR_GIT_PUSH_REMOTE_URL_FORMAT";
export const ERR_REMOTE_URL_SCHEME = "ERR_GIT_PUSH_REMOTE_URL_SCHEME";
export const ERR_REMOTE_URL_CREDENTIALS = "ERR_GIT_PUSH_REMOTE_URL_CREDENTIALS";
export const ERR_REPOSITORY_MISMATCH = "ERR_GIT_PUSH_REPOSITORY_MISMATCH";
export const ERR_NO_OP_PUSH = "ERR_GIT_PUSH_NO_OP";

const FULL_SHA = /^[0-9a-f]{40}$/;
const NULL_SHA = "0".repeat(40);
// Deliberately narrower than git's own check-ref-format. Only a branch, only a
// conservative charset. Widening this is a reviewed change, not a config knob.
const TARGET_REF = /^refs\/heads\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}(?:\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}){0,7}$/;
const REMOTE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function isString(value) {
  return typeof value === "string";
}

function fail(reason, detail) {
  return Object.freeze({ ok: false, reason, detail: detail ?? null });
}

// An option is a string that starts with a dash. Since MNDe builds the argv, no
// bound value may ever look like one — including after git's own scp-like URL
// parsing, so this is checked on the raw string.
function optionLike(value) {
  return isString(value) && value.startsWith("-");
}

// Control characters, whitespace and the separators git gives meaning to. A
// newline in a URL is enough to confuse a credential helper; a NUL is enough to
// truncate an argument in the wrong layer.
function hasUnsafeCharacters(value) {
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u001f\u007f\s]/.test(value);
}

// Canonical repository identity, derived from the remote URL by a fixed rule so
// that `repository` and `remote_url` cannot disagree. This is what makes
// `repository` a real binding rather than a decorative label: a receipt signed
// for one repository cannot be pointed at another's URL.
export function canonicalRepositoryIdentity(remoteUrl) {
  if (!isString(remoteUrl) || !remoteUrl) return null;

  // scp-like: user@host:path — git accepts it and it has no scheme.
  const scpLike = /^([A-Za-z0-9._-]+)@([A-Za-z0-9.-]+):(.+)$/.exec(remoteUrl);
  if (scpLike && !remoteUrl.includes("://")) {
    return `ssh:${scpLike[2].toLowerCase()}/${stripGitSuffix(scpLike[3])}`;
  }

  let url;
  try { url = new URL(remoteUrl); } catch { return null; }
  const scheme = url.protocol.replace(/:$/, "").toLowerCase();
  if (scheme === "file") return `file:${stripGitSuffix(decodeURIComponent(url.pathname))}`;
  if (!url.hostname) return null;
  return `${scheme}:${url.hostname.toLowerCase()}/${stripGitSuffix(decodeURIComponent(url.pathname)).replace(/^\/+/, "")}`;
}

function stripGitSuffix(path) {
  return path.replace(/\/+$/, "").replace(/\.git$/, "");
}

// True when the URL carries userinfo. The scp-like form user@host:path is the
// one exception: there the user is the ssh login, not a secret, and git has no
// other way to express it.
export function hasUrlCredentials(remoteUrl) {
  if (!isString(remoteUrl)) return false;
  if (!remoteUrl.includes("://")) return false;
  let url;
  try { url = new URL(remoteUrl); } catch { return false; }
  return Boolean(url.username) || Boolean(url.password);
}

export function remoteUrlScheme(remoteUrl) {
  if (!isString(remoteUrl) || !remoteUrl) return null;
  if (/^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:/.test(remoteUrl) && !remoteUrl.includes("://")) return "ssh";
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(remoteUrl);
  return match ? match[1].toLowerCase() : null;
}

// Validate the parameters as signed, independent of any caller request.
// `allowedSchemes` is trusted startup config, never a request field.
export function validateGitPushParameters(parameters, { allowedSchemes } = {}) {
  if (!parameters || typeof parameters !== "object" || Array.isArray(parameters)) {
    return fail(ERR_PARAMETER_SHAPE, "parameters must be an object");
  }
  const keys = Object.keys(parameters).sort();
  if (keys.length !== GIT_PUSH_PARAMETER_KEYS.length
    || keys.some((key, index) => key !== GIT_PUSH_PARAMETER_KEYS[index])) {
    return fail(ERR_PARAMETER_SHAPE, `expected exactly [${GIT_PUSH_PARAMETER_KEYS.join(", ")}], got [${keys.join(", ")}]`);
  }
  for (const key of keys) {
    if (!isString(parameters[key]) || parameters[key].length === 0) {
      return fail(ERR_PARAMETER_SHAPE, `${key} must be a non-empty string`);
    }
    if (optionLike(parameters[key])) return fail(ERR_OPTION_LIKE_VALUE, `${key} begins with '-'`);
  }

  const { repository, remote, remote_url: remoteUrl, source_commit: sourceCommit, target_ref: targetRef, expected_old_sha: expectedOldSha } = parameters;

  // Full SHAs only. An abbreviated SHA is ambiguous by construction, and an
  // ambiguous identity cannot be an exact-state guard.
  for (const [name, sha] of [["source_commit", sourceCommit], ["expected_old_sha", expectedOldSha]]) {
    if (!FULL_SHA.test(sha)) return fail(ERR_SHA_FORMAT, `${name} must be a full lowercase 40-hex commit id`);
    if (sha === NULL_SHA) return fail(ERR_SHA_FORMAT, `${name} must not be the null SHA; creating or deleting a ref is not in this effect's scope`);
  }
  // A push whose approved old and new state are identical has nothing to do, and
  // would spend an authority for no effect.
  if (sourceCommit === expectedOldSha) return fail(ERR_NO_OP_PUSH, "source_commit equals expected_old_sha");

  if (!TARGET_REF.test(targetRef) || targetRef.includes("..") || targetRef.includes("@{")
    || targetRef.endsWith(".lock") || targetRef.includes("//") || targetRef.endsWith(".")) {
    return fail(ERR_TARGET_REF_FORMAT, "target_ref must be a fully-qualified branch ref of the form refs/heads/<name>");
  }
  if (!REMOTE_NAME.test(remote)) return fail(ERR_REMOTE_NAME_FORMAT, "remote must be a plain git remote name");

  if (hasUnsafeCharacters(remoteUrl)) return fail(ERR_REMOTE_URL_FORMAT, "remote_url contains whitespace or control characters");
  const scheme = remoteUrlScheme(remoteUrl);
  if (!scheme) return fail(ERR_REMOTE_URL_FORMAT, "remote_url has no recognizable transport scheme");
  // The scheme allowlist is what keeps git's command-executing transports
  // (`ext::`, and anything else a future git grows) out of reach. It is trusted
  // startup config; a request cannot widen it.
  const schemes = Array.isArray(allowedSchemes) && allowedSchemes.length ? allowedSchemes : ["https", "ssh"];
  if (!schemes.includes(scheme)) {
    return fail(ERR_REMOTE_URL_SCHEME, `transport scheme '${scheme}' is not in the configured allowlist [${schemes.join(", ")}]`);
  }

  // Credentials in the URL would be copied into the argv and into the execution
  // evidence, which is a record MNDe intends to be readable. Authentication
  // belongs in the transport environment the operator configures, not in a field
  // an approver signed.
  if (hasUrlCredentials(remoteUrl)) {
    return fail(ERR_REMOTE_URL_CREDENTIALS, "remote_url must not embed credentials; configure authentication through the transport environment");
  }

  const canonical = canonicalRepositoryIdentity(remoteUrl);
  if (!canonical) return fail(ERR_REMOTE_URL_FORMAT, "remote_url could not be canonicalized");
  if (repository !== canonical) {
    return fail(ERR_REPOSITORY_MISMATCH, `repository '${repository}' does not match the identity derived from remote_url ('${canonical}')`);
  }

  return Object.freeze({
    ok: true,
    scheme,
    canonical_repository: canonical,
    parameters: Object.freeze({ ...parameters })
  });
}

// Bind the caller's request to the signed parameters. Every field must be
// present and identical: the caller does not get to supply anything the approver
// did not see, and does not get to omit anything either.
export function bindRequestToAuthority(request, signedParameters) {
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    return fail(ERR_REQUEST_BINDING, "request must be an object");
  }
  const requestKeys = Object.keys(request).sort();
  const signedKeys = Object.keys(signedParameters).sort();
  if (requestKeys.length !== signedKeys.length || requestKeys.some((key, index) => key !== signedKeys[index])) {
    return fail(ERR_REQUEST_BINDING, `request fields [${requestKeys.join(", ")}] do not match the signed fields [${signedKeys.join(", ")}]`);
  }
  for (const key of signedKeys) {
    if (request[key] !== signedParameters[key]) {
      return fail(ERR_REQUEST_BINDING, `request field '${key}' does not equal the authorized value`);
    }
  }
  return Object.freeze({ ok: true });
}
