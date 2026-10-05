// git.push — push credential custody.
//
// THE PROPERTY THIS FILE EXISTS FOR. Only the git.push executor may hold a
// credential that can write to the protected repository. The agent, the
// application that calls MNDe, the sidecar and the request file never see one,
// so a `git push` attempted anywhere else fails for lack of authorization rather
// than for lack of a code path.
//
// How that is arranged:
//
//   - The credential is selected by deployment configuration only:
//     MNDE_GIT_CREDENTIAL_CONFIG, read by the executor itself. No request field,
//     startup argument or transport variable can name a token, key, helper,
//     account or installation. createGitPushExecutor refuses an injected
//     provider exactly as it refuses an injected claim store.
//   - The credential is bound to an explicit allowlist of canonical repository
//     identities (validate.mjs canonicalRepositoryIdentity). A provider
//     configured for org/repo-a refuses to authenticate a push to org/repo-b,
//     whatever the authorization says.
//   - Each kind supports exactly one transport scheme, and the handle pins
//     GIT_ALLOW_PROTOCOL to it, so git cannot be steered onto a transport whose
//     authentication this file does not control (ssh-agent, a netrc, ext::).
//   - Nothing falls back. There is no path to the operator's ~/.gitconfig,
//     credential manager, ssh-agent, default ssh keys, GITHUB_TOKEN, gh login or
//     a test fixture: the transport environment is built from empty
//     (transport.mjs) and this file adds only what the configured kind needs.
//   - Secrets are read at acquire() time, not at startup, and release() drops
//     them: GitHub App installation tokens are revoked, key buffers are zeroed.
//     JavaScript strings cannot be reliably erased; the goal is no persistent
//     copy and no reuse, not a memory-hygiene guarantee.
//   - Metadata about the credential (kind, scope, expiry, a truncated digest) may
//     be recorded. The secret itself never reaches evidence, stdout, a claim or
//     an error message, and handle.redact() scrubs it from anything git printed.
//
// Kinds (docs/PRODUCTION-TRUST-BOUNDARY.md has the operator view):
//
//   github-app        short-lived installation token, minted per execution,
//                     scoped to one repository with contents:write, revoked on
//                     release. The preferred production option.
//   https-token-file  a token file maintained by the deployment's secret
//                     mechanism (a secret-manager agent, a mounted secret).
//   ssh-key-file      a repository deploy key plus a pinned known_hosts file.
//   none              file:// remotes only: authorization is the executor OS
//                     user's filesystem access. Carries no credential at all.

// node:crypto directly, for RS256 only: a GitHub App JWT is RSA-signed and the
// MNDe crypto provider is Ed25519-only. Digests go through the provider.
import { createPrivateKey, sign as cryptoSign } from "node:crypto";
import { readFileSync } from "node:fs";
import { request as httpsRequest } from "node:https";
import { isAbsolute } from "node:path";

import { sha256 } from "../../crypto/provider.mjs";
import { inspectSecretFile } from "./secret-files.mjs";
import { canonicalRepositoryIdentity, remoteUrlScheme } from "./validate.mjs";

export { inspectSecretFile };

export const CREDENTIAL_CONFIG_SCHEMA = "mnde.git-credential-config.v1";

export const ERR_CREDENTIAL_CONFIG = "ERR_GIT_CREDENTIAL_CONFIG";
export const ERR_CREDENTIAL_FILE_INSECURE = "ERR_GIT_CREDENTIAL_FILE_INSECURE";
export const ERR_CREDENTIAL_SCOPE = "ERR_GIT_CREDENTIAL_SCOPE";
export const ERR_CREDENTIAL_UNAVAILABLE = "ERR_GIT_CREDENTIAL_UNAVAILABLE";
export const ERR_CREDENTIAL_SUBSTITUTION = "ERR_GIT_CREDENTIAL_SUBSTITUTION";

export const CREDENTIAL_KINDS = Object.freeze({
  "github-app": "https",
  "https-token-file": "https",
  "ssh-key-file": "ssh",
  none: "file"
});

const KIND_KEYS = Object.freeze({
  "github-app": ["app_id", "installation_id", "private_key_file", "api_base_url"],
  "https-token-file": ["token_file", "username"],
  "ssh-key-file": ["private_key_file", "known_hosts_file", "ssh_executable"],
  none: []
});
const REQUIRED_KIND_KEYS = Object.freeze({
  "github-app": ["app_id", "installation_id", "private_key_file", "api_base_url"],
  "https-token-file": ["token_file"],
  "ssh-key-file": ["private_key_file", "known_hosts_file"],
  none: []
});

// Git does not know this token is special; these are the values a GitHub
// installation token and most forges accept as the basic-auth user.
const DEFAULT_TOKEN_USERNAME = "x-access-token";
// Token characters every forge in practice uses. Deliberately excludes quotes,
// backslashes and whitespace, so a token is never escaped differently in JSON,
// a header or a log line, and redaction always finds it.
const TOKEN_SHAPE = /^[A-Za-z0-9._~+/=-]{1,4096}$/;
const HTTP_TIMEOUT_MS = 10_000;

function configError(detail, code = ERR_CREDENTIAL_CONFIG) {
  return Object.assign(new Error(`${code}: ${detail}`), { code });
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function nonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

function requireSecretFile(path, name, options) {
  const inspected = inspectSecretFile(path, options);
  if (!inspected.ok) throw configError(`${name} ${inspected.detail}`, ERR_CREDENTIAL_FILE_INSECURE);
  return inspected;
}

// Parse and validate a credential configuration object. Throws on anything
// that is not exactly a known shape: an unrecognized key is refused, never
// ignored, because an ignored key reads to the operator as a setting honoured.
export function parseCredentialConfig(config) {
  if (!isPlainObject(config)) throw configError("the credential configuration must be a JSON object");
  if (config.schema !== CREDENTIAL_CONFIG_SCHEMA) throw configError(`schema must be '${CREDENTIAL_CONFIG_SCHEMA}'`);
  const kind = config.kind;
  if (!Object.hasOwn(CREDENTIAL_KINDS, kind)) {
    throw configError(`kind must be one of ${Object.keys(CREDENTIAL_KINDS).join(", ")}`);
  }
  const allowed = new Set(["schema", "kind", "repositories", ...KIND_KEYS[kind]]);
  const unknown = Object.keys(config).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw configError(`unrecognized field(s) for kind '${kind}': ${unknown.join(", ")}`);
  const missing = REQUIRED_KIND_KEYS[kind].filter((key) => config[key] === undefined || config[key] === null || config[key] === "");
  if (missing.length > 0) throw configError(`kind '${kind}' requires: ${missing.join(", ")}`);

  const scheme = CREDENTIAL_KINDS[kind];
  if (!Array.isArray(config.repositories) || config.repositories.length === 0) {
    throw configError("repositories must be a non-empty list of canonical repository identities");
  }
  for (const repository of config.repositories) {
    if (!nonEmptyString(repository) || !repository.startsWith(`${scheme}:`)) {
      throw configError(`kind '${kind}' authenticates ${scheme} remotes only; '${repository}' is not a '${scheme}:' repository identity`);
    }
  }
  if (new Set(config.repositories).size !== config.repositories.length) throw configError("repositories must not repeat");

  for (const key of ["private_key_file", "known_hosts_file", "token_file"]) {
    if (config[key] !== undefined && (!nonEmptyString(config[key]) || !isAbsolute(config[key]))) {
      throw configError(`${key} must be an absolute path`);
    }
  }
  if (kind === "ssh-key-file") {
    for (const key of ["private_key_file", "known_hosts_file", "ssh_executable"]) {
      // GIT_SSH_COMMAND is run through a shell, so every path in it is single
      // quoted; a quote or a control character in a path is refused outright
      // rather than escaped.
      // eslint-disable-next-line no-control-regex
      if (config[key] !== undefined && /['\u0000-\u001f\u007f]/.test(config[key])) {
        throw configError(`${key} must not contain quotes or control characters`);
      }
    }
    if (config.ssh_executable !== undefined && (!nonEmptyString(config.ssh_executable) || !isAbsolute(config.ssh_executable))) {
      throw configError("ssh_executable, when set, must be an absolute path");
    }
  }
  if (kind === "https-token-file" && config.username !== undefined && !/^[A-Za-z0-9._-]{1,128}$/.test(config.username)) {
    throw configError("username must be 1-128 characters of [A-Za-z0-9._-]");
  }
  if (kind === "github-app") {
    for (const key of ["app_id", "installation_id"]) {
      if (!/^[1-9][0-9]{0,19}$/.test(String(config[key]))) throw configError(`${key} must be a positive integer`);
    }
    let api;
    try { api = new URL(config.api_base_url); } catch { throw configError("api_base_url must be a URL"); }
    if (api.protocol !== "https:" || api.username || api.password || api.search || api.hash) {
      throw configError("api_base_url must be a plain https URL with no credentials, query or fragment");
    }
    for (const repository of config.repositories) {
      if (!/^https:[^/]+\/[^/]+\/[^/]+$/.test(repository)) {
        throw configError(`github-app repositories must be 'https:<host>/<owner>/<repo>'; got '${repository}'`);
      }
    }
  }
  return Object.freeze({ ...config, repositories: Object.freeze([...config.repositories]) });
}

function digestPrefix(secret) {
  return `sha256:${sha256(secret).slice(0, 24)}`;
}

function makeRedactor(secrets) {
  const needles = secrets.filter((value) => nonEmptyString(value) && value.length >= 8);
  return (text) => {
    if (typeof text !== "string" || needles.length === 0) return text;
    let out = text;
    for (const needle of needles) out = out.split(needle).join("[REDACTED]");
    return out;
  };
}

// The environment that makes git send one Authorization header, to one URL,
// and nowhere else. Scoped with http.<url>.extraHeader so the header is not
// attached to any other URL git might contact, and redirects are refused so it
// cannot follow one to another host. Passed through GIT_CONFIG_COUNT (git 2.31+)
// so no config file holding the secret is ever written.
export function httpsAuthorizationEnv(remoteUrl, username, token) {
  const basic = Buffer.from(`${username}:${token}`, "utf8");
  const header = `Authorization: Basic ${basic.toString("base64")}`;
  basic.fill(0);
  return {
    env: Object.freeze({
      GIT_CONFIG_COUNT: "2",
      GIT_CONFIG_KEY_0: `http.${remoteUrl}.extraHeader`,
      GIT_CONFIG_VALUE_0: header,
      GIT_CONFIG_KEY_1: "http.followRedirects",
      GIT_CONFIG_VALUE_1: "false"
    }),
    header
  };
}

// The ssh invocation for a deploy key. No config file (-F none), no agent, only
// the configured identity, no prompts, and host keys checked strictly against
// the pinned file for both the user and global lookup, so neither the
// executor user's ~/.ssh nor /etc/ssh can supply a key or a trusted host.
export function sshCommandArgv({ private_key_file: key, known_hosts_file: knownHosts, ssh_executable: executable }) {
  return Object.freeze([
    executable ?? "ssh",
    "-F", "none",
    "-i", key,
    "-o", "IdentitiesOnly=yes",
    "-o", "IdentityAgent=none",
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", `UserKnownHostsFile=${knownHosts}`,
    "-o", `GlobalKnownHostsFile=${knownHosts}`
  ]);
}

function shellQuote(arg) {
  return /^[A-Za-z0-9_./:=-]+$/.test(arg) ? arg : `'${arg}'`;
}

function checkScope(config, { repository, remoteUrl }) {
  const derived = canonicalRepositoryIdentity(remoteUrl);
  if (!derived || derived !== repository) {
    return `remote URL does not derive the authorized repository identity`;
  }
  if (remoteUrlScheme(remoteUrl) !== CREDENTIAL_KINDS[config.kind]) {
    return `a '${config.kind}' credential authenticates ${CREDENTIAL_KINDS[config.kind]} remotes only`;
  }
  if (!config.repositories.includes(repository)) {
    return `the push credential is not scoped to '${repository}'`;
  }
  return null;
}

function defaultHttp({ method, url, headers, body }) {
  return new Promise((resolvePromise, reject) => {
    const req = httpsRequest(url, { method, headers, timeout: HTTP_TIMEOUT_MS }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolvePromise({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error("ETIMEDOUT")));
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

function base64url(value) {
  return Buffer.from(value).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function appJwt(appId, keyPath, nowSeconds) {
  const pem = readFileSync(keyPath);
  let key;
  try {
    key = createPrivateKey(pem);
  } finally {
    pem.fill(0);
  }
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  // GitHub allows ten minutes; back-dated a minute for clock skew.
  const payload = base64url(JSON.stringify({ iat: nowSeconds - 60, exp: nowSeconds + 540, iss: String(appId) }));
  const signature = cryptoSign("sha256", Buffer.from(`${header}.${payload}`, "utf8"), key);
  return `${header}.${payload}.${base64url(signature)}`;
}

function apiUrl(base, path) {
  return `${base.replace(/\/+$/, "")}${path}`;
}

const GITHUB_HEADERS = Object.freeze({
  Accept: "application/vnd.github+json",
  "User-Agent": "mnde-git-push",
  "X-GitHub-Api-Version": "2022-11-28"
});

// Mint a token for exactly one repository with contents:write and nothing else
// the installation might also hold. The response is checked, not trusted: a
// token that came back broader than asked for is revoked and refused.
async function mintInstallationToken(config, repository, { http, now }) {
  const [, owner, repo] = /^https:[^/]+\/([^/]+)\/([^/]+)$/.exec(repository);
  const jwt = appJwt(config.app_id, config.private_key_file, Math.floor(now() / 1000));
  const response = await http({
    method: "POST",
    url: apiUrl(config.api_base_url, `/app/installations/${config.installation_id}/access_tokens`),
    headers: { ...GITHUB_HEADERS, Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" },
    body: JSON.stringify({ repositories: [repo], permissions: { contents: "write" } })
  });
  if (response.status !== 201) {
    // The status only. A response body is the provider's text and is not
    // needed to diagnose a refused mint.
    throw configError(`installation token request was refused (HTTP ${response.status})`, ERR_CREDENTIAL_UNAVAILABLE);
  }
  let parsed;
  try { parsed = JSON.parse(response.body); } catch { throw configError("installation token response was not JSON", ERR_CREDENTIAL_UNAVAILABLE); }
  const token = parsed?.token;
  if (!nonEmptyString(token) || !TOKEN_SHAPE.test(token)) {
    throw configError("installation token response carried no usable token", ERR_CREDENTIAL_UNAVAILABLE);
  }
  const problems = [];
  const expires = Date.parse(parsed.expires_at);
  if (!Number.isFinite(expires) || expires <= now() || expires > now() + 2 * 60 * 60 * 1000) problems.push("expiry");
  const permissions = isPlainObject(parsed.permissions) ? parsed.permissions : {};
  for (const [name, level] of Object.entries(permissions)) {
    const expected = name === "contents" ? "write" : name === "metadata" ? "read" : null;
    if (level !== expected) problems.push(`permission ${name}`);
  }
  if (permissions.contents !== "write") problems.push("contents:write missing");
  const repos = Array.isArray(parsed.repositories) ? parsed.repositories.map((r) => String(r?.full_name ?? "").toLowerCase()) : null;
  if (!repos || repos.length !== 1 || repos[0] !== `${owner}/${repo}`.toLowerCase()) problems.push("repository scope");
  if (problems.length > 0) {
    await revokeInstallationToken(config, token, { http }).catch(() => {});
    throw configError(`installation token was broader or different than requested (${problems.join(", ")}); it was revoked and not used`, ERR_CREDENTIAL_SCOPE);
  }
  return { token, expires_at: new Date(expires).toISOString() };
}

async function revokeInstallationToken(config, token, { http }) {
  const response = await http({
    method: "DELETE",
    url: apiUrl(config.api_base_url, "/installation/token"),
    headers: { ...GITHUB_HEADERS, Authorization: `token ${token}` }
  });
  return response.status === 204;
}

// Open the provider from a parsed configuration.
//
//   forbiddenRoots  directories a secret file must not live under (the local
//                   repository the agent writes to, the MNDe package).
//   http            TEST SEAM for the GitHub App kind only: the HTTPS client.
//                   The executor never passes it; production always uses
//                   node:https against the configured api_base_url.
//   now             clock, for the same tests.
export function openPushCredentialProvider(config, { forbiddenRoots = [], http = defaultHttp, now = Date.now, platform = process.platform, uid } = {}) {
  const parsed = parseCredentialConfig(config);
  const fileOptions = { forbiddenRoots, platform, uid };

  // Startup readiness: every secret file named must already be present and
  // private. It is read again, later, at acquire time.
  const permissionChecks = {};
  for (const key of ["private_key_file", "token_file", "known_hosts_file"]) {
    if (parsed[key] === undefined) continue;
    const secret = key !== "known_hosts_file";
    permissionChecks[key] = requireSecretFile(parsed[key], key, { ...fileOptions, secret }).checked;
  }

  const describe = Object.freeze({
    kind: parsed.kind,
    scheme: CREDENTIAL_KINDS[parsed.kind],
    repositories: parsed.repositories,
    permission_checks: Object.freeze(permissionChecks)
  });

  // Acquire the credential for one execution. Returns a handle or throws a
  // coded error; never returns a partial credential.
  async function acquire({ repository, remoteUrl, executorId } = {}) {
    const scopeProblem = checkScope(parsed, { repository, remoteUrl });
    if (scopeProblem) throw configError(scopeProblem, ERR_CREDENTIAL_SCOPE);
    const allowProtocol = CREDENTIAL_KINDS[parsed.kind];
    const baseMeta = {
      credential_provider_kind: parsed.kind,
      credential_scope: repository,
      executor_id: nonEmptyString(executorId) ? executorId : null
    };

    if (parsed.kind === "none") {
      return Object.freeze({
        env: Object.freeze({}),
        allowProtocol,
        metadata: Object.freeze({ ...baseMeta, credential_issuance_id: null, credential_expires_at: null, credential_fingerprint: null }),
        redact: (text) => text,
        release: async () => ({ released: true })
      });
    }

    if (parsed.kind === "ssh-key-file") {
      requireSecretFile(parsed.private_key_file, "private_key_file", { ...fileOptions, secret: true });
      requireSecretFile(parsed.known_hosts_file, "known_hosts_file", { ...fileOptions, secret: false });
      const argv = sshCommandArgv(parsed);
      const keyBytes = readFileSync(parsed.private_key_file);
      const fingerprint = `sha256:${sha256(keyBytes).slice(0, 24)}`;
      keyBytes.fill(0);
      return Object.freeze({
        env: Object.freeze({ GIT_SSH_COMMAND: argv.map(shellQuote).join(" "), GIT_SSH_VARIANT: "ssh" }),
        allowProtocol,
        metadata: Object.freeze({ ...baseMeta, credential_issuance_id: null, credential_expires_at: null, credential_fingerprint: fingerprint }),
        redact: (text) => text,
        release: async () => ({ released: true })
      });
    }

    let token;
    let expiresAt = null;
    if (parsed.kind === "https-token-file") {
      requireSecretFile(parsed.token_file, "token_file", { ...fileOptions, secret: true });
      const raw = readFileSync(parsed.token_file);
      token = raw.toString("utf8").trim();
      raw.fill(0);
      if (!TOKEN_SHAPE.test(token)) throw configError("token_file does not hold a single printable token", ERR_CREDENTIAL_UNAVAILABLE);
    } else {
      requireSecretFile(parsed.private_key_file, "private_key_file", { ...fileOptions, secret: true });
      const minted = await mintInstallationToken(parsed, repository, { http, now });
      token = minted.token;
      expiresAt = minted.expires_at;
    }

    const username = parsed.kind === "https-token-file" ? (parsed.username ?? DEFAULT_TOKEN_USERNAME) : DEFAULT_TOKEN_USERNAME;
    const { env, header } = httpsAuthorizationEnv(remoteUrl, username, token);
    const fingerprint = parsed.kind === "https-token-file" ? digestPrefix(token) : null;
    const redact = makeRedactor([token, header, header.replace(/^Authorization: Basic /, "")]);
    let released = false;
    const tokenForRevoke = parsed.kind === "github-app" ? token : null;
    token = null;

    return Object.freeze({
      env,
      allowProtocol,
      metadata: Object.freeze({
        ...baseMeta,
        credential_issuance_id: parsed.kind === "github-app" ? `github-app:${parsed.app_id}/installation:${parsed.installation_id}` : null,
        credential_expires_at: expiresAt,
        credential_fingerprint: fingerprint
      }),
      redact,
      // Idempotent. For an installation token, revocation is what makes
      // "the credential becomes unavailable" true before its expiry; a failed
      // revocation is reported, and the token still expires on its own.
      release: async () => {
        if (released) return { released: true };
        released = true;
        if (tokenForRevoke) {
          try {
            return { released: true, revoked: await revokeInstallationToken(parsed, tokenForRevoke, { http }) };
          } catch {
            return { released: true, revoked: false };
          }
        }
        return { released: true };
      }
    });
  }

  return Object.freeze({ describe, acquire });
}

// The executor's own entry point: the configuration file named by
// MNDE_GIT_CREDENTIAL_CONFIG in the executor's environment, and nothing else.
// The config file itself must not be writable by anyone but the executor user,
// because whoever can edit it can point the executor at a different secret.
export function openExecutorPushCredentialProvider(env, { forbiddenRoots = [] } = {}) {
  const path = env?.MNDE_GIT_CREDENTIAL_CONFIG;
  if (!nonEmptyString(path)) {
    throw configError("MNDE_GIT_CREDENTIAL_CONFIG is not set; a protected push has no credential and there is no fallback");
  }
  requireSecretFile(path, "MNDE_GIT_CREDENTIAL_CONFIG", { forbiddenRoots, secret: false });
  let config;
  try {
    config = JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    throw configError(`MNDE_GIT_CREDENTIAL_CONFIG could not be read as JSON (${error?.code ?? error?.name ?? "error"})`);
  }
  return openPushCredentialProvider(config, { forbiddenRoots });
}
