// git.push — push credential custody.
//
//   npm run test:git-push-credential-custody
//
// Unit and mechanism tests for src/effects/git-push/credential-provider.mjs and
// the credentialed transport context. End-to-end cases (a hostile ambient
// environment, scope refusal that spends nothing, readiness refusals) run the
// real CLI in tests/test_git_push_cli.mjs.
//
// What is NOT proven here, and is said so in docs/PRODUCTION-TRUST-BOUNDARY.md:
//   - the GitHub App kind is exercised against a stub of the GitHub API, not
//     GitHub itself;
//   - the ssh kind is checked by the command it builds; no sshd is contacted;
//   - the https header mechanism is observed over plain http against a local
//     server, because a test cannot mint a trusted TLS certificate portably.

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, verify as cryptoVerify } from "node:crypto";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CREDENTIAL_CONFIG_SCHEMA,
  ERR_CREDENTIAL_CONFIG,
  ERR_CREDENTIAL_FILE_INSECURE,
  ERR_CREDENTIAL_SCOPE,
  ERR_CREDENTIAL_UNAVAILABLE,
  httpsAuthorizationEnv,
  inspectSecretFile,
  openExecutorPushCredentialProvider,
  openPushCredentialProvider,
  parseCredentialConfig
} from "../src/effects/git-push/credential-provider.mjs";
import { buildTransportEnv, ERR_CREDENTIAL_ENV_NOT_ALLOWED, withPushCredential } from "../src/effects/git-push/transport.mjs";

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  [PASS] ${name}`); }
  catch (error) { failed += 1; console.error(`  [FAIL] ${name}: ${error instanceof Error ? error.stack : String(error)}`); }
}

const dir = mkdtempSync(join(tmpdir(), "mnde-git-credential-"));
const POSIX = process.platform !== "win32";

function secretFile(name, contents) {
  const path = join(dir, name);
  writeFileSync(path, contents, { encoding: "utf8", mode: 0o600 });
  if (POSIX) chmodSync(path, 0o600);
  return path;
}

const REPO = "https:github.example/acme/widgets";
const REMOTE = "https://github.example/acme/widgets.git";
const TOKEN = "ghs_TestTokenValue0123456789abcdefABCDEF";
const tokenFile = secretFile("token", `${TOKEN}\n`);

function config(fields) {
  return { schema: CREDENTIAL_CONFIG_SCHEMA, ...fields };
}

function codeOf(fn) {
  try { fn(); } catch (error) { return error.code; }
  return null;
}

async function asyncCodeOf(promise) {
  try { await promise; } catch (error) { return { code: error.code, message: error.message }; }
  return { code: null };
}

function runGit(args, env) {
  return new Promise((resolve) => {
    execFile("git", args, { env, timeout: 20_000, windowsHide: true, encoding: "utf8" }, (error, stdout, stderr) => {
      resolve({ ok: !error, stdout, stderr });
    });
  });
}

async function main() {
  console.log("git.push credential custody\n");

  console.log("── configuration is exact and deployment-controlled ──");

  await test("unknown kinds, unknown fields and missing fields are refused, not ignored", () => {
    assert.equal(codeOf(() => parseCredentialConfig(null)), ERR_CREDENTIAL_CONFIG);
    assert.equal(codeOf(() => parseCredentialConfig({ kind: "none", repositories: ["file:/x"] })), ERR_CREDENTIAL_CONFIG, "schema is required");
    assert.equal(codeOf(() => parseCredentialConfig(config({ kind: "env-var", repositories: [REPO] }))), ERR_CREDENTIAL_CONFIG);
    assert.equal(codeOf(() => parseCredentialConfig(config({ kind: "https-token-file", repositories: [REPO], token_file: tokenFile, fallback: "gh-cli" }))), ERR_CREDENTIAL_CONFIG);
    assert.equal(codeOf(() => parseCredentialConfig(config({ kind: "https-token-file", repositories: [REPO] }))), ERR_CREDENTIAL_CONFIG);
    assert.equal(codeOf(() => parseCredentialConfig(config({ kind: "https-token-file", repositories: [], token_file: tokenFile }))), ERR_CREDENTIAL_CONFIG);
    assert.equal(codeOf(() => parseCredentialConfig(config({ kind: "https-token-file", repositories: [REPO], token_file: "token" }))), ERR_CREDENTIAL_CONFIG, "relative path");
  });

  await test("each kind is bound to one scheme: an https credential cannot be scoped to an ssh or file repository", () => {
    assert.equal(codeOf(() => parseCredentialConfig(config({ kind: "https-token-file", repositories: ["ssh:github.example/acme/widgets"], token_file: tokenFile }))), ERR_CREDENTIAL_CONFIG);
    assert.equal(codeOf(() => parseCredentialConfig(config({ kind: "none", repositories: [REPO] }))), ERR_CREDENTIAL_CONFIG);
    assert.equal(codeOf(() => parseCredentialConfig(config({ kind: "ssh-key-file", repositories: [REPO], private_key_file: tokenFile, known_hosts_file: tokenFile }))), ERR_CREDENTIAL_CONFIG);
  });

  await test("github-app requires an https API base with no credentials, and owner/repo identities", () => {
    const base = { kind: "github-app", repositories: [REPO], app_id: "1", installation_id: "2", private_key_file: tokenFile };
    assert.equal(codeOf(() => parseCredentialConfig(config({ ...base, api_base_url: "http://api.github.example" }))), ERR_CREDENTIAL_CONFIG);
    assert.equal(codeOf(() => parseCredentialConfig(config({ ...base, api_base_url: "https://user:pw@api.github.example" }))), ERR_CREDENTIAL_CONFIG);
    assert.equal(codeOf(() => parseCredentialConfig(config({ ...base, app_id: "-1", api_base_url: "https://api.github.example" }))), ERR_CREDENTIAL_CONFIG);
    assert.equal(codeOf(() => parseCredentialConfig(config({ ...base, repositories: ["https:github.example/acme"], api_base_url: "https://api.github.example" }))), ERR_CREDENTIAL_CONFIG);
    assert.doesNotThrow(() => parseCredentialConfig(config({ ...base, api_base_url: "https://api.github.example" })));
  });

  await test("ssh paths that could break out of the quoted ssh command are refused", () => {
    const bad = join(dir, "it's-a-key");
    assert.equal(codeOf(() => parseCredentialConfig(config({ kind: "ssh-key-file", repositories: ["ssh:github.example/acme/widgets"], private_key_file: bad, known_hosts_file: tokenFile }))), ERR_CREDENTIAL_CONFIG);
  });

  await test("the executor opens only MNDE_GIT_CREDENTIAL_CONFIG; unset means refuse, never fall back", () => {
    assert.equal(codeOf(() => openExecutorPushCredentialProvider({})), ERR_CREDENTIAL_CONFIG);
    assert.equal(codeOf(() => openExecutorPushCredentialProvider({ GITHUB_TOKEN: TOKEN, GH_TOKEN: TOKEN, SSH_AUTH_SOCK: "/tmp/agent" })), ERR_CREDENTIAL_CONFIG);
  });

  console.log("\n── secret files ──");

  await test("a secret inside the repository or the package is refused wherever the OS is", () => {
    const repo = join(dir, "repo");
    mkdirSync(repo, { recursive: true });
    const inside = join(repo, "token");
    writeFileSync(inside, TOKEN, { mode: 0o600 });
    assert.equal(inspectSecretFile(inside, { forbiddenRoots: [repo] }).ok, false);
    assert.equal(codeOf(() => openPushCredentialProvider(config({ kind: "https-token-file", repositories: [REPO], token_file: inside }), { forbiddenRoots: [repo] })), ERR_CREDENTIAL_FILE_INSECURE);
  });

  if (POSIX) {
    await test("POSIX: a group- or world-readable secret, a symlink, or a group-writable config is refused", () => {
      const loose = join(dir, "loose-token");
      writeFileSync(loose, TOKEN);
      chmodSync(loose, 0o644);
      assert.equal(inspectSecretFile(loose).ok, false);
      assert.equal(codeOf(() => openPushCredentialProvider(config({ kind: "https-token-file", repositories: [REPO], token_file: loose }))), ERR_CREDENTIAL_FILE_INSECURE);
      chmodSync(loose, 0o600);
      assert.deepEqual(inspectSecretFile(loose), { ok: true, checked: true });

      const link = join(dir, "linked-token");
      symlinkSync(loose, link);
      assert.equal(inspectSecretFile(link).ok, false);

      const cfg = join(dir, "group-writable-config.json");
      writeFileSync(cfg, JSON.stringify(config({ kind: "none", repositories: ["file:/x"] })));
      chmodSync(cfg, 0o664);
      assert.equal(codeOf(() => openExecutorPushCredentialProvider({ MNDE_GIT_CREDENTIAL_CONFIG: cfg })), ERR_CREDENTIAL_FILE_INSECURE);
      chmodSync(cfg, 0o644);
      assert.doesNotThrow(() => openExecutorPushCredentialProvider({ MNDE_GIT_CREDENTIAL_CONFIG: cfg }));
    });
  } else {
    await test("Windows: file permissions are reported as not checked, not as checked-and-fine", () => {
      assert.deepEqual(inspectSecretFile(tokenFile), { ok: true, checked: false });
      const provider = openPushCredentialProvider(config({ kind: "https-token-file", repositories: [REPO], token_file: tokenFile }));
      assert.equal(provider.describe.permission_checks.token_file, false);
    });
  }

  console.log("\n── scope ──");

  await test("a credential scoped to repo-a does not authenticate repo-b, nor a URL that does not derive the repository", async () => {
    const provider = openPushCredentialProvider(config({ kind: "https-token-file", repositories: [REPO], token_file: tokenFile }));
    const other = await asyncCodeOf(provider.acquire({ repository: "https:github.example/acme/other", remoteUrl: "https://github.example/acme/other.git" }));
    assert.equal(other.code, ERR_CREDENTIAL_SCOPE);
    const mismatched = await asyncCodeOf(provider.acquire({ repository: REPO, remoteUrl: "https://github.example/acme/other.git" }));
    assert.equal(mismatched.code, ERR_CREDENTIAL_SCOPE);
    const wrongScheme = await asyncCodeOf(provider.acquire({ repository: "ssh:github.example/acme/widgets", remoteUrl: "ssh://git@github.example/acme/widgets.git" }));
    assert.equal(wrongScheme.code, ERR_CREDENTIAL_SCOPE);
  });

  console.log("\n── https token: only the handle carries it, only to one URL ──");

  await test("the handle's metadata never contains the token; redact() scrubs every form of it", async () => {
    const provider = openPushCredentialProvider(config({ kind: "https-token-file", repositories: [REPO], token_file: tokenFile }));
    const handle = await provider.acquire({ repository: REPO, remoteUrl: REMOTE, executorId: "ex-1" });
    const meta = JSON.stringify(handle.metadata);
    assert.ok(!meta.includes(TOKEN), "token leaked into metadata");
    assert.equal(handle.metadata.credential_provider_kind, "https-token-file");
    assert.equal(handle.metadata.credential_scope, REPO);
    assert.match(handle.metadata.credential_fingerprint, /^sha256:[0-9a-f]{24}$/);
    assert.equal(handle.allowProtocol, "https");
    assert.equal(handle.env.GIT_CONFIG_KEY_0, `http.${REMOTE}.extraHeader`);
    assert.equal(handle.env.GIT_CONFIG_KEY_1, "http.followRedirects");
    assert.equal(handle.env.GIT_CONFIG_VALUE_1, "false");
    const basic = Buffer.from(`x-access-token:${TOKEN}`).toString("base64");
    const noisy = `fatal: ${TOKEN} / Authorization: Basic ${basic} / ${basic}`;
    const scrubbed = handle.redact(noisy);
    assert.ok(!scrubbed.includes(TOKEN) && !scrubbed.includes(basic), scrubbed);
    assert.deepEqual(await handle.release(), { released: true });
  });

  await test("a token file holding anything but one token is refused at acquire, with no content in the error", async () => {
    const odd = secretFile("odd-token", "two tokens\n");
    const provider = openPushCredentialProvider(config({ kind: "https-token-file", repositories: [REPO], token_file: odd }));
    const refused = await asyncCodeOf(provider.acquire({ repository: REPO, remoteUrl: REMOTE }));
    assert.equal(refused.code, ERR_CREDENTIAL_UNAVAILABLE);
    assert.ok(!refused.message.includes("two tokens"));
  });

  await test("real git sends the Authorization header to the scoped URL and to no other", async () => {
    const seen = [];
    const server = createServer((req, res) => {
      seen.push({ url: req.url, authorization: req.headers.authorization ?? null });
      res.statusCode = 404;
      res.end();
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    const scoped = `http://127.0.0.1:${port}/acme/widgets.git`;
    const unscoped = `http://127.0.0.1:${port}/acme/other.git`;
    try {
      const { env: credentialEnv, header } = httpsAuthorizationEnv(scoped, "x-access-token", TOKEN);
      const base = buildTransportEnv({}).env;
      // The executor would pin GIT_ALLOW_PROTOCOL=https; http is used here only
      // because a portable test cannot present a trusted certificate.
      const env = { ...base, ...credentialEnv, GIT_ALLOW_PROTOCOL: "http", HOME: dir };
      await runGit(["ls-remote", "--", scoped], env);
      await runGit(["ls-remote", "--", unscoped], env);
      await runGit(["ls-remote", "--", scoped], { ...base, GIT_ALLOW_PROTOCOL: "http", HOME: dir });
      const toScoped = seen.filter((r) => r.url.startsWith("/acme/widgets.git"));
      const toOther = seen.filter((r) => r.url.startsWith("/acme/other.git"));
      assert.ok(toScoped.length >= 2 && toOther.length >= 1, JSON.stringify(seen));
      assert.equal(toScoped[0].authorization, header.replace(/^Authorization: /, ""), "the scoped URL must get the header");
      assert.ok(toOther.every((r) => r.authorization === null), "the header must not reach another repository's URL");
      assert.equal(toScoped.at(-1).authorization, null, "without the credential env, git sends no credential of its own");
    } finally {
      server.close();
    }
  });

  console.log("\n── the credentialed context ──");

  await test("the base environment allows no transport; the credentialed one allows exactly the handle's", () => {
    const base = buildTransportEnv({}).env;
    assert.equal(base.GIT_ALLOW_PROTOCOL, "");
    const stage = { env: base, repoPath: dir, cwd: dir, timeoutMs: 1000 };
    const ok = withPushCredential(stage, { env: { GIT_SSH_COMMAND: "ssh -F none", GIT_SSH_VARIANT: "ssh" }, allowProtocol: "ssh" });
    assert.equal(ok.ok, true);
    assert.equal(ok.context.env.GIT_ALLOW_PROTOCOL, "ssh");
    assert.equal(stage.env.GIT_SSH_COMMAND, undefined, "the local-only context is untouched");
  });

  await test("a handle that tries to set anything but credential variables, or an unknown protocol, is refused", () => {
    const stage = { env: buildTransportEnv({}).env };
    for (const env of [{ GIT_PROXY_COMMAND: "x" }, { HOME: "/root" }, { GIT_CONFIG_KEY_2: "core.sshCommand" }, { LD_PRELOAD: "x" }]) {
      assert.equal(withPushCredential(stage, { env, allowProtocol: "https" }).reason, ERR_CREDENTIAL_ENV_NOT_ALLOWED, JSON.stringify(env));
    }
    for (const allowProtocol of ["ext", "https:ext", "", undefined]) {
      assert.equal(withPushCredential(stage, { env: {}, allowProtocol }).reason, ERR_CREDENTIAL_ENV_NOT_ALLOWED, String(allowProtocol));
    }
  });

  console.log("\n── ssh deploy key ──");

  await test("the ssh command reads no config, no agent, only the configured key, and pins known_hosts", async () => {
    const key = secretFile("deploy key", "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n");
    const knownHosts = secretFile("known_hosts", "github.example ssh-ed25519 AAAA\n");
    const repo = "ssh:github.example/acme/widgets";
    const provider = openPushCredentialProvider(config({ kind: "ssh-key-file", repositories: [repo], private_key_file: key, known_hosts_file: knownHosts }));
    const handle = await provider.acquire({ repository: repo, remoteUrl: "ssh://git@github.example/acme/widgets.git" });
    const cmd = handle.env.GIT_SSH_COMMAND;
    for (const part of ["-F none", `-i '${key}'`, "IdentitiesOnly=yes", "IdentityAgent=none", "BatchMode=yes", "StrictHostKeyChecking=yes", `UserKnownHostsFile=${knownHosts}`, `GlobalKnownHostsFile=${knownHosts}`]) {
      assert.ok(cmd.includes(part), `missing ${part} in ${cmd}`);
    }
    assert.equal(handle.allowProtocol, "ssh");
    assert.ok(!JSON.stringify(handle.metadata).includes("not-a-real-key"));
  });

  console.log("\n── GitHub App: one repository, contents:write, revoked on release (stub API) ──");

  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const appKey = secretFile("app-key.pem", privateKey.export({ type: "pkcs1", format: "pem" }));
  const appConfig = config({
    kind: "github-app",
    repositories: [REPO],
    app_id: "12345",
    installation_id: "67890",
    private_key_file: appKey,
    api_base_url: "https://api.github.example"
  });
  const NOW = Date.parse("2026-09-27T10:00:00Z");
  const INSTALLATION_TOKEN = "ghs_InstallationToken0123456789abcdefXYZ";

  function stubApi(mintResponse) {
    const calls = [];
    const http = async (req) => {
      calls.push(req);
      if (req.method === "POST") return mintResponse(req);
      if (req.method === "DELETE") return { status: 204, body: "" };
      return { status: 500, body: "" };
    };
    return { calls, http };
  }
  const goodMint = () => ({
    status: 201,
    body: JSON.stringify({
      token: INSTALLATION_TOKEN,
      expires_at: new Date(NOW + 3600_000).toISOString(),
      permissions: { contents: "write", metadata: "read" },
      repositories: [{ full_name: "acme/widgets" }]
    })
  });

  await test("mints a token for exactly this repository with contents:write, signed by the app key", async () => {
    const api = stubApi(goodMint);
    const provider = openPushCredentialProvider(appConfig, { http: api.http, now: () => NOW });
    const handle = await provider.acquire({ repository: REPO, remoteUrl: REMOTE, executorId: "ex-1" });
    const mint = api.calls[0];
    assert.equal(mint.method, "POST");
    assert.equal(mint.url, "https://api.github.example/app/installations/67890/access_tokens");
    assert.deepEqual(JSON.parse(mint.body), { repositories: ["widgets"], permissions: { contents: "write" } });
    const [h, p, s] = mint.headers.Authorization.replace(/^Bearer /, "").split(".");
    const valid = cryptoVerify("sha256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(s, "base64url"));
    assert.equal(valid, true, "the app JWT must verify under the app's public key");
    const claims = JSON.parse(Buffer.from(p, "base64url").toString());
    assert.equal(claims.iss, "12345");
    assert.ok(claims.exp - claims.iat <= 600, "GitHub rejects app JWTs longer than ten minutes");
    assert.equal(handle.metadata.credential_expires_at, new Date(NOW + 3600_000).toISOString());
    assert.equal(handle.metadata.credential_issuance_id, "github-app:12345/installation:67890");
    assert.ok(!JSON.stringify(handle.metadata).includes(INSTALLATION_TOKEN));
    const release = await handle.release();
    assert.deepEqual(release, { released: true, revoked: true });
    assert.equal(api.calls[1].method, "DELETE");
    assert.equal(api.calls[1].headers.Authorization, `token ${INSTALLATION_TOKEN}`);
    assert.deepEqual(await handle.release(), { released: true }, "release is idempotent and revokes once");
    assert.equal(api.calls.length, 2);
  });

  await test("a token broader than requested is revoked and refused", async () => {
    for (const body of [
      { permissions: { contents: "write", metadata: "read", administration: "write" }, repositories: [{ full_name: "acme/widgets" }] },
      { permissions: { contents: "write", metadata: "read" }, repositories: [{ full_name: "acme/widgets" }, { full_name: "acme/other" }] },
      { permissions: { contents: "write", metadata: "read" }, repositories: [{ full_name: "acme/other" }] },
      { permissions: { contents: "read", metadata: "read" }, repositories: [{ full_name: "acme/widgets" }] }
    ]) {
      const api = stubApi(() => ({ status: 201, body: JSON.stringify({ token: INSTALLATION_TOKEN, expires_at: new Date(NOW + 3600_000).toISOString(), ...body }) }));
      const provider = openPushCredentialProvider(appConfig, { http: api.http, now: () => NOW });
      const refused = await asyncCodeOf(provider.acquire({ repository: REPO, remoteUrl: REMOTE }));
      assert.equal(refused.code, ERR_CREDENTIAL_SCOPE, JSON.stringify(body));
      assert.ok(api.calls.some((c) => c.method === "DELETE"), "the over-broad token must be revoked");
      assert.ok(!refused.message.includes(INSTALLATION_TOKEN));
    }
  });

  await test("a refused mint reports only the status, never the response body", async () => {
    const api = stubApi(() => ({ status: 403, body: "secret-ish provider text" }));
    const provider = openPushCredentialProvider(appConfig, { http: api.http, now: () => NOW });
    const refused = await asyncCodeOf(provider.acquire({ repository: REPO, remoteUrl: REMOTE }));
    assert.equal(refused.code, ERR_CREDENTIAL_UNAVAILABLE);
    assert.match(refused.message, /HTTP 403/);
    assert.ok(!refused.message.includes("secret-ish"));
  });

  rmSync(dir, { recursive: true, force: true });
  const total = passed + failed;
  if (failed === 0) console.log(`\nPASS git.push credential custody (${passed}/${total})`);
  else { console.error(`\nFAIL git.push credential custody (${passed}/${total})`); process.exitCode = 1; }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
