// TEST SUPPORT ONLY — a local EMULATOR of the two GitHub surfaces the git.push
// executor's `github-app` credential kind touches. It is NOT GitHub, proves nothing
// about GitHub's own behaviour (rulesets, rate limits, real timeouts), and every
// result obtained through it is labelled "emulator" in the closure report.
//
//   POST   /app/installations/<id>/access_tokens   verifies the App JWT (RS256), mints a scoped token
//   DELETE /installation/token                     revokes it
//   *      /<owner>/<repo>.git/...                 git smart HTTP via `git http-backend`; pushes
//                                                  (git-receive-pack) require a contents:write token
//
// Control files in the state directory switch faults on and off:
//   api-fail-read / api-fail-write   mint of that access level answers HTTP 500
//   api-hang-read / api-hang-write   mint of that access level never answers
//   delay-receive-pack-response      apply the push, then hold the response 40 s
//   down-after-push                  after a push is applied, every request answers 503
//
// Everything it observes is appended to events.log as JSON lines.
import { createPublicKey, createVerify, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:https";
import { join } from "node:path";

export function startEmulator({ stateDir, projectRoot, cert, key, appId, appPublicPem, installationId, repoFullName, port = 0 }) {
  const tokens = new Map(); // token -> { access, revoked }
  const log = (event) => appendFileSync(join(stateDir, "events.log"), `${JSON.stringify({ at: new Date().toISOString(), ...event })}\n`);
  const flag = (name) => existsSync(join(stateDir, name));
  const publicKey = createPublicKey(appPublicPem);

  function verifyJwt(header) {
    const m = /^Bearer ([\w-]+)\.([\w-]+)\.([\w-]+)$/.exec(header ?? "");
    if (!m) return false;
    const v = createVerify("sha256");
    v.update(`${m[1]}.${m[2]}`);
    if (!v.verify(publicKey, Buffer.from(m[3], "base64url"))) return false;
    const claims = JSON.parse(Buffer.from(m[2], "base64url").toString("utf8"));
    return String(claims.iss) === String(appId) && claims.exp * 1000 > Date.now();
  }
  function bearer(req) {
    const m = /^Basic (.+)$/.exec(req.headers.authorization ?? "");
    if (m) { const [, token] = Buffer.from(m[1], "base64").toString("utf8").split(":"); return token; }
    const t = /^token (.+)$/.exec(req.headers.authorization ?? "");
    return t ? t[1] : null;
  }
  const body = async (req) => { const chunks = []; for await (const c of req) chunks.push(c); return Buffer.concat(chunks); };
  const send = (res, code, text = "", headers = {}) => { res.writeHead(code, headers); res.end(text); };

  const server = createServer({ cert, key }, async (req, res) => {
    const url = new URL(req.url, "https://localhost");
    try {
      if (flag("down") ) { log({ e: "down", path: url.pathname }); return send(res, 503); }
      if (req.method === "POST" && url.pathname === `/app/installations/${installationId}/access_tokens`) {
        const raw = JSON.parse((await body(req)).toString("utf8"));
        const access = raw?.permissions?.contents;
        log({ e: "mint-request", access, repositories: raw.repositories, permissions: raw.permissions, jwt_ok: verifyJwt(req.headers.authorization) });
        if (!verifyJwt(req.headers.authorization)) return send(res, 401);
        if (flag(`api-hang-${access}`)) { log({ e: "mint-hang", access }); return; }
        if (flag(`api-fail-${access}`)) { log({ e: "mint-fail", access }); return send(res, 500, "{}"); }
        const token = `ghs_${randomBytes(18).toString("hex")}`;
        tokens.set(token, { access, revoked: false });
        log({ e: "minted", access });
        return send(res, 201, JSON.stringify({ token, expires_at: new Date(Date.now() + 3600_000).toISOString(),
          permissions: { contents: access, metadata: "read" }, repositories: [{ full_name: repoFullName }] }), { "content-type": "application/json" });
      }
      if (req.method === "DELETE" && url.pathname === "/installation/token") {
        const t = bearer(req);
        if (tokens.has(t)) { tokens.get(t).revoked = true; log({ e: "revoked", access: tokens.get(t).access }); return send(res, 204); }
        return send(res, 401);
      }
      if (url.pathname.startsWith("/") && url.pathname.includes(".git/")) {
        const t = bearer(req);
        const info = tokens.get(t);
        const writes = url.searchParams.get("service") === "git-receive-pack" || url.pathname.endsWith("/git-receive-pack");
        if (!info || info.revoked) { log({ e: "git-denied", reason: "no-valid-token", path: url.pathname }); return send(res, 401, "", { "www-authenticate": 'Basic realm="emulator"' }); }
        if (writes && info.access !== "write") { log({ e: "git-denied", reason: "read-token-used-for-write", path: url.pathname }); return send(res, 403); }
        log({ e: "git", writes, access: info.access, path: url.pathname });
        const payload = await body(req);
        const [, pathInfo] = [null, url.pathname];
        const cgi = spawn("git", ["http-backend"], { env: { PATH: process.env.PATH, GIT_PROJECT_ROOT: projectRoot, GIT_HTTP_EXPORT_ALL: "1",
          REQUEST_METHOD: req.method, PATH_INFO: pathInfo, QUERY_STRING: url.search.slice(1), CONTENT_TYPE: req.headers["content-type"] ?? "",
          CONTENT_LENGTH: String(payload.length), HTTP_CONTENT_ENCODING: req.headers["content-encoding"] ?? "", REMOTE_USER: "emulator", REMOTE_ADDR: "127.0.0.1" } });
        const out = [];
        cgi.stdout.on("data", (d) => out.push(d));
        cgi.stdin.on("error", () => {}); // http-backend may exit before reading a body it has already refused
        cgi.stdin.end(payload);
        await new Promise((r) => cgi.on("close", r));
        const raw = Buffer.concat(out);
        const split = raw.indexOf("\r\n\r\n");
        const head = raw.subarray(0, split).toString("utf8").split("\r\n");
        const headers = {};
        let status = 200;
        for (const line of head) {
          const i = line.indexOf(":");
          if (i < 0) continue;
          const name = line.slice(0, i).toLowerCase(), value = line.slice(i + 1).trim();
          if (name === "status") status = Number(value.split(" ")[0]); else headers[name] = value;
        }
        if (writes && req.method === "POST") {
          log({ e: "push-applied", status });
          if (flag("down-after-push-armed")) writeFileSync(join(stateDir, "down"), "");
          if (flag("delay-receive-pack-response")) { log({ e: "response-held" }); await new Promise((r) => setTimeout(r, 40_000)); }
        }
        res.writeHead(status, headers);
        return res.end(raw.subarray(split + 4));
      }
      send(res, 404);
    } catch (error) {
      log({ e: "emulator-error", message: String(error?.message ?? error) });
      send(res, 500);
    }
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve({
    port: server.address().port, close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }),
    events: () => (existsSync(join(stateDir, "events.log")) ? readFileSync(join(stateDir, "events.log"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [])
  })));
}
