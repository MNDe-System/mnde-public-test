import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { hostname, homedir } from "node:os";
import { dirname, join } from "node:path";
import { generateKeyPair, importPrivateKey, randomBytes, sign, verify } from "../crypto/provider.mjs";
import { CLIENT_ID, challengeMessage, rawPublicKey, publicKeyPem } from "../hub/pairing-protocol.mjs";

const DPAPI_SCRIPT = `Add-Type -AssemblyName System.Security
$bytes = [Convert]::FromBase64String([Console]::In.ReadToEnd())
if ('{{MODE}}' -eq 'protect') { $result = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser) }
else { $result = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser) }
[Console]::Out.Write([Convert]::ToBase64String($result))`;

function dpapi(operation, data) {
  if (process.platform !== "win32") throw new Error("ERR_CLIENT_SECURE_STORE_UNAVAILABLE");
  if (!["protect", "unprotect"].includes(operation)) throw new Error("ERR_CLIENT_SECURE_STORE_UNAVAILABLE");
  return new Promise((resolve, reject) => {
    const child = spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
      "-Command", DPAPI_SCRIPT.replace("{{MODE}}", operation)], { windowsHide: true, stdio: ["pipe", "pipe", "pipe"] });
    let output = "", errorSize = 0;
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", part => { output += part; if (output.length > 32_768) child.kill(); });
    child.stderr.on("data", part => { errorSize += part.length; if (errorSize > 32_768) child.kill(); });
    child.on("error", () => reject(new Error("ERR_CLIENT_SECURE_STORE_UNAVAILABLE")));
    child.stdin.on("error", () => reject(new Error("ERR_CLIENT_SECURE_STORE_UNAVAILABLE")));
    child.on("close", code => code === 0 && /^[A-Za-z0-9+/=]+$/.test(output)
      ? resolve(Buffer.from(output, "base64")) : reject(new Error("ERR_CLIENT_SECURE_STORE_UNAVAILABLE")));
    child.stdin.end(data.toString("base64"));
  });
}

export const windowsDpapiStore = Object.freeze({
  protect: data => dpapi("protect", data),
  unprotect: data => dpapi("unprotect", data)
});

export function clientIdentityPath(env = process.env) {
  return join(env.LOCALAPPDATA || join(homedir(), "AppData", "Local"), "MNDe", "client-identity.json");
}

function atomicFile(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temp = `${path}.${randomBytes(8).toString("hex")}.tmp`;
  writeFileSync(temp, value, { flag: "wx", mode: 0o600 });
  renameSync(temp, path);
}

export class DesktopClientIdentity {
  constructor({ path = clientIdentityPath(), secureStore = windowsDpapiStore, name = hostname() } = {}) {
    this.path = path; this.keyPath = join(dirname(path), "client-private-key.dpapi");
    this.secureStore = secureStore; this.name = name;
  }
  async loadOrCreate() {
    if (this.cached) return this.cached;
    if (this.pending) return this.pending;
    this.pending = this.#loadOrCreate();
    try { this.cached = await this.pending; return this.cached; }
    finally { this.pending = null; }
  }
  async #loadOrCreate() {
    if (existsSync(this.path) || existsSync(this.keyPath)) {
      if (!existsSync(this.path) || !existsSync(this.keyPath)) throw new Error("ERR_CLIENT_IDENTITY_PARTIAL");
      const value = JSON.parse(readFileSync(this.path, "utf8"));
      if (!value || !CLIENT_ID.test(value.clientId) || typeof value.clientName !== "string"
        || value.clientName.length < 1 || value.clientName.length > 64 || !publicKeyPem(value.publicKey)
        || !Number.isFinite(Date.parse(value.createdAt))) throw new Error("ERR_CLIENT_IDENTITY_INVALID");
      const privatePem = (await this.secureStore.unprotect(readFileSync(this.keyPath))).toString("utf8");
      const privateKey = importPrivateKey(privatePem);
      const check = randomBytes(32);
      if (!await verify(check, await sign(check, privateKey), publicKeyPem(value.publicKey))) throw new Error("ERR_CLIENT_IDENTITY_KEY_MISMATCH");
      return Object.freeze({ ...value, privateKey });
    }
    const name = String(this.name).trim().slice(0, 64);
    if (!name || /[\x00-\x1f\x7f]/.test(name)) throw new Error("ERR_CLIENT_NAME");
    const keys = generateKeyPair();
    const value = { clientId: `pc-${randomBytes(8).toString("hex")}`, clientName: name,
      publicKey: rawPublicKey(keys.publicPem), createdAt: new Date().toISOString() };
    const encrypted = await this.secureStore.protect(Buffer.from(keys.privatePem, "utf8"));
    atomicFile(this.keyPath, encrypted);
    atomicFile(this.path, `${JSON.stringify(value)}\n`);
    return Object.freeze({ ...value, privateKey: importPrivateKey(keys.privatePem) });
  }
  async publicIdentity() {
    const { clientId, clientName, publicKey, createdAt } = await this.loadOrCreate();
    return { clientId, clientName, publicKey, createdAt };
  }
  async signChallenge(value) {
    const client = await this.loadOrCreate();
    const signature = await sign(challengeMessage({ ...value, clientId: client.clientId }), client.privateKey);
    return Buffer.from(signature, "hex").toString("base64url");
  }
}
