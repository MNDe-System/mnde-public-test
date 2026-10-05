import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { randomBytes } from "../crypto/provider.mjs";
import { HUB_ID } from "../hub/pairing-protocol.mjs";
import { privateIp } from "./hub-discovery.mjs";

export function hubTrustPath(env = process.env) {
  return join(env.LOCALAPPDATA || join(homedir(), "AppData", "Local"), "MNDe", "paired-hubs.json");
}

export class HubTrustStore {
  constructor(path = hubTrustPath()) { this.path = path; }
  list() {
    if (!existsSync(this.path)) return [];
    const data = JSON.parse(readFileSync(this.path, "utf8"));
    if (!data || data.version !== 1 || !Array.isArray(data.hubs) || data.hubs.length > 128) throw new Error("ERR_HUB_TRUST_STORE");
    const seen = new Set();
    for (const hub of data.hubs) {
      if (!HUB_ID.test(hub.hubId) || seen.has(hub.hubId) || !privateIp(hub.lastKnownIp)
        || hub.port !== 8790 || !Number.isFinite(Date.parse(hub.pairedAt))
        || (hub.identityPublicKey != null && !/^[A-Za-z0-9_-]{43}$/.test(hub.identityPublicKey))) throw new Error("ERR_HUB_TRUST_STORE");
      seen.add(hub.hubId);
    }
    return data.hubs;
  }
  get(hubId) { return this.list().find(h => h.hubId === hubId) ?? null; }
  save(record) {
    if (!HUB_ID.test(record?.hubId) || !privateIp(record.lastKnownIp) || record.port !== 8790)
      throw new Error("ERR_HUB_TRUST_STORE");
    const hubs = this.list().filter(h => h.hubId !== record.hubId);
    hubs.push({ hubId: record.hubId, lastKnownIp: record.lastKnownIp, port: 8790,
      pairedAt: record.pairedAt, lastAuthenticatedAt: record.lastAuthenticatedAt ?? null,
      identityPublicKey: record.identityPublicKey ?? null });
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    const temp = `${this.path}.${randomBytes(8).toString("hex")}.tmp`;
    writeFileSync(temp, `${JSON.stringify({ version: 1, hubs })}\n`, { flag: "wx", mode: 0o600 });
    renameSync(temp, this.path);
  }
}
