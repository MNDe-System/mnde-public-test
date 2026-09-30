// Hub metadata is not execution authority. PostgreSQL remains the claim store.
import { closeSync, fsyncSync, lstatSync, openSync, readFileSync, renameSync, writeFileSync, readdirSync } from "node:fs";
import { join, isAbsolute } from "node:path";
import { randomBytes } from "../crypto/provider.mjs";

// A failed durable lock write must never leave this process able to execute.
// This is a refusal-only latch, not a claim store or an authority/replay cache.
const lockVeto = new Set();

export function randomId() {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function durableWrite(path, value) {
  const temporary = `${path}.${randomId()}.tmp`;
  const fd = openSync(temporary, "wx", 0o600);
  try { writeFileSync(fd, JSON.stringify(value)); fsyncSync(fd); }
  finally { closeSync(fd); }
  renameSync(temporary, path);
  // Windows cannot open a directory for fsync. Pi/Linux must acknowledge it.
  if (process.platform !== "win32") {
    const dir = openSync(join(path, ".."), "r");
    try { fsyncSync(dir); } finally { closeSync(dir); }
  }
}

export function readInterlock(dataDir) {
  if (!dataDir) return null; // Existing non-Hub callers retain their behavior.
  if (lockVeto.has(dataDir)) return false;
  try {
    const state = JSON.parse(readFileSync(join(dataDir, "lock.json"), "utf8"));
    if (state.locked !== false || typeof state.epoch !== "string" || !/^[0-9a-f-]{36}$/.test(state.epoch)) return false;
    return state.epoch;
  } catch { return false; }
}

export function openHubState(dataDir) {
  if (!isAbsolute(dataDir)) throw new Error("ERR_HUB_STORAGE");
  // Provision/mount the directory first. Never silently create a fallback on SD.
  const stat = lstatSync(dataDir);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("ERR_HUB_STORAGE");
  if (process.platform !== "win32" && (stat.mode & 0o077)) throw new Error("ERR_HUB_STORAGE_PERMISSIONS");
  const device = stat.dev, inode = stat.ino;
  const check = () => {
    const current = lstatSync(dataDir);
    if (current.dev !== device || current.ino !== inode) throw new Error("ERR_HUB_STORAGE_CHANGED");
  };
  const write = (name, value) => { check(); durableWrite(join(dataDir, name), value); };
  const lock = (locked) => {
    lockVeto.add(dataDir);
    write("lock.json", { locked, epoch: randomId() });
    if (!locked) lockVeto.delete(dataDir);
  };
  lock(true); // Every process boot requires an explicit authenticated unlock.
  const file = (id) => {
    if (!/^[0-9a-f-]{36}$/.test(id)) throw new Error("ERR_HUB_ID");
    return `action-${id}.json`;
  };
  return Object.freeze({
    lock,
    locked: () => { check(); return readInterlock(dataDir) === false; },
    probe: () => { write("storage-probe.json", { at: new Date().toISOString() }); return true; },
    save: (record) => write(file(record.id), record),
    read: (id) => { check(); return JSON.parse(readFileSync(join(dataDir, file(id)), "utf8")); },
    list: () => { check(); return readdirSync(dataDir).filter(n => /^action-[0-9a-f-]{36}\.json$/.test(n)).sort().reverse().slice(0, 100).map(n => n.slice(7, -5)); }
  });
}
