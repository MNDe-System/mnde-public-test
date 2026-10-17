#!/usr/bin/env node
// Reference spend witness (mnde.spend-witness.v1). RUN BY THE WITNESS OPERATOR, ON A
// MACHINE AND UNDER AN ADMINISTRATIVE DOMAIN THE EXECUTOR OPERATOR DOES NOT CONTROL.
// Running it beside the executor proves the mechanism and nothing about independence.
//
//   node deployment/witness/witness-server.mjs /abs/witness-config.json
//
// Config (exact keys):
//   { "host": "0.0.0.0", "port": 8443, "data_dir": "/abs/dir (0700)", "witness_id": "…",
//     "key_id": "…", "key_file": "/abs/ed25519-private.pem (0600)",
//     "tls_cert_file": "/abs/cert.pem", "tls_key_file": "/abs/key.pem",
//     "tokens_file": "/abs/tokens.json" }
//   tokens.json: { "<sha256 hex of token>": { "executor_id": "…", "namespace": "…" } }
//   Tokens are stored hashed, so a copy of this file does not let anyone consume.
//
// STATE. One append-only file, spend-log.jsonl: one line per consumed authorization,
// each `{ entry, entry_digest }`, where entry.prev_hash is the previous entry_digest
// (a hash chain). A line is written and fsynced BEFORE the 201 is sent, and the
// directory entry is fsynced when the log is created. The server has no delete,
// update or overwrite code path. It refuses to start if the log does not verify
// (broken chain, bad digest, duplicate id, torn line); an operator investigates, the
// server never repairs a log by itself. A single-process lock file prevents two
// servers writing one log.
//
// SEMANTICS. Uniqueness is per (namespace, grant_id) and per (namespace,
// execution_id). The check and the append happen with no await between them, so one
// process serializes them; the lock file makes that the only process.
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { createServer } from "node:https";
import { isAbsolute, join } from "node:path";

import { canonicalizeJson } from "../../shared/json.ts";
import { sha256 } from "../../src/crypto/provider.mjs";
import {
  ENTRY_SCHEMA, REQUEST_SCHEMA, RESPONSE_SCHEMA, WITNESS_PROTOCOL, entryDigest, signResponse
} from "../../src/freshness/spend_witness.mjs";

const GENESIS = "0".repeat(64);
const REQ_KEYS = ["aplus_digest", "attempt_id", "execution_id", "executor_id", "grant_id", "namespace", "nonce", "receipt_hash", "requested_at", "schema", "witness_id"];
const nonEmpty = (v) => typeof v === "string" && v.length > 0 && v.length <= 512;
const HEX = /^[0-9a-f]{32,64}$/;

export function openWitnessLog(dataDir) {
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const logPath = join(dataDir, "spend-log.jsonl");
  const lockPath = join(dataDir, "witness.lock");
  const created = !existsSync(logPath);
  let lock;
  const take = () => { lock = openSync(lockPath, "wx", 0o600); writeSync(lock, String(process.pid)); };
  try { take(); }
  catch {
    // A lock whose owner is gone (the witness was killed or the machine lost power) is taken over;
    // one whose owner is alive is never touched. The log itself is re-verified below either way.
    let alive = true;
    try { process.kill(Number(readFileSync(lockPath, "utf8")), 0); } catch (e) { alive = e?.code === "EPERM"; }
    if (alive) throw new Error("ERR_WITNESS_LOCKED: another witness process holds this data directory");
    unlinkSync(lockPath);
    try { take(); } catch { throw new Error("ERR_WITNESS_LOCKED: could not take over a stale lock"); }
  }
  let fd = null;
  const release = () => { try { if (fd !== null) closeSync(fd); } catch { /* */ } try { closeSync(lock); } catch { /* */ } try { unlinkSync(lockPath); } catch { /* */ } };
  const byGrant = new Map(), byExec = new Map();
  let n = 0, head = GENESIS;
  try {
    fd = openSync(logPath, "a", 0o600);
    if (created) { const d = openSync(dataDir, "r"); try { fsyncSync(d); } finally { closeSync(d); } }
    const text = readFileSync(logPath, "utf8");
    if (text.length && !text.endsWith("\n")) throw new Error("ERR_WITNESS_LOG_CORRUPT: torn final line");
    for (const line of text.split("\n").filter(Boolean)) {
      let rec;
      try { rec = JSON.parse(line); } catch { throw new Error("ERR_WITNESS_LOG_CORRUPT: unparseable line"); }
      const e = rec.entry;
      if (!e || e.schema !== ENTRY_SCHEMA || e.n !== n + 1 || e.prev_hash !== head || rec.entry_digest !== entryDigest(e)) throw new Error(`ERR_WITNESS_LOG_CORRUPT: entry ${n + 1} does not chain`);
      const gk = `${e.namespace}\n${e.grant_id}`, xk = `${e.namespace}\n${e.execution_id}`;
      if (byGrant.has(gk) || byExec.has(xk)) throw new Error(`ERR_WITNESS_LOG_CORRUPT: entry ${e.n} repeats an identifier`);
      byGrant.set(gk, rec); byExec.set(xk, rec);
      n = e.n; head = rec.entry_digest;
    }
  } catch (error) {
    release(); // a log that does not verify must not leave the data directory locked
    throw error;
  }

  return {
    head: () => ({ n, head_hash: head }),
    find: (ns, grant, exec) => byGrant.get(`${ns}\n${grant}`) ?? byExec.get(`${ns}\n${exec}`) ?? null,
    // Atomic: no await between the uniqueness check and the durable append.
    consume(fields) {
      const prior = byGrant.get(`${fields.namespace}\n${fields.grant_id}`) ?? byExec.get(`${fields.namespace}\n${fields.execution_id}`);
      if (prior) return { conflict: true, prior };
      const entry = { schema: ENTRY_SCHEMA, n: n + 1, prev_hash: head, ...fields, consumed_at: new Date().toISOString() };
      const rec = { entry, entry_digest: entryDigest(entry) };
      writeSync(fd, `${JSON.stringify(rec)}\n`);
      fsyncSync(fd);                       // durable before anyone is told CONSUMED
      byGrant.set(`${fields.namespace}\n${fields.grant_id}`, rec);
      byExec.set(`${fields.namespace}\n${fields.execution_id}`, rec);
      n = entry.n; head = rec.entry_digest;
      return { conflict: false, rec };
    },
    close: release
  };
}

// The whole protocol as a pure async function: no sockets, no TLS. The HTTPS listener below
// and the in-process tests both drive exactly this, so there is one implementation.
export function createWitnessApp({ log, witnessId, keyId, keyPem, tokens }) {
  const respond = async (status, body) => {
    const signed = await signResponse({ ...body, schema: RESPONSE_SCHEMA, witness_id: witnessId, key_id: keyId, issued_at: new Date().toISOString() }, keyPem);
    return { status, text: JSON.stringify(signed) };
  };
  const plain = (status) => ({ status, text: "{}" });
  return async function handle({ method, url: rawUrl, authorization, bodyBuffer }) {
    try {
      const m = /^Bearer (\S+)$/.exec(authorization ?? "");
      const who = m ? tokens[sha256(m[1])] ?? null : null;
      if (!who) return plain(401);
      const url = new URL(rawUrl, "https://witness.invalid");
      if (method === "GET" && url.pathname === "/v1/head") {
        const ns = url.searchParams.get("namespace"), nonce = url.searchParams.get("nonce");
        if (ns !== who.namespace || !HEX.test(nonce ?? "")) return plain(403);
        return respond(200, { outcome: "HEAD", namespace: ns, nonce, ...log.head() });
      }
      if (method === "GET" && url.pathname === "/v1/lookup") {
        const ns = url.searchParams.get("namespace"), nonce = url.searchParams.get("nonce");
        const grant = url.searchParams.get("grant_id"), exec = url.searchParams.get("execution_id");
        if (ns !== who.namespace || !HEX.test(nonce ?? "") || !nonEmpty(grant) || !nonEmpty(exec)) return plain(403);
        const prior = log.find(ns, grant, exec);
        return respond(200, prior
          ? { outcome: "FOUND", namespace: ns, nonce, grant_id: prior.entry.grant_id, execution_id: prior.entry.execution_id, n: prior.entry.n, entry_digest: prior.entry_digest, executor_id: prior.entry.executor_id, aplus_digest: prior.entry.aplus_digest }
          : { outcome: "NOT_FOUND", namespace: ns, nonce, n: log.head().n, head_hash: log.head().head_hash });
      }
      if (method === "POST" && url.pathname === "/v1/consume") {
        if (!bodyBuffer || bodyBuffer.length > 8192) return plain(413);
        let b;
        try { b = JSON.parse(bodyBuffer.toString("utf8")); } catch { return plain(400); }
        if (!b || typeof b !== "object" || Object.keys(b).sort().join() !== REQ_KEYS.join() || b.schema !== REQUEST_SCHEMA
          || REQ_KEYS.some((k) => !nonEmpty(b[k])) || !HEX.test(b.nonce) || !HEX.test(b.attempt_id) || !/^[0-9a-f]{64}$/.test(b.aplus_digest)) return plain(400);
        if (b.witness_id !== witnessId) return plain(400);
        if (b.executor_id !== who.executor_id || b.namespace !== who.namespace) return plain(403); // identity substitution
        const fields = { namespace: b.namespace, grant_id: b.grant_id, execution_id: b.execution_id, executor_id: b.executor_id, receipt_hash: b.receipt_hash, aplus_digest: b.aplus_digest, attempt_id: b.attempt_id };
        const out = log.consume(fields);
        const echo = { namespace: b.namespace, grant_id: b.grant_id, execution_id: b.execution_id, executor_id: b.executor_id, aplus_digest: b.aplus_digest, attempt_id: b.attempt_id, nonce: b.nonce };
        if (out.conflict) return respond(409, { ...echo, outcome: "CONFLICT", n: out.prior.entry.n, entry_digest: out.prior.entry_digest, head_hash: log.head().head_hash });
        return respond(201, { ...echo, outcome: "CONSUMED", n: out.rec.entry.n, entry_digest: out.rec.entry_digest, head_hash: out.rec.entry_digest });
      }
      return plain(404);
    } catch { return plain(500); }
  };
}

export async function startWitnessServer({ host = "127.0.0.1", port = 0, dataDir, witnessId, keyId, keyPem, cert, key, tokens }) {
  const log = openWitnessLog(dataDir);
  const app = createWitnessApp({ log, witnessId, keyId, keyPem, tokens });
  const server = createServer({ cert, key, minVersion: "TLSv1.2" }, async (req, res) => {
    const chunks = []; let size = 0;
    for await (const c of req) { size += c.length; if (size > 8192) { res.writeHead(413); return res.end("{}"); } chunks.push(c); }
    const out = await app({ method: req.method, url: req.url, authorization: req.headers.authorization, bodyBuffer: Buffer.concat(chunks) });
    res.writeHead(out.status, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(out.text);
  });
  server.requestTimeout = 10_000; server.headersTimeout = 5_000; server.maxConnections = 64;
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, resolve); });
  return {
    protocol: WITNESS_PROTOCOL, port: server.address().port, head: () => log.head(),
    close: () => new Promise((r) => { server.closeAllConnections(); server.close(() => { log.close(); r(); }); })
  };
}

// ── CLI ─────────────────────────────────────────────────────────────────────
if (import.meta.url === `file://${process.argv[1]}`) {
  const path = process.argv[2];
  if (!path || !isAbsolute(path)) { console.error("usage: witness-server.mjs /abs/witness-config.json"); process.exit(2); }
  const c = JSON.parse(readFileSync(path, "utf8"));
  const keys = ["host", "port", "data_dir", "witness_id", "key_id", "key_file", "tls_cert_file", "tls_key_file", "tokens_file"];
  if (Object.keys(c).sort().join() !== [...keys].sort().join() || ![c.data_dir, c.key_file, c.tls_cert_file, c.tls_key_file, c.tokens_file].every(isAbsolute)) { console.error("invalid witness config"); process.exit(2); }
  const s = await startWitnessServer({ host: c.host, port: c.port, dataDir: c.data_dir, witnessId: c.witness_id, keyId: c.key_id,
    keyPem: readFileSync(c.key_file, "utf8"), cert: readFileSync(c.tls_cert_file), key: readFileSync(c.tls_key_file), tokens: JSON.parse(readFileSync(c.tokens_file, "utf8")) });
  console.log(JSON.stringify({ event: "witness.started", protocol: s.protocol, port: s.port, head: s.head() }));
  for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, async () => { await s.close(); process.exit(0); });
}
