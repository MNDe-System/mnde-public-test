// Spend witness protocol and executor-side client — the whole-system-rollback half of F-001.
//
// WHY THIS EXISTS. The PostgreSQL claim row and the executor-local ledger
// (local_spent_ledger.mjs) both live inside the rollback domain of the executor
// and its database. Restore both to a moment before a spend and the same
// authorization claims as fresh and pushes again (closure harness scenario W0).
//
// WHAT THIS ADDS. A third record held by a witness in a SEPARATE administrative
// domain that the executor can append to and read, but not rewrite or delete.
// Before any GitHub-changing step the executor asks the witness to CONSUME the
// authorization. The witness is first-writer-wins on both grant id and execution
// id, so a restored executor and database cannot spend a grant twice: the second
// consume is a signed CONFLICT.
//
// PROTOCOL (mnde.spend-witness.v1, JSON over HTTPS)
//   POST /v1/consume   request below   -> 201 CONSUMED | 409 CONFLICT   (signed)
//   GET  /v1/head      ?nonce=…&namespace=…                              (signed)
//   GET  /v1/lookup    ?nonce=…&namespace=…&grant_id=…&execution_id=…    (signed)
//   Authorization: Bearer <executor token>. The server maps a token to exactly one
//   (executor_id, namespace); a request naming another identity is refused.
//
// Every response is signed with the witness's Ed25519 key over
// "mnde.spend-witness.response.v1\n" + canonical JSON, so it cannot be mistaken
// for any other MNDe signed object, and echoes the request nonce, so a recorded
// response cannot be replayed for a later request. The client pins the witness
// public key(s) in trusted configuration; a key a response merely carries is
// never trusted.
//
// THE CLIENT NEVER RETRIES. A consume whose outcome is unknown (timeout, dropped
// connection, bad signature, malformed body) is UNKNOWN: the executor sends
// nothing and an operator reconciles with `lookup`. Re-sending could only be
// safe if the first attempt did not land, which is exactly what is unknown.
//
// WHAT IT DOES NOT DO. It cannot detect a rollback of the witness itself
// (docs/F001-WITNESS-DEPLOYMENT.md "Trust limits"). It is not exactly-once for
// the remote effect: it makes AUTHORITY at-most-once.

import { readFileSync } from "node:fs";
import { request as httpsRequest } from "node:https";
import { isAbsolute } from "node:path";

import { canonicalizeJson } from "../../shared/json.ts";
import { randomBytes, sha256 } from "../crypto/provider.mjs";
import { signCanonical, verifyCanonical } from "../custody/bundle.mjs";
import { inspectSecretFile } from "../effects/git-push/secret-files.mjs";

export const WITNESS_PROTOCOL = "mnde.spend-witness.v1";
export const REQUEST_SCHEMA = "mnde.spend-witness.request.v1";
export const RESPONSE_SCHEMA = "mnde.spend-witness.response.v1";
export const ENTRY_SCHEMA = "mnde.spend-witness.entry.v1";
export const RESPONSE_DOMAIN = "mnde.spend-witness.response.v1\n";

export const WITNESS_DECISION = Object.freeze({
  CONSUMED: "CONSUMED",         // first spend recorded durably; the executor may proceed
  CONFLICT: "CONFLICT",         // already consumed; refuse and treat as rollback evidence
  UNKNOWN: "UNKNOWN",           // outcome not established; send nothing, never retry
  NOT_CONFIGURED: "NOT_CONFIGURED",
  UNAVAILABLE: "UNAVAILABLE"    // preflight only: nothing was consumed
});

export const ERR_WITNESS_CONFIG = "ERR_WITNESS_CONFIG";

const RESPONSE_KEYS_CONSUME = Object.freeze(["aplus_digest", "attempt_id", "entry_digest", "execution_id", "executor_id", "grant_id", "head_hash", "issued_at", "key_id", "n", "namespace", "nonce", "outcome", "schema", "witness_id"]);
const HEX64 = /^[0-9a-f]{64}$/;
const SKEW_MS = 5 * 60 * 1000;

const nonEmpty = (v) => typeof v === "string" && v.length > 0 && v.length <= 512;
const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const hexId = () => randomBytes(16).toString("hex");

export function responseSigningInput(body) {
  return `${RESPONSE_DOMAIN}${canonicalizeJson(body)}`;
}

// The entry the witness appends and the digest that chains it. Exported so the
// server, the client and offline tooling compute the same bytes.
export function entryDigest(entry) {
  return sha256(canonicalizeJson(entry));
}

export async function signResponse(body, privateKeyPem) {
  return { ...body, signature: await signCanonical(responseSigningInput(body), privateKeyPem) };
}

export async function verifyResponse(signed, keys) {
  if (!isObject(signed) || typeof signed.signature !== "string") return { ok: false, reason: "unsigned" };
  const { signature, ...body } = signed;
  const key = keys.find((k) => k.key_id === body.key_id);
  if (!key) return { ok: false, reason: "unknown witness key" };
  let valid = false;
  try { valid = await verifyCanonical(responseSigningInput(body), signature, key.public_key); } catch { valid = false; }
  return valid ? { ok: true, body } : { ok: false, reason: "bad signature" };
}

// ── configuration ───────────────────────────────────────────────────────────
// Trusted deployment configuration only, read by the executor itself. No request
// field can name a witness, a key, a token or a URL.
const CONFIG_KEYS = ["caFile", "timeoutMs", "tokenFile", "url", "witness_id", "witness_keys"];

export function parseWitnessConfig(config) {
  const fail = (detail) => Object.assign(new Error(`${ERR_WITNESS_CONFIG}: ${detail}`), { code: ERR_WITNESS_CONFIG });
  if (!isObject(config)) throw fail("must be a JSON object");
  const extra = Object.keys(config).filter((k) => !CONFIG_KEYS.includes(k));
  if (extra.length) throw fail(`unrecognized field(s): ${extra.join(", ")}`);
  for (const k of ["caFile", "tokenFile", "url", "witness_id"]) if (!nonEmpty(config[k])) throw fail(`${k} is required`);
  if (!isAbsolute(config.caFile) || !isAbsolute(config.tokenFile)) throw fail("caFile and tokenFile must be absolute paths");
  let url;
  try { url = new URL(config.url); } catch { throw fail("url must be a URL"); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
    throw fail("url must be a plain https origin with no credentials, path, query or fragment");
  }
  const timeoutMs = config.timeoutMs ?? 5000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) throw fail("timeoutMs must be 100..60000");
  if (!Array.isArray(config.witness_keys) || config.witness_keys.length === 0 || config.witness_keys.length > 4) throw fail("witness_keys must list 1 to 4 pinned keys");
  for (const k of config.witness_keys) {
    if (!isObject(k) || Object.keys(k).sort().join() !== "key_id,public_key" || !nonEmpty(k.key_id) || !nonEmpty(k.public_key)) throw fail("each witness key is exactly { key_id, public_key }");
  }
  if (new Set(config.witness_keys.map((k) => k.key_id)).size !== config.witness_keys.length) throw fail("witness key ids must be unique");
  return Object.freeze({ ...config, timeoutMs, origin: url.origin });
}

// ── transport ───────────────────────────────────────────────────────────────
function httpCall({ origin, ca, token, timeoutMs }, { method, path, body }) {
  return new Promise((resolve) => {
    const payload = body === undefined ? null : Buffer.from(JSON.stringify(body), "utf8");
    const headers = { accept: "application/json", authorization: `Bearer ${token}` };
    if (payload) { headers["content-type"] = "application/json"; headers["content-length"] = String(payload.length); }
    const req = httpsRequest(new URL(path, origin), { method, ca, headers, timeout: timeoutMs, rejectUnauthorized: true }, (res) => {
      const chunks = [];
      let size = 0;
      res.on("data", (c) => { size += c.length; if (size > 64 * 1024) res.destroy(new Error("response too large")); else chunks.push(c); });
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }));
      res.on("error", (e) => resolve({ error: e }));
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (e) => resolve({ error: e }));
    if (payload) req.write(payload);
    req.end();
  });
}

// ── client ──────────────────────────────────────────────────────────────────
// Opened by the executor from MNDE_WITNESS_CONFIG. Secrets are read per call.
//
// `call` is a TEST SEAM replacing the HTTPS transport with a function
// ({ method, path, body }) => { status, text } | { error }. The executor never passes it
// (openExecutorSpendWitness does not), so production always uses node:https with the pinned CA.
export function openSpendWitness(config, { forbiddenRoots = [], call = null, readFiles = true } = {}) {
  const parsed = parseWitnessConfig(config);
  if (readFiles) {
    const token = inspectSecretFile(parsed.tokenFile, { secret: true, forbiddenRoots });
    if (!token.ok) throw Object.assign(new Error(`${ERR_WITNESS_CONFIG}: tokenFile ${token.detail}`), { code: ERR_WITNESS_CONFIG });
    const ca = inspectSecretFile(parsed.caFile, { secret: false, forbiddenRoots });
    if (!ca.ok) throw Object.assign(new Error(`${ERR_WITNESS_CONFIG}: caFile ${ca.detail}`), { code: ERR_WITNESS_CONFIG });
  }
  const keys = parsed.witness_keys;
  const httpCallOrSeam = (_ignored, req) => (call ? call(req) : httpCall(_ignored, req));

  const transport = () => (call ? {} : {
    origin: parsed.origin, timeoutMs: parsed.timeoutMs,
    ca: readFileSync(parsed.caFile), token: readFileSync(parsed.tokenFile, "utf8").trim()
  });
  const parseBody = (text) => { try { const v = JSON.parse(text); return isObject(v) ? v : null; } catch { return null; } };

  return Object.freeze({
    witness_id: parsed.witness_id,

    // Signed head of the namespace's spend log. Used before the database claim so an
    // unreachable or lying witness refuses BEFORE any authority is spent.
    async preflight({ namespace }) {
      const nonce = hexId();
      const r = await httpCallOrSeam(transport(), { method: "GET", path: `/v1/head?nonce=${nonce}&namespace=${encodeURIComponent(namespace)}` });
      if (r.error || r.status !== 200) return { decision: WITNESS_DECISION.UNAVAILABLE, detail: r.error ? String(r.error.message) : `HTTP ${r.status}` };
      const signed = parseBody(r.text);
      const v = await verifyResponse(signed, keys);
      const b = v.body;
      if (!v.ok || b.schema !== RESPONSE_SCHEMA || b.outcome !== "HEAD" || b.nonce !== nonce || b.witness_id !== parsed.witness_id || b.namespace !== namespace
        || !Number.isInteger(b.n) || b.n < 0 || Math.abs(Date.parse(b.issued_at) - Date.now()) > SKEW_MS) {
        return { decision: WITNESS_DECISION.UNAVAILABLE, detail: v.ok ? "head response failed validation" : v.reason };
      }
      return { decision: "OK", head: { n: b.n, head_hash: b.head_hash } };
    },

    // The irreversible step. First writer wins; never retried.
    async consume({ namespace, grant_id, execution_id, executor_id, receipt_hash, aplus_digest }) {
      const body = {
        schema: REQUEST_SCHEMA, witness_id: parsed.witness_id, namespace, grant_id, execution_id, executor_id,
        receipt_hash, aplus_digest, attempt_id: hexId(), nonce: hexId(), requested_at: new Date().toISOString()
      };
      const r = await httpCallOrSeam(transport(), { method: "POST", path: "/v1/consume", body });
      if (r.error) return { decision: WITNESS_DECISION.UNKNOWN, detail: String(r.error.message) };
      const signed = parseBody(r.text);
      const v = await verifyResponse(signed, keys);
      if (!v.ok) return { decision: WITNESS_DECISION.UNKNOWN, detail: `response rejected: ${v.reason}`, http_status: r.status };
      const b = v.body;
      const echoed = b.schema === RESPONSE_SCHEMA && b.witness_id === parsed.witness_id && b.namespace === namespace
        && b.grant_id === grant_id && b.execution_id === execution_id && b.executor_id === executor_id
        && b.aplus_digest === aplus_digest && b.nonce === body.nonce && b.attempt_id === body.attempt_id
        && Object.keys(b).sort().join() === RESPONSE_KEYS_CONSUME.join()
        && Math.abs(Date.parse(b.issued_at) - Date.now()) <= SKEW_MS;
      if (!echoed) return { decision: WITNESS_DECISION.UNKNOWN, detail: "response does not echo this request", http_status: r.status };
      if (b.outcome === "CONSUMED" && r.status === 201 && Number.isInteger(b.n) && b.n >= 1 && HEX64.test(b.entry_digest) && HEX64.test(b.head_hash)) {
        return { decision: WITNESS_DECISION.CONSUMED, witness: { witness_id: b.witness_id, key_id: b.key_id, n: b.n, entry_digest: b.entry_digest, head_hash: b.head_hash, attempt_id: b.attempt_id, issued_at: b.issued_at } };
      }
      if (b.outcome === "CONFLICT" && r.status === 409) {
        return { decision: WITNESS_DECISION.CONFLICT, witness: { witness_id: b.witness_id, key_id: b.key_id, n: b.n, entry_digest: b.entry_digest, issued_at: b.issued_at } };
      }
      return { decision: WITNESS_DECISION.UNKNOWN, detail: "unrecognized outcome", http_status: r.status };
    },

    // Read-only reconciliation for an operator after UNKNOWN.
    async lookup({ namespace, grant_id, execution_id }) {
      const nonce = hexId();
      const q = new URLSearchParams({ nonce, namespace, grant_id, execution_id });
      const r = await httpCallOrSeam(transport(), { method: "GET", path: `/v1/lookup?${q}` });
      if (r.error || r.status !== 200) return { decision: WITNESS_DECISION.UNKNOWN, detail: r.error ? String(r.error.message) : `HTTP ${r.status}` };
      const v = await verifyResponse(parseBody(r.text), keys);
      if (!v.ok || v.body.nonce !== nonce) return { decision: WITNESS_DECISION.UNKNOWN, detail: "response rejected" };
      return { decision: v.body.outcome, record: v.body };
    }
  });
}

// Executor entry point: MNDE_WITNESS_CONFIG, read by the executor itself.
export function openExecutorSpendWitness(env, { forbiddenRoots = [] } = {}) {
  const path = env?.MNDE_WITNESS_CONFIG;
  if (!nonEmpty(path)) return null;
  if (!isAbsolute(path)) throw Object.assign(new Error(`${ERR_WITNESS_CONFIG}: MNDE_WITNESS_CONFIG must be an absolute path`), { code: ERR_WITNESS_CONFIG });
  const state = inspectSecretFile(path, { secret: false, forbiddenRoots });
  if (!state.ok) throw Object.assign(new Error(`${ERR_WITNESS_CONFIG}: MNDE_WITNESS_CONFIG ${state.detail}`), { code: ERR_WITNESS_CONFIG });
  let config;
  try { config = JSON.parse(readFileSync(path, "utf8")); } catch { throw Object.assign(new Error(`${ERR_WITNESS_CONFIG}: MNDE_WITNESS_CONFIG is not valid JSON`), { code: ERR_WITNESS_CONFIG }); }
  return openSpendWitness(config, { forbiddenRoots });
}
