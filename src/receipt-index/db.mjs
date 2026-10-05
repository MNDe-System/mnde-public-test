// SQLite-backed receipt index (node:sqlite, zero dependencies).
//
// The index is DERIVED, DISPOSABLE, and UNTRUSTED. Receipt files remain the
// only canonical artifact. Anything stored here is a lookup accelerator that
// the finder re-verifies against disk at read time. Deleting the DB loses
// nothing: `index --rebuild` regenerates it from the stores.

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

export const INDEX_SCHEMA_VERSION = "mnde.receipt-index.v2";

const CREATE_SQL = `
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS receipts (
  path TEXT NOT NULL,
  line INTEGER NOT NULL DEFAULT -1,
  schema_version TEXT,
  request_hash TEXT,
  request_id TEXT,
  decision TEXT,
  reason_code TEXT,
  tenant_id TEXT,
  actor TEXT,
  tools TEXT NOT NULL DEFAULT '[]',
  region TEXT,
  policy_hash TEXT,
  policy_version TEXT,
  rule_id TEXT,
  key_id TEXT,
  timestamp TEXT,
  cost_micro_usd INTEGER,
  surface TEXT,
  file_size INTEGER,
  file_mtime_ms INTEGER,
  parse_error TEXT,
  PRIMARY KEY (path, line)
);
CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts (timestamp);
CREATE INDEX IF NOT EXISTS idx_receipts_request_hash ON receipts (request_hash);
CREATE INDEX IF NOT EXISTS idx_receipts_request_id ON receipts (request_id);
CREATE INDEX IF NOT EXISTS idx_receipts_decision ON receipts (decision);
CREATE INDEX IF NOT EXISTS idx_receipts_actor ON receipts (actor);
CREATE INDEX IF NOT EXISTS idx_receipts_reason ON receipts (reason_code);
`;

const RULE_ID_INDEX_SQL = "CREATE INDEX IF NOT EXISTS idx_receipts_rule_id ON receipts (rule_id)";

const UPSERT_SQL = `
INSERT INTO receipts (
  path, line, schema_version, request_hash, request_id, decision, reason_code,
  tenant_id, actor, tools, region, policy_hash, policy_version, rule_id, key_id,
  timestamp, cost_micro_usd, surface, file_size, file_mtime_ms, parse_error
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (path, line) DO UPDATE SET
  schema_version = excluded.schema_version,
  request_hash = excluded.request_hash,
  request_id = excluded.request_id,
  decision = excluded.decision,
  reason_code = excluded.reason_code,
  tenant_id = excluded.tenant_id,
  actor = excluded.actor,
  tools = excluded.tools,
  region = excluded.region,
  policy_hash = excluded.policy_hash,
  policy_version = excluded.policy_version,
  rule_id = excluded.rule_id,
  key_id = excluded.key_id,
  timestamp = excluded.timestamp,
  cost_micro_usd = excluded.cost_micro_usd,
  surface = excluded.surface,
  file_size = excluded.file_size,
  file_mtime_ms = excluded.file_mtime_ms,
  parse_error = excluded.parse_error
`;

// Total, deterministic ordering: identical queries over identical stores must
// return byte-identical results. Never add a mutable column to this ordering.
const ORDER_SQL = " ORDER BY timestamp ASC, request_hash ASC, path ASC, line ASC";

const FILTER_COLUMNS = {
  decision: "decision",
  reason_code: "reason_code",
  tenant: "tenant_id",
  actor: "actor",
  request_id: "request_id",
  request_hash: "request_hash",
  policy_hash: "policy_hash",
  policy_version: "policy_version",
  rule_id: "rule_id",
  key_id: "key_id",
  region: "region",
  surface: "surface",
  schema_version: "schema_version"
};

export class QueryInvalidError extends Error {
  constructor(message) {
    super(message);
    this.reason_code = "ERR_RECEIPT_QUERY_INVALID";
  }
}

export class CursorInvalidError extends Error {
  constructor(message) {
    super(message);
    this.reason_code = "ERR_CURSOR_INVALID";
  }
}

export function validateFilters(filters) {
  const normalized = {};
  for (const [key, value] of Object.entries(filters ?? {})) {
    if (value === undefined || value === null) continue;
    if (key in FILTER_COLUMNS || key === "tool") {
      const values = (Array.isArray(value) ? value : [value]).map(String);
      if (values.some((entry) => entry.length === 0)) throw new QueryInvalidError(`empty value for filter: ${key}`);
      normalized[key] = values;
    } else if (["since", "until"].includes(key)) {
      const time = String(value);
      if (Number.isNaN(Date.parse(time))) throw new QueryInvalidError(`invalid timestamp for ${key}: ${time}`);
      normalized[key] = time;
    } else if (["min_cost", "max_cost"].includes(key)) {
      const cost = Number(value);
      if (!Number.isSafeInteger(cost) || cost < 0) throw new QueryInvalidError(`invalid cost for ${key}: ${value}`);
      normalized[key] = cost;
    } else {
      throw new QueryInvalidError(`unknown filter: ${key}`);
    }
  }
  if (normalized.decision) {
    for (const entry of normalized.decision) {
      if (entry !== "ALLOW" && entry !== "REFUSE") throw new QueryInvalidError(`invalid decision: ${entry}`);
    }
  }
  return normalized;
}

function buildWhere(filters) {
  const clauses = [];
  const params = [];
  for (const [key, column] of Object.entries(FILTER_COLUMNS)) {
    const values = filters[key];
    if (!values) continue;
    clauses.push(`${column} IN (${values.map(() => "?").join(", ")})`);
    params.push(...values);
  }
  if (filters.tool) {
    // tools is a JSON array string; match any-of via LIKE on the quoted name.
    clauses.push(`(${filters.tool.map(() => "tools LIKE ?").join(" OR ")})`);
    params.push(...filters.tool.map((tool) => `%"${tool}"%`));
  }
  if (filters.since) {
    clauses.push("timestamp >= ?");
    params.push(filters.since);
  }
  if (filters.until) {
    clauses.push("timestamp <= ?");
    params.push(filters.until);
  }
  if (filters.min_cost !== undefined) {
    clauses.push("cost_micro_usd >= ?");
    params.push(filters.min_cost);
  }
  if (filters.max_cost !== undefined) {
    clauses.push("cost_micro_usd <= ?");
    params.push(filters.max_cost);
  }
  return { where: clauses.length > 0 ? ` WHERE ${clauses.join(" AND ")}` : "", params };
}

export function encodeCursor(row) {
  const tuple = [row.timestamp ?? "", row.request_hash ?? "", row.path, row.line];
  return Buffer.from(JSON.stringify(tuple), "utf8").toString("base64url");
}

export function decodeCursor(cursor) {
  try {
    const tuple = JSON.parse(Buffer.from(cursor, "base64url").toString("utf8"));
    if (!Array.isArray(tuple) || tuple.length !== 4) throw new Error("bad tuple");
    return tuple;
  } catch {
    throw new CursorInvalidError("cursor is not a valid receipt-index cursor");
  }
}

export function openIndex(dbPath) {
  mkdirSync(dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec(CREATE_SQL);
  // v1 databases predate rule_id. Add the nullable column in place before
  // preparing statements or indexes; existing rows remain NULL and retain
  // their original meaning. Reopening is idempotent.
  const columns = db.prepare("PRAGMA table_info(receipts)").all();
  if (!columns.some((column) => column.name === "rule_id")) {
    db.exec("ALTER TABLE receipts ADD COLUMN rule_id TEXT");
  }
  db.exec(RULE_ID_INDEX_SQL);
  const setMeta = db.prepare("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value");
  setMeta.run("index_schema", INDEX_SCHEMA_VERSION);
  const upsert = db.prepare(UPSERT_SQL);

  return {
    upsert(record) {
      const envelope = record.envelope;
      upsert.run(
        record.path,
        record.line,
        envelope.schema_version,
        envelope.request_hash,
        envelope.request_id,
        envelope.decision,
        envelope.reason_code,
        envelope.tenant_id,
        envelope.actor,
        JSON.stringify(envelope.tools ?? []),
        envelope.region,
        envelope.policy_hash,
        envelope.policy_version,
        envelope.rule_id ?? null,
        envelope.key_id,
        envelope.timestamp,
        envelope.cost_micro_usd,
        record.surface,
        record.file_size,
        record.file_mtime_ms,
        record.parse_error
      );
    },

    clear() {
      db.exec("DELETE FROM receipts");
    },

    query(rawFilters, { limit = 100, cursor = null } = {}) {
      const filters = validateFilters(rawFilters);
      const boundedLimit = Math.min(Math.max(1, limit), 1000);
      const { where, params } = buildWhere(filters);
      let sql = `SELECT * FROM receipts${where}`;
      if (cursor !== null) {
        const [ts, hash, path, line] = decodeCursor(cursor);
        sql += `${where ? " AND" : " WHERE"} (timestamp, request_hash, path, line) > (?, ?, ?, ?)`;
        params.push(ts, hash, path, line);
      }
      sql += ORDER_SQL + " LIMIT ?";
      params.push(boundedLimit);
      return db.prepare(sql).all(...params);
    },

    stats(groupBy) {
      const allowed = ["decision", "reason_code", "schema_version", "surface", "tenant_id", "actor"];
      if (!allowed.includes(groupBy)) throw new QueryInvalidError(`invalid group-by: ${groupBy}`);
      return db.prepare(`SELECT ${groupBy} AS value, COUNT(*) AS count FROM receipts GROUP BY ${groupBy} ORDER BY count DESC, value ASC`).all();
    },

    status() {
      const row = db.prepare("SELECT COUNT(*) AS rows_indexed, SUM(CASE WHEN parse_error IS NOT NULL THEN 1 ELSE 0 END) AS parse_failures FROM receipts").get();
      return {
        index_schema: INDEX_SCHEMA_VERSION,
        rows_indexed: row.rows_indexed,
        parse_failures: row.parse_failures ?? 0
      };
    },

    close() {
      db.close();
    }
  };
}
