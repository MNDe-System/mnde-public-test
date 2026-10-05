// Receipt finder: query the index (or scan directly), then re-verify every
// hit against the receipt file on disk at read time.
//
// Trust rules (see docs/RECEIPT_SEARCH_SPEC.md):
//   - The index is untrusted. The file always wins. A poisoned index row can
//     waste time; it can never surface a forged receipt as VERIFIED, and it
//     can never change what a receipt says.
//   - Every hit carries verification: VERIFIED | TAMPERED | UNVERIFIABLE.
//   - Zero results is a statement about the index, not the world: responses
//     always carry coverage counts.

import { readFileSync } from "node:fs";

import { extractEnvelope, isKnownSchema } from "./extract.mjs";
import { coverageOf, scanRoots } from "./scan.mjs";
import { encodeCursor, validateFilters } from "./db.mjs";

export const FIND_SCHEMA_VERSION = "mnde.receipts.find.v1";

const TAMPER_REASON = /signature|hash|tamper|mismatch|replay|integrity/i;

function loadReceiptAt(path, line) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return { receipt: null, missing: true };
  }
  if (line >= 1) {
    const lines = text.split("\n");
    if (line > lines.length) return { receipt: null, missing: true };
    text = lines[line - 1];
  }
  try {
    return { receipt: JSON.parse(text), missing: false };
  } catch {
    return { receipt: null, missing: false, unparseable: true };
  }
}

async function classifyVerification(receipt, verify, verifyOptions) {
  if (!isKnownSchema(receipt?.schema_version)) {
    return { status: "UNVERIFIABLE", reason: "schema_unknown" };
  }
  if (typeof verify !== "function") {
    return { status: "UNVERIFIABLE", reason: "no_verifier_configured" };
  }
  let result;
  try {
    result = await verify(receipt, verifyOptions ?? {});
  } catch (error) {
    return { status: "UNVERIFIABLE", reason: `verifier_error: ${error.message}` };
  }
  if (result?.verified === true) return { status: "VERIFIED", reason: null };
  const reason = result?.reason ?? "unverified";
  return TAMPER_REASON.test(reason)
    ? { status: "TAMPERED", reason }
    : { status: "UNVERIFIABLE", reason };
}

function envelopeMatchesRow(envelope, row) {
  return (
    (envelope.decision ?? null) === (row.decision ?? null) &&
    (envelope.reason_code ?? null) === (row.reason_code ?? null) &&
    (envelope.request_hash ?? null) === (row.request_hash ?? null) &&
    (envelope.schema_version ?? null) === (row.schema_version ?? null) &&
    (envelope.rule_id ?? null) === (row.rule_id ?? null) &&
    (envelope.timestamp ?? null) === (row.timestamp ?? null)
  );
}

function envelopeMatchesFilters(envelope, filters) {
  const anyOf = (values, actual) => values === undefined || values.includes(actual ?? "");
  if (!anyOf(filters.decision, envelope.decision)) return false;
  if (!anyOf(filters.reason_code, envelope.reason_code)) return false;
  if (!anyOf(filters.tenant, envelope.tenant_id)) return false;
  if (!anyOf(filters.actor, envelope.actor)) return false;
  if (!anyOf(filters.request_id, envelope.request_id)) return false;
  if (!anyOf(filters.request_hash, envelope.request_hash)) return false;
  if (!anyOf(filters.policy_hash, envelope.policy_hash)) return false;
  if (!anyOf(filters.policy_version, envelope.policy_version)) return false;
  if (!anyOf(filters.rule_id, envelope.rule_id)) return false;
  if (!anyOf(filters.key_id, envelope.key_id)) return false;
  if (!anyOf(filters.region, envelope.region)) return false;
  if (!anyOf(filters.schema_version, envelope.schema_version)) return false;
  if (filters.tool !== undefined && !filters.tool.some((tool) => (envelope.tools ?? []).includes(tool))) return false;
  if (filters.since !== undefined && !(envelope.timestamp !== null && envelope.timestamp >= filters.since)) return false;
  if (filters.until !== undefined && !(envelope.timestamp !== null && envelope.timestamp <= filters.until)) return false;
  if (filters.min_cost !== undefined && !((envelope.cost_micro_usd ?? -1) >= filters.min_cost)) return false;
  if (filters.max_cost !== undefined && !(envelope.cost_micro_usd !== null && envelope.cost_micro_usd <= filters.max_cost)) return false;
  return true;
}

function rowsFromScan(roots, filters) {
  const rows = [];
  for (const record of scanRoots(roots)) {
    if (record.receipt === null) continue;
    const envelope = extractEnvelope(record.receipt);
    if (!envelopeMatchesFilters(envelope, filters)) continue;
    rows.push({
      path: record.path,
      line: record.line,
      surface: record.surface,
      ...envelope,
      tools: JSON.stringify(envelope.tools)
    });
  }
  rows.sort((a, b) =>
    (a.timestamp ?? "").localeCompare(b.timestamp ?? "") ||
    (a.request_hash ?? "").localeCompare(b.request_hash ?? "") ||
    a.path.localeCompare(b.path) ||
    a.line - b.line
  );
  return rows;
}

// Find receipts. Options:
//   index          — an open index from db.mjs (required unless noIndex)
//   roots          — receipt roots (required; used for coverage and --no-index)
//   filters        — raw filter object (validated here)
//   limit, cursor  — pagination
//   noIndex        — bypass the index, scan roots directly
//   verifiedOnly   — drop non-VERIFIED hits; response.ok=false if any dropped
//   verify         — async (receipt, verifyOptions) => { verified, reason? }
//   verifyOptions  — passed through to verify (trust anchors, bundles, ...)
export async function findReceipts(options) {
  const {
    index = null,
    roots = [],
    filters: rawFilters = {},
    limit = 100,
    cursor = null,
    noIndex = false,
    verifiedOnly = false,
    verify = null,
    verifyOptions = null
  } = options;

  const filters = validateFilters(rawFilters);
  const rows = noIndex
    ? rowsFromScan(roots, filters).slice(0, Math.min(Math.max(1, limit), 1000))
    : index.query(filters, { limit, cursor });

  const hits = [];
  const summary = { returned: 0, verified: 0, tampered: 0, unverifiable: 0, dropped_unverified: 0, index_orphans: 0, index_mismatches: 0 };

  for (const row of rows) {
    const { receipt, missing, unparseable } = loadReceiptAt(row.path, row.line);
    if (missing || unparseable) {
      // Index points at something that no longer exists: the row lied.
      summary.index_orphans += 1;
      continue;
    }

    // The file wins. Re-extract and re-check against the query: a row whose
    // indexed fields diverge from the file (poisoned or stale index) must not
    // smuggle a non-matching receipt into the results.
    const envelope = extractEnvelope(receipt);
    const repaired = !noIndex && !envelopeMatchesRow(envelope, row);
    if (repaired) {
      summary.index_mismatches += 1;
      if (index) index.upsert({ path: row.path, line: row.line, envelope, surface: row.surface, file_size: row.file_size, file_mtime_ms: row.file_mtime_ms, parse_error: null });
      if (!envelopeMatchesFilters(envelope, filters)) continue;
    }

    const verification = await classifyVerification(receipt, verify, verifyOptions);
    if (verification.status === "VERIFIED") summary.verified += 1;
    else if (verification.status === "TAMPERED") summary.tampered += 1;
    else summary.unverifiable += 1;

    if (verifiedOnly && verification.status !== "VERIFIED") {
      summary.dropped_unverified += 1;
      continue;
    }

    hits.push({
      verification: verification.status,
      verification_reason: verification.reason,
      ...(envelope.rule_id !== null ? { rule_id: envelope.rule_id } : {}),
      ...(repaired ? { index_repaired: true } : {}),
      receipt,
      provenance: {
        path: row.path,
        line: row.line >= 1 ? row.line : null,
        surface: row.surface ?? null
      }
    });
  }
  summary.returned = hits.length;

  const indexDirty = summary.index_orphans > 0 || summary.index_mismatches > 0;
  const lastRow = rows.length > 0 ? rows[rows.length - 1] : null;

  return {
    ok: !(verifiedOnly && summary.dropped_unverified > 0),
    schema_version: FIND_SCHEMA_VERSION,
    query: filters,
    hits,
    summary,
    index_dirty: indexDirty,
    coverage: {
      ...coverageOf(roots),
      mode: noIndex ? "direct_scan" : "indexed",
      ...(index && !noIndex ? { rows_indexed: index.status().rows_indexed } : {})
    },
    cursor: lastRow !== null && rows.length >= Math.min(Math.max(1, limit), 1000) ? encodeCursor(lastRow) : null
  };
}

// Rebuild or sync the index from the stores. Returns ingest counts.
export function ingestRoots(index, roots, { rebuild = false } = {}) {
  if (rebuild) index.clear();
  const counts = { indexed: 0, parse_failures: 0 };
  for (const record of scanRoots(roots)) {
    if (record.receipt === null) {
      counts.parse_failures += 1;
      index.upsert({ ...record, envelope: extractEnvelope(null) });
      continue;
    }
    index.upsert({ ...record, envelope: extractEnvelope(record.receipt) });
    counts.indexed += 1;
  }
  return counts;
}
