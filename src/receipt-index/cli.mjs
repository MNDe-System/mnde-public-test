#!/usr/bin/env node
// Receipt search CLI.
//
//   node src/receipt-index/cli.mjs index --rebuild [--root <dir-or-file>]... [--db <file>]
//   node src/receipt-index/cli.mjs find [filters] [--verified-only] [--no-index] [--limit N] [--cursor C] [--format json|table]
//   node src/receipt-index/cli.mjs show --request-hash <hex64> | --path <file> [--line N]
//   node src/receipt-index/cli.mjs stats --group-by decision|reason_code|schema_version|surface|tenant_id|actor
//
// Defaults: roots = ./mnde-receipts, db = <first-root>/.receipt-index/receipts.db
// Verification uses the unified verifier (tools/verify.mjs); pass trust
// material via --authority-bundle / --trusted-root-fingerprint when receipts
// require it. Output is deterministic JSON on stdout; diagnostics on stderr.
//
// Exit codes: 0 ok · 1 error · 2 --verified-only dropped at least one hit

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";

import { openIndex } from "./db.mjs";
import { findReceipts, ingestRoots } from "./find.mjs";

const FILTER_FLAGS = [
  "decision", "reason-code", "tenant", "actor", "tool", "request-id",
  "request-hash", "policy-hash", "policy-version", "rule-id", "key-id", "region",
  "surface", "schema-version", "since", "until", "min-cost", "max-cost"
];

function parse(argv) {
  const options = {
    root: { type: "string", multiple: true },
    db: { type: "string" },
    limit: { type: "string" },
    cursor: { type: "string" },
    format: { type: "string" },
    line: { type: "string" },
    path: { type: "string" },
    "group-by": { type: "string" },
    "verified-only": { type: "boolean" },
    "no-index": { type: "boolean" },
    rebuild: { type: "boolean" },
    sync: { type: "boolean" },
    status: { type: "boolean" },
    "authority-bundle": { type: "string" },
    "trusted-root-fingerprint": { type: "string" }
  };
  for (const flag of FILTER_FLAGS) options[flag] = { type: "string", multiple: true };
  return parseArgs({ args: argv, options, allowPositionals: true });
}

export function filtersFrom(values) {
  const map = {
    decision: "decision", "reason-code": "reason_code", tenant: "tenant", actor: "actor",
    tool: "tool", "request-id": "request_id", "request-hash": "request_hash",
    "policy-hash": "policy_hash", "policy-version": "policy_version", "rule-id": "rule_id", "key-id": "key_id",
    region: "region", surface: "surface", "schema-version": "schema_version"
  };
  const filters = {};
  for (const [flag, key] of Object.entries(map)) {
    if (values[flag]) filters[key] = values[flag].flatMap((entry) => entry.split(","));
  }
  if (values.since) filters.since = values.since[values.since.length - 1];
  if (values.until) filters.until = values.until[values.until.length - 1];
  if (values["min-cost"]) filters.min_cost = Number(values["min-cost"][0]);
  if (values["max-cost"]) filters.max_cost = Number(values["max-cost"][0]);
  return filters;
}

async function loadVerifier(values) {
  const { verifyAnyReceiptObject } = await import("../../tools/verify.mjs");
  const verifyOptions = {};
  if (values["authority-bundle"]) {
    verifyOptions.authorityBundle = JSON.parse(readFileSync(values["authority-bundle"], "utf8"));
  }
  if (values["trusted-root-fingerprint"]) {
    verifyOptions.trustedRootFingerprint = values["trusted-root-fingerprint"];
  }
  return { verify: verifyAnyReceiptObject, verifyOptions };
}

function emit(payload) {
  process.stdout.write(JSON.stringify(payload, null, 2) + "\n");
}

function emitTable(response) {
  const header = ["STATUS", "DECISION", "REASON", "TIMESTAMP", "ACTOR", "REQUEST_ID", "PATH"];
  const rows = response.hits.map((hit) => {
    const receipt = hit.receipt ?? {};
    const output = receipt.decision_output ?? {};
    return [
      hit.verification,
      receipt.decision ?? output.decision ?? "",
      receipt.reason_code ?? output.reason_code ?? "",
      receipt.timestamp ?? output.timestamp ?? "",
      receipt.tenant_id ?? "",
      receipt.execution_id ?? receipt.request_id ?? "",
      hit.provenance.path + (hit.provenance.line !== null ? `:${hit.provenance.line}` : "")
    ].map(String);
  });
  const widths = header.map((title, column) => Math.max(title.length, ...rows.map((row) => row[column].length)));
  const render = (row) => row.map((cell, column) => cell.padEnd(widths[column])).join("  ");
  process.stdout.write(render(header) + "\n");
  for (const row of rows) process.stdout.write(render(row) + "\n");
  process.stdout.write(`\n${response.summary.returned} hits (${response.summary.verified} verified, ${response.summary.tampered} tampered, ${response.summary.unverifiable} unverifiable)\n`);
}

export async function main(argv = process.argv.slice(2)) {
  const { values, positionals } = parse(argv);
  const command = positionals[0];
  const roots = (values.root ?? ["./mnde-receipts"]).map((root) => resolve(root));
  const dbPath = resolve(values.db ?? join(roots[0], ".receipt-index", "receipts.db"));

  if (command === "index") {
    const index = openIndex(dbPath);
    try {
      if (values.status) {
        emit({ ok: true, db: dbPath, ...index.status() });
      } else {
        const counts = ingestRoots(index, roots, { rebuild: values.rebuild === true });
        emit({ ok: true, db: dbPath, mode: values.rebuild ? "rebuild" : "sync", ...counts, ...index.status() });
      }
    } finally {
      index.close();
    }
    return 0;
  }

  if (command === "find" || command === "show") {
    const filters = command === "show"
      ? { request_hash: values["request-hash"] }
      : filtersFrom(values);
    if (command === "show" && values.path) {
      // Direct file lookup needs no index at all.
      const { verify, verifyOptions } = await loadVerifier(values);
      const receipt = JSON.parse(readFileSync(resolve(values.path), "utf8"));
      const result = await verify(receipt, verifyOptions).catch((error) => ({ verified: false, reason: `verifier_error: ${error.message}` }));
      emit({ ok: true, verification: result.verified ? "VERIFIED" : "UNVERIFIED", reason: result.reason ?? null, receipt });
      return 0;
    }
    const { verify, verifyOptions } = await loadVerifier(values);
    const index = values["no-index"] ? null : openIndex(dbPath);
    try {
      const response = await findReceipts({
        index,
        roots,
        filters,
        limit: values.limit ? Number(values.limit) : 100,
        cursor: values.cursor ?? null,
        noIndex: values["no-index"] === true,
        verifiedOnly: values["verified-only"] === true,
        verify,
        verifyOptions
      });
      if (values.format === "table") emitTable(response);
      else emit(response);
      return response.ok ? 0 : 2;
    } finally {
      if (index) index.close();
    }
  }

  if (command === "stats") {
    const index = openIndex(dbPath);
    try {
      const groupBy = values["group-by"] ? values["group-by"] : "decision";
      emit({ ok: true, group_by: groupBy, groups: index.stats(groupBy) });
    } finally {
      index.close();
    }
    return 0;
  }

  process.stderr.write("usage: cli.mjs <index|find|show|stats> [options]  (see file header)\n");
  return 1;
}

if (import.meta.url === new URL(`file:///${process.argv[1].replace(/\\/g, "/")}`).href) {
  main().then(
    (code) => process.exit(code),
    (error) => {
      process.stderr.write(`${error.reason_code ?? "ERR"}: ${error.message}\n`);
      process.exit(1);
    }
  );
}
