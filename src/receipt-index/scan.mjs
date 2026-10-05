// Receipt store scanner.
//
// Walks an explicit allowlist of receipt roots and yields one record per
// receipt found. Two store shapes exist today and both are supported:
//   - directories of individual *.json receipt files (demos, proxies)
//   - *.jsonl append logs (sidecar receipt persistence queue)
//
// The scanner never throws on a bad file: unparseable content yields a record
// with receipt: null and a parse_error so callers can count it, not lose it.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { basename, extname, join, relative, sep } from "node:path";

const INDEX_DIR_NAME = ".receipt-index";

function safeStat(path) {
  try {
    return statSync(path);
  } catch {
    return null;
  }
}

function surfaceOf(root, filePath) {
  const rel = relative(root, filePath);
  const parts = rel.split(sep);
  return parts.length > 1 ? parts[0] : basename(root);
}

function parseJson(text) {
  try {
    return { value: JSON.parse(text), error: null };
  } catch (error) {
    return { value: null, error: error.message };
  }
}

function* scanJsonFile(root, filePath, st) {
  const { value, error } = parseJson(readFileSync(filePath, "utf8"));
  yield {
    path: filePath,
    line: -1,
    receipt: value,
    parse_error: error,
    surface: surfaceOf(root, filePath),
    file_size: st.size,
    file_mtime_ms: Math.trunc(st.mtimeMs)
  };
}

function* scanJsonlFile(root, filePath, st) {
  const lines = readFileSync(filePath, "utf8").split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const text = lines[i].trim();
    if (text.length === 0) continue;
    const { value, error } = parseJson(text);
    yield {
      path: filePath,
      line: i + 1,
      receipt: value,
      parse_error: error,
      surface: surfaceOf(root, filePath),
      file_size: st.size,
      file_mtime_ms: Math.trunc(st.mtimeMs)
    };
  }
}

function* scanFile(root, filePath, st) {
  const ext = extname(filePath).toLowerCase();
  if (ext === ".json") yield* scanJsonFile(root, filePath, st);
  else if (ext === ".jsonl") yield* scanJsonlFile(root, filePath, st);
}

function* walkDir(root, dir) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  entries.sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    if (entry.name === INDEX_DIR_NAME) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkDir(root, full);
    } else if (entry.isFile()) {
      const st = safeStat(full);
      if (st) yield* scanFile(root, full, st);
    }
  }
}

// Yields { path, line, receipt, parse_error, surface, file_size, file_mtime_ms }.
// line is -1 for whole-file receipts, 1-based for .jsonl entries.
export function* scanRoots(roots) {
  for (const root of roots) {
    const st = safeStat(root);
    if (!st) continue;
    if (st.isFile()) yield* scanFile(root, root, st);
    else if (st.isDirectory()) yield* walkDir(root, root);
  }
}

// Coverage counts for "absence is not evidence" reporting.
export function coverageOf(roots) {
  const coverage = { roots_configured: roots.length, roots_scanned: 0, files_on_disk: 0 };
  for (const root of roots) {
    const st = safeStat(root);
    if (!st) continue;
    coverage.roots_scanned += 1;
    if (st.isFile()) {
      coverage.files_on_disk += 1;
      continue;
    }
    const stack = [root];
    while (stack.length > 0) {
      const dir = stack.pop();
      let entries;
      try {
        entries = readdirSync(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const entry of entries) {
        if (entry.name === INDEX_DIR_NAME) continue;
        const full = join(dir, entry.name);
        if (entry.isDirectory()) stack.push(full);
        else if ([".json", ".jsonl"].includes(extname(entry.name).toLowerCase())) coverage.files_on_disk += 1;
      }
    }
  }
  return coverage;
}
