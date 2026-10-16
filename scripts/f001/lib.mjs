// Shared helpers for the F-001 proof tools. Read-only by construction: nothing in
// scripts/f001 writes to a repository, a ref, a claim store or a credential file.
// Secrets are never printed: callers report credential NAMES and fingerprints of
// public artifacts only.
import { readFileSync } from "node:fs";
import { sha256 } from "../../src/crypto/provider.mjs";

export function parseArgs(argv, spec) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    if (!flag.startsWith("--")) throw new Error(`unexpected argument ${flag}`);
    const name = flag.slice(2);
    const def = spec[name];
    if (!def) throw new Error(`unknown flag --${name}`);
    if (def === "boolean") { out[name] = true; continue; }
    if (argv[i + 1] === undefined) throw new Error(`--${name} needs a value`);
    out[name] = argv[++i];
  }
  return out;
}

export function fileSha256(path) {
  return sha256(readFileSync(path));
}

export const NOT_PROVIDED = "NOT_PROVIDED";

// Every report separates what a tool OBSERVED from what it INFERRED, and lists what
// it could not observe. A report that leaves `cannot_observe` empty should be
// distrusted.
export function report({ tool, observed, inferred = [], cannot_observe = [], ok }) {
  return { tool, generated_at: new Date().toISOString(), ok, observed, inferred, cannot_observe };
}

export function githubHeaders(token) {
  return { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", ...(token ? { authorization: `Bearer ${token}` } : {}) };
}
export async function githubGet(path, token) {
  const response = await fetch(`https://api.github.com${path}`, { headers: githubHeaders(token) });
  const text = await response.text();
  let body = null;
  try { body = JSON.parse(text); } catch { /* leave null */ }
  return { status: response.status, body };
}
