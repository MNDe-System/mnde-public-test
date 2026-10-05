// Canonical-path repository containment check (F4).
//
// Authority initialization must never write crown-jewel private material inside
// the MNDe repository — including through a path alias: relative traversal,
// trailing separators, Windows drive-letter / directory casing, or an existing
// symlink / junction whose real target lands in the repo. A textual prefix
// comparison is insufficient (it misses casing and symlinks, and it can false-
// positive on siblings like `<repo>-backup`).
//
// This module resolves real filesystem paths — realpath on the nearest existing
// ancestor for a destination that does not exist yet — and compares with
// path-relative, component-aware semantics. It never creates the destination.
//
// Platform note: path.relative uses the running platform's semantics, so on
// Windows drive-letter and directory casing are already compared case-insensitively
// and realpath returns the canonical on-disk casing. The helper is therefore
// correct on the platform it runs on; platform-specific behaviors (junctions,
// drive letters) are exercised by tests that skip cleanly off that platform.

import { existsSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

// Resolve `p` to a canonical absolute path without creating anything. For a path
// that does not yet exist, walk up to the nearest existing ancestor, realpath
// THAT (resolving symlinks / junctions / drive-letter casing against the real
// filesystem), then re-append the still-nonexistent suffix.
export function canonicalizeForContainment(p) {
  const abs = resolve(p);
  const suffix = [];
  let cur = abs;
  while (!existsSync(cur)) {
    suffix.unshift(basename(cur));
    const parent = dirname(cur);
    if (parent === cur) return abs; // reached a root that does not exist; use the resolved form
    cur = parent;
  }
  let realBase;
  try {
    realBase = realpathSync.native(cur);
  } catch {
    realBase = cur; // realpath can fail on exotic mounts; fall back to the resolved ancestor
  }
  return suffix.length > 0 ? join(realBase, ...suffix) : realBase;
}

// True if `candidate` is the repository root itself, or lives inside it, after
// canonical path resolution. Uses path.relative so a sibling that merely shares a
// textual prefix (`<repo>-backup`) and a different drive are both treated as
// OUTSIDE, while casing/alias variants that resolve into the repo are INSIDE.
export function isRepoContained(candidate, repoRoot) {
  const canonCandidate = canonicalizeForContainment(candidate);
  const canonRoot = canonicalizeForContainment(repoRoot);
  const rel = relative(canonRoot, canonCandidate);
  if (rel === "") return true; // same directory as the repo root
  // Outside iff the relative path escapes upward (starts with "..") or is absolute
  // (a different drive on Windows yields an absolute relative path).
  if (rel === ".." || rel.startsWith(".." + sep) || isAbsolute(rel)) return false;
  return true;
}
