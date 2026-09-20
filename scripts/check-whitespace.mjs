#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const git = spawnSync("git", ["ls-files", "-z"], {
  cwd: repoRoot,
  encoding: "buffer"
});

if (git.error) {
  console.error(git.error.message);
  process.exit(1);
}
if (git.status !== 0) {
  process.stderr.write(git.stderr);
  process.exit(git.status ?? 1);
}

const files = git.stdout.toString("utf8").split("\0").filter(Boolean);
const failures = [];

// Files whose trailing whitespace is content, not sloppiness. Normalising these
// would corrupt them, so they are reported as skipped rather than silently
// ignored — an exclusion nobody can see is an exclusion nobody audits.
//
//   *.patch / *.diff  A unified diff marks a context line with a leading space.
//                     For a blank context line that is the WHOLE line: " ".
//                     Strip it and the patch no longer applies.
//   evidence/**       Verbatim captures of what a tool printed (stdout, test
//                     transcripts). Editing a recorded transcript to look tidy
//                     falsifies the record it exists to be.
function isVerbatimArtifact(file) {
  return /\.(patch|diff)$/.test(file) || /(^|\/)evidence\//.test(file);
}

function isBinary(buffer) {
  return buffer.includes(0);
}

const skipped = [];

for (const file of files) {
  if (isVerbatimArtifact(file)) {
    skipped.push(file);
    continue;
  }
  const buffer = readFileSync(resolve(repoRoot, file));
  if (isBinary(buffer) || buffer.length === 0) continue;

  const text = buffer.toString("utf8");
  const lines = text.split(/\n/);
  lines.forEach((line, index) => {
    const normalized = line.endsWith("\r") ? line.slice(0, -1) : line;
    if (/[ \t]+$/.test(normalized)) {
      failures.push(`${file}:${index + 1}: trailing whitespace`);
    }
  });
  if (!text.endsWith("\n")) {
    failures.push(`${file}: missing final newline`);
  }
}

if (failures.length > 0) {
  console.error("Whitespace check failed:");
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}

console.log(`PASS whitespace check (${files.length - skipped.length} tracked files, ${skipped.length} verbatim artifacts skipped)`);
