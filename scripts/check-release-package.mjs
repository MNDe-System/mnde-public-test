#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));
assert.equal(pkg.name, "mnde");
assert.equal(pkg.version, lock.version);
assert.equal(pkg.dependencies.pg, lock.packages[""].dependencies.pg);
assert.equal(pkg.dependencies.pg, lock.packages["node_modules/pg"].version);
assert.deepEqual(Object.keys(pkg.bin).sort(), ["mnde-git-push", "mnde-hub"]);
for (const target of Object.values(pkg.bin)) assert.ok(existsSync(join(root, target)), `missing entrypoint ${target}`);
for (const forbidden of ["executor", "mcp", "shell", "sidecar", "desktop", "experiments", "dist"]) {
  assert.ok(!existsSync(join(root, forbidden)), `unexpected directory ${forbidden}`);
}
const npmCli = process.env.npm_execpath;
assert.ok(npmCli, "run this check through npm so the package file list can be verified");
const packed = JSON.parse(execFileSync(process.execPath,
  [npmCli, "pack", "--dry-run", "--json", "--ignore-scripts"],
  { cwd: root, encoding: "utf8" }));
const paths = packed[0].files.map(file => file.path);
for (const path of paths) {
  assert.ok(!/^(?:tests|experiments|executor|sidecar|mcp|shell|desktop)\//.test(path), `unwanted package file ${path}`);
  assert.ok(!/(?:receipt_keys|private|\.env$|\.pem\.key$|password|token-file)/i.test(path), `sensitive package file ${path}`);
}
process.stdout.write(`Release package and lockfile are consistent. ${paths.length} packaged files contain no tests or private material.\n`);
