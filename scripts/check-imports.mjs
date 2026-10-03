#!/usr/bin/env node
import { builtinModules, createRequire } from "node:module";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
const builtins = new Set(builtinModules.map(name => name.replace(/^node:/, "")));
const roots = ["arm", "bin", "deployment", "orbit", "preflight", "ram0na", "scripts", "shared", "src", "tests", "tools"];
const failures = [];
let files = 0;
let edges = 0;

function visit(path) {
  if (statSync(path).isDirectory()) {
    for (const name of readdirSync(path)) visit(join(path, name));
    return;
  }
  if (!/\.(?:mjs|js|ts)$/.test(path)) return;
  files += 1;
  const source = readFileSync(path, "utf8");
  const specs = [...source.matchAll(/(?:\b(?:import|export)\s+(?:[^'";]*?\s+from\s*)?|\bimport\s*\()\s*["']([^"']+)["']/gs)].map(match => match[1]);
  for (const spec of specs) {
    edges += 1;
    if (spec.startsWith("node:") || builtins.has(spec)) continue;
    if (spec.startsWith(".")) {
      const target = resolve(dirname(path), spec);
      if (!existsSync(target)) failures.push(`${relative(root, path)} -> ${spec} (missing)`);
      if (!target.startsWith(root)) failures.push(`${relative(root, path)} -> ${spec} (outside release)`);
      if (!path.includes(`${join(root, "tests")}`) && target.includes(`${join(root, "tests")}`)) failures.push(`${relative(root, path)} -> ${spec} (production to test)`);
    } else {
      try { require.resolve(spec); } catch { failures.push(`${relative(root, path)} -> ${spec} (undeclared or missing package)`); }
    }
  }
}

for (const dir of roots) if (existsSync(join(root, dir))) visit(join(root, dir));
process.stdout.write(`Checked ${files} code files and ${edges} import references.\n`);
if (failures.length) {
  for (const failure of failures) process.stderr.write(`${failure}\n`);
  process.exitCode = 1;
}
