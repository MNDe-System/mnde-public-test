import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "dist");
const directories = ["arm", "audit", "brand", "conformance", "cosmetic", "desktop", "docs", "executor", "orbit", "preflight", "ram0na", "sample-policies", "shared", "sidecar", "shell", "src", "verifier"];
const files = ["mnde-local-sidecar.mjs", "package.json", "package-lock.json", ".env.example", "LICENSE", "README.md", "scripts/start-app.mjs", "scripts/start-sidecar.mjs", "scripts/bootstrap_dev_receipt_keys.mjs"];

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
for (const name of directories) {
  if (!existsSync(join(root, name))) throw new Error(`Missing source directory: ${name}`);
  cpSync(join(root, name), join(out, name), { recursive: true, filter: path => {
    const relativePath = path.slice(root.length).replaceAll("\\", "/");
    return !/(^|\/)(receipt_keys|\.mnde-test|node_modules|dist|authority|mnde-receipts)(\/|$)/.test(relativePath)
      && !/\.(pem|key|dpapi)$/i.test(path) && !/(client-identity|paired-hubs|hub-pairing|paired-clients)\.json$/i.test(path);
  } });
}
for (const name of files) {
  if (!existsSync(join(root, name))) throw new Error(`Missing source file: ${name}`);
  mkdirSync(dirname(join(out, name)), { recursive: true });
  cpSync(join(root, name), join(out, name));
}

// Verify literal relative source imports in the portable build. Node handles .ts on Node 24.
const checked = new Set();
function check(path) {
  if (checked.has(path)) return;
  checked.add(path);
  const source = readFileSync(path, "utf8");
  for (const match of source.matchAll(/(?:\bfrom\s*|\bimport\s*\(|\bnew URL\s*\()\s*["'](\.\.?\/[^"']+)["']/g)) {
    // Receipt signing keys are generated under MNDE_HOME on first launch.
    if (match[1].includes("receipt_keys/")) continue;
    const target = resolve(dirname(path), match[1]);
    if (!existsSync(target) || !statSync(target).isFile()) throw new Error(`Unresolved source dependency: ${path} -> ${match[1]}`);
    if (/\.(mjs|ts)$/.test(target)) check(target);
  }
}
check(join(out, "scripts", "start-app.mjs"));
check(join(out, "mnde-local-sidecar.mjs"));
console.log(`Built portable source in ${out}; checked ${checked.size} runtime dependencies.`);
