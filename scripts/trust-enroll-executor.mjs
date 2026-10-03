#!/usr/bin/env node
// trust-enroll-executor — issue a short-lived executor credential (Design A).
//
// Generates a NEW Ed25519 keypair for one executor, writes the PRIVATE key to an
// out-of-repository directory (fails closed if the path is inside the tree), and
// issues an authority-signed credential using the custody authority bundle's root
// signer. File mode reads --root-key from OUTSIDE the repo; external-root mode
// invokes MNDE_EXTERNAL_ROOT_SIGNER_CMD and never reads root private material.
// No private material is ever written into the repository or echoed to stdout.
//
// Usage:
//   node scripts/trust-enroll-executor.mjs \
//     --executor-id mnde:local:prod:executor:codex:01 \
//     --environment prod \
//     --bundle   /secure/authority-bundle.json \
//     [--root-key /secure/root_private.pem] \
//     --out-dir  /secure/executors \
//     [--capability sign_execution_receipt] [--ttl-hours 24] [--issued-at ISO]
//
// Outputs (in --out-dir): <id>.key (0600), <id>.pub.pem, <id>.credential.json.

import { lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { platform } from "node:os";
import { dirname, join, parse, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { generateAuthorityKeyPair } from "../src/custody/bundle.mjs";
import { issueExecutorCredential, executorKeyId } from "../src/custody/executor-credential.mjs";
import { resolveRootSigner } from "../src/custody/root-signer.mjs";
import {
  isRepoContainedPath,
  readSecureExecutorPrivateKey,
  EXECUTOR_RECEIPT_CAPABILITY
} from "../src/custody/executor-identity.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith("--")) {
      const key = token.slice(2);
      const value = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[(i += 1)] : "true";
      args[key] = value;
    }
  }
  return args;
}

function die(message) {
  console.error(`trust-enroll-executor: ${message}`);
  process.exit(1);
}

function sanitizeFileStem(executorId) {
  return executorId.replace(/[^A-Za-z0-9._-]/g, "_");
}

function comparisonPath(value) {
  const normalized = resolve(value);
  return platform() === "win32" ? normalized.toLowerCase() : normalized;
}

function pathComponents(absolutePath) {
  const root = parse(absolutePath).root;
  const tail = absolutePath.slice(root.length).split(/[\\/]+/u).filter(Boolean);
  const components = [];
  let current = root;
  for (const part of tail) {
    current = join(current, part);
    components.push(current);
  }
  return components;
}

function inspectPathComponents(absolutePath, { allowMissing = false, finalType }) {
  const components = pathComponents(absolutePath);
  for (let index = 0; index < components.length; index += 1) {
    let stats;
    try {
      stats = lstatSync(components[index]);
    } catch (error) {
      if (allowMissing && (error?.code === "ENOENT" || error?.code === "ENOTDIR")) return;
      throw new Error(`cannot inspect ${components[index]}: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (stats.isSymbolicLink()) {
      throw new Error(`path contains a symbolic link, junction, or reparse point: ${components[index]}`);
    }
    const isLast = index === components.length - 1;
    if (!isLast && !stats.isDirectory()) throw new Error(`path parent is not a directory: ${components[index]}`);
    if (isLast && finalType === "directory" && !stats.isDirectory()) throw new Error(`path is not a directory: ${components[index]}`);
    if (isLast && finalType === "file" && !stats.isFile()) throw new Error(`path is not a regular file: ${components[index]}`);
  }
}

function canonicalExternalPath(absolutePath, label) {
  let canonical;
  let canonicalRepoRoot;
  try {
    canonical = realpathSync(absolutePath);
    canonicalRepoRoot = realpathSync(repoRoot);
  } catch (error) {
    throw new Error(`${label} cannot be canonicalized: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (comparisonPath(canonical) !== comparisonPath(absolutePath)) {
    throw new Error(`${label} resolves through a symbolic link, junction, or reparse point`);
  }
  if (isRepoContainedPath(canonical, canonicalRepoRoot)) {
    throw new Error(`${label} resolves inside the repository`);
  }
  return canonical;
}

function prepareExternalOutputDirectory(outDir) {
  const absolute = resolve(outDir);
  if (isRepoContainedPath(absolute, repoRoot)) throw new Error("--out-dir must be OUTSIDE the repository; refusing to write key material into the tree");
  inspectPathComponents(absolute, { allowMissing: true, finalType: "directory" });
  mkdirSync(absolute, { recursive: true, mode: 0o700 });
  inspectPathComponents(absolute, { finalType: "directory" });
  return canonicalExternalPath(absolute, "--out-dir");
}

async function readExternalRootKey(rootKeyPath) {
  const absolute = resolve(rootKeyPath);
  if (isRepoContainedPath(absolute, repoRoot)) throw new Error("--root-key must be OUTSIDE the repository (production root material never lives in the tree)");
  inspectPathComponents(absolute, { finalType: "file" });
  canonicalExternalPath(absolute, "--root-key");
  const result = await readSecureExecutorPrivateKey(absolute, repoRoot);
  if (!result.ok) throw new Error(`--root-key rejected (${result.code}): ${result.detail}`);
  return result.privatePem;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const executorId = args["executor-id"];
  const environment = args.environment;
  const bundlePath = args.bundle;
  const rootKeyPath = args["root-key"];
  const outDir = args["out-dir"];
  const capability = args.capability ?? EXECUTOR_RECEIPT_CAPABILITY;
  const ttlHours = Number(args["ttl-hours"] ?? 24);

  if (!executorId) die("--executor-id is required");
  if (!environment) die("--environment is required");
  if (!bundlePath) die("--bundle is required");
  if (!outDir) die("--out-dir is required");
  if (!Number.isFinite(ttlHours) || ttlHours <= 0) die("--ttl-hours must be a positive number");

  let bundle;
  try {
    bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
  } catch (error) {
    die(`cannot read/parse authority bundle at ${bundlePath}: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (bundle?.schema_version !== "mnde.authority.bundle.v1" || !bundle.root_key) {
    die("bundle is not a valid mnde.authority.bundle.v1");
  }

  let rootSigner;
  try {
    const root = {
      keyId: bundle.root_key.key_id,
      publicPem: bundle.root_key.public_key,
      fingerprint: bundle.root_key.fingerprint
    };
    // Reject mixed external + PEM configuration before the path is inspected or
    // read, ensuring external-root mode cannot silently bring the key in-process.
    const externalRoot = typeof process.env.MNDE_EXTERNAL_ROOT_SIGNER_CMD === "string"
      && process.env.MNDE_EXTERNAL_ROOT_SIGNER_CMD.trim().length > 0;
    if (externalRoot && rootKeyPath) {
      rootSigner = resolveRootSigner({ env: process.env, root, rootPrivateKeyPem: "configured-via--root-key" });
    } else {
      const rootPrivatePem = rootKeyPath ? await readExternalRootKey(rootKeyPath) : undefined;
      rootSigner = resolveRootSigner({ env: process.env, root, rootPrivateKeyPem: rootPrivatePem });
    }
  } catch (error) {
    die(`root signer unavailable (${error?.code ?? "ERR_ROOT_SIGNER"}): ${error instanceof Error ? error.message : String(error)}`);
  }

  let canonicalOutDir;
  try {
    canonicalOutDir = prepareExternalOutputDirectory(outDir);
  } catch (error) {
    die(`unsafe output directory ${outDir}: ${error instanceof Error ? error.message : String(error)}`);
  }

  const issuedAt = args["issued-at"] ?? new Date().toISOString();
  const issuedMs = Date.parse(issuedAt);
  if (Number.isNaN(issuedMs)) die("--issued-at is not a valid timestamp");
  const expiresAt = new Date(issuedMs + ttlHours * 3600 * 1000).toISOString();

  // Generate the executor's OWN keypair. The private key never leaves this host.
  const { publicPem, privatePem } = generateAuthorityKeyPair();

  let credential;
  try {
    credential = await issueExecutorCredential({
      authorityBundle: bundle,
      rootSigner,
      executorId,
      publicPem,
      environmentId: environment,
      capabilities: [capability],
      issuedAt,
      notBefore: issuedAt,
      expiresAt
    });
  } catch (error) {
    die(`issuance failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  const stem = sanitizeFileStem(executorId);
  const keyPath = join(canonicalOutDir, `${stem}.key`);
  const pubPath = join(canonicalOutDir, `${stem}.pub.pem`);
  const credPath = join(canonicalOutDir, `${stem}.credential.json`);

  writeFileSync(keyPath, privatePem, { mode: 0o600, flag: "wx" });
  writeFileSync(pubPath, publicPem, { mode: 0o644, flag: "wx" });
  writeFileSync(credPath, `${JSON.stringify(credential, null, 2)}\n`, { mode: 0o644, flag: "wx" });

  // Summary only — never the private key.
  console.log(JSON.stringify({
    executor_id: executorId,
    key_id: executorKeyId(publicPem),
    credential_id: credential.credential_id,
    environment_id: environment,
    capabilities: credential.capabilities,
    issued_at: issuedAt,
    expires_at: expiresAt,
    private_key_path: keyPath,
    public_key_path: pubPath,
    credential_path: credPath
  }, null, 2));
}

main().catch((error) => die(error instanceof Error ? error.message : String(error)));
