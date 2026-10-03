#!/usr/bin/env node
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyAnyReceiptFile } from "../tools/verify.mjs";
import { activateSignedPolicyBundle } from "../src/policy-bundles/index.mjs";
import { sha256 } from "../src/crypto/provider.mjs";
import { verifyAuthorityBundle } from "../src/custody/index.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const conformanceRoot = join(repoRoot, "conformance");
const manifestPath = join(conformanceRoot, "manifest.json");
const manifestLockPath = join(conformanceRoot, "manifest.lock.json");
const attributesPath = join(repoRoot, ".gitattributes");
const requiredSchemas = new Set([
  "ecs.receipt.v2",
  "mnde.pe.receipt.v1",
  "mnde.pe.receipt.v2",
  "mnde.signed-receipt.v1",
  "mnde.authority.bundle.v1",
  "mnde.policy.bundle.v1"
]);

function sha256Hex(raw) {
  return sha256(raw);
}

assert.equal(existsSync(manifestPath), true, "conformance/manifest.json is missing");
assert.equal(existsSync(attributesPath), true, ".gitattributes is missing");
const attributes = readFileSync(attributesPath, "utf8");
assert.match(attributes, /^\*\s+text=auto\s+eol=lf$/m, ".gitattributes must force LF for text files");
assert.match(attributes, /^conformance\/\*\*\s+text\s+eol=lf$/m, ".gitattributes must force LF for conformance files");

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
assert.equal(manifest.schema_version, "mnde.conformance.manifest.v1");
assert.ok(Array.isArray(manifest.vectors), "manifest.vectors must be an array");
assert.equal(typeof manifest.trust_roots?.conformance_authority, "string");
assert.match(manifest.trust_roots.conformance_authority, /^[a-f0-9]{64}$/);
assert.equal(typeof manifest.trust_roots?.conformance_authority_v2, "string");
assert.match(manifest.trust_roots.conformance_authority_v2, /^[a-f0-9]{64}$/);

assert.equal(existsSync(manifestLockPath), true, "conformance/manifest.lock.json is missing");
const manifestLock = JSON.parse(readFileSync(manifestLockPath, "utf8"));
assert.equal(manifestLock.schema_version, "mnde.conformance.lock.v1");
assert.deepEqual(
  {
    conformance_authority: manifest.trust_roots.conformance_authority,
    conformance_authority_v2: manifest.trust_roots.conformance_authority_v2,
    vectors: manifest.vectors.map((vector) => ({
      id: vector.id,
      schema_version: vector.schema_version,
      path: vector.path,
      sha256: vector.sha256,
      ...(vector.expected_kind ? { expected_kind: vector.expected_kind } : {})
    }))
  },
  manifestLock.approved,
  "conformance manifest root and vector hashes must match manifest.lock.json"
);

const bySchema = new Map();
const byId = new Map();
for (const vector of manifest.vectors) {
  assert.equal(typeof vector.path, "string", "vector.path is required");
  assert.equal(typeof vector.sha256, "string", `${vector.path} sha256 is required`);
  assert.match(vector.sha256, /^[a-f0-9]{64}$/);

  const filePath = join(conformanceRoot, vector.path);
  assert.equal(existsSync(filePath), true, `${vector.path} is missing`);
  const raw = readFileSync(filePath, "utf8");
  assert.equal(sha256Hex(raw), vector.sha256, `${vector.path} hash drifted`);
  assert.equal(raw.includes("\r\n"), false, `${vector.path} must be LF-only in the working tree`);
  if (raw.includes("\n")) {
    assert.notEqual(sha256Hex(raw.replaceAll("\n", "\r\n")), vector.sha256, `${vector.path} CRLF drift must be detected`);
  }

  const parsed = JSON.parse(raw);
  assert.equal(parsed.schema_version, vector.schema_version, `${vector.path} schema mismatch`);
  assert.equal(raw, `${JSON.stringify(parsed, null, 2)}\n`, `${vector.path} must remain pretty-printed with a final newline`);
  const entry = { ...vector, filePath, parsed };
  assert.equal(byId.has(vector.id), false, `duplicate conformance vector id ${vector.id}`);
  byId.set(vector.id, entry);
  // First vector for a schema wins so the canonical v1 authority bundle is not
  // shadowed by the v2 authority bundle (both use schema mnde.authority.bundle.v1).
  // Version-specific lookups below go through byId, not bySchema.
  if (!bySchema.has(vector.schema_version)) bySchema.set(vector.schema_version, entry);
}

for (const schema of requiredSchemas) {
  assert.equal(bySchema.has(schema), true, `missing conformance vector for ${schema}`);
}

const authorityVector = bySchema.get("mnde.authority.bundle.v1");
const authorityBundle = authorityVector.parsed;
const rootFingerprint = manifest.trust_roots.conformance_authority;
assert.equal((await verifyAuthorityBundle(authorityBundle, { trustedRootFingerprint: rootFingerprint })).ok, true);

const policyVector = bySchema.get("mnde.policy.bundle.v1");
const stateDir = mkdtempSync(join(tmpdir(), "mnde-conformance-policy-"));
try {
  const activation = await activateSignedPolicyBundle({
    bundle: policyVector.parsed,
    authorityBundle,
    trustedRootFingerprint: rootFingerprint,
    statePath: join(stateDir, "policy-state.json"),
    now: "2026-06-25T00:00:00.000Z"
  });
  assert.equal(activation.ok, true, activation.reason);
} finally {
  rmSync(stateDir, { recursive: true, force: true });
}

const sharedReceiptOptions = {
  authorityBundle,
  trustedRootFingerprint: rootFingerprint,
  historicalPolicyBundle: policyVector.parsed,
  policyAuthorityBundle: authorityBundle,
  policyTrustedRootFingerprint: rootFingerprint,
  now: "2026-06-25T00:00:00.000Z"
};

for (const schema of ["ecs.receipt.v2", "mnde.pe.receipt.v1", "mnde.signed-receipt.v1"]) {
  const vector = bySchema.get(schema);
  const result = await verifyAnyReceiptFile(vector.filePath, sharedReceiptOptions);
  assert.equal(result.verified, true, `${schema} failed conformance verification: ${result.reason ?? "unknown"}`);
  assert.equal(result.kind, vector.expected_kind, `${schema} verifier kind drifted`);
}

// mnde.pe.receipt.v2 is a NEW frozen format that binds rule_id into decision_hash.
// It is signed by its own dedicated conformance authority (mnde-conformance-authority-v2)
// and verified against that authority's independently-pinned root — the same
// root-pinned offline path as v1, under a distinct trust anchor. The frozen v1
// vectors above are verified with the original conformance authority, untouched.
const v2Root = manifest.trust_roots.conformance_authority_v2;
const v2Bundle = byId.get("mnde-authority-bundle-v2").parsed;
assert.equal(
  (await verifyAuthorityBundle(v2Bundle, { trustedRootFingerprint: v2Root, now: "2026-06-25T00:00:00.000Z" })).ok,
  true,
  "v2 authority bundle must verify against its pinned root"
);
const v2ReceiptVector = byId.get("mnde-pe-receipt-v2-allow");
const v2Result = await verifyAnyReceiptFile(v2ReceiptVector.filePath, {
  authorityBundle: v2Bundle,
  trustedRootFingerprint: v2Root,
  now: "2026-06-25T00:00:00.000Z"
});
assert.equal(v2Result.verified, true, `mnde.pe.receipt.v2 failed conformance verification: ${v2Result.reason ?? "unknown"}`);
assert.equal(v2Result.kind, v2ReceiptVector.expected_kind, "mnde.pe.receipt.v2 verifier kind drifted");

console.log(`PASS conformance vectors (${manifest.vectors.length}/${manifest.vectors.length})`);
