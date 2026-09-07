#!/usr/bin/env node
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createMndeExecutor } from "../executor/index.mjs";
import { startMndeSidecar } from "../executor/sidecar-harness.mjs";
import {
  CONTAINMENT_CAPABILITIES,
  CONTAINMENT_MANIFEST_SCHEMA,
  createContainmentGuard
} from "../src/containment/index.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sidecarUrl = "http://127.0.0.1:8831";
const results = [];

async function test(name, fn) {
  try {
    await fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

function manifest(tool, capabilities) {
  return { schema_version: CONTAINMENT_MANIFEST_SCHEMA, tools: { [tool]: capabilities } };
}

async function main() {
  console.log("MNDe strict containment profile tests\n");

  await test("off mode preserves existing integrations", () => {
    assert.equal(createContainmentGuard().assess("anything").ok, true);
  });

  await test("strict mode refuses a missing or malformed manifest", () => {
    assert.equal(createContainmentGuard({ mode: "strict" }).assess("read_status").reason, "ERR_CONTAINMENT_MANIFEST_INVALID");
    assert.equal(createContainmentGuard({ mode: "strict", manifest: {} }).assess("read_status").reason, "ERR_CONTAINMENT_MANIFEST_INVALID");
  });

  await test("strict mode refuses every unregistered tool", () => {
    const guard = createContainmentGuard({ mode: "strict", manifest: manifest("read_status", ["observability.read"]) });
    assert.equal(guard.assess("new_tool").reason, "ERR_CONTAINMENT_TOOL_UNREGISTERED");
  });

  await test("strict mode refuses every escape-enabling capability", () => {
    for (const capability of CONTAINMENT_CAPABILITIES.BLOCKED) {
      const guard = createContainmentGuard({ mode: "strict", manifest: manifest("hostile", [capability]) });
      const result = guard.assess("hostile");
      assert.equal(result.ok, false, capability);
      assert.equal(result.reason, "ERR_CONTAINMENT_CAPABILITY_BLOCKED", capability);
      assert.equal(result.capability, capability);
    }
  });

  await test("strict mode permits only the named local capabilities", () => {
    const guard = createContainmentGuard({ mode: "strict", manifest: manifest("safe", [...CONTAINMENT_CAPABILITIES.SAFE]) });
    const result = guard.assess("safe");
    assert.equal(result.ok, true);
    assert.equal(result.evidence.action, "safe");
    assert.match(result.evidence.manifest_digest, /^sha256:[0-9a-f]{64}$/);
  });

  await test("the guard snapshots the manifest against later mutation", () => {
    const source = manifest("safe", ["observability.read"]);
    const guard = createContainmentGuard({ mode: "strict", manifest: source });
    source.tools.safe[0] = "network.egress";
    assert.equal(guard.assess("safe").ok, true);
  });

  await test("executor blocks containment failures before contacting a sidecar", async () => {
    const receiptsDir = mkdtempSync(join(tmpdir(), "mnde-containment-local-"));
    try {
      const guarded = createMndeExecutor({
        sidecarUrl: "http://127.0.0.1:1",
        receiptsDir,
        containmentMode: "strict",
        containmentManifest: manifest("web_request", ["network.egress"])
      });
      let ran = false;
      const result = await guarded.execute({ action: "web_request", input: {}, run: async () => { ran = true; } });
      assert.equal(result.reason, "ERR_CONTAINMENT_CAPABILITY_BLOCKED");
      assert.equal(result.executed, false);
      assert.equal(ran, false);
      assert.match(readFileSync(result.receiptPath, "utf8"), /blocked before the sidecar was contacted/);
    } finally {
      rmSync(receiptsDir, { recursive: true, force: true });
    }
  });

  await test("safe execution requires signed receipt-bound containment evidence", async () => {
    const receiptsDir = mkdtempSync(join(tmpdir(), "mnde-containment-live-"));
    const sidecar = await startMndeSidecar({
      url: sidecarUrl,
      testerId: "CONTAINMENT-TEST-001",
      env: {
        MNDE_DECISION_ENGINE: "policy-engine",
        MNDE_PE_POLICY: join(repoRoot, "tests", "fixtures", "containment", "allow-read-status-policy.json")
      }
    });
    try {
      const guarded = createMndeExecutor({
        sidecarUrl,
        receiptsDir,
        containmentMode: "strict",
        containmentManifest: manifest("read_status", ["observability.read"])
      });
      let ran = false;
      const result = await guarded.execute({
        action: "read_status",
        input: {},
        requestOverrides: {
          execution_request: {
            mnde_containment: {
              schema_version: "attacker-controlled",
              mode: "off",
              action: "read_status",
              capabilities: ["network.egress"],
              manifest_digest: "sha256:attacker"
            }
          }
        },
        run: async () => { ran = true; return "ok"; }
      });
      assert.equal(result.decision, "ALLOW", JSON.stringify({ reason: result.reason, verified: result.verified, failClosed: result.failClosed }));
      assert.equal(result.verified, true);
      assert.equal(result.executed, true);
      assert.equal(ran, true);
      const inner = result.receipt.receipt ?? result.receipt;
      const canonicalRequest = JSON.parse(inner.canonical_request);
      assert.equal(canonicalRequest.context.mnde_containment.mode, "strict");
      assert.deepEqual(canonicalRequest.context.mnde_containment.capabilities, ["observability.read"]);
    } finally {
      await sidecar.stop();
      rmSync(receiptsDir, { recursive: true, force: true });
    }
  });

  const failed = results.filter((ok) => !ok).length;
  console.log("");
  if (failed > 0) {
    console.log(`FAIL containment tests (${results.length - failed}/${results.length})`);
    process.exit(1);
  }
  console.log(`PASS containment tests (${results.length}/${results.length})`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
