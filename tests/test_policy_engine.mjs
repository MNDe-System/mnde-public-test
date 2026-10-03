#!/usr/bin/env node
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { evaluatePolicyRequest } from "../src/policy-engine/index.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const policy = JSON.parse(readFileSync(join(repoRoot, "tests", "fixtures", "policy-engine", "demo-policy.json"), "utf8"));
const now = "2026-06-14T15:30:00Z";

const results = [];
function test(name, fn) {
  try {
    fn();
    results.push(true);
    console.log(`  [PASS] ${name}`);
  } catch (error) {
    results.push(false);
    console.log(`  [FAIL] ${name}: ${error.message}`);
  }
}

function baseRequest(overrides = {}) {
  return {
    schema_version: "1.0",
    request_id: "req_test_001",
    timestamp: "2026-06-14T15:30:00Z",
    principal: {
      principal_id: "user_123",
      roles: ["operator"]
    },
    agent: {
      agent_id: "agent_456",
      agent_type: "mcp-client",
      session_id: "sess_789"
    },
    tool: {
      tool_server_id: "server_demo",
      tool_name: "read_status"
    },
    parameters: {},
    environment: {
      workspace_id: "workspace_test",
      environment_name: "test",
      host_id: "host_001",
      region: "local"
    },
    context: {
      estimated_cost: 0,
      risk_label: "low"
    },
    ...overrides
  };
}

const validAuthorities = [
  {
    authority_id: "tmp_file_delete_authority",
    issued_to: "user_123",
    valid_from: "2026-06-01T00:00:00Z",
    valid_until: "2026-07-01T00:00:00Z"
  }
];

function decide(request, options = {}) {
  return evaluatePolicyRequest(request, policy, { now, authorities: [], ...options });
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function decideWithPolicy(request, candidatePolicy, options = {}) {
  return evaluatePolicyRequest(request, candidatePolicy, { now, authorities: [], ...options });
}

console.log("MNDe Policy Engine slice tests\n");

test("ALLOW read_status", () => {
  const result = decide(baseRequest());
  assert.equal(result.decision, "ALLOW");
  assert.equal(result.reason_code, "OK_ALLOW");
});

test("REFUSE recursive_delete", () => {
  const result = decide(baseRequest({ tool: { tool_server_id: "server_demo", tool_name: "recursive_delete" } }));
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "RULE_REFUSE");
});

test("REFUSE no matching rule", () => {
  const result = decide(baseRequest({ tool: { tool_server_id: "server_demo", tool_name: "unknown_tool" } }));
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "NO_MATCHING_RULE");
});

test("REFUSE invalid request", () => {
  const request = baseRequest();
  delete request.principal;
  const result = decide(request);
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "INVALID_REQUEST");
});

test("REFUSE invalid policy", () => {
  const invalidPolicy = { ...policy, rules: [{ rule_id: "bad", effect: "WARN", match: { all: [] } }] };
  const result = evaluatePolicyRequest(baseRequest(), invalidPolicy, { now });
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "INVALID_POLICY");
});

test("REFUSE wins over ALLOW", () => {
  const conflictPolicy = clone(policy);
  conflictPolicy.rules.push({
    rule_id: "allow_customer_data_delete_conflict",
    effect: "ALLOW",
    match: {
      all: [
        { field: "tool.tool_name", op: "eq", value: "delete_file" },
        { field: "parameters.path", op: "path_prefix", value: "/customer-data/" }
      ]
    }
  });
  const result = decideWithPolicy(baseRequest({
    tool: { tool_server_id: "server_demo", tool_name: "delete_file" },
    parameters: { path: "/customer-data/account-001.json" }
  }), conflictPolicy, { authorities: validAuthorities });
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "RULE_REFUSE");
});

test("REFUSE missing authority", () => {
  const result = decide(baseRequest({
    tool: { tool_server_id: "server_demo", tool_name: "delete_file" },
    parameters: { path: "/tmp/cache.txt" }
  }));
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "AUTHORITY_REQUIRED");
});

test("REFUSE expired authority", () => {
  const result = decide(baseRequest({
    tool: { tool_server_id: "server_demo", tool_name: "delete_file" },
    parameters: { path: "/tmp/cache.txt" }
  }), {
    authorities: [{
      authority_id: "tmp_file_delete_authority",
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2026-02-01T00:00:00Z"
    }]
  });
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "AUTHORITY_EXPIRED");
});

test("ALLOW valid authority", () => {
  const result = decide(baseRequest({
    tool: { tool_server_id: "server_demo", tool_name: "delete_file" },
    parameters: { path: "/tmp/cache.txt" }
  }), { authorities: validAuthorities });
  assert.equal(result.decision, "ALLOW");
  assert.equal(result.reason_code, "OK_ALLOW");
});

test("deterministic decision hash stays stable", () => {
  const request = baseRequest();
  const a = decide(request);
  const b = decide(JSON.parse(JSON.stringify(request)));
  assert.equal(a.decision_hash, b.decision_hash);
  assert.equal(a.request_hash, b.request_hash);
  assert.equal(a.policy_hash, b.policy_hash);
});

test("tampered request changes hash", () => {
  const a = decide(baseRequest());
  const b = decide(baseRequest({ context: { estimated_cost: 0, risk_label: "changed" } }));
  assert.notEqual(a.request_hash, b.request_hash);
  assert.notEqual(a.decision_hash, b.decision_hash);
});

test("nested all/any/not logic is deterministic", () => {
  const nestedPolicy = {
    ...clone(policy),
    rules: [{
      rule_id: "allow_nested",
      effect: "ALLOW",
      match: {
        all: [
          {
            any: [
              { field: "principal.roles", op: "contains", value: "operator" },
              { field: "principal.roles", op: "contains", value: "admin" }
            ]
          },
          {
            not: { field: "environment.environment_name", op: "eq", value: "production" }
          }
        ]
      }
    }]
  };
  const result = decideWithPolicy(baseRequest(), nestedPolicy);
  assert.equal(result.decision, "ALLOW");
});

test("REFUSE malformed policy structures", () => {
  const malformed = { ...clone(policy), rules: [{ rule_id: "bad", effect: "ALLOW", match: { all: {} } }] };
  const result = decideWithPolicy(baseRequest(), malformed);
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "INVALID_POLICY");
});

test("REFUSE unknown operators", () => {
  const unknownOperator = { ...clone(policy), rules: [{ rule_id: "bad_op", effect: "ALLOW", match: { field: "tool.tool_name", op: "regex", value: ".*" } }] };
  const result = decideWithPolicy(baseRequest(), unknownOperator);
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "INVALID_POLICY");
});

test("REFUSE policy with unknown attribute root", () => {
  const unknownRoot = { ...clone(policy), rules: [{ rule_id: "bad_root", effect: "ALLOW", match: { field: "system.user", op: "eq", value: "root" } }] };
  const result = decideWithPolicy(baseRequest(), unknownRoot);
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "INVALID_POLICY");
});

test("REFUSE missing field unless rule explicitly checks missing", () => {
  const missingField = { ...clone(policy), rules: [{ rule_id: "missing_field", effect: "ALLOW", match: { field: "parameters.path", op: "eq", value: "/tmp/cache.txt" } }] };
  const result = decideWithPolicy(baseRequest(), missingField);
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "ATTRIBUTE_MISSING");

  const explicitMissing = { ...clone(policy), rules: [{ rule_id: "explicit_missing", effect: "ALLOW", match: { field: "parameters.path", op: "missing" } }] };
  const missingResult = decideWithPolicy(baseRequest(), explicitMissing);
  assert.equal(missingResult.decision, "ALLOW");
});

test("REFUSE wildcard-like input when no literal wildcard policy exists", () => {
  const result = decide(baseRequest({
    tool: { tool_server_id: "server_demo", tool_name: "delete_file" },
    parameters: { path: "/tmp/*" }
  }), { authorities: validAuthorities });
  assert.equal(result.decision, "REFUSE");
});

test("REFUSE path traversal style values that escape allowed prefix", () => {
  const result = decide(baseRequest({
    tool: { tool_server_id: "server_demo", tool_name: "delete_file" },
    parameters: { path: "/tmp/../customer-data/account-001.json" }
  }), { authorities: validAuthorities });
  assert.equal(result.decision, "REFUSE");
});

test("REFUSE empty rule sets", () => {
  const emptyPolicy = { ...clone(policy), rules: [] };
  const result = decideWithPolicy(baseRequest(), emptyPolicy);
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "NO_MATCHING_RULE");
});

test("REFUSE duplicate rule IDs as invalid policy", () => {
  const duplicateIds = {
    ...clone(policy),
    rules: [
      { rule_id: "dup", effect: "ALLOW", match: { field: "tool.tool_name", op: "eq", value: "read_status" } },
      { rule_id: "dup", effect: "ALLOW", match: { field: "principal.roles", op: "contains", value: "operator" } }
    ]
  };
  const result = decideWithPolicy(baseRequest(), duplicateIds);
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "INVALID_POLICY");
});

test("REFUSE invalid authority expiration dates", () => {
  const result = decide(baseRequest({
    tool: { tool_server_id: "server_demo", tool_name: "delete_file" },
    parameters: { path: "/tmp/cache.txt" }
  }), {
    authorities: [{
      authority_id: "tmp_file_delete_authority",
      valid_from: "not-a-date",
      valid_until: "also-not-a-date"
    }]
  });
  assert.equal(result.decision, "REFUSE");
  assert.equal(result.reason_code, "AUTHORITY_EXPIRED");
});

test("decision hash is stable without explicit clock override", () => {
  const request = baseRequest();
  const a = evaluatePolicyRequest(request, policy, { authorities: [] });
  const b = evaluatePolicyRequest(clone(request), policy, { authorities: [] });
  assert.equal(a.evaluated_at, request.timestamp);
  assert.equal(a.decision_hash, b.decision_hash);
});

test("policy tampering changes policy and decision hashes", () => {
  const a = decide(baseRequest());
  const tamperedPolicy = clone(policy);
  tamperedPolicy.version = "0.1.1";
  const b = decideWithPolicy(baseRequest(), tamperedPolicy);
  assert.notEqual(a.policy_hash, b.policy_hash);
  assert.notEqual(a.decision_hash, b.decision_hash);
});

const failed = results.filter((ok) => !ok).length;
console.log("");
if (failed > 0) {
  console.log(`FAIL policy engine tests (${results.length - failed}/${results.length})`);
  process.exit(1);
}
console.log(`PASS policy engine tests (${results.length}/${results.length})`);
