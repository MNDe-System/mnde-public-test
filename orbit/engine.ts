import { createHash } from "crypto";
import { REASON_CODES, canonicalizeJson, type CanonicalExecutionInput, type JsonValue, type OrbitTrace } from "../shared/index.ts";

type PatternRule = {
  id: string;
  matcher: (parameters: Record<string, JsonValue>) => boolean;
};

const FORBIDDEN_CODE_PATTERNS = ["rm -rf", "drop_database", "delete_database", "/etc/credentials", "os.remove(", "unlink("];
const FORBIDDEN_NETWORK_PATTERNS = ["169.254.169.254", "127.0.0.1", "::1", "localhost", ":2375", ":2376"];
const FORBIDDEN_QUERY_PATTERNS = ["select * from secrets", "export select", "api_key", "token dump"];
const FORBIDDEN_PLAN_PATTERNS = ["retry_until_success", "\"limit\":\"none\"", "\"count\":1000", "\"count\":10000"];
const ACTION_FIELD_NAMES = new Set([
  "action",
  "actions",
  "tool_calls",
  "execution_targets",
  "commands",
  "workflow",
  "steps",
  "tasks",
  "operations",
  "pipeline",
  "run",
  "exec",
  "spawn",
  "shell"
]);
const ACTION_TEXT_PATTERNS = ["deploy_irreversible", "irreversible", "delete", "destroy", "scale_gpu_cluster", "start_training_job", "retry_failed_job", "run", "exec", "spawn", "shell"];

function normalizeSuspiciousText(value: string): string {
  return value.normalize("NFKC").toLowerCase().trim().replace(/\s+/g, " ");
}

function normalizedPattern(pattern: string): string {
  return normalizeSuspiciousText(pattern);
}

function parameterText(parameters: Record<string, JsonValue>): string {
  return normalizeOrbitText(normalizeSuspiciousText(canonicalizeJson(parameters as unknown as JsonValue)));
}

const RULES: PatternRule[] = [
  {
    id: "destructive_code",
    matcher: (parameters) => FORBIDDEN_CODE_PATTERNS.some((pattern) => parameterText(parameters).includes(normalizedPattern(pattern)))
  },
  {
    id: "internal_network",
    matcher: (parameters) => FORBIDDEN_NETWORK_PATTERNS.some((pattern) => parameterText(parameters).includes(normalizedPattern(pattern)))
  },
  {
    id: "data_exfiltration",
    matcher: (parameters) => FORBIDDEN_QUERY_PATTERNS.some((pattern) => parameterText(parameters).includes(normalizedPattern(pattern)))
  },
  {
    id: "recursive_or_fanout",
    matcher: (parameters) => FORBIDDEN_PLAN_PATTERNS.some((pattern) => parameterText(parameters).includes(normalizedPattern(pattern)))
  }
];

function toolCallsEqual(
  left: CanonicalExecutionInput["execution_request"]["tool_calls"],
  right: CanonicalExecutionInput["execution_request"]["orbit_intent"]["payload"]["tool_calls"]
) {
  return canonicalizeJson(left as unknown as JsonValue) === canonicalizeJson(right as unknown as JsonValue);
}

function ipv4FromNumber(value: number): string | null {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) return null;
  return [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255
  ].join(".");
}

function parseIpToken(token: string): string | null {
  const trimmed = normalizeSuspiciousText(token);
  const mapped = trimmed.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) return mapped[1];
  if (trimmed === "0:0:0:0:0:0:0:1" || trimmed === "::1") return "::1";
  if (/^0x[0-9a-f]{1,8}$/.test(trimmed)) return ipv4FromNumber(Number.parseInt(trimmed.slice(2), 16));
  if (/^\d{8,10}$/.test(trimmed)) return ipv4FromNumber(Number.parseInt(trimmed, 10));
  return null;
}

function normalizeOrbitText(text: string): string {
  const whitespaceCollapsed = text.replace(/\s+/g, " ");
  return whitespaceCollapsed.replace(/(?<![a-z0-9])(?:::ffff:)?(?:0x[0-9a-f]{1,8}|\d{8,10}|\d{1,3}(?:\.\d{1,3}){3}|::1|0:0:0:0:0:0:0:1)(?![a-z0-9])/g, (token) => {
    return parseIpToken(token) ?? token;
  });
}

function countNestedActionMarkers(value: JsonValue): number {
  if (Array.isArray(value)) {
    return value.reduce((sum, item) => sum + countNestedActionMarkers(item), 0);
  }
  if (typeof value === "string") {
    const lower = normalizeSuspiciousText(value);
    return ACTION_TEXT_PATTERNS.some((pattern) => lower.includes(normalizedPattern(pattern))) && (lower.includes("action") || lower.includes("task") || lower.includes("step")) ? 1 : 0;
  }
  if (typeof value !== "object" || value === null) {
    return 0;
  }

  let markers = 0;
  for (const [key, nested] of Object.entries(value)) {
    const lowerKey = normalizeSuspiciousText(key);
    if (ACTION_FIELD_NAMES.has(lowerKey)) {
      markers += Array.isArray(nested) ? nested.length : 1;
    }
    markers += countNestedActionMarkers(nested);
  }
  return markers;
}

function hasMultipleActions(input: CanonicalExecutionInput): boolean {
  if (
    input.execution_request.tool_calls.length > 1 &&
    input.execution_request.tool_calls.some((call) => ACTION_TEXT_PATTERNS.some((pattern) => call.tool.toLowerCase().includes(pattern)))
  ) {
    return true;
  }
  return intentParameterObjects(input).some((parameters) => countNestedActionMarkers(parameters as unknown as JsonValue) > 0);
}

function intentParameterObjects(input: CanonicalExecutionInput): Array<Record<string, JsonValue>> {
  const parameters: Array<Record<string, JsonValue>> = [];
  if (input.execution_request.parameters) {
    parameters.push(input.execution_request.parameters);
  }
  for (const call of input.execution_request.tool_calls) {
    if (call.parameters) {
      parameters.push(call.parameters);
    }
  }
  for (const call of input.execution_request.orbit_intent.payload.tool_calls) {
    if (call.parameters) {
      parameters.push(call.parameters);
    }
  }
  return parameters;
}

function hasUnsafeParameters(input: CanonicalExecutionInput): boolean {
  return intentParameterObjects(input).some((parameters) => RULES.some((rule) => rule.matcher(parameters)));
}

export function runStrictOrbit(input: CanonicalExecutionInput): OrbitTrace {
  const validationHash = createHash("sha256")
    .update(canonicalizeJson(input.execution_request.orbit_intent as unknown as JsonValue))
    .digest("hex");

  if (input.execution_request.orbit_intent.orbit_version !== "2.0" || input.execution_request.orbit_intent.lifecycle_state !== "ARMED") {
    return {
      layer: "orbit",
      decision: "REFUSE",
      reason_code: REASON_CODES.ToolCallSequence,
      validation_hash: validationHash
    };
  }

  if (hasMultipleActions(input)) {
    return {
      layer: "orbit",
      decision: "REFUSE",
      reason_code: REASON_CODES.OrbitMultipleActions,
      validation_hash: validationHash
    };
  }

  if (hasUnsafeParameters(input)) {
    return {
      layer: "orbit",
      decision: "REFUSE",
      reason_code: REASON_CODES.ForbiddenActionInParameters,
      validation_hash: validationHash
    };
  }

  if (!toolCallsEqual(input.execution_request.tool_calls, input.execution_request.orbit_intent.payload.tool_calls)) {
    return {
      layer: "orbit",
      decision: "REFUSE",
      reason_code: REASON_CODES.ToolCallSequence,
      validation_hash: validationHash
    };
  }

  return {
    layer: "orbit",
    decision: "ALLOW",
    reason_code: REASON_CODES.OkOrbit,
    validation_hash: validationHash
  };
}
