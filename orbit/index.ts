import { hashCanonicalJson } from "../shared/index.ts";
import type { JsonValue, OrbitIntent } from "../shared/index.ts";
import type { OrbitValidationResult } from "./types.ts";

const PINNED_ORBIT_VERSION = "2.0";
const PASS_LIFECYCLE_STATE = "ARMED";
const ALLOWED_TOP_LEVEL_KEYS = [
  "orbit_version",
  "action",
  "boundary",
  "payload",
  "lifecycle_state",
  "signatures",
  "ext"
] as const;
const REQUIRED_TOP_LEVEL_KEYS = [
  "orbit_version",
  "action",
  "boundary",
  "payload",
  "lifecycle_state",
  "signatures"
] as const;
const FORBIDDEN_COMPOSITION_KEYS = ["intent", "intents", "bundle"] as const;
const LIFECYCLE_STATES = ["CREATED", "ARMED", "RELEASED", "CONSUMED", "EXPIRED", "FAILED"] as const;

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stripExt(input: OrbitIntent): JsonValue {
  const { ext: _ext, ...decisionInput } = input;
  return decisionInput as unknown as JsonValue;
}

function buildResult(
  decision: "PASS" | "FAIL",
  reason: OrbitValidationResult["reason"],
  validationHash: string
): OrbitValidationResult {
  return {
    decision,
    reason,
    validation_hash: validationHash,
    hash_algorithm: "SHA-256",
    canonicalization: "RFC8785-JSON"
  };
}

function isValidSignatureRecord(value: unknown): value is { alg: string; sig: string } {
  if (!isJsonObject(value)) {
    return false;
  }
  const keys = Object.keys(value);
  return keys.length === 2 && typeof value.alg === "string" && typeof value.sig === "string";
}

export function validateOrbitIntent(intent: OrbitIntent): OrbitValidationResult {
  const validationHash = hashCanonicalJson(stripExt(intent));

  if (!isJsonObject(intent)) {
    return buildResult("FAIL", "invalid_json_root", validationHash);
  }

  for (const key of FORBIDDEN_COMPOSITION_KEYS) {
    if (key in intent) {
      return buildResult("FAIL", "forbidden_composition", validationHash);
    }
  }

  const allowed = new Set<string>(ALLOWED_TOP_LEVEL_KEYS);
  for (const key of Object.keys(intent)) {
    if (!allowed.has(key)) {
      return buildResult("FAIL", "invalid_top_level_keys", validationHash);
    }
  }

  for (const key of REQUIRED_TOP_LEVEL_KEYS) {
    if (!(key in intent)) {
      return buildResult("FAIL", "missing_required_field", validationHash);
    }
  }

  if (intent.orbit_version !== PINNED_ORBIT_VERSION) {
    return buildResult("FAIL", "invalid_orbit_version", validationHash);
  }
  if (typeof intent.action !== "string" || intent.action.length === 0) {
    return buildResult("FAIL", "invalid_action", validationHash);
  }
  if (typeof intent.boundary !== "string" || intent.boundary.length === 0) {
    return buildResult("FAIL", "invalid_boundary", validationHash);
  }
  if (!isJsonObject(intent.payload)) {
    return buildResult("FAIL", "invalid_payload", validationHash);
  }
  if (!LIFECYCLE_STATES.includes(intent.lifecycle_state as (typeof LIFECYCLE_STATES)[number])) {
    return buildResult("FAIL", "invalid_lifecycle_state", validationHash);
  }
  if (intent.lifecycle_state !== PASS_LIFECYCLE_STATE) {
    return buildResult("FAIL", "lifecycle_not_armed", validationHash);
  }
  if (!Array.isArray(intent.signatures) || intent.signatures.length === 0) {
    return buildResult("FAIL", "invalid_signatures", validationHash);
  }
  for (const signature of intent.signatures) {
    if (!isValidSignatureRecord(signature)) {
      return buildResult("FAIL", "invalid_signature_record", validationHash);
    }
  }

  return buildResult("PASS", "authorized", validationHash);
}
