export type OrbitFailReason =
  | "invalid_json_root"
  | "forbidden_composition"
  | "invalid_top_level_keys"
  | "missing_required_field"
  | "invalid_orbit_version"
  | "invalid_action"
  | "invalid_boundary"
  | "invalid_payload"
  | "invalid_lifecycle_state"
  | "lifecycle_not_armed"
  | "invalid_signatures"
  | "invalid_signature_record"
  | "internal_error";

export type OrbitValidationResult = {
  decision: "PASS" | "FAIL";
  reason: "authorized" | OrbitFailReason;
  validation_hash: string;
  hash_algorithm: "SHA-256";
  canonicalization: "RFC8785-JSON";
};
