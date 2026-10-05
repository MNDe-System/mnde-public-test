import { createHash } from "crypto";
import { canonicalizeJson } from "./json.ts";
import type { JsonValue } from "./json.ts";

export function sha256Hex(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function hashCanonicalJson(value: JsonValue): string {
  return sha256Hex(canonicalizeJson(value));
}
