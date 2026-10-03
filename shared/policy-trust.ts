import { createHash, createPublicKey, verify } from "crypto";
import { canonicalizeJson, type JsonValue } from "./json.ts";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function deriveKeyId(publicKeyHex: string): string {
  return createHash("sha256").update(Buffer.from(publicKeyHex, "hex")).digest("hex").slice(0, 16);
}

export function canonicalPolicyPayload(policy: {
  schema_version: string;
  policy_version: string;
  rules: Record<string, number | boolean>;
}): string {
  return canonicalizeJson({
    schema_version: policy.schema_version,
    policy_version: policy.policy_version,
    rules: policy.rules
  } as unknown as JsonValue);
}

export function policyHash(policy: {
  schema_version: string;
  policy_version: string;
  rules: Record<string, number | boolean>;
}): string {
  return createHash("sha256").update(canonicalPolicyPayload(policy)).digest("hex");
}

export function verifyPolicySignature(publicKeyHex: string, payload: string, signatureHex: string): boolean {
  const rawKey = Buffer.from(publicKeyHex, "hex");
  const publicKey = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, rawKey]),
    format: "der",
    type: "spki"
  });
  return verify(null, Buffer.from(payload, "utf8"), publicKey, Buffer.from(signatureHex, "hex"));
}
