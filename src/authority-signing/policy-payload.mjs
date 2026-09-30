// Shared production inner-signature path; receipt formats are unchanged.
import { RECEIPT_SIGNATURE_ALGORITHM } from "../../shared/index.ts";
import { canonicalPayloadWithoutSignature } from "../policy-engine/receipt.mjs";

export async function signPolicyPayload(payload, signingConfig, bundle, now) {
  const signature = await signingConfig.provider.signReceipt(canonicalPayloadWithoutSignature(payload));
  return {
    ...payload,
    verifiable_signature: {
      algorithm: RECEIPT_SIGNATURE_ALGORITHM,
      authority_id: bundle.authority_id,
      key_id: signature.key_id,
      public_key_fingerprint: signature.fingerprint,
      signed_at: now,
      value: signature.value
    }
  };
}
