// Crypto / harness self-checks under CUSTODY mode.
//
// These establish that MNDe's signature/trust verification behaves as expected
// under real Ed25519 custody signing. They are NOT evidence that temporal exact
// binding works — they only prove the crypto substrate the other conjuncts
// assume. Reported separately from the security conjuncts.
//
// Uses MNDe's real custody provider, real signer, and real verifier. No sidecar
// needed; no MNDe source modified.

import { loadSigningConfig, signReceiptForDelivery, verifyCustodyAttestation } from "../../../src/authority-signing/index.mjs";
import { record, writeEvidence } from "../harness/common.mjs";

const results = [];

// A minimal legacy-shaped inner receipt (the object custody wraps + attests).
function innerReceipt(execId = "CS-EXEC-1", decision = "ALLOW") {
  return {
    schema_version: "ecs.receipt.v2",
    canonical_request: JSON.stringify({ execution_request: { request_id: execId, tool_calls: [{ tool: "github.merge", priority: 1 }] } }),
    request_hash: "cs-req-hash",
    decision_output: { decision, execution_id: execId, policy_hash: "cs-ph", policy_version: "cs.v1" }
  };
}

async function main() {
  // Two independent custody authorities: A (trusted) and B (foreign/untrusted).
  const cfgA = await loadSigningConfig({ MNDE_RECEIPT_SIGNING_MODE: "custody" });
  const cfgB = await loadSigningConfig({ MNDE_RECEIPT_SIGNING_MODE: "custody" });
  if (!cfgA.ok || !cfgB.ok) throw new Error(`custody config failed: ${cfgA.reason_code ?? ""} ${cfgB.reason_code ?? ""}`);
  const bundleA = cfgA.provider.getPublicBundle();
  const fpA = cfgA.fingerprint;
  const verifyA = (env, opts = {}) => verifyCustodyAttestation(env, { authorityBundle: bundleA, trustedRootFingerprint: fpA, ...opts });

  // CS1: a genuinely custody-signed receipt verifies under its own authority.
  const signed = await signReceiptForDelivery(innerReceipt(), cfgA);
  if (!signed.ok) throw new Error(`signing failed: ${signed.reason_code}`);
  const v1 = await verifyA(signed.receipt);
  results.push(record("CS1", "crypto", v1.ok ? "PASS" : "FAIL",
    "valid custody-signed receipt verifies", { verified: v1.ok, reason: v1.reason ?? null }));

  // CS2: tamper ONE field of the inner receipt → attestation receipt_hash mismatch.
  const tamperedInner = structuredClone(signed.receipt);
  tamperedInner.receipt.decision_output.decision = "REFUSE"; // flip the signed decision
  const v2 = await verifyA(tamperedInner);
  results.push(record("CS2", "crypto", v2.ok === false ? "PASS" : "FAIL",
    "inner-receipt tamper is detected (verify fails)", { verified: v2.ok, reason: v2.reason ?? null }));

  // CS3: tamper the attestation SIGNATURE bytes → signature verification fails.
  const tamperedSig = structuredClone(signed.receipt);
  const val = tamperedSig.custody_attestation.signature.value;
  tamperedSig.custody_attestation.signature.value = flipOneChar(val);
  const v3 = await verifyA(tamperedSig);
  results.push(record("CS3", "crypto", v3.ok === false ? "PASS" : "FAIL",
    "attestation signature tamper is detected", { verified: v3.ok, reason: v3.reason ?? null }));

  // CS4 (T011): UNTRUSTED signer — sign with authority B, verify against A's
  // bundle. A structurally valid signature from a foreign key must be rejected.
  const forged = await signReceiptForDelivery(innerReceipt("CS-FORGED"), cfgB);
  if (!forged.ok) throw new Error(`forge signing failed: ${forged.reason_code}`);
  const v4 = await verifyA(forged.receipt);
  results.push(record("CS4", "crypto", v4.ok === false ? "PASS" : "FAIL",
    "foreign-authority (untrusted signer) receipt is rejected", { verified: v4.ok, reason: v4.reason ?? null }));

  // CS5: valid receipt but verifier pinned to the WRONG root fingerprint → reject.
  const v5 = await verifyCustodyAttestation(signed.receipt, { authorityBundle: bundleA, trustedRootFingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000" });
  results.push(record("CS5", "crypto", v5.ok === false ? "PASS" : "FAIL",
    "wrong pinned root fingerprint is rejected", { verified: v5.ok, reason: v5.reason ?? null }));

  const summary = {
    group: "crypto-custody-selfcheck",
    total: results.length,
    fail: results.filter((r) => r.verdict === "FAIL").length,
    results
  };
  writeEvidence("E_crypto_custody.json", summary);
  for (const r of results) console.log(`  [${r.verdict}] ${r.id} ${r.expected} — verified=${r.observed.verified} ${r.observed.reason ?? ""}`);
  console.log(`crypto-custody: ${summary.total - summary.fail}/${summary.total} PASS, ${summary.fail} FAIL`);
  return summary;
}

// Deterministically change the DECODED signature value by one symbol. The
// signature is lowercase hex; toggling case (a↔A) would be a no-op because hex is
// case-insensitive (this bit us once). Swapping to a different digit (0↔1)
// changes the nibble for hex and the sextet for base64, so the decoded bytes
// always differ and Ed25519 verification must fail on every run.
function flipOneChar(s) {
  if (typeof s !== "string" || s.length === 0) return "00";
  const i = Math.floor(s.length / 2);
  const c = s[i] === "0" ? "1" : "0";
  return s.slice(0, i) + c + s.slice(i + 1);
}

export default await main();
