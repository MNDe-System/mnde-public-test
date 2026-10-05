// Single-receipt inclusion-proof verifier — PURE and OFFLINE.
//
// Given only a proof bundle and a trusted authority bundle (public), this verifies
// the full chain with NO filesystem, NO network, and NO mutable runtime state:
//
//   receipt signature
//     -> receipt-to-entry binding
//       -> entry signature (ledger key)
//         -> Merkle inclusion in the checkpoint's tree
//           -> checkpoint signature
//             -> authority-bundle key validity (window + revocation)
//
// It reports assurance honestly: Phase-1 checkpoints carry only the operator's
// (ledger key) signature, so a valid proof means "this receipt is included in a
// history the operator committed to" — NOT that the history is rewrite-resistant.
// Rewrite-resistance requires witnesses (Phase 2). Time is operator-asserted:
// issued_at is used to select the key-validity instant, never trusted as proof
// that the checkpoint existed at that time.

import {
  LEDGER_CHECKPOINT_SCHEMA,
  LEDGER_CHECKPOINT_VERSION,
  LEDGER_INCLUSION_PROOF_SCHEMA,
  LEDGER_SIGNATURE_ALGORITHM,
  LEDGER_SIGNING_ROLE,
  LEDGER_ASSURANCE,
  LEDGER_ERRORS,
  canonicalReceiptHash,
  computeEntryHash,
  ledgerSignablePayload,
  checkpointSignablePayload
} from "./index.mjs";
import { leafHash, verifyInclusion } from "./merkle.mjs";
import { verifyAgainstBundle, verifyAuthorityBundle } from "../custody/bundle.mjs";
import { isSignedReceiptEnvelope, verifyCustodyAttestation } from "../authority-signing/index.mjs";
import { verifyPolicyReceipt } from "../policy-engine/receipt.mjs";

function bad(step, code, reason) {
  return { ok: false, step, reason: `${code}: ${reason}` };
}
function isObj(v) { return typeof v === "object" && v !== null && !Array.isArray(v); }
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;

export async function verifyProofBundle(bundle, trustedBundle, options = {}) {
  // ── 0. Shape ────────────────────────────────────────────────────────────────
  if (!isObj(bundle) || bundle.schema !== LEDGER_INCLUSION_PROOF_SCHEMA) {
    return bad("shape", LEDGER_ERRORS.PROOF_MALFORMED, "not an inclusion proof bundle");
  }
  const { receipt, entry, inclusion, checkpoint } = bundle;
  if (!isObj(receipt) || !isObj(entry) || !isObj(inclusion) || !isObj(checkpoint)) {
    return bad("shape", LEDGER_ERRORS.PROOF_MALFORMED, "missing receipt/entry/inclusion/checkpoint");
  }
  if (checkpoint.schema !== LEDGER_CHECKPOINT_SCHEMA) {
    return bad("shape", LEDGER_ERRORS.CHECKPOINT_MALFORMED, "unexpected checkpoint schema");
  }
  if (checkpoint.version !== LEDGER_CHECKPOINT_VERSION ||
      !Number.isSafeInteger(checkpoint.tree_size) || checkpoint.tree_size < 1 ||
      !SHA256_HEX_RE.test(checkpoint.root_hash) ||
      typeof checkpoint.issued_at !== "string" || Number.isNaN(Date.parse(checkpoint.issued_at)) ||
      !isObj(checkpoint.ledger_head) ||
      checkpoint.ledger_head.sequence !== checkpoint.tree_size ||
      !SHA256_HEX_RE.test(checkpoint.ledger_head.entry_hash)) {
    return bad("shape", LEDGER_ERRORS.CHECKPOINT_MALFORMED, "checkpoint fields are malformed or internally inconsistent");
  }
  if (!Number.isSafeInteger(entry.sequence) || entry.sequence < 1 ||
      !Number.isSafeInteger(inclusion.tree_size) || inclusion.tree_size < 1 ||
      !Number.isSafeInteger(inclusion.leaf_index) || inclusion.leaf_index < 0 ||
      !Array.isArray(inclusion.audit_path) ||
      inclusion.audit_path.length > Math.ceil(Math.log2(inclusion.tree_size)) ||
      inclusion.audit_path.some((hash) => !SHA256_HEX_RE.test(hash))) {
    return bad("shape", LEDGER_ERRORS.PROOF_MALFORMED, "entry or inclusion fields are malformed");
  }
  if (!isObj(trustedBundle) || !isObj(trustedBundle.root_key)) {
    return bad("trust", LEDGER_ERRORS.NO_TRUST_BUNDLE, "a trusted authority bundle is required");
  }
  const trustedRootFingerprint = options.trustedRootFingerprint ?? trustedBundle.root_key.fingerprint;
  const now = checkpoint.issued_at; // operator-asserted time; used ONLY for key validity
  const authority = await verifyAuthorityBundle(trustedBundle, { trustedRootFingerprint, now });
  if (!authority.ok) {
    return bad("trust", LEDGER_ERRORS.NO_TRUST_BUNDLE, `authority bundle rejected: ${authority.reason}`);
  }

  // ── 1. Receipt signature / integrity ─────────────────────────────────────────
  if (isSignedReceiptEnvelope(receipt)) {
    const att = await verifyCustodyAttestation(receipt, {
      authorityBundle: trustedBundle,
      trustedRootFingerprint,
      now,
      environmentId: options.executorEnvironmentId,
      expectedExecutorId: options.expectedExecutorId
    });
    if (!att.ok) return bad("receipt", LEDGER_ERRORS.RECEIPT_INVALID, att.reason);
  } else {
    const r = await verifyPolicyReceipt(receipt);
    if (!r.verified) return bad("receipt", LEDGER_ERRORS.RECEIPT_INVALID, r.reason ?? "receipt did not verify");
  }

  // ── 2. Receipt-to-entry binding ──────────────────────────────────────────────
  if (canonicalReceiptHash(receipt) !== entry.receipt_hash) {
    return bad("binding", LEDGER_ERRORS.RECEIPT_BINDING, "receipt bytes do not match entry.receipt_hash");
  }

  // ── 3. Entry signature (ledger key) ──────────────────────────────────────────
  if (computeEntryHash(entry) !== entry.entry_hash) {
    return bad("entry", LEDGER_ERRORS.ENTRY_HASH, "entry_hash does not match recomputed body");
  }
  const esig = entry.signature;
  if (!isObj(esig) || esig.algorithm !== LEDGER_SIGNATURE_ALGORITHM ||
      typeof esig.value !== "string" || typeof esig.key_id !== "string") {
    return bad("entry", LEDGER_ERRORS.SIGNATURE_MISSING, "entry signature missing/malformed");
  }
  const echeck = await verifyAgainstBundle(ledgerSignablePayload(entry), esig.value, LEDGER_SIGNING_ROLE, esig.key_id, entry.created_at, trustedBundle);
  if (!echeck.ok) {
    const code = echeck.reason === "SIGNATURE_INVALID" ? LEDGER_ERRORS.SIGNATURE_INVALID : LEDGER_ERRORS.SIGNATURE_KEY_UNTRUSTED;
    return bad("entry", code, `entry signature rejected: ${echeck.reason}`);
  }

  // ── 4. Merkle inclusion in the checkpoint's tree ─────────────────────────────
  if (inclusion.tree_size !== checkpoint.tree_size) {
    return bad("inclusion", LEDGER_ERRORS.INCLUSION_INVALID, "inclusion tree_size != checkpoint tree_size");
  }
  if (inclusion.leaf_index !== entry.sequence - 1) {
    return bad("inclusion", LEDGER_ERRORS.INCLUSION_INVALID, "leaf_index does not match entry sequence");
  }
  const leaf = leafHash(entry.entry_hash);
  if (!verifyInclusion(leaf, inclusion.leaf_index, inclusion.tree_size, inclusion.audit_path ?? [], checkpoint.root_hash)) {
    return bad("inclusion", LEDGER_ERRORS.INCLUSION_INVALID, "audit path does not reproduce the checkpoint root");
  }

  // ── 5. Checkpoint binding + signature ────────────────────────────────────────
  if (checkpoint.log_id !== trustedRootFingerprint) {
    return bad("checkpoint", LEDGER_ERRORS.CHECKPOINT_LOG_ID_MISMATCH, "checkpoint log_id != trusted root fingerprint");
  }
  const csig = checkpoint.signature;
  if (!isObj(csig) || csig.algorithm !== LEDGER_SIGNATURE_ALGORITHM ||
      typeof csig.value !== "string" || typeof csig.key_id !== "string") {
    return bad("checkpoint", LEDGER_ERRORS.CHECKPOINT_MALFORMED, "checkpoint signature missing/malformed");
  }
  // key_id must equal signature key_id AND the key recorded at key_epoch — a rotated
  // historical key is only usable for the epoch it was recorded under.
  const ledgerKeys = Array.isArray(trustedBundle.keys?.ledger) ? trustedBundle.keys.ledger : [];
  const epochKey = ledgerKeys[checkpoint.key_epoch];
  if (checkpoint.key_id !== csig.key_id || !epochKey || epochKey.key_id !== checkpoint.key_id) {
    return bad("checkpoint", LEDGER_ERRORS.CHECKPOINT_KEY_EPOCH_MISMATCH, "key_id/key_epoch do not agree with the authority bundle");
  }
  // Validity window + revocation enforced here (via signedAt = issued_at).
  const ccheck = await verifyAgainstBundle(checkpointSignablePayload(checkpoint), csig.value, LEDGER_SIGNING_ROLE, csig.key_id, now, trustedBundle);
  if (!ccheck.ok) {
    const code = ccheck.reason === "SIGNATURE_INVALID" ? LEDGER_ERRORS.CHECKPOINT_SIGNATURE_INVALID : LEDGER_ERRORS.CHECKPOINT_KEY_UNTRUSTED;
    return bad("checkpoint", code, `checkpoint signature rejected: ${ccheck.reason}`);
  }
  if (entry.sequence === checkpoint.tree_size && checkpoint.ledger_head.entry_hash !== entry.entry_hash) {
    return bad("checkpoint", LEDGER_ERRORS.CHECKPOINT_MALFORMED, "checkpoint ledger_head does not match the terminal proof entry");
  }

  // ── 6. Success ───────────────────────────────────────────────────────────────
  return {
    ok: true,
    assurance: LEDGER_ASSURANCE.OPERATOR_SIGNED_INCLUSION,
    time_basis: "operator-asserted", // issued_at is a claim, not proof of time
    log_id: checkpoint.log_id,
    tree_size: checkpoint.tree_size,
    root_hash: checkpoint.root_hash,
    sequence: entry.sequence,
    revoked_now: Boolean(ccheck.revoked_now || echeck.revoked_now),
    note: "Operator-signed inclusion: the receipt is included in a history the ledger key committed to. This is NOT proof of a rewrite-resistant history (requires witnesses)."
  };
}
