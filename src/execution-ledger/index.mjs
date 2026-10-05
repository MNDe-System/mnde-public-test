// MNDe V1 Execution Ledger — public surface.
//
// A tamper-evident, append-only hash chain OVER finalized receipts. It is a
// separate integrity layer: it does not change the canonical receipt format, the
// signed envelope, the receipt signing path, or standalone receipt verification.
// Each ledger entry commits to the receipt's canonical hash, the previous entry's
// hash, a monotonic sequence number, a creation timestamp, and the metadata a
// verifier needs to re-find and re-hash the receipt. Delete, edit, reorder, or
// replace a receipt (or a ledger line) and chain verification fails closed.
//
// Hashing reuses the SAME canonicalizer used for receipt signatures
// (canonicalizeJson) and the SAME sha256 helper used elsewhere. No new JSON
// canonicalizer is invented here.

import { canonicalizeJson } from "../../shared/json.ts";
import { sha256Hex } from "../../shared/receipt-replay.mjs";

// v1 = legacy keyless hash-chain entry (frozen; readable only in legacy mode).
// v2 = hash-chain entry PLUS a custody ledger-key signature over the entry_hash.
// The signature is what makes excision-and-rebuild infeasible: recomputing a
// forged chain also requires re-signing every entry, which an attacker without
// the ledger signing key cannot do.
export const LEDGER_ENTRY_SCHEMA = "mnde.execution_ledger.entry.v1";
export const LEDGER_ENTRY_SCHEMA_V2 = "mnde.execution_ledger.entry.v2";
export const LEDGER_ENTRY_SCHEMAS = Object.freeze([LEDGER_ENTRY_SCHEMA, LEDGER_ENTRY_SCHEMA_V2]);
export const LEDGER_VERIFY_RESULT_SCHEMA = "mnde.execution_ledger.verify_result.v1";

// Anchoring (Phase 1): a CT-style Merkle transparency layer over the entry
// sequence. A checkpoint is a signed tree head; an inclusion proof lets a
// counterparty verify ONE receipt offline against a checkpoint.
export const LEDGER_CHECKPOINT_SCHEMA = "mnde.execution_ledger.checkpoint.v1";
export const LEDGER_INCLUSION_PROOF_SCHEMA = "mnde.execution_ledger.inclusion_proof.v1";
export const LEDGER_CHECKPOINT_VERSION = 1;
// Assurance a proof reports. Phase 1 = operator-signed inclusion: the receipt is
// provably included in a history the ledger key committed to — it does NOT prove
// the history is rewrite-resistant (an operator holding the key could re-anchor a
// rewritten history). WITNESSED (Phase 2) is the rewrite-resistant level.
export const LEDGER_ASSURANCE = Object.freeze({
  OPERATOR_SIGNED_INCLUSION: "operator-signed-inclusion",
  WITNESSED: "witnessed"
});

// The custody role and algorithm the ledger signature uses. "ledger" keys are
// already published in mnde.authority.bundle.v1 and exercised by custody
// rotation/revocation — this wires that existing key into the chain.
export const LEDGER_SIGNING_ROLE = "ledger";
export const LEDGER_SIGNATURE_ALGORITHM = "ED25519";

// Stable, documented error codes. These are part of the ledger's contract.
export const LEDGER_ERRORS = Object.freeze({
  PARSE: "ERR_LEDGER_PARSE",
  SCHEMA: "ERR_LEDGER_SCHEMA",
  SEQUENCE: "ERR_LEDGER_SEQUENCE",
  CHAIN_BROKEN: "ERR_LEDGER_CHAIN_BROKEN",
  ENTRY_HASH: "ERR_LEDGER_ENTRY_HASH",
  RECEIPT_REF_UNSAFE: "ERR_LEDGER_RECEIPT_REF_UNSAFE",
  RECEIPT_MISSING: "ERR_LEDGER_RECEIPT_MISSING",
  RECEIPT_HASH: "ERR_LEDGER_RECEIPT_HASH",
  DUPLICATE_SEQUENCE: "ERR_LEDGER_DUPLICATE_SEQUENCE",
  DUPLICATE_ENTRY_HASH: "ERR_LEDGER_DUPLICATE_ENTRY_HASH",
  APPEND_FAILED: "ERR_LEDGER_APPEND_FAILED",
  LOCK_FAILED: "ERR_LEDGER_LOCK_FAILED",
  DISABLED_IN_PRODUCTION: "ERR_LEDGER_DISABLED_IN_PRODUCTION",
  // v2 signature contract.
  SIGNER_REQUIRED: "ERR_LEDGER_SIGNER_REQUIRED",
  SIGNATURE_MISSING: "ERR_LEDGER_SIGNATURE_MISSING",
  SIGNATURE_INVALID: "ERR_LEDGER_SIGNATURE_INVALID",
  SIGNATURE_KEY_UNTRUSTED: "ERR_LEDGER_SIGNATURE_KEY_UNTRUSTED",
  NO_TRUST_BUNDLE: "ERR_LEDGER_NO_TRUST_BUNDLE",
  LEGACY_ENTRY_REJECTED: "ERR_LEDGER_LEGACY_ENTRY_REJECTED",
  // Anchoring / inclusion-proof contract (Phase 1).
  ANCHOR_FAILED: "ERR_LEDGER_ANCHOR_FAILED",
  ANCHOR_KEY_UNRESOLVED: "ERR_LEDGER_ANCHOR_KEY_UNRESOLVED",
  CHECKPOINT_MALFORMED: "ERR_LEDGER_CHECKPOINT_MALFORMED",
  CHECKPOINT_SIGNATURE_INVALID: "ERR_LEDGER_CHECKPOINT_SIGNATURE_INVALID",
  CHECKPOINT_KEY_UNTRUSTED: "ERR_LEDGER_CHECKPOINT_KEY_UNTRUSTED",
  CHECKPOINT_LOG_ID_MISMATCH: "ERR_LEDGER_CHECKPOINT_LOG_ID_MISMATCH",
  CHECKPOINT_KEY_EPOCH_MISMATCH: "ERR_LEDGER_CHECKPOINT_KEY_EPOCH_MISMATCH",
  CHECKPOINT_ROLLBACK: "ERR_LEDGER_CHECKPOINT_ROLLBACK",
  CHECKPOINT_EQUIVOCATION: "ERR_LEDGER_CHECKPOINT_EQUIVOCATION",
  RECEIPT_INVALID: "ERR_LEDGER_RECEIPT_INVALID",
  RECEIPT_BINDING: "ERR_LEDGER_RECEIPT_BINDING",
  INCLUSION_INVALID: "ERR_LEDGER_INCLUSION_INVALID",
  NOT_ANCHORED: "ERR_LEDGER_NOT_ANCHORED",
  PROOF_MALFORMED: "ERR_LEDGER_PROOF_MALFORMED"
});

// sha256:<hex> of canonical bytes. The "sha256:" prefix names the algorithm in
// the stored ledger so a future hash agility change is explicit, not silent.
export function sha256Prefixed(bytes) {
  return `sha256:${sha256Hex(bytes)}`;
}

// Canonical hash of a receipt object exactly as stored. Reuses canonicalizeJson,
// the same canonicalization the receipt signature is taken over, so re-parsing a
// persisted receipt and re-hashing reproduces this value byte-for-byte (the
// frozen integer-only number model guarantees the round-trip is exact).
export function canonicalReceiptHash(receipt) {
  return sha256Prefixed(canonicalizeJson(receipt));
}

// The body a ledger entry's entry_hash commits to: every field EXCEPT entry_hash
// and signature. canonicalizeJson sorts keys, so object construction order is
// irrelevant. Excluding signature keeps entry_hash a pure function of the entry's
// content, so the signature can be taken over entry_hash without a circular
// dependency.
export function ledgerEntryBody(entry) {
  const { entry_hash: _h, signature: _s, ...body } = entry;
  return body;
}

export function computeEntryHash(entryWithoutHash) {
  return sha256Prefixed(canonicalizeJson(ledgerEntryBody(entryWithoutHash)));
}

// The exact canonical bytes the ledger signature is taken over: the full entry
// INCLUDING its committed entry_hash, minus the signature envelope itself. Signing
// this binds the signature to entry_hash — hence to previous_entry_hash and
// receipt_hash, i.e. the entry's whole chain position. Reproduced byte-for-byte at
// verify time, so a re-signed excision is impossible without the ledger key.
export function ledgerSignablePayload(entryWithHash) {
  const { signature: _omit, ...rest } = entryWithHash;
  return canonicalizeJson(rest);
}

// The canonical bytes a checkpoint signature is taken over: the full checkpoint
// minus its signature envelope. This covers schema, version, log_id, tree_size,
// root_hash, key_id, key_epoch, issued_at, and ledger_head — so tampering with any
// of them breaks the signature. issued_at is included but is the operator's CLAIM
// of signing time, not trusted proof of time (a verifier must not treat it as such).
export function checkpointSignablePayload(checkpointWithoutSig) {
  const { signature: _omit, ...rest } = checkpointWithoutSig;
  return canonicalizeJson(rest);
}

export { resolveLedgerPath, isLedgerDisabled, isProductionProfile, ledgerStartupGate, DEFAULT_LEDGER_PATH } from "./paths.mjs";
export { appendLedgerEntry, buildLedgerEntry } from "./append.mjs";
export { verifyLedger } from "./verify.mjs";
// merkle.mjs / anchor.mjs / proof.mjs import constants FROM this module and are
// imported directly by consumers (kept out of here to avoid an import cycle).
