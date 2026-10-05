// RFC 6962 Merkle tree — pure, byte-precise, no I/O.
//
// This is the anchoring commitment structure over the execution ledger's entry
// sequence. It is deliberately independent of the ledger signing key and of any
// runtime state: given the same leaf inputs it produces byte-identical roots and
// proofs on any machine and in any language (test vectors in
// tests/vectors/ledger-anchoring/ pin this for TS/Go/Rust verifier parity).
//
// Domain separation (RFC 6962 §2.1) is mandatory and is the whole point of the
// prefix bytes: a leaf hash and an interior-node hash are computed over disjoint
// input spaces, so no leaf can be forged to equal an interior node.
//
//   leaf(h)        = SHA256(0x00 ‖ h)          where h is the 32 raw bytes of entry_hash
//   node(l, r)     = SHA256(0x01 ‖ l ‖ r)      where l, r are 32 raw bytes each
//
// Hashes cross the API as canonical "sha256:<hex>" strings (same convention as the
// rest of the ledger); bytes are only used internally for hashing. Hashing routes
// through the shared sha256 helper (no direct node:crypto import — crypto stays
// centralized). sha256Hex over Buffer.concat(...) is byte-identical to a sequence
// of hash.update() calls, so the domain-separated inputs hash exactly as specified.

import { sha256Hex } from "../../shared/receipt-replay.mjs";

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;

function toBytes(prefixed) {
  if (typeof prefixed !== "string" || !SHA256_HEX_RE.test(prefixed)) {
    throw new Error(`merkle: expected a 'sha256:<64 hex>' value, got ${JSON.stringify(prefixed)}`);
  }
  return Buffer.from(prefixed.slice("sha256:".length), "hex");
}

function sha256Prefixed(...buffers) {
  return `sha256:${sha256Hex(Buffer.concat(buffers))}`;
}

// leaf hash of an entry_hash (itself a "sha256:<hex>" string).
export function leafHash(entryHash) {
  return sha256Prefixed(Buffer.from([LEAF_PREFIX]), toBytes(entryHash));
}

// interior node hash over two child hashes (each "sha256:<hex>").
export function nodeHash(left, right) {
  return sha256Prefixed(Buffer.from([NODE_PREFIX]), toBytes(left), toBytes(right));
}

// Largest power of two strictly less than n (n >= 2). e.g. 2->1, 4->2, 5->4, 8->4.
function largestPow2LessThan(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

// Merkle root over an array of leaf hashes (already leaf-hashed). RFC 6962 MTH,
// operating on precomputed leaves (the leaf-hashing step is leafHash() above).
//   n == 0 : SHA256 of the empty string (RFC 6962 MTH({}))
//   n == 1 : the single leaf
//   n  > 1 : node(MTH(left k), MTH(right n-k))
export function merkleRoot(leaves) {
  if (!Array.isArray(leaves)) throw new Error("merkle: leaves must be an array");
  const n = leaves.length;
  if (n === 0) return sha256Prefixed(Buffer.alloc(0));
  if (n === 1) return leaves[0];
  const k = largestPow2LessThan(n);
  return nodeHash(merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

// Inclusion (audit) path for leaf at 0-based index m among n leaves. RFC 6962
// PATH(m, D[n]): sibling hashes ordered leaf→root (nearest sibling first, the
// top-most split's sibling last).
export function inclusionProof(leaves, m) {
  const n = leaves.length;
  if (!Number.isInteger(m) || m < 0 || m >= n) {
    throw new Error(`merkle: index ${m} out of range for ${n} leaves`);
  }
  if (n === 1) return [];
  const k = largestPow2LessThan(n);
  if (m < k) {
    return [...inclusionProof(leaves.slice(0, k), m), merkleRoot(leaves.slice(k))];
  }
  return [...inclusionProof(leaves.slice(k), m - k), merkleRoot(leaves.slice(0, k))];
}

// Recompute the root from a leaf hash, its 0-based index m, the tree size n, and
// the audit path. Mirrors PATH: the LAST path element is this level's sibling.
// Pure and deterministic — this is exactly what an offline verifier runs.
export function rootFromInclusionProof(leaf, m, n, auditPath) {
  if (!Number.isInteger(m) || m < 0 || m >= n) {
    throw new Error(`merkle: index ${m} out of range for ${n} leaves`);
  }
  if (n === 1) {
    if (auditPath.length !== 0) throw new Error("merkle: non-empty path for single-leaf tree");
    return leaf;
  }
  const k = largestPow2LessThan(n);
  if (auditPath.length === 0) throw new Error("merkle: audit path too short");
  const sibling = auditPath[auditPath.length - 1];
  const rest = auditPath.slice(0, -1);
  if (m < k) {
    return nodeHash(rootFromInclusionProof(leaf, m, k, rest), sibling);
  }
  return nodeHash(sibling, rootFromInclusionProof(leaf, m - k, n - k, rest));
}

// Verify inclusion: recompute the root and constant-time-ish compare to expected.
export function verifyInclusion(leaf, m, n, auditPath, expectedRoot) {
  let computed;
  try {
    computed = rootFromInclusionProof(leaf, m, n, auditPath);
  } catch {
    return false;
  }
  return computed === expectedRoot;
}
