// Conjunct A — Encoding & canonicalization.
//
// Property under test:  enc(X) = enc(Y)  ⇒  X ≡auth Y
// The FAIL condition is a COLLISION: two security-distinct inputs that produce
// the same canonical identity. We drive MNDe's real canonicalizer/parser.
//
// enc(request) in MNDe = SHA-256 over canonicalizeJson(parseStrictJson(bytes)).
// We compare canonicalizeJson output directly (the pre-image of the hash); equal
// canonical strings ⇒ equal request_hash ⇒ same authorization identity.

import { canonicalizeJson, parseStrictJson } from "../../../shared/json.ts";
import { record, writeEvidence } from "../harness/common.mjs";

const results = [];
const notes = [];

// Canonical identity of a raw JSON byte string, or a structured parse failure.
function identity(bytes) {
  const parsed = parseStrictJson(bytes);
  if (!parsed.ok) return { ok: false, reason: parsed.reason };
  return { ok: true, canon: canonicalizeJson(parsed.value) };
}

// A collision test: two DISTINCT real actions must NOT share one identity.
// pass = identities differ (or one is rejected). fail = identical identity.
function collisionCase(id, label, aBytes, bBytes, semanticallyDistinct = true) {
  const a = identity(aBytes);
  const b = identity(bBytes);
  const bothOk = a.ok && b.ok;
  const collide = bothOk && a.canon === b.canon;
  const observed = {
    a: a.ok ? a.canon : `REJECTED:${a.reason}`,
    b: b.ok ? b.canon : `REJECTED:${b.reason}`,
    collision: collide
  };
  // For distinct inputs, a collision is FAIL; distinct identities (or a strict
  // rejection of one) is PASS. For inputs we EXPECT to be equal (key-order), a
  // collision is the correct/PASS behavior.
  let verdict;
  if (semanticallyDistinct) verdict = collide ? "FAIL" : "PASS";
  else verdict = collide ? "PASS" : "FAIL";
  results.push(record(id, "A-encoding", verdict,
    semanticallyDistinct ? "distinct identities" : "identical identity",
    observed, { label }));
}

// A rejection test: malformed/ambiguous serialization must be refused by the
// strict parser rather than silently accepted.
function rejectionCase(id, label, bytes, expectReason) {
  const r = parseStrictJson(bytes);
  const verdict = (!r.ok && (!expectReason || r.reason === expectReason)) ? "PASS" : "FAIL";
  results.push(record(id, "A-encoding", verdict,
    `reject (${expectReason ?? "any"})`, r.ok ? "ACCEPTED" : `REJECTED:${r.reason}`, { label }));
}

// A1: key order must not change identity (canonicalization actually canonicalizes).
collisionCase("A1", "key-order independence",
  '{"repository":"r","target_ref":"main","operation":"merge"}',
  '{"operation":"merge","target_ref":"main","repository":"r"}', false);

// A2: duplicate keys must be rejected (no last-wins ambiguity).
rejectionCase("A2", "duplicate key rejection",
  '{"target_ref":"main","target_ref":"production"}', "duplicate_json_keys");

// A3: string "17" vs number 17 must be distinct identities (no type coercion).
collisionCase("A3", "numeric-vs-string PR id",
  '{"pull_request":17}', '{"pull_request":"17"}', true);

// A4: refs must be exact — main vs refs/heads/main are distinct strings.
collisionCase("A4", "short vs full ref",
  '{"target_ref":"main"}', '{"target_ref":"refs/heads/main"}', true);

// A5: case sensitivity — main vs Main distinct.
collisionCase("A5", "ref case sensitivity",
  '{"target_ref":"main"}', '{"target_ref":"Main"}', true);

// A6: Unicode NFC vs NFD of the same grapheme are distinct byte strings.
// MNDe does NOT Unicode-normalize (documented characteristic). For the collision
// property this is SAFE (distinct → distinct). We assert distinctness AND record
// the non-normalization as a note for downstream adapters.
const nfc = "café";          // é as U+00E9
const nfd = "café";         // e + combining acute U+0301
collisionCase("A6", "unicode NFC vs NFD",
  JSON.stringify({ target_ref: nfc }), JSON.stringify({ target_ref: nfd }), true);
notes.push("A6: MNDe applies no Unicode normalization; NFC and NFD forms are distinct authorization identities. Safe against collision, but a downstream executor that normalizes refs before acting could re-introduce ambiguity (Stage 2 concern).");

// A7: leading/trailing whitespace inside a string value is significant (not trimmed).
collisionCase("A7", "value whitespace significance",
  '{"target_ref":"main"}', '{"target_ref":"main "}', true);

// A8: float / exponent numbers are rejected (constrained number model).
rejectionCase("A8", "float rejected", '{"hours":1.5}', "invalid_json_number");
rejectionCase("A8b", "exponent rejected", '{"hours":1e3}', "invalid_json_number");

// A9: unsafe integers rejected (no silent precision loss that could alias ids).
rejectionCase("A9", "unsafe integer rejected", '{"pull_request":9007199254740993}', "invalid_json_number");

// A10: whitespace BETWEEN tokens must not change identity (structural).
collisionCase("A10", "inter-token whitespace",
  '{"a":1,"b":2}', '{ "a" : 1 , "b" : 2 }', false);

const summary = {
  conjunct: "A-encoding",
  total: results.length,
  fail: results.filter((r) => r.verdict === "FAIL").length,
  inconclusive: results.filter((r) => r.verdict === "INCONCLUSIVE").length,
  notes,
  results
};
writeEvidence("A_encoding.json", summary);
for (const r of results) console.log(`  [${r.verdict}] ${r.id} ${r.detail.label}`);
console.log(`A-encoding: ${summary.total - summary.fail - summary.inconclusive}/${summary.total} PASS, ${summary.fail} FAIL`);

export default summary;
