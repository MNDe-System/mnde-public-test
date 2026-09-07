// Generalized, high-confidence package-boundary secret scanner.
//
// This is the successor to the earlier content-based *private-key* scan
// (build/lib/private-key-scan.mjs, now a thin re-export of this module). It
// keeps every property that scan already had — content-based (not filename- or
// extension-based), byte-accurate on malformed/binary content, and fail-closed
// — and broadens the recognized secret set beyond PEM headers.
//
// WHAT THIS DETECTS (each with a stable detector id):
//   pem-private-key       Five standard PEM private-key headers (unchanged from
//                         the prior scan): PRIVATE KEY, RSA/EC/OPENSSH/ENCRYPTED.
//   der-private-key       Complete-file binary DER private keys (PKCS#8, PKCS#1
//                         RSA, SEC1 EC), verified by Node's own crypto parser —
//                         never by weak byte heuristics.
//   jwk-private-key       JSON Web Keys carrying a private parameter `d`
//                         (kty RSA / EC / OKP).
//   jwk-symmetric-key     Symmetric JWKs (kty oct) with populated key material `k`.
//   putty-private-key     PuTTY key containers (v2/v3) with populated
//                         Private-Lines material.
//   token-<provider>      A conservative registry of recognizable provider
//                         secret-token formats (see PROVIDER_TOKEN_DETECTORS).
//   credential-assignment High-entropy values assigned to an explicitly
//                         secret-bearing field name (JSON / dotenv / YAML /
//                         simple assignment).
//
// WHAT THIS DELIBERATELY DOES NOT DO — do not claim broader coverage:
//   * It is NOT exhaustive secret detection. Provider token formats change over
//     time and this registry is non-exhaustive.
//   * It does not recognize unknown/proprietary credential formats, encrypted or
//     custom binary containers, or key material with no textual/structural
//     marker.
//   * It does not attempt "high entropy anywhere" scanning — that would flag
//     hashes, signatures, receipts, and compiled assets. Entropy is only ever
//     considered for a value already bound to a secret-bearing field name.
//   * Secrets split, encoded, compressed, or obfuscated across multiple values
//     are not guaranteed to be found.
//   * It covers the npm package boundary only — not runtime logs, user-supplied
//     request content, or external systems. It is not a substitute for
//     repository, CI, host, or organization-level secret scanning.
//
// PRIVACY: a finding NEVER contains the matched secret or its surrounding
// content. Findings carry only { detectorId, relativePath, line, fingerprint },
// where fingerprint is a truncated SHA-256 of the matched material — enough to
// correlate and allowlist a specific occurrence, not enough to recover it.

import { readdirSync, readFileSync, lstatSync } from "node:fs";
import { join } from "node:path";
import { createHash, createPrivateKey } from "node:crypto";

// ---------------------------------------------------------------------------
// Detector ids
// ---------------------------------------------------------------------------
export const DETECTOR_PEM = "pem-private-key";
export const DETECTOR_DER = "der-private-key";
export const DETECTOR_JWK_PRIVATE = "jwk-private-key";
export const DETECTOR_JWK_SYMMETRIC = "jwk-symmetric-key";
export const DETECTOR_PUTTY = "putty-private-key";
export const DETECTOR_CREDENTIAL_ASSIGNMENT = "credential-assignment";

// Private-key-class findings that must NEVER be suppressible by an allowlist.
// (PEM, DER, JWK private, JWK symmetric key material, and PuTTY.) An allowlist
// entry naming one of these ids is treated as malformed and fails closed.
export const NON_ALLOWLISTABLE_DETECTORS = new Set([
  DETECTOR_PEM,
  DETECTOR_DER,
  DETECTOR_JWK_PRIVATE,
  DETECTOR_JWK_SYMMETRIC,
  DETECTOR_PUTTY
]);

// Preserved verbatim for backward compatibility with callers that imported it
// from the old private-key-scan module. Matches exactly the five PEM headers.
export const PRIVATE_KEY_MARKER = /BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY/;

// ---------------------------------------------------------------------------
// Provider secret-token registry.
//
// NON-EXHAUSTIVE AND SUBJECT TO CHANGE: provider token formats evolve; new
// providers and formats are not covered until added here. Every pattern is
// deliberately conservative — it targets the *secret* form of a credential and
// is written to avoid matching public identifiers, publishable keys, ordinary
// UUIDs, JWTs, commit hashes, or non-secret access-key IDs. Add new detectors
// here rather than scattering token regexes through the codebase.
// ---------------------------------------------------------------------------
export const PROVIDER_TOKEN_DETECTORS = [
  {
    // GitHub PATs / OAuth / server / refresh tokens (ghp_/gho_/ghu_/ghs_/ghr_
    // + 36 base62) and fine-grained PATs (github_pat_ + 82 chars). Not the
    // legacy 40-hex token, which is indistinguishable from a commit hash.
    id: "token-github",
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/g
  },
  {
    // GitLab personal access token: glpat- + 20 url-safe chars.
    id: "token-gitlab",
    pattern: /\bglpat-[A-Za-z0-9_-]{20}\b/g
  },
  {
    // npm automation/access token: npm_ + 36 base62.
    id: "token-npm",
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g
  },
  {
    // Slack bot/user/app tokens: xoxb-/xoxp-/xoxa-/xoxr-/xoxs- + long body.
    id: "token-slack",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g
  },
  {
    // Stripe LIVE secret / restricted keys only (sk_live_ / rk_live_). Never
    // publishable keys (pk_live_/pk_test_) or test secrets (sk_test_).
    id: "token-stripe-live",
    pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b/g
  },
  {
    // OpenAI secret / project / service-account keys: sk-..., sk-proj-...,
    // sk-svcacct-.... Uses a hyphen (Stripe uses an underscore), so the two do
    // not collide. Requires a 20+ char body at a word boundary.
    id: "token-openai",
    pattern: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g
  }
];

// ---------------------------------------------------------------------------
// Contextual credential-assignment detector configuration
// ---------------------------------------------------------------------------
// Field names that are explicitly secret-bearing. Compared case-insensitively
// against the assigned key (so `apiKey`, `API_KEY`, `api_key` all match).
const SECRET_FIELD_NAMES = new Set([
  "password",
  "passwd",
  "api_key",
  "apikey",
  "secret",
  "client_secret",
  "access_token",
  "auth_token",
  "private_token",
  "aws_secret_access_key"
]);

// A value is only considered a credential when ALL of these hold:
//   * the field name is explicitly secret-bearing (above);
//   * the value uses only the Base64 / Base64URL alphabet (letters, digits and
//     `/ + _ - =`) — including `/` and `//`, which real standard-Base64 secrets
//     do contain; characters that mark a reference/URL/interpolation instead
//     (`:`, `.`, `{`, `}`, `$`, `<`, `>`, whitespace) are absent from this
//     class, and the explicit reference/path/placeholder checks below reject
//     the remainder structurally rather than by banning any secret character;
//   * it meets a conservative minimum length;
//   * a digit is NOT required — strong length, character diversity, and entropy
//     stand in for it, so all-letter Base64URL key material is still caught; a
//     pure run of letters simply needs stronger evidence (see below) so ordinary
//     long code identifiers on a secret-named field are not misread;
//   * it has enough distinct characters / entropy to resemble a credential;
//   * it is not an obvious reference, URL, filesystem path, or placeholder.
const CREDENTIAL_MIN_LENGTH = 16;
const CREDENTIAL_MIN_DISTINCT = 10;
const CREDENTIAL_MIN_ENTROPY = 3.2; // Shannon bits per character
// Full Base64 / Base64URL alphabet. `/` and `+` are deliberately permitted:
// standard-Base64 secrets contain them (e.g. `...01//234567+AB`). URLs and
// references are excluded because they carry `:`/`.`/`{`/`$` which are NOT in
// this class, and absolute paths are rejected structurally below.
const CREDENTIAL_VALUE_SHAPE = /^[A-Za-z0-9_+/=-]{16,512}$/;
// A symmetric JWK `k` is Base64URL key material (no `/` or `+`).
const SYMMETRIC_KEY_MIN_LENGTH = 16;
const SYMMETRIC_KEY_SHAPE = /^[A-Za-z0-9_-]+={0,2}$/;
const PLACEHOLDER_WORDS = [
  "redacted",
  "replace",
  "changeme",
  "change_me",
  "example",
  "placeholder",
  "sample",
  "dummy",
  "your_",
  "your-",
  "xxxx",
  "test_token",
  "notarealsecret",
  "insert"
];

// Key/value on a single line, across JSON / dotenv / YAML / simple-assignment
// forms. The value capture stops at whitespace, quotes, commas, and closing
// braces, so a quoted JSON value yields just the inner token. The capture length
// bound MUST cover the full credential-value length range (up to 512, see
// CREDENTIAL_VALUE_SHAPE) — a shorter cap here would silently miss long secrets
// that isCredentialValue would otherwise flag.
const ASSIGNMENT_RE =
  /(?:^|[\s,{[])(["']?)([A-Za-z_][A-Za-z0-9_]*)\1\s*[:=]\s*(["']?)([^\s"',}\]]{8,512})\3/g;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
export class SecretScanError extends Error {
  constructor(message) {
    super(message);
    this.name = "SecretScanError";
  }
}

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------
function toPosix(relPath) {
  return relPath.split(/[\\/]/).join("/");
}

function fromPosix(rootDir, relPosix) {
  return join(rootDir, ...relPosix.split("/"));
}

// 1-based line number of a byte index within latin1 text.
function lineOf(latin1, index) {
  let line = 1;
  const end = Math.min(index, latin1.length);
  for (let i = 0; i < end; i++) {
    if (latin1.charCodeAt(i) === 10) line++;
  }
  return line;
}

// Truncated SHA-256 of the matched material. Prefixed "sha256-". This is the
// ONLY thing derived from the secret that ever leaves this module, and it is a
// one-way digest — the secret cannot be recovered from it.
function fingerprintOf(value) {
  return "sha256-" + createHash("sha256").update(value, "latin1").digest("hex").slice(0, 16);
}

function shannonEntropy(str) {
  const counts = new Map();
  for (const ch of str) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const c of counts.values()) {
    const p = c / str.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

function distinctChars(str) {
  return new Set(str).size;
}

// True when the value is not a real secret but a reference, interpolation,
// URL, redaction, or documentation placeholder. These are rejected explicitly
// (by shape, not by banning valid secret characters) so that, e.g., a genuine
// Base64 secret containing `/` is not thrown out alongside a URL.
function isReferenceOrPlaceholder(value) {
  const v = value.trim();
  if (v.length === 0) return true;
  if (/\$\{[^}]*\}/.test(v)) return true; // ${TOKEN}
  if (/^\$[A-Za-z_][A-Za-z0-9_]*$/.test(v)) return true; // $TOKEN
  if (/(^|[^A-Za-z0-9_])(process\.env|env)\.[A-Za-z_]/i.test(v)) return true; // process.env.X / env.X
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return true; // scheme:// (http, https, file, ...)
  if (/[<>]/.test(v)) return true; // <redacted>
  const lower = v.toLowerCase();
  if (PLACEHOLDER_WORDS.some((w) => lower.includes(w))) return true;
  if (/^(.)\1+$/.test(v)) return true; // a single repeated character
  return false;
}

// Contextual credential value gate. The field name is already known to be
// secret-bearing before this is called. A digit is NOT required; strong length,
// character diversity, and entropy stand in for it, so all-letter high-entropy
// key material is caught.
//
// FAIL CLOSED on the path/Base64 ambiguity: a value that is *simultaneously* a
// valid filesystem path and valid Base64 (e.g. `AbCd/EfGh/IjKl/MnOpQrStUv`) is
// NOT excused as a path — doing so would let a real Base64 secret ship. Only
// UNAMBIGUOUS references (URL schemes, `${...}`, `$VAR`, `process.env.X`,
// angle-bracket redactions, placeholder words, repeated dummies — all handled
// by isReferenceOrPlaceholder) are allowed through. Genuine path *references*
// that also meet the entropy/length bar are therefore reported here; that is the
// intended conservative outcome, and such a legitimate shipped value can be
// allowlisted with a written justification rather than silently missed.
function isCredentialValue(value) {
  if (value.length < CREDENTIAL_MIN_LENGTH) return false;
  if (!CREDENTIAL_VALUE_SHAPE.test(value)) return false;
  if (isReferenceOrPlaceholder(value)) return false;
  if (distinctChars(value) < CREDENTIAL_MIN_DISTINCT) return false;
  if (shannonEntropy(value) < CREDENTIAL_MIN_ENTROPY) return false;
  // When there is no digit and no Base64 special character (a pure run of
  // letters), demand stronger evidence so ordinary long code identifiers on a
  // secret-named field are not misread as a credential — while still catching
  // realistic all-letter Base64URL key material.
  if (!/[0-9_+/=-]/.test(value)) {
    if (value.length < 20 || distinctChars(value) < 12) return false;
  }
  return true;
}

// Symmetric JWK `k` classification — deliberately independent of the generic
// contextual-credential heuristic. The `k` of an `oct` JWK IS the symmetric
// secret; realistic key material may be all letters, so no digit or mixed-class
// requirement applies. Only explicit placeholders/references are excused.
function isSymmetricKeyMaterial(k) {
  const v = k.trim();
  if (v.length < SYMMETRIC_KEY_MIN_LENGTH) return false;
  if (!SYMMETRIC_KEY_SHAPE.test(v)) return false;
  if (isReferenceOrPlaceholder(v)) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Per-detector scans. Each returns partial findings { detectorId, line,
// fingerprint }; the engine attaches relativePath and sorts/dedupes.
// ---------------------------------------------------------------------------
function scanPem(latin1) {
  const out = [];
  const re = new RegExp(PRIVATE_KEY_MARKER.source, "g");
  let m;
  while ((m = re.exec(latin1)) !== null) {
    // Fingerprint the block from BEGIN to the matching END (or a bounded window
    // if the END marker is absent), so distinct keys fingerprint distinctly.
    const start = m.index;
    const endMarker = latin1.indexOf("-----END", start);
    const region = latin1.slice(start, endMarker >= 0 ? endMarker + 64 : start + 512);
    out.push({ detectorId: DETECTOR_PEM, line: lineOf(latin1, start), fingerprint: fingerprintOf(region) });
    if (re.lastIndex <= m.index) re.lastIndex = m.index + 1;
  }
  return out;
}

function scanDer(bytes) {
  // Only whole-file DER is considered. DER SEQUENCE tag is 0x30; anything that
  // does not start with it (PEM text, JSON, source, most binaries) is skipped
  // cheaply and cannot be a bare DER key. Node's crypto parser is the arbiter —
  // random bytes and DER *public* keys fail to parse as a private key.
  if (bytes.length < 40 || bytes[0] !== 0x30) return [];
  for (const type of ["pkcs8", "pkcs1", "sec1"]) {
    try {
      createPrivateKey({ key: bytes, format: "der", type });
      return [
        { detectorId: DETECTOR_DER, line: 1, fingerprint: fingerprintOf(bytes.toString("latin1")) }
      ];
    } catch {
      // Not this encoding — try the next.
    }
  }
  return [];
}

// Maximum structural nesting we will walk / track. This is a fail-closed guard,
// NOT a silent cap: exceeding it throws SecretScanError so the scan can never
// report "clean" merely because a structure was too deep to finish inspecting.
// It is set far above any nesting a real shipped artifact contains.
const JWK_MAX_DEPTH = 200;

// Recursively inspect a parsed JSON value (object, array, or a string whose
// decoded value is itself JSON) for private / symmetric JWK material. A private
// `d` and a symmetric `k` both appear verbatim in the source text, so indexOf
// yields an accurate line even for embedded or string-decoded JWKs. Depth is
// bounded by a THROW (fail closed), never a silent return.
function jwkFindingsFrom(node, latin1, acc, depth) {
  if (depth > JWK_MAX_DEPTH) {
    throw new SecretScanError("embedded JSON nesting exceeds the safe depth limit; failing closed");
  }
  if (typeof node === "string") {
    // A JWK serialized inside a JSON string: decode once and inspect it. Its
    // braces live inside a string in the raw text, so the textual region scan
    // below cannot see them — this is the path that catches them.
    const trimmed = node.trim();
    if (trimmed.length >= 2 && (trimmed[0] === "{" || trimmed[0] === "[")) {
      let inner;
      try {
        inner = JSON.parse(node);
      } catch {
        return; // not nested JSON
      }
      if (inner && typeof inner === "object") jwkFindingsFrom(inner, latin1, acc, depth + 1);
    }
    return;
  }
  if (Array.isArray(node)) {
    for (const item of node) jwkFindingsFrom(item, latin1, acc, depth + 1);
    return;
  }
  if (!node || typeof node !== "object") return;

  const kty = node.kty;
  if (typeof kty === "string") {
    if ((kty === "RSA" || kty === "EC" || kty === "OKP") && typeof node.d === "string" && node.d.length > 0) {
      const idx = latin1.indexOf(node.d);
      acc.push({
        detectorId: DETECTOR_JWK_PRIVATE,
        line: idx >= 0 ? lineOf(latin1, idx) : 1,
        fingerprint: fingerprintOf(node.d)
      });
    } else if (kty === "oct" && typeof node.k === "string" && isSymmetricKeyMaterial(node.k)) {
      // `k` IS the symmetric secret — classified by its own key-material gate,
      // NOT the generic contextual-credential heuristic.
      const idx = latin1.indexOf(node.k);
      acc.push({
        detectorId: DETECTOR_JWK_SYMMETRIC,
        line: idx >= 0 ? lineOf(latin1, idx) : 1,
        fingerprint: fingerprintOf(node.k)
      });
    }
  }

  for (const value of Object.values(node)) {
    if (value && typeof value === "object") jwkFindingsFrom(value, latin1, acc, depth + 1);
    else if (typeof value === "string") jwkFindingsFrom(value, latin1, acc, depth + 1);
  }
}

// Only regions that could actually be JSON are examined: a `{` whose first
// non-space content is `"` or `}`, or a `[` that opens a JSON value. This skips
// JavaScript blocks like `{ const key = ... }` cheaply, WITHOUT skipping the
// valid JSON object nested inside them (the outer loop advances into the block
// and reaches the inner `{` on its own).
function isPlausibleJsonStart(text, openerIndex, openerCh) {
  let k = openerIndex + 1;
  while (k < text.length) {
    const ch = text[k];
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") k++;
    else break;
  }
  const ch = text[k];
  if (ch === undefined) return false;
  if (openerCh === "{") return ch === '"' || ch === "}";
  return (
    ch === '"' || ch === "{" || ch === "[" || ch === "]" || ch === "-" ||
    (ch >= "0" && ch <= "9") || ch === "t" || ch === "f" || ch === "n"
  );
}

// Find the end of the balanced JSON region that STARTS at `start`, using
// JSON's own string rules (only `"` delimits a string, `\` escapes). Returns the
// index just past the closing brace/bracket, or -1 if the region does not close
// within the text. Throws (fails closed) if nesting exceeds the depth limit.
//
// Crucially, string tracking begins fresh AT the opener — it never carries state
// in from earlier in the file. That is the fix for the "a stray JavaScript quote
// desyncs the parser" bypass: a `"` in a comment or single-quoted JS string that
// sits BEFORE a JWK can no longer flip the scanner into a phantom string and
// swallow the JWK's opening brace, because each candidate is balanced on its own.
function balancedJsonEnd(text, start) {
  const n = text.length;
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = start; i < n; i++) {
    const c = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
    } else if (c === "{" || c === "[") {
      depth++;
      if (depth > JWK_MAX_DEPTH) {
        throw new SecretScanError("embedded JSON nesting exceeds the safe depth limit; failing closed");
      }
    } else if (c === "}" || c === "]") {
      depth--;
      if (depth === 0) return i + 1;
      if (depth < 0) return -1; // unbalanced close
    }
  }
  return -1; // never closed
}

// Inspect every balanced JSON object/array region embedded anywhere in the
// file's text — including regions nested inside NON-JSON JavaScript blocks — for
// JWK material. The outer loop looks only for `{`/`[` openers and does NOT track
// string state across the file, so arbitrary JS quoting cannot desync it; each
// candidate region is balanced and parsed independently starting at its own
// opener. On a valid-JSON region we inspect it and skip past it; otherwise we
// advance one character so a JSON JWK nested inside a non-JSON block is still
// reached on its own opener. There is NO cap on the number of regions — a
// resource limit must never silently make the scan report clean; the only bound
// is nesting depth, which fails closed (throws) via balancedJsonEnd.
function scanEmbeddedJson(text, latin1, acc) {
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i];
    if (c === "{" || c === "[") {
      if (isPlausibleJsonStart(text, i, c)) {
        const end = balancedJsonEnd(text, i); // may throw (fail closed) on excess depth
        if (end > i) {
          let parsed;
          try {
            parsed = JSON.parse(text.slice(i, end));
          } catch {
            parsed = undefined; // balanced but not JSON (e.g. a JS block)
          }
          if (parsed && typeof parsed === "object") {
            jwkFindingsFrom(parsed, latin1, acc, 0);
            i = end; // consumed a valid JSON region — skip past it
            continue;
          }
        }
      }
      i++; // not a JSON region here — descend so inner openers are still reached
    } else {
      i++;
    }
  }
}

// Inspect JWKs two ways, deduplicated downstream by fingerprint:
//   1. the whole file parsed as JSON (also catches a file that is a lone JSON
//      *string* whose decoded value is a JWK — no unescaped braces to scan); and
//   2. every complete JSON object/array region embedded in the file's text,
//      including regions nested inside non-JSON JavaScript blocks.
// Depth limits inside both paths fail closed rather than returning a false clean.
function scanJwk(bytes, latin1) {
  const acc = [];
  try {
    jwkFindingsFrom(JSON.parse(bytes.toString("utf8")), latin1, acc, 0);
  } catch (error) {
    if (error instanceof SecretScanError) throw error; // depth guard must propagate
    // Otherwise: not whole-file JSON — the embedded pass below still applies.
  }
  scanEmbeddedJson(latin1, latin1, acc);
  return acc;
}

function scanPutty(latin1) {
  // Require a PuTTY key-file header (v2/v3) AND an actually-present private
  // body — not merely a positive Private-Lines count. A truncated file that
  // declares `Private-Lines: N` but carries fewer than N (or blank / non-Base64)
  // body lines has no private material and is NOT flagged. Prose mentioning
  // PuTTY, a header without Private-Lines, and `Private-Lines: 0` are all
  // allowed. No decryption is performed, so encrypted containers whose body IS
  // present are still detected.
  const header = /PuTTY-User-Key-File-[23]:/.exec(latin1);
  if (!header) return [];
  const decl = /(^|\n)Private-Lines:[ \t]*(\d+)[ \t]*\r?\n/.exec(latin1);
  if (!decl) return [];
  const declared = Number.parseInt(decl[2], 10);
  if (!(declared > 0)) return []; // Private-Lines: 0 (or malformed) → no body

  const bodyStart = decl.index + decl[0].length;
  const following = latin1.slice(bodyStart).split(/\r?\n/);
  if (following.length < declared) return []; // truncated: fewer lines than declared
  const body = following.slice(0, declared);
  for (const line of body) {
    const trimmed = line.trim();
    if (trimmed.length === 0) return []; // a required body line is blank
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) return []; // not plausibly Base64
  }
  const concatenated = body.join("").trim();
  if (concatenated.length === 0) return []; // no private body material

  return [
    { detectorId: DETECTOR_PUTTY, line: lineOf(latin1, header.index), fingerprint: fingerprintOf(concatenated) }
  ];
}

function scanProviderTokens(latin1) {
  const out = [];
  for (const detector of PROVIDER_TOKEN_DETECTORS) {
    const re = new RegExp(detector.pattern.source, "g");
    let m;
    while ((m = re.exec(latin1)) !== null) {
      out.push({ detectorId: detector.id, line: lineOf(latin1, m.index), fingerprint: fingerprintOf(m[0]) });
    }
  }
  return out;
}

function scanCredentialAssignments(latin1) {
  const out = [];
  const lines = latin1.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const re = new RegExp(ASSIGNMENT_RE.source, "g");
    let m;
    while ((m = re.exec(line)) !== null) {
      const field = m[2].toLowerCase();
      const value = m[4];
      if (!SECRET_FIELD_NAMES.has(field)) continue;
      if (!isCredentialValue(value)) continue;
      out.push({
        detectorId: DETECTOR_CREDENTIAL_ASSIGNMENT,
        line: i + 1,
        fingerprint: fingerprintOf(value)
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// File + tree walking
// ---------------------------------------------------------------------------
const SKIP_DIRS = new Set([".git", "node_modules", "__pycache__"]);

function scanFileBytes(bytes) {
  // latin1 decode: one byte -> one char, so ASCII markers survive intact inside
  // malformed UTF-8 or genuine binary, with no multi-byte shifting.
  const latin1 = bytes.toString("latin1");
  return [
    ...scanPem(latin1),
    ...scanDer(bytes),
    ...scanJwk(bytes, latin1),
    ...scanPutty(latin1),
    ...scanProviderTokens(latin1),
    ...scanCredentialAssignments(latin1)
  ];
}

function walk(rootDir, dirAbs, relParts, onFinding) {
  let entries;
  try {
    entries = readdirSync(dirAbs);
  } catch {
    throw new SecretScanError(`unreadable directory in scan target: ${toPosix(relParts.join("/")) || "."}`);
  }
  for (const entry of entries) {
    const full = join(dirAbs, entry);
    const childRel = [...relParts, entry];
    const relPosix = toPosix(childRel.join("/"));

    let st;
    try {
      st = lstatSync(full); // lstat: never dereference a symlink.
    } catch {
      throw new SecretScanError(`unreadable entry in scan target: ${relPosix}`);
    }

    if (st.isSymbolicLink()) {
      // Containment-safe handling: refuse rather than silently follow a link
      // that could point outside the package boundary. Fail closed.
      throw new SecretScanError(`refusing to follow symlink in package boundary: ${relPosix}`);
    }

    if (st.isDirectory()) {
      if (SKIP_DIRS.has(entry)) continue; // scanner-internal dirs only
      walk(rootDir, full, childRel, onFinding);
      continue;
    }

    if (!st.isFile()) {
      // Sockets, FIFOs, devices, etc. have no place in a package artifact.
      throw new SecretScanError(`refusing to scan non-regular file in package boundary: ${relPosix}`);
    }

    let bytes;
    try {
      bytes = readFileSync(full);
    } catch {
      throw new SecretScanError(`unreadable file in scan target: ${relPosix}`);
    }
    for (const partial of scanFileBytes(bytes)) {
      onFinding({ detectorId: partial.detectorId, relativePath: relPosix, line: partial.line, fingerprint: partial.fingerprint });
    }
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Scan every regular file under rootDir and return structured findings. Never
// includes matched content. Deterministically ordered by (relativePath,
// detectorId, line, fingerprint). Fails closed (throws SecretScanError) on an
// unreadable entry, a symlink, or a non-regular file inside the boundary.
export function scanForPackageSecrets(rootDir, _options = {}) {
  const raw = [];
  walk(rootDir, rootDir, [], (finding) => raw.push(finding));

  // Deduplicate by (path, detector, fingerprint) — NOT by line — so the same
  // secret found by more than one inspection path (e.g. a JWK seen both by the
  // whole-file parse and by the embedded-object pass, at slightly different
  // reported offsets) collapses to a single logical finding. The earliest line
  // is kept.
  const byKey = new Map();
  for (const f of raw) {
    const key = `${f.relativePath} ${f.detectorId} ${f.fingerprint}`;
    const existing = byKey.get(key);
    if (existing) {
      if (f.line < existing.line) existing.line = f.line;
      continue;
    }
    byKey.set(key, { ...f });
  }
  const deduped = [...byKey.values()];
  deduped.sort((a, b) => {
    if (a.relativePath !== b.relativePath) return a.relativePath < b.relativePath ? -1 : 1;
    if (a.detectorId !== b.detectorId) return a.detectorId < b.detectorId ? -1 : 1;
    if (a.line !== b.line) return a.line - b.line;
    return a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0;
  });
  return deduped;
}

// ---------------------------------------------------------------------------
// Backward-compatibility shim for the original PEM-only scan.
//
// Returns the list of ABSOLUTE file paths whose content contains a PEM private-
// key marker — exactly the contract the old scanForPrivateKeyMaterial() had.
// Implemented by delegating to the generalized engine and projecting the
// pem-private-key findings back to absolute paths.
// ---------------------------------------------------------------------------
export function scanForPrivateKeyMaterial(rootDir) {
  const offenders = [];
  const seen = new Set();
  for (const f of scanForPackageSecrets(rootDir)) {
    if (f.detectorId !== DETECTOR_PEM) continue;
    if (seen.has(f.relativePath)) continue;
    seen.add(f.relativePath);
    offenders.push(fromPosix(rootDir, f.relativePath));
  }
  return offenders;
}

// ---------------------------------------------------------------------------
// Allowlist
//
// An allowlist entry is an EXACT, hash-bound suppression of one finding:
//   { relativePath, detectorId, sha256, reason }
//   * relativePath  exact normalized (posix) package-relative path — no globs,
//                   no directory-wide entries, no path-only suppression.
//   * detectorId    exact detector id — never a private-key-class detector
//                   (NON_ALLOWLISTABLE_DETECTORS), and no detector-wide wildcard.
//   * sha256        SHA-256 of the COMPLETE current file. If the file changes,
//                   the hash no longer matches and the finding becomes active
//                   again.
//   * reason        non-empty human-readable justification.
// Malformed or duplicate entries fail closed. Prefer replacing an example secret
// with a placeholder over adding an allowance; keep the list empty if possible.
// ---------------------------------------------------------------------------
export function loadAllowlist(allowlistPath) {
  let text;
  try {
    text = readFileSync(allowlistPath, "utf8");
  } catch {
    return []; // No allowlist file = nothing allowed. That is the safe default.
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new SecretScanError("secret-scan allowlist is not valid JSON (failing closed)");
  }
  if (!Array.isArray(parsed)) {
    throw new SecretScanError("secret-scan allowlist must be a JSON array (failing closed)");
  }
  const seen = new Set();
  for (const entry of parsed) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new SecretScanError("secret-scan allowlist entry must be an object (failing closed)");
    }
    const { relativePath, detectorId, sha256, reason } = entry;
    if (typeof relativePath !== "string" || relativePath.length === 0) {
      throw new SecretScanError("secret-scan allowlist entry needs a non-empty relativePath (failing closed)");
    }
    if (relativePath.includes("*") || relativePath.includes("\\") || relativePath.endsWith("/")) {
      throw new SecretScanError(`secret-scan allowlist entry must be an exact posix file path, not a glob/dir: ${relativePath}`);
    }
    if (typeof detectorId !== "string" || detectorId.length === 0 || detectorId === "*") {
      throw new SecretScanError("secret-scan allowlist entry needs an exact detectorId (failing closed)");
    }
    if (NON_ALLOWLISTABLE_DETECTORS.has(detectorId)) {
      throw new SecretScanError(`secret-scan allowlist may not suppress private-key-class findings: ${detectorId}`);
    }
    if (typeof sha256 !== "string" || !/^[0-9a-f]{64}$/.test(sha256)) {
      throw new SecretScanError("secret-scan allowlist entry needs a full lowercase sha256 file hash (failing closed)");
    }
    if (typeof reason !== "string" || reason.trim().length === 0) {
      throw new SecretScanError("secret-scan allowlist entry needs a non-empty reason (failing closed)");
    }
    const key = `${relativePath} ${detectorId} ${sha256}`;
    if (seen.has(key)) {
      throw new SecretScanError(`duplicate secret-scan allowlist entry (failing closed): ${relativePath} / ${detectorId}`);
    }
    seen.add(key);
  }
  return parsed;
}

function sha256File(absPath) {
  return createHash("sha256").update(readFileSync(absPath)).digest("hex");
}

// Filter findings through the allowlist, returning only the findings that are
// NOT suppressed (i.e. the ones that must fail the build). A finding is
// suppressed only when an allowlist entry matches its exact relativePath and
// detectorId AND the SHA-256 of the current file equals the entry's sha256.
// Private-key-class findings are never suppressed (belt-and-suspenders: such
// entries already fail closed at load time).
export function applyAllowlist(findings, { rootDir, allowlistPath, allowlist } = {}) {
  const entries = allowlist ?? (allowlistPath ? loadAllowlist(allowlistPath) : []);
  if (entries.length === 0) return findings;

  const hashCache = new Map();
  const active = [];
  for (const finding of findings) {
    if (NON_ALLOWLISTABLE_DETECTORS.has(finding.detectorId)) {
      active.push(finding);
      continue;
    }
    const match = entries.find(
      (e) => e.relativePath === finding.relativePath && e.detectorId === finding.detectorId
    );
    if (!match) {
      active.push(finding);
      continue;
    }
    let currentHash = hashCache.get(finding.relativePath);
    if (currentHash === undefined) {
      try {
        currentHash = sha256File(fromPosix(rootDir, finding.relativePath));
      } catch {
        throw new SecretScanError(`allowlisted file is unreadable, cannot verify hash (failing closed): ${finding.relativePath}`);
      }
      hashCache.set(finding.relativePath, currentHash);
    }
    if (currentHash === match.sha256) {
      continue; // exact path + detector + current file hash all match: suppressed
    }
    active.push(finding); // file changed since it was allowed → active again
  }
  return active;
}
