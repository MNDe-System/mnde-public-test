#!/usr/bin/env node
// Hostile tests for the generalized package-boundary secret scanner
// (build/lib/package-secret-scan.mjs).
//
// Every scenario runs against a throwaway scratch directory (never the real
// repo), and every secret used is a SYNTHETIC, test-only value — no real
// credential is ever written into this repository. The synthetic tokens below
// match the *shape* of real provider tokens (which is all the detectors look
// at); they are not, and never were, valid credentials.
//
// Coverage:
//   * Positives for every detector: all five PEM forms, DER PKCS#8 / PKCS#1 /
//     SEC1, private RSA/EC/OKP JWKs, symmetric oct JWK, PuTTY v2/v3, each
//     provider token, credential assignments in JSON/dotenv/YAML, and secrets
//     hidden by prose / misleading filename / deep nesting / malformed-binary.
//   * Negatives for the look-alikes that must NOT trip: public PEM, public JWKs,
//     random binary, DER public keys, JWTs, UUIDs, commit hashes, integrity
//     hashes, receipt-signature-shaped values, Stripe publishable keys,
//     placeholders/env references, prose, and URLs.
//   * Diagnostics never contain the secret.
//   * Allowlist is exact + hash-bound and cannot suppress private-key findings.
//   * Unsafe entries (symlinks) fail closed where the platform permits testing.

import assert from "node:assert/strict";
import { generateKeyPairSync, createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  scanForPackageSecrets,
  scanForPrivateKeyMaterial,
  applyAllowlist,
  loadAllowlist,
  SecretScanError,
  PROVIDER_TOKEN_DETECTORS
} from "../build/lib/package-secret-scan.mjs";

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------
const results = [];
function scenario(name, fn) {
  const dir = mkdtempSync(join(tmpdir(), "secretscan-"));
  try {
    const outcome = fn(dir);
    if (outcome === "SKIP") {
      results.push({ name, skip: true });
      console.log(`  skip - ${name}`);
    } else {
      results.push({ name, ok: true });
      console.log(`  ok - ${name}`);
    }
  } catch (error) {
    results.push({ name, ok: false, error });
    console.log(`FAIL - ${name}: ${error.message}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function toPosix(rel) {
  return rel.split(/[\\/]/).join("/");
}
function detectorsIn(dir) {
  return scanForPackageSecrets(dir).map((f) => f.detectorId);
}
function assertDetector(dir, detectorId, relPath) {
  const findings = scanForPackageSecrets(dir);
  const hit = findings.some(
    (f) => f.detectorId === detectorId && (relPath === undefined || f.relativePath === toPosix(relPath))
  );
  assert.ok(hit, `expected ${detectorId}${relPath ? ` in ${relPath}` : ""}; got ${JSON.stringify(findings)}`);
}
function assertClean(dir) {
  const findings = scanForPackageSecrets(dir);
  assert.deepEqual(findings, [], `expected no findings; got ${JSON.stringify(findings)}`);
}
const PRIVATE_KEY_CLASS = new Set([
  "pem-private-key",
  "der-private-key",
  "jwk-private-key",
  "jwk-symmetric-key",
  "putty-private-key"
]);
function assertNoPrivateKeyClass(dir) {
  const offenders = detectorsIn(dir).filter((id) => PRIVATE_KEY_CLASS.has(id));
  assert.deepEqual(offenders, [], `expected no private-key-class findings; got ${JSON.stringify(offenders)}`);
}

// ---------------------------------------------------------------------------
// Synthetic key material (real crypto for DER/JWK; literal markers for PEM)
// ---------------------------------------------------------------------------
const ed = generateKeyPairSync("ed25519");
const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ec = generateKeyPairSync("ec", { namedCurve: "prime256v1" });

const PRIVATE_PEM = ed.privateKey.export({ type: "pkcs8", format: "pem" });
const PUBLIC_PEM = ed.publicKey.export({ type: "spki", format: "pem" });
const RSA_PEM = "-----BEGIN RSA PRIVATE KEY-----\nZmFrZSBib2R5\n-----END RSA PRIVATE KEY-----\n";
const EC_PEM = "-----BEGIN EC PRIVATE KEY-----\nZmFrZSBib2R5\n-----END EC PRIVATE KEY-----\n";
const OPENSSH_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZSBib2R5\n-----END OPENSSH PRIVATE KEY-----\n";
const ENCRYPTED_PEM = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nZmFrZSBib2R5\n-----END ENCRYPTED PRIVATE KEY-----\n";

const DER_PKCS8 = ed.privateKey.export({ type: "pkcs8", format: "der" });
const DER_PKCS1 = rsa.privateKey.export({ type: "pkcs1", format: "der" });
const DER_SEC1 = ec.privateKey.export({ type: "sec1", format: "der" });
const DER_PUBLIC_SPKI = rsa.publicKey.export({ type: "spki", format: "der" });

const JWK_RSA_PRIVATE = JSON.stringify(rsa.privateKey.export({ format: "jwk" }), null, 2);
const JWK_EC_PRIVATE = JSON.stringify(ec.privateKey.export({ format: "jwk" }), null, 2);
const JWK_OKP_PRIVATE = JSON.stringify(ed.privateKey.export({ format: "jwk" }), null, 2);
const JWK_RSA_PUBLIC = JSON.stringify(rsa.publicKey.export({ format: "jwk" }), null, 2);
const JWK_EC_PUBLIC = JSON.stringify(ec.publicKey.export({ format: "jwk" }), null, 2);
const JWK_OKP_PUBLIC = JSON.stringify(ed.publicKey.export({ format: "jwk" }), null, 2);

// Synthetic symmetric key material: high-entropy base64url-shaped, letters+digits.
const SYMMETRIC_K = "Zx9Kd2Lm4Qw7Zb3Rt6Yv1Np5ScAaBbCcDdEeFf0123";
const JWK_SYMMETRIC = JSON.stringify({ kty: "oct", k: SYMMETRIC_K, alg: "A256GCM" }, null, 2);
const JWK_SYMMETRIC_PLACEHOLDER = JSON.stringify({ kty: "oct", k: "changeme" }, null, 2);

const PUTTY_V2 =
  "PuTTY-User-Key-File-2: ssh-ed25519\nEncryption: none\nComment: test-only\n" +
  "Public-Lines: 2\nAAAAsynthetic\nAAAAsynthetic\nPrivate-Lines: 1\nZmFrZQ==\nPrivate-MAC: 00\n";
const PUTTY_V3 = PUTTY_V2.replace("PuTTY-User-Key-File-2:", "PuTTY-User-Key-File-3:");
const PUTTY_PROSE = "We connected to the host using PuTTY earlier today; see the runbook.\n";

// Synthetic provider tokens (shape-valid, NOT real credentials). Assemble the
// detector prefixes at runtime so repository push protection does not mistake
// these inert fixtures for live credentials in source history.
const syntheticToken = (...parts) => parts.join("");
const TOKENS = {
  "token-github": syntheticToken("gh", "p_0123456789abcdefABCDEFghijklmnop0123"),
  "token-gitlab": syntheticToken("gl", "pat-0123456789abcdefABCD"),
  "token-npm": syntheticToken("np", "m_0123456789abcdefABCDEFghijklmnop0123"),
  "token-slack": syntheticToken("xo", "xb-0123456789abcdefABCDEFxyz"),
  "token-stripe-live": syntheticToken("sk_", "live_0123456789abcdefABCDEFghij"),
  "token-openai": syntheticToken("sk-", "proj-0123456789abcdefABCDEFXyz")
};

// A synthetic credential value: high entropy, letters+digits, no placeholder.
const CRED_VALUE = "A1b2C3d4E5f6G7h8I9j0KxLmNpQr";

// ---------------------------------------------------------------------------
// POSITIVES — private keys
// ---------------------------------------------------------------------------
scenario("PEM PKCS8 private key is caught", (dir) => {
  writeFileSync(join(dir, "a.pem"), PRIVATE_PEM);
  assertDetector(dir, "pem-private-key", "a.pem");
});
scenario("PEM RSA private key is caught", (dir) => {
  writeFileSync(join(dir, "a.key"), RSA_PEM);
  assertDetector(dir, "pem-private-key", "a.key");
});
scenario("PEM EC private key is caught", (dir) => {
  writeFileSync(join(dir, "noext"), EC_PEM);
  assertDetector(dir, "pem-private-key", "noext");
});
scenario("PEM OPENSSH private key is caught", (dir) => {
  writeFileSync(join(dir, "id"), OPENSSH_PEM);
  assertDetector(dir, "pem-private-key", "id");
});
scenario("PEM ENCRYPTED private key is caught", (dir) => {
  writeFileSync(join(dir, "enc.txt"), ENCRYPTED_PEM);
  assertDetector(dir, "pem-private-key", "enc.txt");
});
scenario("DER PKCS#8 private key is caught", (dir) => {
  writeFileSync(join(dir, "key.der"), DER_PKCS8);
  assertDetector(dir, "der-private-key", "key.der");
});
scenario("DER PKCS#1 RSA private key is caught", (dir) => {
  writeFileSync(join(dir, "rsa.bin"), DER_PKCS1);
  assertDetector(dir, "der-private-key", "rsa.bin");
});
scenario("DER SEC1 EC private key is caught", (dir) => {
  writeFileSync(join(dir, "ec.bin"), DER_SEC1);
  assertDetector(dir, "der-private-key", "ec.bin");
});
scenario("private RSA JWK is caught", (dir) => {
  writeFileSync(join(dir, "rsa.jwk.json"), JWK_RSA_PRIVATE);
  assertDetector(dir, "jwk-private-key", "rsa.jwk.json");
});
scenario("private EC JWK is caught", (dir) => {
  writeFileSync(join(dir, "ec.jwk.json"), JWK_EC_PRIVATE);
  assertDetector(dir, "jwk-private-key", "ec.jwk.json");
});
scenario("private OKP JWK is caught", (dir) => {
  writeFileSync(join(dir, "okp.jwk.json"), JWK_OKP_PRIVATE);
  assertDetector(dir, "jwk-private-key", "okp.jwk.json");
});
scenario("symmetric oct JWK is caught", (dir) => {
  writeFileSync(join(dir, "sym.jwk.json"), JWK_SYMMETRIC);
  assertDetector(dir, "jwk-symmetric-key", "sym.jwk.json");
});
scenario("JWK inside a JWK Set (nested array) is caught", (dir) => {
  writeFileSync(join(dir, "jwks.json"), JSON.stringify({ keys: [JSON.parse(JWK_EC_PRIVATE)] }));
  assertDetector(dir, "jwk-private-key", "jwks.json");
});
scenario("PuTTY v2 private key is caught", (dir) => {
  writeFileSync(join(dir, "key.ppk"), PUTTY_V2);
  assertDetector(dir, "putty-private-key", "key.ppk");
});
scenario("PuTTY v3 private key is caught", (dir) => {
  writeFileSync(join(dir, "key3.ppk"), PUTTY_V3);
  assertDetector(dir, "putty-private-key", "key3.ppk");
});

// ---------------------------------------------------------------------------
// POSITIVES — provider tokens (one scenario per detector)
// ---------------------------------------------------------------------------
for (const detector of PROVIDER_TOKEN_DETECTORS) {
  scenario(`${detector.id} is caught`, (dir) => {
    const token = TOKENS[detector.id];
    assert.ok(token, `test is missing a synthetic token for ${detector.id}`);
    writeFileSync(join(dir, "config.txt"), `value = ${token}\n`);
    assertDetector(dir, detector.id, "config.txt");
  });
}

// ---------------------------------------------------------------------------
// POSITIVES — credential assignments (JSON / dotenv / YAML)
// ---------------------------------------------------------------------------
scenario("credential assignment in JSON is caught", (dir) => {
  writeFileSync(join(dir, "settings.json"), JSON.stringify({ note: "ok", api_key: CRED_VALUE }, null, 2));
  assertDetector(dir, "credential-assignment", "settings.json");
});
scenario("credential assignment (camelCase apiKey) in JSON is caught", (dir) => {
  writeFileSync(join(dir, "settings.json"), JSON.stringify({ apiKey: CRED_VALUE }));
  assertDetector(dir, "credential-assignment", "settings.json");
});
scenario("credential assignment in dotenv is caught", (dir) => {
  writeFileSync(join(dir, ".env"), `PORT=3000\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI1K7MDENGbPxR0C8gT2hVq9zLm3B\n`);
  assertDetector(dir, "credential-assignment", ".env");
});
scenario("credential assignment in YAML is caught", (dir) => {
  writeFileSync(join(dir, "conf.yaml"), `service:\n  host: localhost\n  password: P4ssw0rdX9KdLm2Qb7Rt\n`);
  assertDetector(dir, "credential-assignment", "conf.yaml");
});

// ---------------------------------------------------------------------------
// POSITIVES — hidden by context (filename / nesting / prose / binary)
// ---------------------------------------------------------------------------
scenario("secret in a misleading filename is caught", (dir) => {
  writeFileSync(join(dir, "logo.png"), `token = ${TOKENS["token-github"]}\n`);
  assertDetector(dir, "token-github", "logo.png");
});
scenario("secret in a deeply nested file is caught", (dir) => {
  mkdirSync(join(dir, "a", "b", "c", "d"), { recursive: true });
  writeFileSync(join(dir, "a", "b", "c", "d", "notes.txt"), RSA_PEM);
  assertDetector(dir, "pem-private-key", join("a", "b", "c", "d", "notes.txt"));
});
scenario("secret embedded in ordinary prose is caught", (dir) => {
  writeFileSync(join(dir, "readme.md"), `Deploy notes:\n- rotate creds\n- token: ${TOKENS["token-npm"]}\n- done\n`);
  assertDetector(dir, "token-npm", "readme.md");
});
scenario("secret in malformed UTF-8 / binary content is caught", (dir) => {
  const buf = Buffer.concat([Buffer.from([0xff, 0xfe, 0x00, 0x80]), Buffer.from(RSA_PEM), Buffer.from([0xff, 0x00])]);
  writeFileSync(join(dir, "blob.bin"), buf);
  assertDetector(dir, "pem-private-key", "blob.bin");
});

// ---------------------------------------------------------------------------
// NEGATIVES — public material and non-secrets must remain allowed
// ---------------------------------------------------------------------------
scenario("PEM public key is allowed", (dir) => {
  writeFileSync(join(dir, "pub.pem"), PUBLIC_PEM);
  assertClean(dir);
});
scenario("public RSA JWK is allowed", (dir) => {
  writeFileSync(join(dir, "rsa.pub.json"), JWK_RSA_PUBLIC);
  assertClean(dir);
});
scenario("public EC JWK is allowed", (dir) => {
  writeFileSync(join(dir, "ec.pub.json"), JWK_EC_PUBLIC);
  assertClean(dir);
});
scenario("public OKP JWK is allowed", (dir) => {
  writeFileSync(join(dir, "okp.pub.json"), JWK_OKP_PUBLIC);
  assertClean(dir);
});
scenario("DER public key is not classified as a private key", (dir) => {
  writeFileSync(join(dir, "pub.der"), DER_PUBLIC_SPKI);
  assertNoPrivateKeyClass(dir);
});
scenario("random binary data is allowed", (dir) => {
  const buf = Buffer.alloc(4096);
  for (let i = 0; i < buf.length; i++) buf[i] = i % 256;
  writeFileSync(join(dir, "random.bin"), buf);
  assertClean(dir);
});
scenario("symmetric JWK with placeholder k is allowed", (dir) => {
  writeFileSync(join(dir, "sym.placeholder.json"), JWK_SYMMETRIC_PLACEHOLDER);
  assertClean(dir);
});
scenario("PuTTY mentioned only in prose is allowed", (dir) => {
  writeFileSync(join(dir, "runbook.md"), PUTTY_PROSE);
  assertClean(dir);
});
scenario("a JWT is allowed", (dir) => {
  const jwt =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  writeFileSync(join(dir, "jwt.txt"), jwt + "\n");
  assertClean(dir);
});
scenario("a UUID is allowed", (dir) => {
  writeFileSync(join(dir, "id.txt"), "123e4567-e89b-12d3-a456-426614174000\n");
  assertClean(dir);
});
scenario("a git commit hash is allowed", (dir) => {
  writeFileSync(join(dir, "rev.txt"), "9fceb02d0ae598e95dc970b74767f19372d61af8\n");
  assertClean(dir);
});
scenario("a package integrity hash is allowed", (dir) => {
  writeFileSync(
    join(dir, "lock.json"),
    JSON.stringify({ integrity: "sha512-abc123DEF456ghi789JKL012mno345PQR678stu901VWX234yz567+/==" })
  );
  assertClean(dir);
});
scenario("a receipt-signature-shaped value is allowed", (dir) => {
  writeFileSync(
    join(dir, "receipt.json"),
    JSON.stringify({ signature: "MEUCIQD0aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdefghij", alg: "ed25519" })
  );
  assertClean(dir);
});
scenario("a Stripe publishable key is allowed", (dir) => {
  writeFileSync(join(dir, "pub.txt"), "pk_live_0123456789abcdefABCDEFghij\n");
  assertClean(dir);
});
scenario("an AWS access key ID (not a secret) is allowed", (dir) => {
  writeFileSync(join(dir, "id.txt"), "AKIAIOSFODNN7SYNTHETIC\n");
  assertClean(dir);
});
scenario("placeholders and env references are allowed", (dir) => {
  const cfg = {
    a: "<redacted>",
    password: "${TOKEN}",
    api_key: "$TOKEN",
    client_secret: "process.env.CLIENT_SECRET",
    secret: "changeme",
    auth_token: "REPLACE_ME",
    passwd: "xxxxxxxxxxxxxxxxxxxx"
  };
  writeFileSync(join(dir, "cfg.json"), JSON.stringify(cfg, null, 2));
  assertClean(dir);
});
scenario("a high-entropy value on a NON-secret field is allowed", (dir) => {
  writeFileSync(join(dir, "cfg.json"), JSON.stringify({ build_id: CRED_VALUE, integrity: CRED_VALUE }));
  assertClean(dir);
});
scenario("a URL without embedded credentials is allowed", (dir) => {
  writeFileSync(join(dir, "cfg.json"), JSON.stringify({ secret: "https://example.com/callback?ok=1" }));
  assertClean(dir);
});
scenario('prose containing "private", "secret", "password" is allowed', (dir) => {
  writeFileSync(join(dir, "notes.txt"), "This is a private, secret matter; keep the password policy confidential.\n");
  assertClean(dir);
});

// ---------------------------------------------------------------------------
// Diagnostics never contain the secret
// ---------------------------------------------------------------------------
scenario("findings never contain the matched secret", (dir) => {
  writeFileSync(join(dir, "c.txt"), `api_key = ${CRED_VALUE}\ngh = ${TOKENS["token-github"]}\n`);
  writeFileSync(join(dir, "k.pem"), PRIVATE_PEM);
  const findings = scanForPackageSecrets(dir);
  assert.ok(findings.length >= 3, `expected several findings; got ${findings.length}`);
  const blob = JSON.stringify(findings);
  assert.ok(!blob.includes(CRED_VALUE), "credential value leaked into findings");
  assert.ok(!blob.includes(TOKENS["token-github"]), "github token leaked into findings");
  assert.ok(!blob.includes(PRIVATE_PEM.slice(40, 80)), "PEM body leaked into findings");
  for (const f of findings) {
    assert.match(f.fingerprint, /^sha256-[0-9a-f]{16}$/, "fingerprint must be a truncated sha256, not the secret");
    assert.equal(typeof f.line, "number");
  }
});

// ---------------------------------------------------------------------------
// Deterministic ordering
// ---------------------------------------------------------------------------
scenario("findings are deterministically ordered", (dir) => {
  mkdirSync(join(dir, "z"), { recursive: true });
  writeFileSync(join(dir, "z", "b.txt"), `api_key = ${CRED_VALUE}\n`);
  writeFileSync(join(dir, "a.pem"), PRIVATE_PEM);
  const a = JSON.stringify(scanForPackageSecrets(dir));
  const b = JSON.stringify(scanForPackageSecrets(dir));
  assert.equal(a, b, "scan output must be stable across runs");
  const paths = scanForPackageSecrets(dir).map((f) => f.relativePath);
  assert.deepEqual(paths, [...paths].sort(), "findings must be ordered by relativePath");
});

// ---------------------------------------------------------------------------
// Allowlist — exact, hash-bound, cannot suppress private keys
// ---------------------------------------------------------------------------
function sha256File(p) {
  return createHash("sha256").update(readFileSync(p)).digest("hex");
}

scenario("allowlist suppresses only an exact path+detector+hash match", (dir) => {
  const rel = "settings.json";
  const abs = join(dir, rel);
  writeFileSync(abs, JSON.stringify({ api_key: CRED_VALUE }));
  const before = scanForPackageSecrets(dir);
  assert.ok(before.some((f) => f.detectorId === "credential-assignment"), "precondition: finding exists");

  const allowlist = [
    { relativePath: rel, detectorId: "credential-assignment", sha256: sha256File(abs), reason: "synthetic test fixture" }
  ];
  const active = applyAllowlist(before, { rootDir: dir, allowlist });
  assert.deepEqual(active, [], "exact match must suppress the finding");

  // Wrong detector id → not suppressed.
  const wrongDetector = applyAllowlist(before, {
    rootDir: dir,
    allowlist: [{ ...allowlist[0], detectorId: "token-github" }]
  });
  assert.ok(wrongDetector.length > 0, "a different detector id must not suppress");

  // Wrong path → not suppressed.
  const wrongPath = applyAllowlist(before, {
    rootDir: dir,
    allowlist: [{ ...allowlist[0], relativePath: "other.json" }]
  });
  assert.ok(wrongPath.length > 0, "a different path must not suppress");
});

scenario("modifying an allowed file reactivates the finding (hash-bound)", (dir) => {
  const rel = "settings.json";
  const abs = join(dir, rel);
  writeFileSync(abs, JSON.stringify({ api_key: CRED_VALUE }));
  const before = scanForPackageSecrets(dir);
  const allowlist = [
    { relativePath: rel, detectorId: "credential-assignment", sha256: sha256File(abs), reason: "synthetic test fixture" }
  ];
  assert.deepEqual(applyAllowlist(before, { rootDir: dir, allowlist }), [], "precondition: suppressed while unchanged");

  // Change the file: same finding, but the recorded hash no longer matches.
  writeFileSync(abs, JSON.stringify({ api_key: CRED_VALUE, added: "field" }));
  const after = scanForPackageSecrets(dir);
  const active = applyAllowlist(after, { rootDir: dir, allowlist });
  assert.ok(
    active.some((f) => f.detectorId === "credential-assignment"),
    "a changed file must make its allowance stale and the finding active again"
  );
});

scenario("allowlist can never suppress a private-key finding (load fails closed)", (dir) => {
  const rel = "k.pem";
  const abs = join(dir, rel);
  writeFileSync(abs, PRIVATE_PEM);
  // Attempting to allowlist a private-key-class detector is rejected at load.
  const tmp = join(dir, "allowlist.json");
  writeFileSync(
    tmp,
    JSON.stringify([{ relativePath: rel, detectorId: "pem-private-key", sha256: sha256File(abs), reason: "nope" }])
  );
  assert.throws(() => loadAllowlist(tmp), SecretScanError, "must refuse to load a private-key allowlist entry");

  // And even if such an entry were passed directly, the finding survives.
  const findings = scanForPackageSecrets(dir);
  const active = applyAllowlist(findings, {
    rootDir: dir,
    allowlist: [{ relativePath: rel, detectorId: "pem-private-key", sha256: sha256File(abs), reason: "nope" }]
  });
  assert.ok(active.some((f) => f.detectorId === "pem-private-key"), "private-key finding must never be suppressed");
});

scenario("malformed and duplicate allowlist entries fail closed", (dir) => {
  const good = { relativePath: "a.json", detectorId: "token-github", sha256: "a".repeat(64), reason: "x" };
  const cases = [
    [{ ...good, reason: "" }, "empty reason"],
    [{ ...good, sha256: "short" }, "bad hash"],
    [{ ...good, relativePath: "dir/*" }, "glob path"],
    [{ ...good, relativePath: "dir/" }, "directory path"],
    [{ ...good, detectorId: "*" }, "detector wildcard"]
  ];
  for (const [entry, label] of cases) {
    const p = join(dir, `al-${label.replace(/\s+/g, "-")}.json`);
    writeFileSync(p, JSON.stringify([entry]));
    assert.throws(() => loadAllowlist(p), SecretScanError, `must fail closed on ${label}`);
  }
  const dup = join(dir, "dup.json");
  writeFileSync(dup, JSON.stringify([good, { ...good }]));
  assert.throws(() => loadAllowlist(dup), SecretScanError, "must fail closed on duplicate entries");
});

// ---------------------------------------------------------------------------
// Fail-closed on unsafe entries (symlinks) — skipped where unsupported
// ---------------------------------------------------------------------------
scenario("a symlink in the package boundary fails closed", (dir) => {
  const target = join(dir, "target.txt");
  writeFileSync(target, "harmless\n");
  const link = join(dir, "link.txt");
  let created = false;
  try {
    symlinkSync(target, link);
    created = true;
  } catch {
    // Windows without the symlink privilege: fall back to a directory junction,
    // which is also a reparse point and needs no privilege. lstat reports it as
    // a symbolic link, so it exercises the same fail-closed path.
    try {
      const realDir = join(dir, "realdir");
      mkdirSync(realDir);
      writeFileSync(join(realDir, "f.txt"), "harmless\n");
      symlinkSync(realDir, join(dir, "linkdir"), "junction");
      created = true;
    } catch {
      created = false;
    }
  }
  if (!created) {
    // No reparse point could be created on this platform/filesystem: report an
    // honest skip rather than a false pass.
    return "SKIP";
  }
  assert.throws(() => scanForPackageSecrets(dir), SecretScanError, "scanner must refuse to follow a symlink");
});

// ---------------------------------------------------------------------------
// Backward compatibility with the PEM-only shim
// ---------------------------------------------------------------------------
scenario("scanForPrivateKeyMaterial still returns absolute PEM offenders only", (dir) => {
  writeFileSync(join(dir, "k.pem"), PRIVATE_PEM);
  writeFileSync(join(dir, "pub.pem"), PUBLIC_PEM);
  writeFileSync(join(dir, "c.txt"), `api_key = ${CRED_VALUE}\n`); // a non-PEM finding
  const offenders = scanForPrivateKeyMaterial(dir);
  assert.deepEqual(offenders, [join(dir, "k.pem")], `expected only the PEM file; got ${JSON.stringify(offenders)}`);
});

// ===========================================================================
// Regression tests for the five review findings. Each asserts the corrected
// behavior; these fail against the pre-remediation implementation.
// ===========================================================================

// --- Finding 1: valid symmetric JWK must not depend on the generic credential
//     heuristic (which required a digit / mixed classes). ---
scenario("F1: all-letter base64url oct JWK is detected", (dir) => {
  writeFileSync(join(dir, "k.json"), JSON.stringify({ kty: "oct", k: "abcdefghijklmnopqrstuvwx" }));
  assertDetector(dir, "jwk-symmetric-key", "k.json");
});
scenario("F1: mixed-character oct JWK remains detected", (dir) => {
  writeFileSync(join(dir, "k.json"), JSON.stringify({ kty: "oct", k: "Ab3Cd9Ef1Gh2Ij7Kl0Mn" }));
  assertDetector(dir, "jwk-symmetric-key", "k.json");
});
scenario("F1: oct JWK nested in a JWK Set is detected", (dir) => {
  writeFileSync(join(dir, "jwks.json"), JSON.stringify({ keys: [{ kty: "oct", k: "abcdefghijklmnopqrstuvwx" }] }));
  assertDetector(dir, "jwk-symmetric-key", "jwks.json");
});
scenario("F1: explicit placeholder oct keys remain allowed", (dir) => {
  for (const k of ["changeme", "example", "REPLACE_ME", "<redacted>", "${JWK_KEY}", "$JWK_KEY"]) {
    writeFileSync(join(dir, "k.json"), JSON.stringify({ kty: "oct", k }));
    const findings = scanForPackageSecrets(dir);
    assert.deepEqual(findings, [], `placeholder k=${k} must be allowed; got ${JSON.stringify(findings)}`);
  }
});
scenario("F1: public RSA/EC/OKP JWKs remain allowed", (dir) => {
  writeFileSync(join(dir, "r.json"), JWK_RSA_PUBLIC);
  writeFileSync(join(dir, "e.json"), JWK_EC_PUBLIC);
  writeFileSync(join(dir, "o.json"), JWK_OKP_PUBLIC);
  assertClean(dir);
});

// --- Finding 2: contextual credential must permit Base64 `/`/`+` and all-letter
//     high-diversity values, while still rejecting refs/URLs/paths/placeholders. ---
scenario("F2: AWS secret containing / and + is detected", (dir) => {
  writeFileSync(join(dir, ".env"), "AWS_SECRET_ACCESS_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz01234567/89+AB\n");
  assertDetector(dir, "credential-assignment", ".env");
});
scenario("F2: all-letter high-diversity API_KEY is detected", (dir) => {
  writeFileSync(join(dir, ".env"), "API_KEY=abcdefghijklmnopqrstuvwx\n");
  assertDetector(dir, "credential-assignment", ".env");
});
scenario("F2: Base64URL credential with _ and - is detected", (dir) => {
  writeFileSync(join(dir, ".env"), "SECRET=abcABC012_-defDEF345ghiGHI-_x\n");
  assertDetector(dir, "credential-assignment", ".env");
});
scenario("F2: quoted JSON credential is detected", (dir) => {
  writeFileSync(join(dir, "c.json"), JSON.stringify({ client_secret: "Zk9/Xa2+Bc3Dd4Ee5Ff6Gg7Hh==" }));
  assertDetector(dir, "credential-assignment", "c.json");
});
scenario("F2: quoted YAML credential is detected", (dir) => {
  writeFileSync(join(dir, "c.yaml"), 'auth_token: "Zk9Xa2Bc3Dd4Ee5Ff6Gg7Hh8Ii"\n');
  assertDetector(dir, "credential-assignment", "c.yaml");
});
scenario("F2: dotenv credential is detected", (dir) => {
  writeFileSync(join(dir, ".env"), "PRIVATE_TOKEN=Zk9Xa2Bc3Dd4Ee5Ff6Gg7Hh8Ii\n");
  assertDetector(dir, "credential-assignment", ".env");
});
scenario("F2: unambiguous references / placeholders on a secret field remain allowed", (dir) => {
  // NOTE: only UNAMBIGUOUS references are excused (URL schemes carry `:`,
  // interpolations/env refs, angle-bracket redactions, placeholder words). A
  // bare filesystem path is NOT excused any more — see B3 fail-closed tests.
  const cases = [
    "https://example.com/callback?token=abcdefghijkl",
    "process.env.SECRET",
    "${SECRET}",
    "$SECRET",
    "<redacted>",
    "REPLACE_ME",
    "changeme"
  ];
  for (const v of cases) {
    writeFileSync(join(dir, "c.json"), JSON.stringify({ secret: v }));
    const findings = scanForPackageSecrets(dir);
    assert.deepEqual(findings, [], `value must be allowed: ${v}; got ${JSON.stringify(findings)}`);
  }
});
scenario("F2: high-entropy on a non-secret field remains allowed", (dir) => {
  writeFileSync(join(dir, "c.json"), JSON.stringify({ build_id: "AbCd/Ef+Gh1234567890XyZ" }));
  assertClean(dir);
});
scenario("F2: low-diversity repeated value remains allowed", (dir) => {
  writeFileSync(join(dir, ".env"), "SECRET=aaaaaaaaaaaaaaaaaaaaaaaa\n");
  assertClean(dir);
});

// --- Finding 3: private/symmetric JWKs embedded in text / JS / JSON strings. ---
const EMBEDDED_OKP = '{"kty":"OKP","crv":"Ed25519","x":"publicpart0123456789","d":"privatepart0123456789"}';
const EMBEDDED_OCT = '{"kty":"oct","k":"abcdefghijklmnopqrstuvwx"}';
scenario("F3: private JWK as the complete JSON file", (dir) => {
  writeFileSync(join(dir, "k.json"), EMBEDDED_OKP);
  assertDetector(dir, "jwk-private-key", "k.json");
});
scenario("F3: private JWK nested as an object", (dir) => {
  writeFileSync(join(dir, "k.json"), JSON.stringify({ wrapper: { the_key: JSON.parse(EMBEDDED_OKP) } }));
  assertDetector(dir, "jwk-private-key", "k.json");
});
scenario("F3: private JWK inside a JSON-encoded string", (dir) => {
  writeFileSync(join(dir, "k.json"), JSON.stringify({ key: EMBEDDED_OKP }));
  assertDetector(dir, "jwk-private-key", "k.json");
});
scenario("F3: private JWK embedded in prose", (dir) => {
  writeFileSync(join(dir, "notes.md"), `Here is the key we used:\n${EMBEDDED_OKP}\nkeep it safe.\n`);
  assertDetector(dir, "jwk-private-key", "notes.md");
});
scenario("F3: private JWK embedded after `const key =`", (dir) => {
  writeFileSync(join(dir, "app.js"), `const key = ${EMBEDDED_OKP};\nexport default key;\n`);
  assertDetector(dir, "jwk-private-key", "app.js");
});
scenario("F3: symmetric JWK embedded in prose and JSON string", (dir) => {
  writeFileSync(join(dir, "a.md"), `token: ${EMBEDDED_OCT}\n`);
  assertDetector(dir, "jwk-symmetric-key", "a.md");
  const dir2 = mkdtempSync(join(tmpdir(), "secretscan-"));
  try {
    writeFileSync(join(dir2, "b.json"), JSON.stringify({ key: EMBEDDED_OCT }));
    assertDetector(dir2, "jwk-symmetric-key", "b.json");
  } finally {
    rmSync(dir2, { recursive: true, force: true });
  }
});
scenario("F3: multiple embedded candidates in one file", (dir) => {
  const second = '{"kty":"EC","crv":"P-256","x":"pubx","y":"puby","d":"ecprivate01234567890abc"}';
  writeFileSync(join(dir, "many.txt"), `first ${EMBEDDED_OKP} then ${second} done\n`);
  const jwk = scanForPackageSecrets(dir).filter((f) => f.detectorId === "jwk-private-key");
  assert.equal(jwk.length, 2, `expected two distinct JWK findings; got ${JSON.stringify(jwk)}`);
});
scenario("F3: whole-file + embedded inspection produce one logical finding", (dir) => {
  writeFileSync(join(dir, "k.json"), EMBEDDED_OKP); // found by both whole-file parse and embedded pass
  const jwk = scanForPackageSecrets(dir).filter((f) => f.detectorId === "jwk-private-key");
  assert.equal(jwk.length, 1, `duplicate inspection paths must dedup to one finding; got ${JSON.stringify(jwk)}`);
});
scenario("F3 negatives: prose/malformed/public/ordinary strings are allowed", (dir) => {
  writeFileSync(join(dir, "1.txt"), "We discussed kty and the d parameter of a JWK in the meeting.\n");
  writeFileSync(join(dir, "2.txt"), '{"kty":"OKP","d": broken json here');
  writeFileSync(join(dir, "3.txt"), `public key: {"kty":"OKP","crv":"Ed25519","x":"publiconly0123456789"}\n`);
  writeFileSync(join(dir, "4.json"), JSON.stringify({ note: "just an ordinary string value" }));
  assertClean(dir);
});
scenario("F3: an oversized embedded candidate is still parsed (no size-based miss)", (dir) => {
  // A single flat JWK object with a huge padding value: there is no smaller
  // nested region, so a size cap here would silently miss it. It must be caught.
  const huge = `{"pad":"${"A".repeat(300000)}","kty":"OKP","crv":"Ed25519","x":"pub0123456789","d":"privatepart0123456789"}`;
  writeFileSync(join(dir, "huge.txt"), `const k = ${huge};\n`);
  assertDetector(dir, "jwk-private-key", "huge.txt");
});

// --- Finding 4: dist/ and extracted-tarball scans must yield identical
//     package-relative paths, so one allowlist entry works at both boundaries. ---
scenario("F4: dist/ and extract/package/ produce identical paths + allowlist behavior", (root) => {
  const distDir = join(root, "dist");
  const pkgDir = join(root, "extract", "package");
  mkdirSync(distDir, { recursive: true });
  mkdirSync(pkgDir, { recursive: true });
  const content = `api_key = ${CRED_VALUE}\n`;
  writeFileSync(join(distDir, "a.txt"), content);
  writeFileSync(join(pkgDir, "a.txt"), content);

  const distFindings = scanForPackageSecrets(distDir);
  const pkgFindings = scanForPackageSecrets(pkgDir);
  assert.deepEqual(distFindings.map((f) => f.relativePath), ["a.txt"], "dist scan must report a.txt");
  assert.deepEqual(pkgFindings.map((f) => f.relativePath), ["a.txt"], "package-content scan must report a.txt, not package/a.txt");

  // One exact allowlist entry (path+detector+hash) suppresses at BOTH roots.
  const allowlist = [
    { relativePath: "a.txt", detectorId: "credential-assignment", sha256: sha256File(join(distDir, "a.txt")), reason: "synthetic parity fixture" }
  ];
  assert.deepEqual(applyAllowlist(distFindings, { rootDir: distDir, allowlist }), [], "suppressed at dist root");
  assert.deepEqual(applyAllowlist(pkgFindings, { rootDir: pkgDir, allowlist }), [], "suppressed at package root");

  // Changing the extracted file invalidates the allowance there.
  writeFileSync(join(pkgDir, "a.txt"), content + "# changed\n");
  const changed = applyAllowlist(scanForPackageSecrets(pkgDir), { rootDir: pkgDir, allowlist });
  assert.ok(changed.some((f) => f.detectorId === "credential-assignment"), "changed extracted file reactivates the finding");

  // A private-key finding can never be suppressed at either root.
  writeFileSync(join(distDir, "k.pem"), PRIVATE_PEM);
  const pemFindings = scanForPackageSecrets(distDir);
  const pemAllow = [
    { relativePath: "k.pem", detectorId: "pem-private-key", sha256: sha256File(join(distDir, "k.pem")), reason: "must not work" }
  ];
  assert.ok(
    applyAllowlist(pemFindings, { rootDir: distDir, allowlist: pemAllow }).some((f) => f.detectorId === "pem-private-key"),
    "private-key findings must never be suppressible"
  );
});

// --- Finding 5: PuTTY detection must parse the private body, not trust the count. ---
const PUTTY_BODY =
  "PuTTY-User-Key-File-2: ssh-ed25519\nEncryption: none\nComment: t\nPublic-Lines: 1\nAAAApub\n" +
  "Private-Lines: 2\nZmFrZWJvZHkx\nZmFrZWJvZHky\nPrivate-MAC: 00\n";
scenario("F5: valid-shaped PuTTY v2 private body is detected", (dir) => {
  writeFileSync(join(dir, "a.ppk"), PUTTY_BODY);
  assertDetector(dir, "putty-private-key", "a.ppk");
});
scenario("F5: valid-shaped PuTTY v3 private body is detected", (dir) => {
  writeFileSync(join(dir, "a.ppk"), PUTTY_BODY.replace("File-2:", "File-3:"));
  assertDetector(dir, "putty-private-key", "a.ppk");
});
scenario("F5: encrypted PuTTY container with a populated body is detected", (dir) => {
  writeFileSync(join(dir, "a.ppk"), PUTTY_BODY.replace("Encryption: none", "Encryption: aes256-cbc"));
  assertDetector(dir, "putty-private-key", "a.ppk");
});
scenario("F5: Private-Lines: 0 is allowed", (dir) => {
  writeFileSync(join(dir, "a.ppk"), "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPrivate-Lines: 0\n");
  assertClean(dir);
});
scenario("F5: truncated Private-Lines: 1 with no body is allowed", (dir) => {
  writeFileSync(join(dir, "a.ppk"), "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPrivate-Lines: 1\n");
  assertClean(dir);
});
scenario("F5: positive count with fewer body lines than declared is allowed", (dir) => {
  writeFileSync(join(dir, "a.ppk"), "PuTTY-User-Key-File-2: ssh-ed25519\nPrivate-Lines: 3\nZmFrZQ==\nPrivate-MAC: 00\n");
  assertClean(dir);
});
scenario("F5: a blank required body line is allowed", (dir) => {
  writeFileSync(join(dir, "a.ppk"), "PuTTY-User-Key-File-2: ssh-ed25519\nPrivate-Lines: 2\nZmFrZQ==\n\nPrivate-MAC: 00\n");
  assertClean(dir);
});
scenario("F5: non-Base64 body is allowed", (dir) => {
  writeFileSync(join(dir, "a.ppk"), "PuTTY-User-Key-File-2: ssh-ed25519\nPrivate-Lines: 1\n!!! not base64 !!!\nPrivate-MAC: 00\n");
  assertClean(dir);
});
scenario("F5: prose mentioning PuTTY remains allowed", (dir) => {
  writeFileSync(join(dir, "r.md"), "We used PuTTY to connect; Private-Lines were discussed only in passing.\n");
  assertClean(dir);
});

// ===========================================================================
// Second-round regression tests: three bypasses found by independent review of
// the first remediation. Each fails against that intermediate implementation.
// ===========================================================================

// --- B1: a valid JSON JWK nested inside a NON-JSON JavaScript block. The outer
//     block never parses as JSON; the inner object must still be inspected. ---
scenario("B1: private JWK inside a JS function body is detected", (dir) => {
  writeFileSync(join(dir, "load.js"), `function load() {\n  const key = ${EMBEDDED_OKP};\n  return key;\n}\n`);
  assertDetector(dir, "jwk-private-key", "load.js");
});
scenario("B1: private JWK inside an if-block is detected", (dir) => {
  writeFileSync(join(dir, "cfg.js"), `if (env === "prod") {\n  cfg.jwk = ${EMBEDDED_OKP};\n}\n`);
  assertDetector(dir, "jwk-private-key", "cfg.js");
});
scenario("B1: symmetric JWK nested inside a JS block is detected", (dir) => {
  writeFileSync(join(dir, "s.js"), `export function f(){ return { k: ${EMBEDDED_OCT} }; }\n`);
  assertDetector(dir, "jwk-symmetric-key", "s.js");
});

// --- B2: resource limits must never silently produce a clean result — they
//     either keep inspecting or fail closed. ---
scenario("B2: 200 harmless candidates followed by a private JWK is detected", (dir) => {
  let text = "";
  for (let i = 0; i < 200; i++) text += `{"index":${i}}\n`;
  text += EMBEDDED_OKP + "\n";
  writeFileSync(join(dir, "many.txt"), text);
  assertDetector(dir, "jwk-private-key", "many.txt");
});
scenario("B2: a huge number of candidates before the JWK is still detected", (dir) => {
  let text = "";
  for (let i = 0; i < 5000; i++) text += `{"i":${i}}\n`;
  text += `const key = ${EMBEDDED_OKP};\n`;
  writeFileSync(join(dir, "lots.js"), text);
  assertDetector(dir, "jwk-private-key", "lots.js");
});
scenario("B2: oversized embedded candidate containing JWK material is detected", (dir) => {
  const huge = `{"pad":"${"Z".repeat(500000)}","kty":"EC","crv":"P-256","x":"px","y":"py","d":"ecprivate01234567890abc"}`;
  writeFileSync(join(dir, "big.js"), `module.exports = ${huge};\n`);
  assertDetector(dir, "jwk-private-key", "big.js");
});
scenario("B2: excessive nesting containing JWK material fails closed (not clean)", (dir) => {
  writeFileSync(join(dir, "deep.txt"), "[".repeat(400) + EMBEDDED_OKP + "]".repeat(400));
  assert.throws(() => scanForPackageSecrets(dir), SecretScanError, "deep nesting must fail closed, never return clean");
});
scenario("B2: a resource limit never yields a false clean result", (dir) => {
  // For each pathological shape, the scan must EITHER surface the JWK OR throw
  // SecretScanError — it must never quietly return an empty (clean) result.
  const shapes = [
    "[".repeat(400) + EMBEDDED_OKP + "]".repeat(400), // exceeds depth → fail closed
    (() => { let s = ""; for (let i = 0; i < 400; i++) s += `{"n":${i}}`; return s + EMBEDDED_OKP; })() // many candidates → detect
  ];
  for (const content of shapes) {
    writeFileSync(join(dir, "s.txt"), content);
    let threw = false;
    let findings = [];
    try {
      findings = scanForPackageSecrets(dir);
    } catch (e) {
      threw = e instanceof SecretScanError;
      assert.ok(threw, `unexpected error type: ${e}`);
    }
    assert.ok(
      threw || findings.some((f) => f.detectorId === "jwk-private-key"),
      "a resource limit must detect the secret or fail closed, never return clean"
    );
  }
});

// --- B3: standard-Base64 credentials containing `/`, `//`, `+`, `=` must be
//     detected; real URLs / paths must still be rejected. ---
scenario("B3: Base64 credential with a single / is detected", (dir) => {
  writeFileSync(join(dir, ".env"), "SECRET=AbCdEfGhIjKl/MnOpQrStUvWxYz012345\n");
  assertDetector(dir, "credential-assignment", ".env");
});
scenario("B3: Base64 credential with // is detected", (dir) => {
  writeFileSync(join(dir, ".env"), "AWS_SECRET_ACCESS_KEY=AbCdEfGhIjKlMnOpQrStUvWxYz01//234567+AB\n");
  assertDetector(dir, "credential-assignment", ".env");
});
scenario("B3: Base64 credential with + is detected", (dir) => {
  writeFileSync(join(dir, ".env"), "SECRET=AbCd+EfGhIjKlMnOpQrSt+UvWxYz0123\n");
  assertDetector(dir, "credential-assignment", ".env");
});
scenario("B3: Base64 credential with = padding is detected", (dir) => {
  writeFileSync(join(dir, "c.json"), JSON.stringify({ client_secret: "AbCdEfGhIjKlMnOpQrStUvWx0123456789==" }));
  assertDetector(dir, "credential-assignment", "c.json");
});
scenario("B3: Base64 credential combining / + = is detected", (dir) => {
  writeFileSync(join(dir, "c.json"), JSON.stringify({ access_token: "Ab/Cd+Ef/Gh1234567890+Xy/Zz==" }));
  assertDetector(dir, "credential-assignment", "c.json");
});
scenario("B3: Base64 credential that merely starts with / (with +/=) is detected", (dir) => {
  // A leading `/` alone must NOT be read as a path when the value is Base64.
  writeFileSync(join(dir, "c.json"), JSON.stringify({ secret: "/9x+AbCdEf0123456789Gh==" }));
  assertDetector(dir, "credential-assignment", "c.json");
});
scenario("B3 negatives: unambiguous URL / scheme / drive references remain allowed", (dir) => {
  // These are unambiguous references (scheme or drive), all carrying `:` — never
  // the raw Base64 credential form. Bare filesystem paths are handled by the
  // fail-closed test below, not here.
  const cases = [
    "https://user:pass@example.com/token/abcdefgh",
    "http://example.com/a//b//c",
    "file:///etc/secret/key",
    "C:/Users/app/secret/key.dat"
  ];
  for (const v of cases) {
    writeFileSync(join(dir, "c.json"), JSON.stringify({ secret: v }));
    const findings = scanForPackageSecrets(dir);
    assert.deepEqual(findings, [], `reference must be allowed: ${v}; got ${JSON.stringify(findings)}`);
  }
});

// ===========================================================================
// Third-round regression tests: three more bypasses found by independent review.
// Each fails against the previous implementation.
// ===========================================================================

// --- C1: a stray JavaScript quote must not desync the JWK region scanner and
//     cause a later private key to be missed. ---
scenario("C1: stray double-quote in a JS line comment before a JWK", (dir) => {
  writeFileSync(join(dir, "a.js"), `// don't worry about the " character here\nconst key = ${EMBEDDED_OKP};\n`);
  assertDetector(dir, "jwk-private-key", "a.js");
});
scenario("C1: unbalanced quote in a single-quoted JS string before a JWK", (dir) => {
  writeFileSync(join(dir, "b.js"), `const msg = 'he said "hi';\nconst key = ${EMBEDDED_OKP};\n`);
  assertDetector(dir, "jwk-private-key", "b.js");
});
scenario("C1: several stray quotes across lines before a JWK", (dir) => {
  const noise = `let a = '"';\nlet b = "x\\"y";\n// a lone " here\n`;
  writeFileSync(join(dir, "c.js"), `${noise}const k = ${EMBEDDED_OKP};\n`);
  assertDetector(dir, "jwk-private-key", "c.js");
});
scenario("C1: stray quote before a symmetric JWK is still caught", (dir) => {
  writeFileSync(join(dir, "d.js"), `const note = "it's fine;\nexport const k = ${EMBEDDED_OCT};\n`);
  assertDetector(dir, "jwk-symmetric-key", "d.js");
});

// --- C2: quoted JSON credentials longer than the old 200-char capture cap must
//     be captured up to the full supported length (512). ---
scenario("C2: a 300-char quoted JSON credential is detected", (dir) => {
  const long = "A1b2C3d4E5".repeat(30); // 300 chars, letters+digits, high entropy
  writeFileSync(join(dir, "c.json"), JSON.stringify({ api_key: long }));
  assertDetector(dir, "credential-assignment", "c.json");
});
scenario("C2: a 512-char credential (the claimed maximum) is detected", (dir) => {
  const long = "A1b2C3d4E5".repeat(51) + "Xy"; // 512 chars
  assert.equal(long.length, 512);
  writeFileSync(join(dir, ".env"), `API_KEY=${long}\n`);
  assertDetector(dir, "credential-assignment", ".env");
});
scenario("C2: a 400-char dotenv credential is detected", (dir) => {
  const long = "Zk9Xa2Bc3D".repeat(40); // 400 chars
  writeFileSync(join(dir, ".env"), `PRIVATE_TOKEN=${long}\n`);
  assertDetector(dir, "credential-assignment", ".env");
});

// --- C3: a valid Base64 secret that merely looks like a filesystem path must
//     no longer be deliberately allowed — it fails closed (is detected). ---
scenario("C3: path-shaped Base64 secret on a secret field is detected", (dir) => {
  writeFileSync(join(dir, ".env"), "SECRET=AbCd/EfGh/IjKl/MnOp/QrStUvWx\n");
  assertDetector(dir, "credential-assignment", ".env");
});
scenario("C3: an absolute-path-shaped secret value fails closed (is detected)", (dir) => {
  writeFileSync(join(dir, "c.json"), JSON.stringify({ secret: "/var/lib/app/secret-store/credentials" }));
  assertDetector(dir, "credential-assignment", "c.json");
});
scenario("C3: a Base64 secret with / + = on a secret field is still detected", (dir) => {
  writeFileSync(join(dir, "c.json"), JSON.stringify({ client_secret: "Ab/Cd+Ef/Gh12/34+56==Xy/Zz" }));
  assertDetector(dir, "credential-assignment", "c.json");
});

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
const failed = results.filter((r) => r.ok === false);
const skipped = results.filter((r) => r.skip);
const passed = results.filter((r) => r.ok === true);
if (failed.length > 0) {
  console.error(`\nFAIL package secret scan hostile tests (${passed.length} passed, ${failed.length} failed, ${skipped.length} skipped)`);
  process.exit(1);
}
console.log(
  `\nPASS package secret scan hostile tests (${passed.length} passed, ${skipped.length} skipped, 0 failed)`
);
