// Backward-compatibility shim.
//
// The content-based private-key scan that used to live here has been GENERALIZED
// into build/lib/package-secret-scan.mjs (which now also detects binary DER
// private keys, private/symmetric JWKs, PuTTY key files, a conservative registry
// of provider secret tokens, and contextual credential assignments — in addition
// to the same five PEM private-key headers this module always caught).
//
// This file is preserved only so existing importers keep working unchanged:
//   import { scanForPrivateKeyMaterial, PRIVATE_KEY_MARKER } from ".../private-key-scan.mjs"
// Both are re-exported from the generalized engine with identical semantics:
// scanForPrivateKeyMaterial() still returns the absolute paths of files whose
// content contains a PEM private-key marker, and PRIVATE_KEY_MARKER is the same
// regexp. New code should import from package-secret-scan.mjs directly and use
// scanForPackageSecrets()/applyAllowlist() for the full secret set.

export { scanForPrivateKeyMaterial, PRIVATE_KEY_MARKER } from "./package-secret-scan.mjs";
