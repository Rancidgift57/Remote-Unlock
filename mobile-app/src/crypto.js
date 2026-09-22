/**
 * crypto.js — ECDSA P-256 keypair generation and signing.
 *
 * Uses jsrsasign (pure JS, no native module needed — works in Expo Go).
 * Verified cross-compatible with the laptop's Python `cryptography`
 * library: signatures produced here verify correctly in Python and
 * vice versa (standard SEC1/DER ECDSA over SHA-256).
 */

import { KEYUTIL, KJUR } from "jsrsasign";

/**
 * Generates a fresh ECDSA P-256 keypair.
 * Returns { publicKeyPem, privateKeyPem } — caller is responsible for
 * putting the private key straight into biometric-gated secure storage
 * and never persisting it anywhere else.
 */
export function generateKeypair() {
  const kp = KEYUTIL.generateKeypair("EC", "secp256r1");
  return {
    publicKeyPem: KEYUTIL.getPEM(kp.pubKeyObj),
    privateKeyPem: KEYUTIL.getPEM(kp.prvKeyObj, "PKCS8PRV"),
  };
}

/**
 * Signs `${nonce}:${timestamp}` with the given private key PEM.
 * Returns a hex-encoded DER signature, matching the format the laptop's
 * Python side expects and produces.
 */
export function signChallenge(privateKeyPem, nonce, timestamp) {
  const message = `${nonce}:${timestamp}`;
  const sig = new KJUR.crypto.Signature({ alg: "SHA256withECDSA" });
  sig.init(privateKeyPem);
  sig.updateString(message);
  return sig.sign();
}

/**
 * Verifies a signature over `${nonce}:${timestamp}` against a public key
 * PEM. Returns false on ANY problem (malformed key, malformed signature,
 * bad match) — never throws out to the caller, so callers can treat this
 * as a simple boolean gate.
 */
export function verifySignature(publicKeyPem, nonce, timestamp, signatureHex) {
  try {
    const message = `${nonce}:${timestamp}`;
    const v = new KJUR.crypto.Signature({ alg: "SHA256withECDSA" });
    v.init(publicKeyPem);
    v.updateString(message);
    return v.verify(signatureHex);
  } catch (e) {
    return false; // fail closed
  }
}
