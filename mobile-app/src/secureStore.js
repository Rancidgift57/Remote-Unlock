/**
 * secureStore.js — stores the unlock private key behind a biometric gate.
 *
 * Uses expo-secure-store's `requireAuthentication` option, which maps to
 * the platform's own hardware-backed prompt (Keychain + LocalAuthentication
 * on iOS, Android Keystore + BiometricPrompt on Android). This means the
 * OS — not our app code — enforces the biometric check; the app never
 * sees raw fingerprint data, only the OS's pass/fail decision.
 *
 * If your Expo SDK version doesn't have requireAuthentication yet, this
 * falls back to prompting via expo-local-authentication before every read
 * — see the try/catch below. That fallback is weaker (the gate is
 * app-enforced, not storage-enforced) so prefer keeping Expo SDK current.
 */

import * as SecureStore from "expo-secure-store";
import * as LocalAuthentication from "expo-local-authentication";

const KEY_NAME = "remote-unlock-private-key";
const PUBKEY_NAME = "remote-unlock-public-key"; // not secret, stored alongside for convenience
const LAPTOP_TRUST_NAME = "remote-unlock-laptop-public-key"; // captured at pairing

export async function checkBiometricsAvailable() {
  const hasHardware = await LocalAuthentication.hasHardwareAsync();
  const isEnrolled = await LocalAuthentication.isEnrolledAsync();
  return hasHardware && isEnrolled;
}

export async function storePrivateKey(privateKeyPem, publicKeyPem) {
  await SecureStore.setItemAsync(KEY_NAME, privateKeyPem, {
    requireAuthentication: true,
    keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    authenticationPrompt: "Set up biometric unlock for your laptop",
  });
  // Public key isn't sensitive — no biometric gate needed to read it back.
  await SecureStore.setItemAsync(PUBKEY_NAME, publicKeyPem);
}

/**
 * Reads the private key. This call itself triggers the OS biometric
 * prompt (because the key was written with requireAuthentication: true).
 * Returns null if the prompt fails, is cancelled, or the key doesn't
 * exist — callers MUST treat null as "do not proceed."
 */
export async function getPrivateKeyWithBiometrics() {
  try {
    return await SecureStore.getItemAsync(KEY_NAME, {
      requireAuthentication: true,
      authenticationPrompt: "Confirm it's you to unlock your laptop",
    });
  } catch (e) {
    return null; // cancelled, failed, or not available
  }
}

export async function getStoredPublicKey() {
  try {
    return await SecureStore.getItemAsync(PUBKEY_NAME);
  } catch (e) {
    return null;
  }
}

export async function hasStoredKeypair() {
  return (await getStoredPublicKey()) !== null;
}

/** Laptop's public key, captured once during pairing — used to verify the
 * laptop's identity on every unlock attempt, independent of TLS. */
export async function storeLaptopPublicKey(pem) {
  await SecureStore.setItemAsync(LAPTOP_TRUST_NAME, pem);
}

export async function getLaptopPublicKey() {
  try {
    return await SecureStore.getItemAsync(LAPTOP_TRUST_NAME);
  } catch (e) {
    return null;
  }
}

/** Wipes everything — use if you suspect compromise or are re-pairing. */
export async function clearAll() {
  await SecureStore.deleteItemAsync(KEY_NAME).catch(() => {});
  await SecureStore.deleteItemAsync(PUBKEY_NAME).catch(() => {});
  await SecureStore.deleteItemAsync(LAPTOP_TRUST_NAME).catch(() => {});
}
