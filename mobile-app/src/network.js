/**
 * network.js — talks to the laptop's listener over wss://.
 *
 * TLS validation happens automatically, the normal way: once you've
 * installed the laptop's local CA certificate as trusted on this phone
 * (a one-time OS-level step, done in Settings — see the pairing screen),
 * React Native's built-in WebSocket validates the server's certificate
 * chain against the OS trust store just like it would for any HTTPS site.
 * No custom pinning code is needed or used here.
 *
 * On top of that transport-level guarantee, every challenge is ALSO
 * verified at the application layer against the laptop's own signing key
 * (captured at pairing) before we ever touch biometrics — two independent
 * checks, not one.
 *
 * Two commands are supported: "unlock" and "shutdown". They are NOT
 * interchangeable at the crypto level — see crypto.js's action-bound
 * signing. A signature proving "the phone holder approved an unlock" can
 * never be reinterpreted as "the phone holder approved a shutdown."
 */

import { verifySignature, signChallenge } from "./crypto";
import { getPrivateKeyWithBiometrics, getLaptopPublicKey } from "./secureStore";

const CONNECT_TIMEOUT_MS = 15000;

function runCommand(laptopHost, laptopPort, action, biometricPromptReason) {
  return new Promise(async (resolve, reject) => {
    const laptopPublicKeyPem = await getLaptopPublicKey();
    if (!laptopPublicKeyPem) {
      reject(new Error("Not paired yet — pair with your laptop first."));
      return;
    }

    let settled = false;
    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { ws.close(); } catch (e) {}
      fn(arg);
    };

    const ws = new WebSocket(`wss://${laptopHost}:${laptopPort}`);

    const timer = setTimeout(() => {
      finish(reject, new Error("Timed out connecting to laptop. Is it reachable?"));
    }, CONNECT_TIMEOUT_MS);

    ws.onerror = () => {
      finish(
        reject,
        new Error(
          "Connection failed. If this is the first attempt, make sure you've " +
            "installed the laptop's certificate as trusted (see pairing screen)."
        )
      );
    };

    ws.onmessage = async (event) => {
      let msg;
      try {
        msg = JSON.parse(event.data);
      } catch (e) {
        finish(reject, new Error("Laptop sent malformed data."));
        return;
      }

      if (msg.type === "challenge") {
        // The laptop's own signature is bound to the "challenge" action —
        // distinct from "unlock"/"shutdown" so these three signature
        // classes can never be confused with each other.
        const laptopVerified = verifySignature(
          laptopPublicKeyPem, msg.nonce, msg.timestamp, msg.signature, "challenge"
        );
        if (!laptopVerified) {
          finish(reject, new Error(
            "Could not verify this is your paired laptop. Refusing to proceed."
          ));
          return;
        }

        const privateKeyPem = await getPrivateKeyWithBiometrics(biometricPromptReason);
        if (!privateKeyPem) {
          finish(reject, new Error("Biometric authentication failed or cancelled."));
          return;
        }

        const timestamp = Date.now() / 1000;
        const signature = signChallenge(privateKeyPem, msg.nonce, timestamp, action);

        ws.send(JSON.stringify({
          type: "response",
          action,
          nonce: msg.nonce,
          timestamp,
          signature,
        }));
      } else if (msg.type === "result") {
        finish(resolve, msg.ok === true);
      }
    };
  });
}

/**
 * Attempts one unlock. Resolves to `true`/`false` (the laptop's verdict),
 * or rejects with an Error describing what went wrong.
 */
export function attemptUnlock(laptopHost, laptopPort = 8765) {
  return runCommand(laptopHost, laptopPort, "unlock", "Confirm it's you to unlock your laptop");
}

/**
 * Sends a signed shutdown command. Resolves to `true` if the laptop
 * accepted and executed it, `false` if rejected (bad signature, replay,
 * rate-limited, or the laptop has the shutdown feature disabled in its
 * config). The UI layer is responsible for getting explicit user
 * confirmation BEFORE calling this — this function itself still requires
 * a fresh biometric prompt on top of that, since it's a destructive,
 * irreversible action.
 */
export function attemptShutdown(laptopHost, laptopPort = 8765) {
  return runCommand(laptopHost, laptopPort, "shutdown", "Confirm it's you to shut down your laptop");
}
