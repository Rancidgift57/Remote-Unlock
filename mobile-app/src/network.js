/**
 * network.js — talks to the laptop's listener over wss://.
 *
 * TLS validation happens automatically, the normal way: once you've
 * installed the laptop's local CA certificate as trusted on this phone
 * (a one-time OS-level step, done in Settings — see the pairing screen),
 * React Native's built-in WebSocket validates the server's certificate
 * chain against the OS trust store just like it would for any HTTPS site.
 * No custom pinning code is needed or used here — that's deliberate: a
 * hand-rolled pinning check that isn't backed by the OS's actual TLS
 * stack is easy to get wrong and easy to silently no-op.
 *
 * On top of that transport-level guarantee, every challenge is ALSO
 * verified at the application layer against the laptop's own signing key
 * (captured at pairing) before we ever touch biometrics — two independent
 * checks, not one.
 */

import { verifySignature, signChallenge } from "./crypto";
import { getPrivateKeyWithBiometrics, getLaptopPublicKey } from "./secureStore";

const CONNECT_TIMEOUT_MS = 15000;

/**
 * Attempts one unlock. Resolves to `true`/`false` (the laptop's verdict),
 * or rejects with an Error describing what went wrong (bad laptop
 * identity, biometric cancelled, network error, timeout).
 */
export function attemptUnlock(laptopHost, laptopPort = 8765) {
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
      finish(reject, new Error("Timed out connecting to laptop. Is it on the same Wi-Fi?"));
    }, CONNECT_TIMEOUT_MS);

    ws.onerror = (err) => {
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
        const laptopVerified = verifySignature(
          laptopPublicKeyPem,
          msg.nonce,
          msg.timestamp,
          msg.signature
        );
        if (!laptopVerified) {
          finish(reject, new Error(
            "Could not verify this is your paired laptop. Refusing to proceed."
          ));
          return;
        }

        const privateKeyPem = await getPrivateKeyWithBiometrics();
        if (!privateKeyPem) {
          finish(reject, new Error("Biometric authentication failed or cancelled."));
          return;
        }

        const timestamp = Date.now() / 1000;
        const signature = signChallenge(privateKeyPem, msg.nonce, timestamp);

        ws.send(JSON.stringify({
          type: "response",
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
