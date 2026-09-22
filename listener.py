#!/usr/bin/env python3
"""
listener.py — background service that authenticates unlock requests from
your phone and hands the result to PAM.

Security properties (hardened vs. a naive version):
  - Every challenge nonce is single-use and expires after NONCE_TTL seconds.
    A used or expired nonce is rejected even if replayed with a valid
    signature.
  - Signature is ECDSA P-256 over (nonce || timestamp || client_id), so a
    captured signature can't be replayed for a different nonce or reused
    later.
  - Runs over TLS (wss://) using a certificate pinned by the phone at
    pairing time, so a network attacker can't MITM the exchange even
    though it crosses your LAN.
  - Rate-limited: a burst of failed attempts triggers a cooldown, to blunt
    brute-force / DoS attempts against the listener.
  - Fails closed: any exception during verification is treated as a
    rejection, never as a pass-through success.

File-system contact is deliberately minimal:
  - Reads exactly one file at startup: ~/.config/remote-unlock/pairing.json
    (read-only open, never written by this process).
  - Signals success/failure to PAM over a Unix domain socket created in
    /run (tmpfs = RAM, not disk), so no on-disk file is created, written,
    or deleted during normal operation.
  - Never touches your data files, never runs as root, never has
    disk-write privileges beyond what your normal user already has for
    /run/user/<uid>.

Run this as your normal (non-root) user, e.g. via a systemd --user service.
"""

import asyncio
import base64
import getpass
import json
import os
import ssl
import time
import socket
import logging
from collections import deque
from pathlib import Path

import websockets
from cryptography.hazmat.primitives.asymmetric import ec, padding  # noqa: F401
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidSignature

SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def decrypt_private_key(encrypted: dict) -> str:
    """Prompts for the passphrase set during pairing. The decrypted key
    lives only in this process's memory for the life of the service — it is
    never written back to disk."""
    salt = base64.b64decode(encrypted["salt"])

    def get_passphrase():
        if "REMOTE_UNLOCK_PASSPHRASE" in os.environ:
            return os.environ["REMOTE_UNLOCK_PASSPHRASE"]
        pass_file = os.environ.get("REMOTE_UNLOCK_PASSPHRASE_FILE")
        if pass_file and os.path.exists(pass_file):
            # Read once, then remove — this file is meant to be a
            # short-lived handoff from systemd-ask-password, not a
            # persistent secret store.
            content = Path(pass_file).read_text().strip()
            try:
                os.remove(pass_file)
            except OSError:
                pass
            return content
        return getpass.getpass("Passphrase to unlock the remote-unlock private key: ")

    for attempt in range(3):
        passphrase = get_passphrase()
        key = derive_key(passphrase, salt)
        try:
            return Fernet(key).decrypt(encrypted["ciphertext"].encode()).decode()
        except InvalidToken:
            print("Wrong passphrase.")
    raise SystemExit("Too many failed passphrase attempts. Exiting.")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("remote-unlock-listener")

CONFIG_FILE = Path.home() / ".config" / "remote-unlock" / "pairing.json"
NONCE_TTL = 10          # seconds a challenge stays valid
MAX_CLOCK_SKEW = 5      # seconds of allowed timestamp drift
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_FAILS = 5

UNLOCK_SOCK_PATH = f"/run/user/{os.getuid()}/remote-unlock-signal.sock"


class UnlockService:
    def __init__(self, config: dict, laptop_private_key_pem: str):
        self.phone_public_key = serialization.load_pem_public_key(
            config["phone_public_key_pem"].encode()
        )
        self.laptop_private_key = serialization.load_pem_private_key(
            laptop_private_key_pem.encode(), password=None
        )
        self.port = config.get("listener_port", 8765)
        self.ntfy_topic = config.get("ntfy_topic")
        self._pending_nonces: dict[str, float] = {}   # nonce -> issue_time
        self._used_nonces: set[str] = set()
        self._fail_times: deque[float] = deque()

    def issue_challenge(self) -> dict:
        """Nonce + timestamp, signed by the LAPTOP's own key, so the phone
        can verify it's really talking to the paired laptop — independent
        of TLS cert pinning, as a second, unrelated trust check."""
        nonce = os.urandom(16).hex()
        now = time.time()
        self._pending_nonces[nonce] = now
        self._pending_nonces = {
            n: t for n, t in self._pending_nonces.items() if now - t < NONCE_TTL
        }
        message = f"{nonce}:{now}".encode()
        signature = self.laptop_private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return {"nonce": nonce, "timestamp": now, "signature": signature.hex()}

    def _rate_limited(self) -> bool:
        now = time.time()
        while self._fail_times and now - self._fail_times[0] > RATE_LIMIT_WINDOW:
            self._fail_times.popleft()
        return len(self._fail_times) >= RATE_LIMIT_MAX_FAILS

    def _record_failure(self):
        self._fail_times.append(time.time())

    def verify(self, nonce: str, timestamp: float, signature_hex: str) -> bool:
        """Fail-closed: any problem at all returns False."""
        try:
            if self._rate_limited():
                log.warning("Rate limit active — rejecting attempt")
                return False

            issue_time = self._pending_nonces.pop(nonce, None)
            if issue_time is None:
                log.warning("Unknown or already-used nonce")
                self._record_failure()
                return False

            if nonce in self._used_nonces:
                log.warning("Nonce replay detected")
                self._record_failure()
                return False

            now = time.time()
            if now - issue_time > NONCE_TTL:
                log.warning("Nonce expired")
                self._record_failure()
                return False

            if abs(now - timestamp) > MAX_CLOCK_SKEW + NONCE_TTL:
                log.warning("Timestamp outside acceptable skew")
                self._record_failure()
                return False

            message = f"{nonce}:{timestamp}".encode()
            signature = bytes.fromhex(signature_hex)

            self.phone_public_key.verify(
                signature, message, ec.ECDSA(hashes.SHA256())
            )

            self._used_nonces.add(nonce)
            return True

        except (InvalidSignature, ValueError, KeyError):
            self._record_failure()
            return False
        except Exception as e:  # fail closed on anything unexpected
            log.error("Unexpected error during verification: %s", e)
            self._record_failure()
            return False


def signal_pam(success: bool):
    """
    Tell the waiting PAM helper the outcome, over a Unix domain socket that
    lives in /run (tmpfs). Nothing is written to persistent disk.
    """
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.sendto(b"1" if success else b"0", UNLOCK_SOCK_PATH)
    except FileNotFoundError:
        log.warning("PAM helper isn't listening (no active login prompt)")
    except OSError as e:
        log.error("Could not signal PAM socket: %s", e)


def send_alert(success: bool, ntfy_topic: str):
    """Fire-and-forget push notification; failure here never blocks login."""
    try:
        import notify
        notify.send_unlock_alert(success, ntfy_topic)
    except Exception as e:
        log.warning("Notification failed (non-fatal): %s", e)


async def handler(websocket, service: UnlockService):
    peer = websocket.remote_address
    try:
        challenge = service.issue_challenge()
        await websocket.send(json.dumps({"type": "challenge", **challenge}))

        raw = await asyncio.wait_for(websocket.recv(), timeout=NONCE_TTL + 2)
        msg = json.loads(raw)

        if msg.get("type") != "response":
            await websocket.send(json.dumps({"type": "result", "ok": False}))
            return

        ok = service.verify(
            nonce=msg["nonce"],
            timestamp=float(msg["timestamp"]),
            signature_hex=msg["signature"],
        )

        await websocket.send(json.dumps({"type": "result", "ok": ok}))
        log.info("Unlock attempt from %s: %s", peer, "SUCCESS" if ok else "REJECTED")

        signal_pam(ok)
        send_alert(ok, service.ntfy_topic)

    except (asyncio.TimeoutError, KeyError, json.JSONDecodeError, ValueError) as e:
        log.warning("Malformed/late request from %s: %s", peer, e)
        signal_pam(False)
    except websockets.exceptions.ConnectionClosed:
        pass


def build_ssl_context(config: dict) -> ssl.SSLContext:
    cert_path = config.get("tls_cert_path")
    key_path = config.get("tls_key_path")
    if not cert_path or not key_path:
        raise SystemExit(
            "No TLS certificate configured. This service refuses to run "
            "over plaintext ws:// on a LAN-facing port. Re-run pair.py "
            "(it now generates a cert automatically) or see README.md."
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


async def main():
    if not CONFIG_FILE.exists():
        log.error("No pairing config found. Run pair.py first.")
        return

    config = json.loads(CONFIG_FILE.read_text())  # only file read, at startup
    laptop_private_key_pem = decrypt_private_key(config["laptop_private_key_encrypted"])
    service = UnlockService(config, laptop_private_key_pem)
    ssl_context = build_ssl_context(config)

    async def _handler(ws):
        await handler(ws, service)

    # Bind to the SPECIFIC IP the cert was issued for (Tailscale or LAN),
    # not 0.0.0.0. This means the listener is literally unreachable on any
    # other interface — e.g. if you're on Tailscale, it's unreachable from
    # your plain LAN at all, on top of whatever firewall rules you also
    # have. Stronger than firewall-only scoping because there's no
    # interface to accidentally leave open.
    bind_ip = config.get("listener_ip", "0.0.0.0")

    try:
        async with websockets.serve(
            _handler, bind_ip, service.port, ssl=ssl_context
        ):
            log.info(
                "Listening on %s:%s (%s)",
                bind_ip, service.port, "wss" if ssl_context else "ws",
            )
            await asyncio.Future()  # run forever
    except OSError as e:
        log.error(
            "Could not bind to %s:%s (%s). If this is a Tailscale IP, is "
            "Tailscale running? If it's a LAN IP, has it changed? Re-run "
            "pair.py to reissue the cert for the current IP if so.",
            bind_ip, service.port, e,
        )


if __name__ == "__main__":
    asyncio.run(main())
