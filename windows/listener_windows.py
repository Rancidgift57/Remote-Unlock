#!/usr/bin/env python3
"""
listener_windows.py — Windows port of listener.py.

Everything about the crypto (challenge/response, nonce TTL, rate limiting,
fail-closed verification) is IDENTICAL to the Linux listener.py — that
logic is pure Python and already cross-platform. The only two things that
had to change for Windows:

  1. Signaling the result to the login screen.
     Linux uses a Unix domain socket in /run (tmpfs). Windows has no
     equivalent path or socket family available to an unprivileged
     process at the LogonUI stage, so this uses a named pipe instead:
     \\.\pipe\remote-unlock-signal
     The Credential Provider (C++, runs inside LogonUI) connects to this
     pipe and waits for a single byte, exactly like pam_unlock_helper.py
     waits on the Unix socket.

  2. What gets "signaled".
     PAM only needed pass/fail, because your password was already being
     collected by the OS's own auth stack in parallel. Windows Credential
     Providers must hand LogonUI a *complete* credential to finish a
     logon — there's no "defer to whatever's next" mechanism. So on
     success this also decrypts your Windows password (captured once at
     pairing time, DPAPI-protected at rest, see pair_windows.py) and
     writes it down the pipe alongside the success byte. It is never
     written to disk in decrypted form and lives only in this process's
     memory for the few milliseconds it takes to hand it to the pipe.

Run this as a normal user (not SYSTEM) — e.g. via Task Scheduler "run at
log on" / "run whether user is logged on or not" with your own account,
or NSSM as a user-mode service. It must be running *before* you try a
phone unlock, same as on Linux.
"""

import asyncio
import base64
import getpass
import json
import os
import ssl
import sys
import time
import logging
from collections import deque
from pathlib import Path

import websockets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidSignature

if sys.platform != "win32":
    raise SystemExit(
        "listener_windows.py is the Windows build. On Linux/macOS, use "
        "listener.py instead."
    )

import win32file    # pywin32 — pip install pywin32
import win32con
import pywintypes

SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def decrypt_secret(encrypted: dict, passphrase: str) -> str:
    salt = base64.b64decode(encrypted["salt"])
    key = derive_key(passphrase, salt)
    return Fernet(key).decrypt(encrypted["ciphertext"].encode()).decode()


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("remote-unlock-listener-windows")

CONFIG_DIR = Path(os.environ["LOCALAPPDATA"]) / "remote-unlock"
CONFIG_FILE = CONFIG_DIR / "pairing.json"

NONCE_TTL = 10
MAX_CLOCK_SKEW = 5
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_FAILS = 5

PIPE_NAME = r"\\.\pipe\remote-unlock-signal"


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
        self._pending_nonces: dict[str, float] = {}
        self._used_nonces: set[str] = set()
        self._fail_times: deque[float] = deque()

    def issue_challenge(self) -> dict:
        nonce = os.urandom(16).hex()
        now = time.time()
        self._pending_nonces[nonce] = now
        self._pending_nonces = {
            n: t for n, t in self._pending_nonces.items() if now - t < NONCE_TTL
        }
        message = f"challenge:{nonce}:{now}".encode()
        signature = self.laptop_private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return {"nonce": nonce, "timestamp": now, "signature": signature.hex()}

    def _rate_limited(self) -> bool:
        now = time.time()
        while self._fail_times and now - self._fail_times[0] > RATE_LIMIT_WINDOW:
            self._fail_times.popleft()
        return len(self._fail_times) >= RATE_LIMIT_MAX_FAILS

    def _record_failure(self):
        self._fail_times.append(time.time())

    def verify(self, nonce: str, timestamp: float, signature_hex: str, action: str = "unlock") -> bool:
        try:
            if action not in ("unlock", "shutdown"):
                log.warning("Unknown action %r — rejecting", action)
                self._record_failure()
                return False
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
            message = f"{action}:{nonce}:{timestamp}".encode()
            signature = bytes.fromhex(signature_hex)
            self.phone_public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            self._used_nonces.add(nonce)
            return True
        except (InvalidSignature, ValueError, KeyError):
            self._record_failure()
            return False
        except Exception as e:
            log.error("Unexpected error during verification: %s", e)
            self._record_failure()
            return False


def signal_credential_provider(success: bool, windows_password: str | None):
    """
    Equivalent of listener.py's signal_pam(), but over a named pipe to the
    Credential Provider running inside LogonUI, instead of a Unix socket
    to pam_unlock_helper.py.

    Wire format (all one write, pipe closes immediately after):
      byte 0:       0x01 success / 0x00 failure
      remaining:    UTF-8 password bytes (only present, and only sent, on success)

    If no Credential Provider is currently waiting (no active login/lock
    prompt), ERROR_FILE_NOT_FOUND / ERROR_PIPE_BUSY is expected and
    logged, not raised — this mirrors the Linux "PAM helper isn't
    listening" case.
    """
    try:
        handle = win32file.CreateFile(
            PIPE_NAME,
            win32con.GENERIC_WRITE,
            0,
            None,
            win32con.OPEN_EXISTING,
            0,
            None,
        )
        payload = (b"\x01" + windows_password.encode()) if success else b"\x00"
        win32file.WriteFile(handle, payload)
        win32file.CloseHandle(handle)
    except pywintypes.error as e:
        log.warning("Credential Provider isn't listening (no active login prompt): %s", e)


def send_alert(kind: str, ntfy_topic: str):
    try:
        import notify
        notify.send_alert(kind, ntfy_topic)
    except Exception as e:
        log.warning("Notification failed (non-fatal): %s", e)


def trigger_shutdown(shutdown_command: list):
    """Only ever called after UnlockService.verify() returns True for
    action="shutdown" — a fresh, single-use, rate-limited, biometric-gated
    signature from the paired phone. Default command is `shutdown /s /t 0`."""
    import subprocess
    try:
        log.warning("Executing remote shutdown command: %s", shutdown_command)
        subprocess.run(shutdown_command, check=True, timeout=10)
    except Exception as e:
        log.error("Shutdown command failed: %s", e)


async def handler(
    websocket, service: UnlockService, windows_password: str,
    shutdown_enabled: bool, shutdown_command: list,
):
    peer = websocket.remote_address
    try:
        challenge = service.issue_challenge()
        await websocket.send(json.dumps({"type": "challenge", **challenge}))
        raw = await asyncio.wait_for(websocket.recv(), timeout=NONCE_TTL + 2)
        msg = json.loads(raw)
        if msg.get("type") != "response":
            await websocket.send(json.dumps({"type": "result", "ok": False}))
            return

        action = msg.get("action", "unlock")
        if action not in ("unlock", "shutdown"):
            await websocket.send(json.dumps({"type": "result", "ok": False}))
            log.warning("Rejected request from %s: unknown action %r", peer, action)
            return

        if action == "shutdown" and not shutdown_enabled:
            await websocket.send(json.dumps({"type": "result", "ok": False}))
            log.warning("Rejected shutdown request from %s: feature disabled", peer)
            send_alert("shutdown_rejected", service.ntfy_topic)
            return

        ok = service.verify(
            nonce=msg["nonce"],
            timestamp=float(msg["timestamp"]),
            signature_hex=msg["signature"],
            action=action,
        )
        await websocket.send(json.dumps({"type": "result", "ok": ok}))
        log.info("%s attempt from %s: %s", action.upper(), peer, "SUCCESS" if ok else "REJECTED")

        if action == "unlock":
            signal_credential_provider(ok, windows_password if ok else None)
            send_alert("unlock_success" if ok else "unlock_failed", service.ntfy_topic)
        elif action == "shutdown":
            # Deliberately does not touch signal_credential_provider at
            # all — shutdown never interacts with the login/credential
            # flow, it's a fully separate verified action.
            if ok:
                trigger_shutdown(shutdown_command)
                send_alert("shutdown_triggered", service.ntfy_topic)
            else:
                send_alert("shutdown_rejected", service.ntfy_topic)

    except (asyncio.TimeoutError, KeyError, json.JSONDecodeError, ValueError) as e:
        log.warning("Malformed/late request from %s: %s", peer, e)
        signal_credential_provider(False, None)
    except websockets.exceptions.ConnectionClosed:
        pass


def build_ssl_context(config: dict) -> ssl.SSLContext:
    cert_path = config.get("tls_cert_path")
    key_path = config.get("tls_key_path")
    if not cert_path or not key_path:
        raise SystemExit(
            "No TLS certificate configured. Re-run pair_windows.py."
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


async def main():
    if not CONFIG_FILE.exists():
        log.error("No pairing config found. Run pair_windows.py first.")
        return

    config = json.loads(CONFIG_FILE.read_text())

    passphrase = os.environ.get("REMOTE_UNLOCK_PASSPHRASE") or getpass.getpass(
        "Passphrase to unlock the remote-unlock private key and Windows password: "
    )
    laptop_private_key_pem = decrypt_secret(config["laptop_private_key_encrypted"], passphrase)
    try:
        windows_password = decrypt_secret(config["windows_password_encrypted"], passphrase)
    except InvalidToken:
        raise SystemExit("Wrong passphrase.")

    service = UnlockService(config, laptop_private_key_pem)
    ssl_context = build_ssl_context(config)

    shutdown_enabled = bool(config.get("shutdown_enabled", False))
    shutdown_command = config.get("shutdown_command", ["shutdown", "/s", "/t", "0"])
    if shutdown_enabled:
        log.info("Remote shutdown is ENABLED (command: %s)", shutdown_command)
    else:
        log.info("Remote shutdown is disabled (see README.md to enable)")

    async def _handler(ws):
        await handler(ws, service, windows_password, shutdown_enabled, shutdown_command)

    bind_ip = config.get("listener_ip", "0.0.0.0")
    try:
        async with websockets.serve(_handler, bind_ip, service.port, ssl=ssl_context):
            log.info("Listening on %s:%s (wss)", bind_ip, service.port)
            await asyncio.Future()
    except OSError as e:
        log.error(
            "Could not bind to %s:%s (%s). Re-run pair_windows.py if the IP changed.",
            bind_ip, service.port, e,
        )


if __name__ == "__main__":
    asyncio.run(main())
