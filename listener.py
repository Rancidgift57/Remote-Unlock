#!/usr/bin/env python3
"""
listener.py - remote-unlock v2 service.

Security properties
  * Mutual TLS (TLS 1.3, private CA). The client certificate must chain to
    the CA AND its fingerprint must be pinned to a registered, non-revoked
    device. Unauthenticated peers never reach application logic.
  * Server-issued, single-use 128-bit nonce + server-side TTL. The nonce is
    consumed on first use whether or not the signature is valid.
  * ECDSA P-256 signatures in both directions (phone proves identity, laptop
    proves identity), bound to nonce, issue time, device id, target id.
  * Exponential-backoff lockout per IP and per device; connection cap;
    small message sizes; short handshake/read timeouts.
  * Binds to ONE specific interface IP; refuses wildcard binds by default.
  * Fail closed: every error path is a rejection.
  * Hash-chained audit log + out-of-band alerts on every outcome.
  * PAM never reads a file or trusts a message from "anyone": the PAM helper
    asks THIS process, over a root-only Unix socket, whether a verified unlock
    grant exists. The grant is single-use and expires in grant_ttl seconds.
"""
import asyncio
import json
import logging
import os
import secrets
import signal
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

import websockets
from cryptography.hazmat.primitives import serialization

from audit import AuditLog
from common import (NONCE_RE, Config, check_private, get_passphrase, home_dir,
                    load_public_key, sha256_hex, sign, signed_message,
                    state_dir, verify_sig)
from notify import Notifier

log = logging.getLogger("remote-unlock")
MAX_PENDING = 64
MSG_TIMEOUT = 5  # seconds for hello


# --------------------------------------------------------------------------
class Backoff:
    """Per-key failure counter with exponentially growing lockouts."""

    def __init__(self, threshold, base, maximum, quiet_reset=3600, clock=time.monotonic):
        self.threshold, self.base, self.maximum = threshold, base, maximum
        self.quiet_reset, self.clock = quiet_reset, clock
        self.state = {}

    def remaining(self, key) -> float:
        st = self.state.get(key)
        return max(0.0, st["until"] - self.clock()) if st else 0.0

    def fail(self, key) -> bool:
        """Record a failure. True if this failure STARTED a new lockout."""
        now = self.clock()
        st = self.state.setdefault(key, {"fails": 0, "level": 0, "until": 0.0, "last": now})
        if now - st["last"] > self.quiet_reset and now >= st["until"]:
            st["fails"], st["level"] = 0, 0
        st["last"] = now
        if now < st["until"]:
            return False
        st["fails"] += 1
        if st["fails"] >= self.threshold:
            st["until"] = now + min(self.base * (2 ** st["level"]), self.maximum)
            st["level"] += 1
            st["fails"] = 0
            return True
        if len(self.state) > 2048:
            self._prune(now)
        return False

    def success(self, key):
        self.state.pop(key, None)

    def _prune(self, now):
        for k in [k for k, s in self.state.items()
                  if now >= s["until"] and now - s["last"] > self.quiet_reset]:
            del self.state[k]


# --------------------------------------------------------------------------
class GrantBroker:
    """Single-use, short-lived 'a verified unlock just happened' token."""

    def __init__(self, ttl):
        self.ttl = ttl
        self._expires = 0.0
        self._event = asyncio.Event()

    def issue(self):
        self._expires = asyncio.get_running_loop().time() + self.ttl
        self._event.set()

    async def consume(self, timeout) -> bool:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            now = loop.time()
            if self._expires > now:
                self._expires = 0.0
                self._event.clear()
                return True
            remaining = deadline - now
            if remaining <= 0:
                return False
            self._event.clear()
            try:
                await asyncio.wait_for(self._event.wait(), remaining)
            except asyncio.TimeoutError:
                return False


# --------------------------------------------------------------------------
class UnlockService:
    def __init__(self, cfg: Config, signing_key, audit: AuditLog, notifier):
        self.cfg, self.signing_key, self.audit, self.notifier = cfg, signing_key, audit, notifier
        self.pending = {}  # nonce -> (device_id, monotonic_issue_time, issued_ms)
        lo = cfg["lockout"]
        self.ip_backoff = Backoff(lo["threshold"], lo["base_seconds"], lo["max_seconds"])
        self.dev_backoff = Backoff(lo["threshold"], lo["base_seconds"], lo["max_seconds"])
        self.broker = GrantBroker(cfg["grant_ttl"])
        self.active = 0
        self._last_lock_audit = {}
        self._tasks = set()

    # ---- challenge / response -------------------------------------------
    def issue_challenge(self, device_id: str) -> dict:
        now = time.monotonic()
        ttl = self.cfg["challenge_ttl"]
        self.pending = {n: r for n, r in self.pending.items() if now - r[1] <= ttl}
        if len(self.pending) >= MAX_PENDING:
            raise RuntimeError("too many pending challenges")
        nonce = secrets.token_hex(16)
        issued_ms = int(time.time() * 1000)
        self.pending[nonce] = (device_id, now, issued_ms)
        target = self.cfg["target_id"]
        msg = signed_message("challenge", nonce, issued_ms, device_id, target)
        return {"type": "challenge", "nonce": nonce, "issued_ms": issued_ms,
                "target_id": target, "server_sig": sign(self.signing_key, msg)}

    def check_response(self, device: dict, nonce, signature):
        """Returns None on success, else an internal failure reason."""
        if not isinstance(nonce, str) or not NONCE_RE.match(nonce):
            return "malformed_nonce"
        rec = self.pending.pop(nonce, None)  # single use, even on failure
        if rec is None:
            return "unknown_or_replayed_nonce"
        dev_id, t0, issued_ms = rec
        if dev_id != device["id"]:
            return "nonce_issued_to_other_device"
        if time.monotonic() - t0 > self.cfg["challenge_ttl"]:
            return "challenge_expired"
        msg = signed_message("response", nonce, issued_ms, dev_id, self.cfg["target_id"])
        if not verify_sig(load_public_key(device["public_key_pem"]), msg, signature):
            return "bad_signature"
        return None

    # ---- alerts / audit ---------------------------------------------------
    def alert(self, title, text, priority, tags, seq, head):
        body = f"{text}\naudit #{seq} head={head[:16]}"
        t = asyncio.create_task(self.notifier.send(title, body, priority, tags))
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    def record(self, event, title=None, priority="default", tags=(), **data):
        seq, head = self.audit.append(event, **data)
        if title:
            self.alert(title, ", ".join(f"{k}={v}" for k, v in data.items()), priority, tags, seq, head)
        return seq, head

    # ---- websocket session --------------------------------------------------
    async def handle(self, ws):
        ip = ws.remote_address[0] if ws.remote_address else "unknown"
        if self.active >= self.cfg["max_connections"]:
            await ws.close(1013)
            return
        self.active += 1
        try:
            self.cfg.reload_if_changed()
            await self._session(ws, ip)
        except websockets.exceptions.ConnectionClosed:
            pass
        except (asyncio.TimeoutError, ValueError, KeyError, TypeError, RuntimeError) as e:
            await self._fail(ws, ip, None, f"malformed_or_late:{type(e).__name__}")
        except Exception:  # noqa: BLE001 - fail closed
            log.exception("unexpected error")
            await self._fail(ws, ip, None, "internal_error")
        finally:
            self.active -= 1

    def _locked(self, key, kind):
        left = (self.ip_backoff if kind == "ip" else self.dev_backoff).remaining(key)
        if left > 0:
            now = time.monotonic()
            if now - self._last_lock_audit.get((kind, key), 0) > 10:  # don't let spam bloat the log
                self._last_lock_audit[(kind, key)] = now
                self.audit.append("attempt_during_lockout", kind=kind, key=key, seconds_left=int(left))
            return True
        return False

    async def _send(self, ws, obj):
        try:
            await ws.send(json.dumps(obj))
        except websockets.exceptions.ConnectionClosed:
            pass

    async def _recv_json(self, ws, timeout):
        raw = await asyncio.wait_for(ws.recv(), timeout)
        if not isinstance(raw, str):
            raise ValueError("binary frame")
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            raise ValueError("not an object")
        return obj

    async def _fail(self, ws, ip, device_id, reason):
        lock_ip = self.ip_backoff.fail(ip)
        lock_dev = bool(device_id) and self.dev_backoff.fail(device_id)
        self.record("unlock_rejected", "Unlock REJECTED", "urgent", ("warning",),
                    ip=ip, device=device_id, reason=reason)
        await self._send(ws, {"type": "result", "ok": False})  # generic: no oracle
        for kind, key, hit in (("ip", ip, lock_ip), ("device", device_id, lock_dev)):
            if hit:
                self.record("lockout", "LOCKOUT triggered", "urgent", ("rotating_light",),
                            kind=kind, key=key,
                            seconds=int((self.ip_backoff if kind == "ip" else self.dev_backoff).remaining(key)))

    async def _session(self, ws, ip):
        if self._locked(ip, "ip"):
            await ws.close(1008)
            return

        # 1. Identify the device from its mTLS certificate (pinned fingerprint).
        cert_device = None
        ssl_obj = ws.transport.get_extra_info("ssl_object")
        der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
        if der:
            cert_device = self.cfg.device_by_fp(sha256_hex(der))
        if self.cfg["require_mtls"] and cert_device is None:
            await self._fail(ws, ip, None, "no_registered_client_certificate")
            return

        hello = await self._recv_json(ws, MSG_TIMEOUT)
        if hello.get("type") != "hello" or not isinstance(hello.get("device_id"), str):
            await self._fail(ws, ip, None, "bad_hello")
            return
        device = cert_device if cert_device else self.cfg.device_by_id(hello["device_id"])
        if device is None or device["id"] != hello["device_id"]:
            await self._fail(ws, ip, None, "unknown_device_or_id_mismatch")
            return
        did = device["id"]
        if self._locked(did, "device"):
            await ws.close(1008)
            return

        # 2. Challenge / response.
        await self._send(ws, self.issue_challenge(did))
        resp = await self._recv_json(ws, self.cfg["challenge_ttl"] + 2)
        if resp.get("type") != "response":
            await self._fail(ws, ip, did, "bad_response_type")
            return
        reason = self.check_response(device, resp.get("nonce"), resp.get("signature"))
        if reason:
            await self._fail(ws, ip, did, reason)
            return

        # 3. Success.
        self.ip_backoff.success(ip)
        self.dev_backoff.success(did)
        self.broker.issue()
        self.record("unlock_authorized", "Unlock AUTHORIZED", "high", ("unlock",),
                    ip=ip, device=did, target=self.cfg["target_id"])
        await self._send(ws, {"type": "result", "ok": True})

    # ---- PAM broker (Unix socket) --------------------------------------------
    async def handle_pam(self, reader, writer):
        ok = False
        try:
            sock = writer.get_extra_info("socket")
            pid, uid, _gid = struct.unpack("3i", sock.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if uid not in self.cfg["pam_allowed_uids"]:
                self.record("pam_denied", "PAM request from disallowed uid", "high",
                            ("no_entry",), uid=uid, pid=pid)
                return
            req = json.loads(await asyncio.wait_for(reader.readline(), 3))
            if req.get("user") != self.cfg["unlock_user"]:
                self.record("pam_denied", user=str(req.get("user"))[:64], uid=uid)
                return
            ok = await self.broker.consume(self.cfg["pam_wait"])
            self.record("pam_grant_consumed" if ok else "pam_no_grant",
                        "PAM unlock granted" if ok else None, "default", ("key",),
                        user=req["user"], uid=uid, pid=pid)
        except Exception as e:  # noqa: BLE001 - fail closed
            log.warning("pam request failed: %s", e)
            ok = False
        finally:
            try:
                writer.write(b"1\n" if ok else b"0\n")
                await writer.drain()
            except Exception:  # noqa: BLE001
                pass
            writer.close()


# --------------------------------------------------------------------------
class Runtime:
    def __init__(self, ws_server, pam_server, service, pam_path):
        self.ws_server, self.pam_server, self.service, self.pam_path = ws_server, pam_server, service, pam_path

    async def close(self):
        for s in (self.ws_server, self.pam_server):
            s.close()
            await s.wait_closed()
        try:
            os.unlink(self.pam_path)
        except FileNotFoundError:
            pass


def build_ssl_context(cfg: Config, passphrase: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    tls = cfg["tls"]
    ctx.load_cert_chain(cfg.resolve(tls["server_cert"]), cfg.resolve(tls["server_key"]),
                        password=passphrase)
    ctx.load_verify_locations(cfg.resolve(tls["ca_cert"]))
    # Optional only when the operator explicitly disabled mTLS (migration mode).
    ctx.verify_mode = ssl.CERT_REQUIRED if cfg["require_mtls"] else ssl.CERT_OPTIONAL
    return ctx


async def start(cfg_path: Path, passphrase: str, notifier=None, allow_root=False) -> Runtime:
    if os.getuid() == 0 and not allow_root:
        raise SystemExit("Refusing to run as root. Use a dedicated 'remote-unlock' user "
                         "(see README / systemd unit).")
    cfg = Config(cfg_path)
    for rel in (cfg["signing_key"], cfg["tls"]["server_key"]):
        check_private(cfg.resolve(rel))
    check_private(cfg_path)

    bind_ip = cfg["listener_ip"]
    if bind_ip in ("0.0.0.0", "::", "") and not cfg["allow_any_interface"]:
        raise SystemExit("Refusing wildcard bind. Set listener_ip to your Tailscale/WireGuard IP.")
    if not cfg["require_mtls"]:
        log.warning("require_mtls is FALSE - running in migration mode, "
                    "only application-layer signatures protect this service")

    signing_key = serialization.load_pem_private_key(
        cfg.resolve(cfg["signing_key"]).read_bytes(), password=passphrase.encode())
    ssl_ctx = build_ssl_context(cfg, passphrase)

    audit_path = Path(cfg["audit_log"]) if cfg["audit_log"] else state_dir() / "audit.log"
    audit = AuditLog(audit_path)
    service = UnlockService(cfg, signing_key, audit,
                            notifier if notifier is not None else Notifier(cfg["alerts"]))

    # PAM socket: 0600, owned by the service user. Root (PAM) can connect; nobody else can.
    pam_path = cfg["pam_socket"]
    Path(pam_path).parent.mkdir(parents=True, exist_ok=True)
    try:
        os.unlink(pam_path)
    except FileNotFoundError:
        pass
    old = os.umask(0o177)
    try:
        pam_server = await asyncio.start_unix_server(service.handle_pam, path=pam_path)
    finally:
        os.umask(old)
    os.chmod(pam_path, 0o600)

    ws_server = await websockets.serve(
        service.handle, bind_ip, cfg["listener_port"], ssl=ssl_ctx,
        max_size=2048, open_timeout=5, ping_interval=None, compression=None)

    if audit.tamper_error:
        service.record("audit_tamper_detected", "AUDIT LOG TAMPERING DETECTED", "urgent",
                       ("skull",), error=audit.tamper_error)
    service.record("service_start", "remote-unlock started", "low", ("white_check_mark",),
                   ip=bind_ip, port=cfg["listener_port"], mtls=cfg["require_mtls"])
    log.info("Listening on wss://%s:%s (mTLS=%s)", bind_ip, cfg["listener_port"], cfg["require_mtls"])
    return Runtime(ws_server, pam_server, service, pam_path)


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cfg_path = home_dir() / "config.json"
    if not cfg_path.exists():
        raise SystemExit("No config found. Run: python3 pair.py init ...")
    pw = get_passphrase("Passphrase for remote-unlock keys: ")
    rt = await start(cfg_path, pw)
    del pw
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    rt.service.record("service_stop")
    await rt.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (ValueError, TypeError) as e:  # wrong passphrase surfaces as ValueError/TypeError
        sys.exit(f"Could not load keys (wrong passphrase?): {e}")
