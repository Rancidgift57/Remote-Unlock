"""End-to-end tests: real TLS, real mTLS, real sockets. Run: python3 -m unittest -v"""
import asyncio
import json
import os
import shutil
import socket
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import websockets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import audit as audit_mod
import listener
import pair
from client_example import ServerAuthError, make_ssl_context, unlock
from common import Config, load_public_key, public_pem, sign, signed_message
from pam_unlock_helper import request_unlock

PW = "correct-horse-battery-staple"


class FakeNotifier:
    def __init__(self):
        self.sent = []

    async def send(self, title, message, priority="default", tags=()):
        self.sent.append((title, priority))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Base(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        os.environ["REMOTE_UNLOCK_STATE"] = str(self.tmp / "state")
        self.cfgdir = self.tmp / "cfg"
        self.port = free_port()
        pair.init(self.cfgdir, ip="127.0.0.1", port=self.port, target_id="testbox",
                  unlock_user="tester", passphrase=PW)
        # point PAM socket + allowed uids at things a test process can use
        cfg = Config(self.cfgdir / "config.json")
        cfg.data["pam_socket"] = str(self.tmp / "pam.sock")
        cfg.data["pam_allowed_uids"] = [os.getuid()]
        cfg.data["challenge_ttl"] = 2
        cfg.data["pam_wait"] = 1
        cfg.save()

        self.dkey = ec.generate_private_key(ec.SECP256R1())
        r = pair.add_device(self.cfgdir, name="phone1", phone_pubkey=public_pem(self.dkey.public_key()),
                            passphrase=PW)
        (self.tmp / "c.crt").write_bytes(r["cert_pem"])
        (self.tmp / "c.key").write_bytes(r["key_pem"])
        self.ca = str(self.cfgdir / "ca-cert.pem")
        self.laptop_pub = load_public_key(Config(self.cfgdir / "config.json")["laptop_public_key_pem"])
        self.ctx = make_ssl_context(self.ca, str(self.tmp / "c.crt"), str(self.tmp / "c.key"))
        self.notifier = FakeNotifier()
        self.rt = await listener.start(self.cfgdir / "config.json", PW,
                                       notifier=self.notifier, allow_root=True)
        self.svc = self.rt.service

    async def asyncTearDown(self):
        await self.rt.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def good_unlock(self):
        return await unlock("127.0.0.1", self.port, self.ctx, self.dkey, "phone1",
                            self.laptop_pub, "testbox")

    async def raw_session(self, ctx=None, device_id="phone1"):
        ws = await websockets.connect(f"wss://127.0.0.1:{self.port}", ssl=ctx or self.ctx,
                                      open_timeout=5)
        await ws.send(json.dumps({"type": "hello", "device_id": device_id}))
        ch = json.loads(await ws.recv())
        return ws, ch

    def respond(self, ch, key=None, device_id="phone1"):
        msg = signed_message("response", ch["nonce"], ch["issued_ms"], device_id, "testbox")
        return json.dumps({"type": "response", "nonce": ch["nonce"],
                           "signature": sign(key or self.dkey, msg)})

    async def good_unlock_expect_fail(self):
        try:
            return await self.good_unlock()
        except Exception:
            return False

    def events(self):
        return [json.loads(l)["event"] for l in (self.tmp / "state" / "audit.log").read_text().splitlines()]


class TestAuth(Base):
    async def test_happy_path_audit_and_alert(self):
        self.assertTrue(await self.good_unlock())
        await asyncio.sleep(0.05)
        self.assertIn("unlock_authorized", self.events())
        self.assertIn(("Unlock AUTHORIZED", "high"), self.notifier.sent)

    async def test_replayed_signature_rejected(self):
        ws, ch = await self.raw_session()
        captured = self.respond(ch)
        await ws.send(captured)
        self.assertTrue(json.loads(await ws.recv())["ok"])
        await ws.close()
        # attacker (with a stolen cert) replays the captured response
        ws2, _ch2 = await self.raw_session()
        await ws2.send(captured)
        self.assertFalse(json.loads(await ws2.recv())["ok"])
        self.assertIn("unlock_rejected", self.events())

    async def test_same_nonce_cannot_be_used_twice_on_one_connection(self):
        ws, ch = await self.raw_session()
        bad = self.respond(ch, key=ec.generate_private_key(ec.SECP256R1()))
        await ws.send(bad)
        self.assertFalse(json.loads(await ws.recv())["ok"])
        self.assertNotIn(ch["nonce"], self.svc.pending)  # burned even though it failed

    async def test_wrong_device_key_rejected(self):
        ws, ch = await self.raw_session()
        await ws.send(self.respond(ch, key=ec.generate_private_key(ec.SECP256R1())))
        self.assertFalse(json.loads(await ws.recv())["ok"])

    async def test_expired_challenge_rejected(self):
        ws, ch = await self.raw_session()
        await asyncio.sleep(2.3)  # ttl = 2s
        try:
            await ws.send(self.respond(ch))
            self.assertFalse(json.loads(await ws.recv())["ok"])
        except websockets.exceptions.ConnectionClosed:
            pass  # server may already have timed the session out - also a rejection
        self.assertNotIn("unlock_authorized", self.events())

    async def test_no_client_certificate_cannot_connect(self):
        ctx = make_ssl_context(self.ca)  # no client cert
        with self.assertRaises(Exception):
            ws = await websockets.connect(f"wss://127.0.0.1:{self.port}", ssl=ctx, open_timeout=5)
            await ws.send(json.dumps({"type": "hello", "device_id": "phone1"}))
            await asyncio.wait_for(ws.recv(), 3)

    async def test_cert_from_foreign_ca_cannot_connect(self):
        other = self.tmp / "other"
        pair.init(other, ip="127.0.0.1", port=1, target_id="evil", unlock_user="x", passphrase=PW)
        r = pair.add_device(other, name="phone1", phone_pubkey=public_pem(self.dkey.public_key()),
                            passphrase=PW)
        (self.tmp / "e.crt").write_bytes(r["cert_pem"])
        (self.tmp / "e.key").write_bytes(r["key_pem"])
        ctx = make_ssl_context(self.ca, str(self.tmp / "e.crt"), str(self.tmp / "e.key"))
        with self.assertRaises(Exception):
            ws = await websockets.connect(f"wss://127.0.0.1:{self.port}", ssl=ctx, open_timeout=5)
            await ws.send(json.dumps({"type": "hello", "device_id": "phone1"}))
            await asyncio.wait_for(ws.recv(), 3)

    async def test_revocation_is_immediate(self):
        self.assertTrue(await self.good_unlock())
        pair.revoke_device(self.cfgdir, "phone1")
        self.assertFalse(await self.good_unlock_expect_fail())

    async def test_client_refuses_fake_laptop(self):
        fake = ec.generate_private_key(ec.SECP256R1())
        self.svc.signing_key = fake  # simulate impostor server key
        with self.assertRaises(ServerAuthError):
            await self.good_unlock()

    async def test_hello_device_must_match_certificate(self):
        r = pair.add_device(self.cfgdir, name="phone2",
                            phone_pubkey=public_pem(ec.generate_private_key(ec.SECP256R1()).public_key()),
                            passphrase=PW)
        ws = await websockets.connect(f"wss://127.0.0.1:{self.port}", ssl=self.ctx, open_timeout=5)
        await ws.send(json.dumps({"type": "hello", "device_id": "phone2"}))  # cert says phone1
        self.assertFalse(json.loads(await ws.recv())["ok"])


class TestLockout(Base):
    async def test_exponential_lockout_and_alert(self):
        for _ in range(3):  # threshold
            ws, ch = await self.raw_session()
            await ws.send(self.respond(ch, key=ec.generate_private_key(ec.SECP256R1())))
            await ws.recv()
        await asyncio.sleep(0.05)
        self.assertIn("lockout", self.events())
        self.assertIn("LOCKOUT triggered", [t for t, _ in self.notifier.sent])
        # even the legitimate phone is refused while locked
        self.assertFalse(await self.good_unlock_expect_fail())
        self.assertNotIn("unlock_authorized", self.events())
        # second lockout doubles
        b = self.svc.dev_backoff
        first = b.remaining("phone1")
        self.assertGreater(first, 25)

    def test_backoff_doubles(self):
        t = [0.0]
        b = listener.Backoff(2, 10, 100, clock=lambda: t[0])
        b.fail("k"); self.assertTrue(b.fail("k")); self.assertEqual(round(b.remaining("k")), 10)
        t[0] = 11; b.fail("k"); self.assertTrue(b.fail("k")); self.assertEqual(round(b.remaining("k")), 20)
        t[0] = 40; b.fail("k"); b.fail("k"); self.assertEqual(round(b.remaining("k")), 40)


class TestPam(Base):
    def _ask(self, user="tester", uid=None):
        uid = os.getuid() if uid is None else uid
        return asyncio.to_thread(request_unlock, str(self.tmp / "pam.sock"), user, uid, 3)

    async def test_no_grant_means_deny(self):
        self.assertFalse(await self._ask())

    async def test_grant_after_verified_unlock_is_single_use(self):
        self.assertTrue(await self.good_unlock())
        self.assertTrue(await self._ask())
        self.assertFalse(await self._ask())  # consumed

    async def test_wrong_user_denied_even_with_grant(self):
        self.assertTrue(await self.good_unlock())
        self.assertFalse(await self._ask(user="mallory"))
        self.assertTrue(await self._ask())  # grant was not burned by the bad request

    async def test_helper_rejects_impostor_socket_owner(self):
        self.assertTrue(await self.good_unlock())
        self.assertFalse(await self._ask(uid=os.getuid() + 1))

    async def test_disallowed_uid_denied(self):
        self.svc.cfg.data["pam_allowed_uids"] = [os.getuid() + 12345]
        self.assertTrue(await self.good_unlock())
        self.assertFalse(await self._ask())
        self.assertIn("pam_denied", self.events())

    async def test_grant_expires(self):
        self.svc.broker.ttl = 0.2
        self.assertTrue(await self.good_unlock())
        await asyncio.sleep(0.4)
        self.assertFalse(await self._ask())


class TestAudit(Base):
    async def test_chain_verifies_then_detects_tampering(self):
        await self.good_unlock()
        path = self.tmp / "state" / "audit.log"
        ok, n, head, err = audit_mod.verify_file(path)
        self.assertTrue(ok, err)
        self.assertGreaterEqual(n, 2)
        ok, *_ = audit_mod.verify_file(path, expected_head=head[:12])
        self.assertTrue(ok)
        # edit a line
        lines = path.read_text().splitlines()
        lines[0] = lines[0].replace("service_start", "nothing_here")
        path.write_text("\n".join(lines) + "\n")
        ok, _n, _h, err = audit_mod.verify_file(path)
        self.assertFalse(ok)
        self.assertIn("modified", err)

    async def test_truncation_detected_with_anchor(self):
        await self.good_unlock()
        path = self.tmp / "state" / "audit.log"
        _ok, _n, head, _ = audit_mod.verify_file(path)
        path.write_text("\n".join(path.read_text().splitlines()[:-1]) + "\n")
        ok, *_ = audit_mod.verify_file(path, expected_head=head[:12])
        self.assertFalse(ok)


class TestSafety(unittest.TestCase):
    def test_wildcard_bind_refused(self):
        async def go():
            tmp = Path(tempfile.mkdtemp())
            try:
                with self.assertRaises(SystemExit):
                    pair.init(tmp, ip="0.0.0.0", port=1, target_id="x", unlock_user="u", passphrase=PW)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        asyncio.run(go())

    def test_weak_passphrase_refused(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(SystemExit):
                pair.init(tmp, ip="127.0.0.1", port=1, target_id="x", unlock_user="u", passphrase="short")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
