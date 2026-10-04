#!/usr/bin/env python3
"""
client_example.py - reference client. It is the executable spec for what the
phone app must do, and lets you test the whole system without a phone.

    python3 client_example.py keygen --out device-key.pem      # prints public key
    python3 client_example.py unlock --host 100.64.0.5 --port 8765 \
        --ca ca-cert.pem --cert phone1.crt --key phone1.key \
        --device-key device-key.pem --device-id phone1 \
        --laptop-pub laptop.pub --target-id mylaptop

NOTE: device-key.pem here is a software key. On a real phone this key must be
generated inside the Secure Enclave / Android Keystore with user
authentication (biometric) required for every signature.
"""
import argparse
import asyncio
import json
import ssl
import sys
from pathlib import Path

import websockets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from common import (load_public_key, public_pem, sign, signed_message, verify_sig)


class ServerAuthError(Exception):
    pass


def make_ssl_context(ca, cert=None, key=None):
    ctx = ssl.create_default_context(cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if cert and key:
        ctx.load_cert_chain(cert, key)
    return ctx


async def unlock(host, port, ssl_ctx, device_key, device_id, laptop_pub, target_id) -> bool:
    async with websockets.connect(f"wss://{host}:{port}", ssl=ssl_ctx, open_timeout=5) as ws:
        await ws.send(json.dumps({"type": "hello", "device_id": device_id}))
        ch = json.loads(await asyncio.wait_for(ws.recv(), 10))
        if ch.get("type") != "challenge" or ch.get("target_id") != target_id:
            raise ServerAuthError("unexpected challenge")
        # Verify the LAPTOP's signature before signing anything.
        smsg = signed_message("challenge", ch["nonce"], ch["issued_ms"], device_id, target_id)
        if not verify_sig(laptop_pub, smsg, ch.get("server_sig")):
            raise ServerAuthError("server signature invalid - refusing to sign")
        rmsg = signed_message("response", ch["nonce"], ch["issued_ms"], device_id, target_id)
        await ws.send(json.dumps({"type": "response", "nonce": ch["nonce"],
                                  "signature": sign(device_key, rmsg)}))
        res = json.loads(await asyncio.wait_for(ws.recv(), 10))
        return res.get("ok") is True


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out", required=True)
    u = sub.add_parser("unlock")
    for a in ("host", "ca", "cert", "key", "device_key", "device_id", "laptop_pub", "target_id"):
        u.add_argument("--" + a.replace("_", "-"), required=True)
    u.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()

    if a.cmd == "keygen":
        key = ec.generate_private_key(ec.SECP256R1())
        p = Path(a.out)
        p.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
        p.chmod(0o600)
        print(public_pem(key.public_key()))
        return 0
    dk = serialization.load_pem_private_key(Path(a.device_key).read_bytes(), password=None)
    lp = load_public_key(Path(a.laptop_pub).read_text())
    ok = asyncio.run(unlock(a.host, a.port, make_ssl_context(a.ca, a.cert, a.key),
                            dk, a.device_id, lp, a.target_id))
    print("UNLOCKED" if ok else "REJECTED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
