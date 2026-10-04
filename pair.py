#!/usr/bin/env python3
"""
pair.py - one-time setup and device management for remote-unlock v2.

  init            create private CA, server TLS cert, laptop signing key, config
  add-device      register a phone: pin its signing key, issue its mTLS client cert
  list-devices    show registered devices
  revoke-device   disable a device (takes effect immediately, no restart)
  renew-server    re-issue the server TLS cert (e.g. after an IP change)

Files are written to $REMOTE_UNLOCK_HOME (default ~/.config/remote-unlock),
directory 0700, files 0600. All private keys are encrypted (PKCS#8, AES-256)
with your passphrase. ca-key.pem is only needed by this tool - MOVE IT OFFLINE
after setup (see README) so the running service can never mint certificates.
"""
import argparse
import datetime as dt
import ipaddress
import json
import secrets
import socket
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from common import (Config, DEFAULTS, ID_RE, get_passphrase, home_dir,
                    load_public_key, public_pem, sha256_hex, write_private)

MIN_PASSPHRASE = 12


# ----------------------------- crypto helpers -----------------------------
def _gen_key():
    return ec.generate_private_key(ec.SECP256R1())


def _enc_pem(key, pw: str) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(pw.encode()),
    )


def _cert_pem(c) -> bytes:
    return c.public_bytes(serialization.Encoding.PEM)


def _build_cert(cn, pub, issuer_cn, issuer_key, days, *, ca=False,
                san_ip=None, san_dns=None, eku=None):
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
         .public_key(pub)
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(minutes=5))
         .not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
             issuer_key.public_key()), False))
    ku = dict(digital_signature=not ca, content_commitment=False, key_encipherment=False,
              data_encipherment=False, key_agreement=False, key_cert_sign=ca,
              crl_sign=ca, encipher_only=False, decipher_only=False)
    b = b.add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), True)
    b = b.add_extension(x509.KeyUsage(**ku), True)
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([eku]), False)
    sans = []
    if san_ip:
        sans.append(x509.IPAddress(ipaddress.ip_address(san_ip)))
    if san_dns:
        sans.append(x509.DNSName(san_dns))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), False)
    return b.sign(issuer_key, hashes.SHA256())


def _load_key(path: Path, pw: str):
    return serialization.load_pem_private_key(path.read_bytes(), password=pw.encode())


def _issue_server(cfg_dir: Path, ca_key, ca_cert, target_id, ip, pw):
    key = _gen_key()
    cert = _build_cert(target_id, key.public_key(), ca_cert.subject.rfc4514_string()[3:],
                       ca_key, 365, san_ip=ip, san_dns=target_id,
                       eku=ExtendedKeyUsageOID.SERVER_AUTH)
    write_private(cfg_dir / "server-key.pem", _enc_pem(key, pw))
    write_private(cfg_dir / "server-cert.pem", _cert_pem(cert))


# ------------------------------- commands ---------------------------------
def init(cfg_dir: Path, *, ip: str, port: int, target_id: str, unlock_user: str,
         passphrase: str, force=False) -> Config:
    if len(passphrase) < MIN_PASSPHRASE:
        raise SystemExit(f"Passphrase must be at least {MIN_PASSPHRASE} characters.")
    if not ID_RE.match(target_id):
        raise SystemExit("target-id must match [a-z0-9][a-z0-9-]* (max 63 chars)")
    ipaddress.ip_address(ip)
    if ip in ("0.0.0.0", "::"):
        raise SystemExit("Give the specific Tailscale/WireGuard/LAN IP, not a wildcard.")
    cfg_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    cfg_dir.chmod(0o700)
    cfg_path = cfg_dir / "config.json"
    if cfg_path.exists() and not force:
        raise SystemExit(f"{cfg_path} exists. Use --force to overwrite (this revokes everything).")

    # Private CA
    ca_key = _gen_key()
    ca_cert = _build_cert("remote-unlock-ca", ca_key.public_key(), "remote-unlock-ca",
                          ca_key, 3650, ca=True)
    write_private(cfg_dir / "ca-key.pem", _enc_pem(ca_key, passphrase))
    write_private(cfg_dir / "ca-cert.pem", _cert_pem(ca_cert))

    # Server TLS identity
    _issue_server(cfg_dir, ca_key, ca_cert, target_id, ip, passphrase)

    # Laptop application-layer signing key (second, independent identity check)
    sign_key = _gen_key()
    write_private(cfg_dir / "laptop-signing-key.pem", _enc_pem(sign_key, passphrase))

    data = json.loads(json.dumps(DEFAULTS))
    data.update({
        "target_id": target_id,
        "listener_ip": ip,
        "listener_port": port,
        "unlock_user": unlock_user,
        "laptop_public_key_pem": public_pem(sign_key.public_key()),
        "tls": {"ca_cert": "ca-cert.pem", "server_cert": "server-cert.pem",
                "server_key": "server-key.pem"},
        "signing_key": "laptop-signing-key.pem",
        "alerts": {"ntfy": {"server": "https://ntfy.sh",
                            "topic": "ru-" + secrets.token_urlsafe(24), "token": None}},
    })
    write_private(cfg_path, json.dumps(data, indent=2).encode())
    return Config(cfg_path)


def add_device(cfg_dir: Path, *, name: str, phone_pubkey: str, passphrase: str,
               days: int = 365) -> dict:
    """Register a device. Returns {'p12': bytes, 'p12_password': str,
    'cert_pem': bytes, 'key_pem': bytes}."""
    if not ID_RE.match(name):
        raise SystemExit("device name must match [a-z0-9][a-z0-9-]*")
    cfg = Config(cfg_dir / "config.json")
    if any(d["id"] == name for d in cfg["devices"]):
        raise SystemExit(f"device '{name}' already exists (revoke it first to re-issue)")
    load_public_key(phone_pubkey)  # validates P-256

    ca_key = _load_key(cfg_dir / "ca-key.pem", passphrase)
    ca_cert = x509.load_pem_x509_certificate((cfg_dir / "ca-cert.pem").read_bytes())
    key = _gen_key()
    cert = _build_cert(name, key.public_key(), "remote-unlock-ca", ca_key, days,
                       eku=ExtendedKeyUsageOID.CLIENT_AUTH)

    p12_password = secrets.token_urlsafe(12)
    p12 = pkcs12.serialize_key_and_certificates(
        name.encode(), key, cert, [ca_cert],
        serialization.BestAvailableEncryption(p12_password.encode()))

    cfg.data["devices"].append({
        "id": name,
        "public_key_pem": public_pem(load_public_key(phone_pubkey)),
        "cert_sha256": sha256_hex(cert.public_bytes(serialization.Encoding.DER)),
        "enabled": True,
        "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "cert_expires": cert.not_valid_after_utc.isoformat(timespec="seconds"),
    })
    cfg.save()
    return {"p12": p12, "p12_password": p12_password, "cert_pem": _cert_pem(cert),
            "key_pem": key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption())}


def revoke_device(cfg_dir: Path, name: str):
    cfg = Config(cfg_dir / "config.json")
    for d in cfg["devices"]:
        if d["id"] == name:
            d["enabled"] = False
            d["revoked"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
            cfg.save()
            return
    raise SystemExit(f"no such device: {name}")


def renew_server(cfg_dir: Path, *, ip: str | None, passphrase: str):
    cfg = Config(cfg_dir / "config.json")
    ca_key = _load_key(cfg_dir / "ca-key.pem", passphrase)
    ca_cert = x509.load_pem_x509_certificate((cfg_dir / "ca-cert.pem").read_bytes())
    ip = ip or cfg["listener_ip"]
    _issue_server(cfg_dir, ca_key, ca_cert, cfg["target_id"], ip, passphrase)
    cfg.data["listener_ip"] = ip
    cfg.save()


# --------------------------------- CLI ------------------------------------
def _safe_hostname():
    h = "".join(c if c.isalnum() else "-" for c in socket.gethostname().lower()).strip("-")
    return (h or "laptop")[:40]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init")
    p.add_argument("--ip", required=True, help="Tailscale/WireGuard/LAN IP to bind to")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--target-id", default=_safe_hostname())
    p.add_argument("--unlock-user", required=True, help="local account PAM may unlock")
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("add-device")
    p.add_argument("name")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--pubkey-file", help="file with the phone's P-256 public key (PEM or base64 DER)")
    g.add_argument("--pubkey", help="phone's public key, inline")
    p.add_argument("--out", default=".", help="directory for the .p12 bundle")

    sub.add_parser("list-devices")
    p = sub.add_parser("revoke-device")
    p.add_argument("name")
    p = sub.add_parser("renew-server")
    p.add_argument("--ip")

    a = ap.parse_args()
    d = home_dir()

    if a.cmd == "init":
        pw = get_passphrase("Choose a passphrase (>=12 chars): ", confirm=True)
        cfg = init(d, ip=a.ip, port=a.port, target_id=a.target_id,
                   unlock_user=a.unlock_user, passphrase=pw, force=a.force)
        print(f"\nCreated {d}\n")
        print("Laptop public key (give to the phone app, pin it there):")
        print(cfg["laptop_public_key_pem"])
        print(f"target_id : {cfg['target_id']}")
        print(f"CA cert   : {d / 'ca-cert.pem'}  (install/pin on the phone)")
        print(f"ntfy topic: {cfg['alerts']['ntfy']['topic']}  (subscribe in the ntfy app)")
        print(f"\nNEXT: python3 pair.py add-device <name> --pubkey-file phone.pub")
        print(f"THEN: move {d / 'ca-key.pem'} to offline storage.")
    elif a.cmd == "add-device":
        pub = Path(a.pubkey_file).read_text() if a.pubkey_file else a.pubkey
        pw = get_passphrase("Passphrase (to use the CA key): ")
        r = add_device(d, name=a.name, phone_pubkey=pub, passphrase=pw)
        out = Path(a.out) / f"{a.name}.p12"
        write_private(out, r["p12"])
        print(f"Registered '{a.name}'.\n  Client certificate bundle: {out}")
        print(f"  Bundle password (shown ONCE): {r['p12_password']}")
        print("  Transfer the .p12 to the phone over a trusted channel, import it, "
              "then delete the file.")
    elif a.cmd == "list-devices":
        for dev in Config(d / "config.json")["devices"]:
            state = "active" if dev.get("enabled", True) else f"REVOKED {dev.get('revoked', '')}"
            print(f"{dev['id']:<20} {state:<10} cert-expires {dev.get('cert_expires', '?')}")
    elif a.cmd == "revoke-device":
        revoke_device(d, a.name)
        print(f"Revoked {a.name}. Active immediately.")
    elif a.cmd == "renew-server":
        renew_server(d, ip=a.ip, passphrase=get_passphrase("Passphrase: "))
        print("Server certificate re-issued. Restart the service.")


if __name__ == "__main__":
    sys.exit(main())
