#!/usr/bin/env python3
"""
pair_windows.py — Windows port of pair.py.

Does everything pair.py does (generate laptop ECDSA keypair, set a
passphrase, encrypt the private key, generate a self-signed TLS cert,
generate an ntfy.sh topic, exchange public keys with the phone app)
PLUS one Windows-specific step: it also asks for your Windows account
password and stores it encrypted with the same passphrase-derived key.

Why this extra step is needed (and isn't on Linux):
PAM only ever needs a pass/fail signal, because Windows/Linux's own auth
stack already has your real password. A Windows Credential Provider has
no such stack to hand off to — it must supply LogonUI a complete,
working credential itself. So the Credential Provider needs *something*
to submit as your password once your phone confirms, and the only
correct thing to submit is your actual Windows password. Storing it
encrypted-at-rest, unlockable only with your passphrase, is the same
trust model your Linux private key already uses — see the security
table in the main README.

Everything lives in %LOCALAPPDATA%\\remote-unlock\\, ACLed to your user
account only (the Windows analog of the Linux build's chmod 600/700).
"""

import base64
import getpass
import json
import os
import socket
import sys
from pathlib import Path

if sys.platform != "win32":
    raise SystemExit("pair_windows.py is the Windows build. Use pair.py on Linux/macOS.")

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import ipaddress
import secrets

import win32api
import win32security
import ntsecuritycon as con

SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1

CONFIG_DIR = Path(os.environ["LOCALAPPDATA"]) / "remote-unlock"
CONFIG_FILE = CONFIG_DIR / "pairing.json"


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def encrypt_secret(secret: str, passphrase: str) -> dict:
    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    ciphertext = Fernet(key).encrypt(secret.encode()).decode()
    return {"salt": base64.b64encode(salt).decode(), "ciphertext": ciphertext}


def lock_down_config_dir():
    """Restrict %LOCALAPPDATA%\\remote-unlock to the current user + SYSTEM
    only — the Windows equivalent of chmod 700 on ~/.config/remote-unlock."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    user, domain, _ = win32security.LookupAccountName("", win32api.GetUserName())
    sd = win32security.GetFileSecurity(str(CONFIG_DIR), win32security.DACL_SECURITY_INFORMATION)
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, user)
    system_sid, _, _ = win32security.LookupAccountName("", "SYSTEM")
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, system_sid)
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(str(CONFIG_DIR), win32security.DACL_SECURITY_INFORMATION, sd)


def generate_tls_cert(ip: str, cert_path: Path, key_path: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "remote-unlock-local")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def main():
    print("Remote-Unlock pairing (Windows)\n")

    lock_down_config_dir()

    ip = input(
        "Laptop IP the phone will connect to (Tailscale IP recommended, or LAN IP): "
    ).strip()

    passphrase = getpass.getpass(
        "Set a passphrase to encrypt the private key + Windows password at rest: "
    )
    confirm = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirm:
        raise SystemExit("Passphrases didn't match.")

    windows_password = getpass.getpass(
        "\nYour Windows account password (needed so the Credential Provider can "
        "complete login after your phone confirms — stored encrypted, see README-Windows.md): "
    )

    # Laptop ECDSA keypair
    laptop_key = ec.generate_private_key(ec.SECP256R1())
    laptop_priv_pem = laptop_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    laptop_pub_pem = laptop_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    cert_path = CONFIG_DIR / "cert.pem"
    key_path = CONFIG_DIR / "key.pem"
    generate_tls_cert(ip, cert_path, key_path)

    print("\n--- Laptop public key (paste into the phone app) ---")
    print(laptop_pub_pem)

    print("--- TLS cert fingerprint (pin it in the phone app) ---")
    cert_bytes = cert_path.read_bytes()
    cert_obj = x509.load_pem_x509_certificate(cert_bytes)
    fp = cert_obj.fingerprint(hashes.SHA256()).hex(":")
    print(fp, "\n")

    ntfy_topic = "remote-unlock-" + secrets.token_hex(16)
    print(f"--- ntfy.sh topic (subscribe to this in the ntfy app) ---\n{ntfy_topic}\n")

    print("Enable remote shutdown from the phone?")
    print("Adds a second button in the app: shut the laptop down instead of")
    print("approving an unlock attempt you didn't make. Same signature/nonce/")
    print("rate-limit protections as unlock, but destructive — off by default.")
    shutdown_enabled = input("Enable remote shutdown? [y/N] ").strip().lower() == "y"

    phone_pub_pem = input("Paste the phone app's public key, then press Enter:\n")

    config = {
        "listener_ip": ip,
        "listener_port": 8765,
        "phone_public_key_pem": phone_pub_pem,
        "laptop_private_key_encrypted": encrypt_secret(laptop_priv_pem, passphrase),
        "windows_password_encrypted": encrypt_secret(windows_password, passphrase),
        "tls_cert_path": str(cert_path),
        "tls_key_path": str(key_path),
        "ntfy_topic": ntfy_topic,
        "shutdown_enabled": shutdown_enabled,
        "shutdown_command": ["shutdown", "/s", "/t", "0"],
    }
    CONFIG_FILE.write_text(json.dumps(config, indent=2))
    print(f"\nSaved to {CONFIG_FILE}")
    if shutdown_enabled:
        print("Remote shutdown: ENABLED (command: shutdown /s /t 0)")
    else:
        print('Remote shutdown: disabled (set "shutdown_enabled": true in the')
        print("config file to turn it on later)")
    print(
        "\nNext: run credential-provider\\install.ps1 as Administrator, then start "
        "listener_windows.py (see README-Windows.md)."
    )


if __name__ == "__main__":
    main()
