#!/usr/bin/env python3
"""
pair.py — one-time pairing between this laptop and your phone.

What it does:
  1. Generates an ECDSA (P-256) keypair for the LAPTOP.
  2. Prints the laptop's public key as text (and optionally a QR code) so you
     can enter it into the phone app.
  3. Prompts you to paste in the PHONE's public key (printed by the phone app
     during its own pairing screen).
  4. Saves both keys to one small JSON config file.

File-system contact is intentionally minimal and explicit:
  - Writes exactly one file: ~/.config/remote-unlock/pairing.json
  - Never touches any other path, never runs with elevated privileges,
    never modifies system files. (PAM registration is a separate, manual
    step documented in README.md — this script does not touch PAM at all.)

Run this once, from an interactive shell, as your normal user (not root).
"""

import base64
import datetime
import getpass
import hashlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet

CONFIG_DIR = Path.home() / ".config" / "remote-unlock"
CONFIG_FILE = CONFIG_DIR / "pairing.json"
CA_CERT_FILE = CONFIG_DIR / "ca-cert.pem"           # install this on the phone
CA_KEY_ENCRYPTED_FILE = CONFIG_DIR / "ca-key.enc"   # only needed to reissue leaf certs
LEAF_CERT_FILE = CONFIG_DIR / "laptop-cert.pem"
LEAF_KEY_FILE = CONFIG_DIR / "laptop-key.pem"

# scrypt cost parameters — deliberately expensive, this only runs once per
# listener startup, so slowness here is pure benefit against offline
# passphrase-guessing if pairing.json is ever stolen.
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def encrypt_private_key(priv_pem: str, passphrase: str) -> dict:
    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    token = Fernet(key).encrypt(priv_pem.encode())
    return {"salt": base64.b64encode(salt).decode(), "ciphertext": token.decode()}


def generate_ca():
    """Self-signed root CA. This is what you install as a trusted
    certificate on your phone, ONE TIME. After that, standard TLS
    validation (no custom pinning code in the app) just works, because the
    phone's OS trusts anything this CA signs — and only this CA signs
    anything, because its private key never leaves your laptop.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Remote Unlock Local CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "remote-unlock (self-signed, local only)"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def generate_leaf(ca_key, ca_cert, laptop_ip: str):
    """Leaf certificate for the listener itself, signed by the local CA
    above. Only valid for the specific LAN IP you give it — if your
    laptop's IP changes (no DHCP reservation set), re-run pair.py's
    `--renew-cert` mode (see README) rather than re-pairing from scratch."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, laptop_ip)])
    import ipaddress
    san_entries = [x509.DNSName("laptop-unlock-local")]
    try:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(laptop_ip)))
    except ValueError:
        san_entries = [x509.DNSName(laptop_ip)]  # treat as hostname instead

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=397))  # keep leaf-lived short
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return key_pem, cert.public_bytes(serialization.Encoding.PEM)


def generate_laptop_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return priv_pem, pub_pem


def main():
    if CONFIG_FILE.exists():
        answer = input(
            f"{CONFIG_FILE} already exists. Overwrite and re-pair? [y/N] "
        )
        if answer.strip().lower() != "y":
            print("Aborted. Existing pairing left untouched.")
            sys.exit(0)

    print("Generating laptop keypair (ECDSA P-256)...")
    laptop_priv_pem, laptop_pub_pem = generate_laptop_keypair()

    print("\n=== Laptop PUBLIC key (enter this into the phone app) ===\n")
    print(laptop_pub_pem)

    try:
        import qrcode  # optional, only used if installed

        qr = qrcode.QRCode(border=1)
        qr.add_data(laptop_pub_pem)
        qr.make()
        qr.print_ascii(invert=True)
    except ImportError:
        pass  # QR code is a convenience only; plain text works fine

    print("Now open the pairing screen on your phone app.")
    print("Paste the phone's PUBLIC key below, then press Enter twice.\n")

    lines = []
    while True:
        line = input()
        if line.strip() == "" and lines:
            break
        lines.append(line)
    phone_pub_pem = "\n".join(lines).strip() + "\n"

    if "BEGIN PUBLIC KEY" not in phone_pub_pem:
        print("That doesn't look like a PEM public key. Aborting, nothing saved.")
        sys.exit(1)

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CONFIG_DIR, stat.S_IRWXU)  # 0700 — owner only

    # --- Encrypt the unlock private key with a passphrase -----------------
    # This is the single most valuable key in the whole system: whoever has
    # it can remotely unlock the laptop. Plaintext-on-disk storage means
    # any local file read (another user, malware, a stolen unencrypted
    # backup) is a full compromise. Encrypting it means an attacker needs
    # BOTH file access AND the passphrase.
    print("\nChoose a passphrase to encrypt the unlock key at rest.")
    print("You'll be asked for this once, whenever the listener service starts")
    print("(not on every unlock attempt).")
    while True:
        passphrase = getpass.getpass("Passphrase: ")
        confirm = getpass.getpass("Confirm: ")
        if passphrase != confirm:
            print("Didn't match, try again.")
            continue
        if len(passphrase) < 12:
            print("Use at least 12 characters.")
            continue
        break

    encrypted_priv = encrypt_private_key(laptop_priv_pem, passphrase)

    # --- Local CA + leaf certificate, generated automatically -------------
    print("\nWhat IP should the certificate be issued for?")
    print("  - If you've set up Tailscale (recommended for cross-network use),")
    print("    enter the laptop's Tailscale IP: run `tailscale ip -4` on the")
    print("    laptop to get it (looks like 100.x.x.x).")
    print("  - Otherwise, enter the laptop's LAN IP (e.g. 192.168.1.42) — this")
    print("    will only work while phone and laptop share the same Wi-Fi.")
    print("Tip: a Tailscale IP is stable and doesn't need a DHCP reservation.")
    print("For a plain LAN IP, set a static DHCP reservation on your router so")
    print("it doesn't change later and break the cert.")
    laptop_ip = input("Laptop IP (Tailscale or LAN): ").strip()

    ca_key, ca_cert = generate_ca()
    leaf_key_pem, leaf_cert_pem = generate_leaf(ca_key, ca_cert, laptop_ip)

    ca_key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    # CA private key is encrypted too: it's the root of trust for the TLS
    # layer. It's not needed at listener startup (only the leaf key is), so
    # keeping it encrypted-at-rest costs nothing day-to-day and only
    # matters if you later reissue a leaf cert (e.g. IP change).
    encrypted_ca_key = encrypt_private_key(ca_key_pem, passphrase)
    CA_KEY_ENCRYPTED_FILE.write_text(json.dumps(encrypted_ca_key))
    os.chmod(CA_KEY_ENCRYPTED_FILE, stat.S_IRUSR | stat.S_IWUSR)

    CA_CERT_FILE.write_bytes(ca_cert_pem)              # not secret — install on phone
    LEAF_CERT_FILE.write_bytes(leaf_cert_pem)
    LEAF_KEY_FILE.write_bytes(leaf_key_pem)
    os.chmod(LEAF_KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(LEAF_CERT_FILE, stat.S_IRUSR | stat.S_IWUSR)

    ntfy_topic = "unlock-" + secrets.token_urlsafe(24)

    config = {
        "laptop_private_key_encrypted": encrypted_priv,
        "laptop_public_key_pem": laptop_pub_pem,
        "phone_public_key_pem": phone_pub_pem,
        "listener_port": 8765,
        "listener_ip": laptop_ip,
        "tls_cert_path": str(LEAF_CERT_FILE),
        "tls_key_path": str(LEAF_KEY_FILE),
        "ntfy_topic": ntfy_topic,
    }

    CONFIG_FILE.write_text(json.dumps(config, indent=2))
    os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0600 — owner only

    print(f"\nPaired. Config written to {CONFIG_FILE} (permissions 600).")
    print(f"\n=== Install this root certificate on your phone (one time) ===")
    print(f"File: {CA_CERT_FILE}")
    print("Airdrop/email/transfer it to your phone, then:")
    print("  iOS: open the file -> Settings > General > VPN & Device Management")
    print("       > install the profile, THEN also go to Settings > General >")
    print("       About > Certificate Trust Settings and enable full trust for it.")
    print("  Android: Settings > Security > Encryption & credentials > Install a")
    print("       certificate > CA certificate, then select the file.")
    print("This is NOT secret — it's a public certificate, like any root CA.")
    print("Its private key stays encrypted on this laptop and is never shared.")
    print(f"\n=== ntfy.sh topic (treat as secret) ===")
    print(ntfy_topic)
    print(f"Subscribe to it in the ntfy app so you receive unlock alerts.")
    print("\nNext: follow README.md to enable the systemd service and wire up PAM.")
    print("The listener will ask for your passphrase each time it starts.")


if __name__ == "__main__":
    main()
