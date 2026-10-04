"""
common.py - shared helpers for remote-unlock v2.

Wire protocol (all messages JSON over wss with mutual TLS):

    C -> S   {"type":"hello",     "device_id": "<id>"}
    S -> C   {"type":"challenge", "nonce": "<32 hex>", "issued_ms": <int>,
              "target_id": "<id>", "server_sig": "<hex ECDSA>"}
    C -> S   {"type":"response",  "nonce": "<same>", "signature": "<hex ECDSA>"}
    S -> C   {"type":"result",    "ok": true|false}

Both signatures are ECDSA P-256 / SHA-256 over the exact bytes returned by
signed_message().  The role label ("challenge" vs "response") is part of the
signed bytes so a signature made for one purpose can never be reflected back
as the other.  Nonce and timestamp are issued by the SERVER and kept in server
memory, so no clock synchronisation with the phone is needed.
"""
import base64
import getpass
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as ec_utils

PROTO = "remote-unlock/v2"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_SIG_HEX = 200


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------
def home_dir() -> Path:
    env = os.environ.get("REMOTE_UNLOCK_HOME")
    return Path(env) if env else Path.home() / ".config" / "remote-unlock"


def state_dir() -> Path:
    env = os.environ.get("REMOTE_UNLOCK_STATE")
    return Path(env) if env else Path.home() / ".local" / "state" / "remote-unlock"


# --------------------------------------------------------------------------
# Signed message + ECDSA helpers
# --------------------------------------------------------------------------
def signed_message(role: str, nonce: str, issued_ms: int,
                   device_id: str, target_id: str) -> bytes:
    if role not in ("challenge", "response"):
        raise ValueError("bad role")
    if not NONCE_RE.match(nonce):
        raise ValueError("bad nonce")
    if not ID_RE.match(device_id) or not ID_RE.match(target_id):
        raise ValueError("bad id")
    return f"{PROTO}|{role}|{nonce}|{int(issued_ms)}|{device_id}|{target_id}|unlock".encode()


def sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> str:
    return private_key.sign(message, ec.ECDSA(hashes.SHA256())).hex()


def verify_sig(public_key, message: bytes, sig_hex) -> bool:
    """True only for a valid signature. Accepts DER or raw r||s (64 bytes)."""
    try:
        if not isinstance(sig_hex, str) or len(sig_hex) > MAX_SIG_HEX:
            return False
        sig = bytes.fromhex(sig_hex)
        if len(sig) == 64:
            r = int.from_bytes(sig[:32], "big")
            s = int.from_bytes(sig[32:], "big")
            sig = ec_utils.encode_dss_signature(r, s)
        public_key.verify(sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def load_public_key(text: str):
    """Load a P-256 public key from PEM or base64-encoded SPKI DER."""
    text = text.strip()
    if "BEGIN" in text:
        key = serialization.load_pem_public_key(text.encode())
    else:
        key = serialization.load_der_public_key(base64.b64decode(text, validate=True))
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise ValueError("public key must be ECDSA P-256 (secp256r1)")
    return key


def public_pem(key) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Secrets / files
# --------------------------------------------------------------------------
def get_passphrase(prompt="Remote-unlock passphrase: ", confirm=False) -> str:
    """Order: systemd credential -> passphrase file -> interactive prompt.
    Deliberately NOT read from a plain environment variable (visible in
    /proc/<pid>/environ and often leaked into logs)."""
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir and (Path(cred_dir) / "passphrase").exists():
        return (Path(cred_dir) / "passphrase").read_text().strip()
    pass_file = os.environ.get("REMOTE_UNLOCK_PASSPHRASE_FILE")
    if pass_file and Path(pass_file).exists():
        check_private(Path(pass_file))
        return Path(pass_file).read_text().strip()
    pw = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repeat passphrase: ") != pw:
        raise SystemExit("Passphrases do not match.")
    return pw


def check_private(path: Path):
    """Refuse secrets that other users can read."""
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise SystemExit(f"{path} is accessible by group/others (mode {oct(mode)}). "
                         f"Run: chmod 600 {path}")


def write_private(path: Path, data: bytes):
    """Atomic write with 0600 permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
DEFAULTS = {
    "version": 2,
    "listener_port": 8765,
    "challenge_ttl": 10,          # seconds a challenge stays valid
    "grant_ttl": 20,              # seconds an authorised unlock can be claimed by PAM
    "pam_wait": 15,               # seconds PAM helper waits for the phone
    "pam_socket": "/run/remote-unlock/pam.sock",
    "pam_allowed_uids": [0],      # only these local uids may claim a grant
    "service_user": "remote-unlock",
    "require_mtls": True,
    "allow_any_interface": False,
    "max_connections": 16,
    "lockout": {"threshold": 3, "base_seconds": 30, "max_seconds": 3600},
    "alerts": {},
    "audit_log": None,
    "devices": [],
}


class Config:
    def __init__(self, path):
        self.path = Path(path)
        self.dir = self.path.parent
        self.data = {}
        self._mtime = None
        self.reload()

    def reload(self):
        raw = json.loads(self.path.read_text())
        data = json.loads(json.dumps(DEFAULTS))
        data.update(raw)
        self.data = data
        self._mtime = self.path.stat().st_mtime_ns

    def reload_if_changed(self):
        """Lets `pair.py revoke-device` take effect without a restart."""
        try:
            if self.path.stat().st_mtime_ns != self._mtime:
                self.reload()
        except (OSError, ValueError):
            pass  # keep the last good config (fail-safe: revocations already loaded stay)

    def __getitem__(self, k):
        return self.data[k]

    def get(self, k, default=None):
        return self.data.get(k, default)

    def save(self):
        write_private(self.path, json.dumps(self.data, indent=2).encode())
        self._mtime = self.path.stat().st_mtime_ns

    def resolve(self, rel: str) -> Path:
        p = Path(rel)
        return p if p.is_absolute() else self.dir / p

    def device_by_fp(self, fp: str):
        for d in self.data["devices"]:
            if d.get("enabled", True) and d["cert_sha256"] == fp:
                return d
        return None

    def device_by_id(self, device_id: str):
        for d in self.data["devices"]:
            if d.get("enabled", True) and d["id"] == device_id:
                return d
        return None
