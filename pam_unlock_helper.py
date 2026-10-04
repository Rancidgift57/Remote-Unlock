#!/usr/bin/env python3
"""
pam_unlock_helper.py - called by pam_exec.so (as root) during login/unlock.

v1 listened on a socket that ANY process of the same user could write "1" to.
v2 inverts the trust: this helper connects OUT to the listener's root-only
socket and asks "has a verified unlock grant been issued for this user?".

  * The helper checks (SO_PEERCRED) that the socket is really served by the
    configured service user, so a planted fake socket cannot say "yes".
  * The listener checks the helper's uid (default: root only) and the user name.
  * The grant is single-use and short-lived, and lives only in listener memory.
  * Every error, timeout or odd reply => exit 1 (deny).

Install it root-owned and not writable by anyone else:
    sudo install -o root -g root -m 0755 pam_unlock_helper.py common.py \
         /usr/local/lib/remote-unlock/
"""
import json
import os
import pwd
import socket
import struct
import sys
from pathlib import Path


def request_unlock(sock_path: str, user: str, expected_uid: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(sock_path)
            _pid, peer_uid, _gid = struct.unpack("3i", s.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if peer_uid != expected_uid:
                return False  # not the real listener
            s.sendall((json.dumps({"user": user}) + "\n").encode())
            reply = b""
            while not reply.endswith(b"\n") and len(reply) < 8:
                chunk = s.recv(8)
                if not chunk:
                    break
                reply += chunk
            return reply == b"1\n"
    except Exception:  # noqa: BLE001 - fail closed
        return False


def main() -> int:
    user = os.environ.get("PAM_USER", "")
    home = Path(os.environ.get("REMOTE_UNLOCK_HOME", "/etc/remote-unlock"))
    try:
        cfg = json.loads((home / "config.json").read_text())
        sock_path = cfg.get("pam_socket", "/run/remote-unlock/pam.sock")
        expected_uid = pwd.getpwnam(cfg.get("service_user", "remote-unlock")).pw_uid
        wait = float(cfg.get("pam_wait", 15)) + 3
    except Exception:  # noqa: BLE001
        return 1
    if os.getuid() != 0 or not user:
        return 1
    return 0 if request_unlock(sock_path, user, expected_uid, wait) else 1


if __name__ == "__main__":
    sys.exit(main())
