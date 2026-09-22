#!/usr/bin/env python3
"""
pam_unlock_helper.py — invoked by pam_exec.so during login/unlock.

Contract with PAM:
  - Exit code 0  -> pam_exec reports success -> (combined with `expose_authtok`
                     or a following pam_permit, this can satisfy auth)
  - Exit code != 0 -> pam_exec reports failure -> normal password prompt still
                     applies (this is an ADDITIONAL factor, not a replacement
                     for your password, unless you explicitly configure PAM
                     with `sufficient` — see README's security warning)

Behavior:
  - Opens a Unix domain socket in /run (tmpfs, RAM-backed, wiped on reboot).
  - Waits up to WAIT_TIMEOUT seconds for listener.py to signal a result.
  - ANY failure mode (timeout, malformed signal, socket error) exits 1.
    This script never assumes success; it only ever reports success when
    an explicit, verified "1" byte arrives from the listener.
  - Deletes its own socket file on exit so no stale file is left in /run.
    This is the only filesystem cleanup this script performs, and it's
    tmpfs (memory), not persistent disk.
"""

import os
import socket
import sys
import time

WAIT_TIMEOUT = 15  # seconds to wait for a phone-unlock signal
SOCK_PATH = f"/run/user/{os.getuid()}/remote-unlock-signal.sock"


def wait_for_signal() -> bool:
    # Clean up any stale socket from a previous run before binding.
    try:
        os.unlink(SOCK_PATH)
    except FileNotFoundError:
        pass

    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
        s.bind(SOCK_PATH)
        os.chmod(SOCK_PATH, 0o600)
        s.settimeout(WAIT_TIMEOUT)
        try:
            data, _ = s.recvfrom(1)
        except socket.timeout:
            return False
        finally:
            try:
                os.unlink(SOCK_PATH)
            except FileNotFoundError:
                pass

    return data == b"1"


def main() -> int:
    start = time.time()
    success = wait_for_signal()
    elapsed = time.time() - start

    # Extra safety: never accept a "success" that arrived suspiciously fast
    # (faster than a real network round-trip + biometric prompt could be),
    # since that would suggest something local is spoofing the socket
    # rather than the listener relaying a genuine phone response.
    if success and elapsed < 0.05:
        return 1

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
