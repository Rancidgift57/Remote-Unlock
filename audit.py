#!/usr/bin/env python3
"""
audit.py - tamper-evident, append-only audit log.

Each line is a JSON object that contains the SHA-256 of the previous line, so
editing, deleting or reordering any line breaks every hash after it.

Honest limits:
  * A chain only proves integrity against someone who CANNOT rewrite the whole
    file consistently. An attacker with write access can recompute the chain.
  * Two things close that gap, and you should use both:
      1. every alert (ntfy/Telegram/Slack) carries "#seq head=<hash prefix>",
         which anchors the chain OUTSIDE the laptop;
      2. `sudo chattr +a <logfile>` makes the file append-only at the
         filesystem level (needs root to undo).
  * `python3 audit.py verify --head <hash>` checks the log against an anchor
    you copied from an alert; this also detects truncation.
"""
import argparse
import hashlib
import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash(prev: str, entry_without_hash: dict) -> str:
    return hashlib.sha256((prev + _canon(entry_without_hash)).encode()).hexdigest()


def verify_file(path, expected_head=None):
    """Returns (ok, entries, head, error_message)."""
    path = Path(path)
    if not path.exists():
        return True, 0, GENESIS, None
    prev, n = GENESIS, 0
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line:
                continue
            try:
                entry = json.loads(line)
                claimed = entry.pop("hash")
            except (ValueError, KeyError):
                return False, n, prev, f"line {lineno}: unparsable"
            n += 1
            if entry.get("seq") != n:
                return False, n, prev, f"line {lineno}: sequence gap/reorder"
            if entry.get("prev") != prev:
                return False, n, prev, f"line {lineno}: broken chain link"
            if _hash(prev, entry) != claimed:
                return False, n, prev, f"line {lineno}: content modified"
            prev = claimed
    if expected_head and not prev.startswith(expected_head.lower()):
        return False, n, prev, "head does not match anchor (log truncated or rewritten)"
    return True, n, prev, None


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = threading.Lock()
        ok, self.seq, self.head, err = verify_file(self.path)
        self.tamper_error = None if ok else err
        # If the existing chain is broken we still continue appending from the
        # last good point; the listener raises an alert about tamper_error.

    def append(self, event: str, **data):
        with self._lock:
            self.seq += 1
            entry = {
                "seq": self.seq,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "event": event,
                "data": data,
                "prev": self.head,
            }
            digest = _hash(self.head, entry)
            line = _canon({**entry, "hash": digest}) + "\n"
            # O_APPEND so it also works when the file has chattr +a set.
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line.encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            self.head = digest
            return self.seq, self.head


def _main():
    ap = argparse.ArgumentParser(description="Audit log tools")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify the hash chain")
    v.add_argument("--path", default=None)
    v.add_argument("--head", default=None,
                   help="hash prefix copied from an alert, to detect truncation")
    t = sub.add_parser("tail", help="show last entries")
    t.add_argument("--path", default=None)
    t.add_argument("-n", type=int, default=20)
    args = ap.parse_args()

    from common import state_dir
    path = Path(args.path) if args.path else state_dir() / "audit.log"

    if args.cmd == "verify":
        ok, n, head, err = verify_file(path, args.head)
        if ok:
            print(f"OK: {n} entries, head={head}")
            return 0
        print(f"TAMPER DETECTED after {n} valid entries: {err}")
        return 1
    lines = path.read_text().splitlines()[-args.n:]
    for ln in lines:
        e = json.loads(ln)
        print(e["seq"], e["ts"], e["event"], json.dumps(e["data"]))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
