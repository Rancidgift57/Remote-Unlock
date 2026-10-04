# Remote-Unlock v2 — hardened phone-unlock for Linux

A phone-approved unlock for your laptop, rebuilt around mutual TLS, server-issued
single-use challenges, exponential lockout, a tamper-evident audit log, and a PAM
bridge that attackers on the machine cannot spoof.

> **Nothing is "silver-bullet secure."** This is a strong baseline, and the
> [limits](#what-this-does-not-protect-against) section says exactly where it stops.
> Disk encryption and a good account password still matter.

## What changed from v1, and why

Reading v1 turned up two problems that mattered more than the checklist:

1. **The PAM bridge could be spoofed.** The old helper waited on a Unix socket in
   `/run/user/<uid>/`, and *any process running as that user* could send the byte `1`
   (after a 50 ms delay, which the "timing check" required) and PAM would accept it.
   v2 reverses the direction: the helper (root) connects *out* to the listener's
   root-only socket and asks whether a verified grant exists. Both sides check the
   other's uid with `SO_PEERCRED`. Grants are single-use, held in listener memory,
   and expire in 20 s.
2. **`auth optional pam_exec.so` does nothing useful.** With a normal stack
   (`pam_unix` required), an `optional` success cannot grant or deny access, so v1's
   phone factor was effectively decorative. v2 documents the two modes that do work
   ([below](#6-wire-up-pam)).

### Your checklist → what's implemented

| Item | Status |
|---|---|
| Asymmetric signatures, no PSKs | ✅ ECDSA **P-256** both directions. P-256 rather than Ed25519 because it is what iOS Secure Enclave and Android Keystore can generate in hardware |
| Mutual TLS + private CA | ✅ TLS 1.3 only. Client cert must chain to your CA **and** its fingerprint must be pinned to a registered device. Revocation is instant |
| FIDO2 / hardware factor | ⚠️ **Partly.** The server cannot *prove* a biometric happened unless it verifies hardware attestation or WebAuthn, which is not implemented. The factor is enforced on the phone by creating the key with user-authentication required. See [Hardware factor](#hardware-factor) |
| Nonce + timestamp, ±5 s window | ✅ **Stronger variant.** The *server* issues a 128-bit nonce and timestamp and keeps them in memory; the phone signs them back. No clock sync, no drift window to tune. TTL is 10 s by default (biometric prompts take a few seconds) |
| Bloom filter / Redis for nonces | ➖ Not used. Server-issued nonces live in a small exact dict and are deleted on first use. A Bloom filter would give false positives, and there is no client-chosen nonce to track |
| HMAC/signature over timestamp, nonce, target, payload | ✅ Signature covers role, nonce, issue time, device id, target id. The role label prevents reflecting a challenge signature as a response |
| No public endpoint | ✅ Binds to one specific IP; wildcard binds refused. Use Tailscale/WireGuard (below). Cloudflare Zero Trust is not set up |
| Rate limiting + backoff + lockout + alert | ✅ Per-IP and per-device, 3 fails → 30 s, doubling to 1 h; connection cap; 2 KB message limit; alert on lockout |
| Immutable audit log | ✅ Hash-chained JSONL, `audit.py verify`. "Immutable" needs `chattr +a` plus the off-box anchor — see [Audit](#audit-log) |
| Real-time alerts | ✅ ntfy, Telegram, Slack/generic webhook, on success, failure, lockout, PAM grant, and tampering |

## Architecture

```
 Phone app ──wss + client cert──▶ listener.py (user: remote-unlock, bound to Tailscale IP)
   │  signs challenge                │  verifies cert pin + ECDSA, rate limits, audits, alerts
   │  with biometric-gated key       │  issues single-use grant (memory only)
   │                                 ▼
   │                     /run/remote-unlock/pam.sock  (0600, service user)
   │                                 ▲
   └──────────── (nothing)           │  "grant for <user>?"  (root only, SO_PEERCRED both ways)
                              pam_unlock_helper.py ◀── pam_exec.so ◀── gdm / sudo / lock screen
```

## Setup

### 1. Install

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin remote-unlock
sudo install -d -o root -g root -m 0755 /opt/remote-unlock /usr/local/lib/remote-unlock
sudo cp common.py audit.py notify.py listener.py pair.py client_example.py /opt/remote-unlock/
sudo install -o root -g root -m 0755 pam_unlock_helper.py common.py /usr/local/lib/remote-unlock/
pip install -r requirements.txt            # or your distro's python3-cryptography / python3-websockets
```

### 2. Private network (strongly recommended)

```bash
curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up
tailscale ip -4        # use this IP below
```

Do not port-forward the listener. It binds only to the IP you give it.

### 3. Create the PKI

```bash
sudo mkdir -p /etc/remote-unlock
sudo REMOTE_UNLOCK_HOME=/etc/remote-unlock python3 pair.py init \
     --ip 100.x.y.z --unlock-user YOURLOGIN
```

Passphrase: ≥ 12 characters. It encrypts every private key (AES-256 PKCS#8). The output
shows the **laptop public key**, the **CA cert** path and your **ntfy topic** (a long
random string; subscribe to it in the ntfy app).

### 4. Register the phone

On the phone, generate a P-256 key whose use requires biometrics (see
[Phone app](#phone-app-what-must-change)) and export its public key, then:

```bash
sudo REMOTE_UNLOCK_HOME=/etc/remote-unlock python3 pair.py add-device phone1 \
     --pubkey-file phone1.pub --out ~
```

This pins the phone's signing key and issues its mTLS client certificate as an
encrypted `phone1.p12` (password printed **once**). Move it to the phone over a trusted
channel, import it, and delete the file.

### 5. Lock down permissions and move the CA key offline

```bash
sudo mv /etc/remote-unlock/ca-key.pem ~/ca-key.pem.OFFLINE   # then store off-machine
sudo chown -R remote-unlock:remote-unlock /etc/remote-unlock
sudo chmod 700 /etc/remote-unlock && sudo chmod 600 /etc/remote-unlock/*
```

The running service can then never mint certificates. You need `ca-key.pem` back (in
`REMOTE_UNLOCK_HOME`) only for `add-device` and `renew-server`.

Passphrase for the service, encrypted to this machine:

```bash
printf '%s' 'YOUR PASSPHRASE' | sudo systemd-creds encrypt --name=passphrase - /etc/remote-unlock/passphrase.cred
sudo cp remote-unlock.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now remote-unlock
```

The unit file and the root/service-user permission split are **untested on a live
systemd host**; the Python code is tested (below). Check `journalctl -u remote-unlock`
after starting.

### 6. Wire up PAM

Copy `pam_unlock_helper.py` and `common.py` as in step 1, then pick **one** mode in
`/etc/pam.d/<service>` (e.g. `sudo`, or `gdm-password` for the lock screen). Keep a root
shell open while you test.

**Phone AND password (recommended).** Put this *before* the password module; if the
phone isn't approved, the whole stack fails:

```
auth  requisite  pam_exec.so quiet /usr/local/lib/remote-unlock/pam_unlock_helper.py
```

**Phone only (convenience, e.g. lock screen).** Phone approval alone logs you in:

```
auth  sufficient pam_exec.so quiet /usr/local/lib/remote-unlock/pam_unlock_helper.py
```

With `sufficient`, a stolen phone *plus* its biometric is a full login. Don't use it
for `sudo` on a machine you care about.

Do **not** use `optional`: it has no effect on the outcome in a normal stack.

### 7. Test

```bash
# Run the automated tests (no phone needed):
python3 -m unittest discover -s tests -v

# Or exercise a live listener with the reference client:
python3 client_example.py keygen --out dk.pem > dk.pub     # software stand-in for the phone key
# ... add-device with dk.pub, extract cert/key, then:
python3 client_example.py unlock --host 100.x.y.z --ca ca-cert.pem --cert c.crt --key c.key \
        --device-key dk.pem --device-id phone1 --laptop-pub laptop.pub --target-id mylaptop
```

## Day-to-day

```bash
python3 pair.py list-devices
python3 pair.py revoke-device phone1       # effective immediately, no restart
python3 pair.py renew-server --ip NEW_IP   # after an IP change; restart the service
python3 audit.py verify                    # chain integrity
python3 audit.py verify --head 3fa91c02    # also checks against an alert's anchor
python3 audit.py tail -n 20
```

## Audit log

Location: `$REMOTE_UNLOCK_STATE/audit.log` (`/var/lib/remote-unlock/` under systemd).
Every connection outcome, lockout, PAM grant/denial, start/stop is a line containing the
hash of the previous line.

A hash chain only proves integrity against someone who can't rewrite the *whole* file
consistently. Close that gap with both of these:

1. **Append-only at the filesystem level:** `sudo chattr +a /var/lib/remote-unlock/audit.log`
   (after the first run creates it; root is needed to undo, so rotate deliberately).
2. **Off-box anchor:** every alert ends with `audit #<seq> head=<hash prefix>`. That
   anchors the chain on your phone/Slack. `audit.py verify --head <prefix>` then detects
   truncation or a rewrite.

Note that v1's "zero disk writes" claim no longer holds: the audit log is a deliberate
exception. Challenges, nonces and grants are still memory-only.

## Phone app: what must change

The wire protocol changed, so the Expo app needs updating. I couldn't read `mobile-app/`,
so this is the spec rather than a patch. `client_example.py` is the executable reference.

1. **Client certificate (mTLS).** The app must present the `.p12` client cert on the
   TLS connection. As far as I know React Native's built-in `WebSocket` can't be
   configured with a client certificate, so you'll likely need a custom dev build with a
   native module that supports it. I haven't verified a specific library. Expo Go won't
   do it. If you need a stopgap, set `"require_mtls": false` in `config.json`; the
   service logs a warning and falls back to signatures alone. Don't leave it that way.
2. **Hello first:** send `{"type":"hello","device_id":"phone1"}`.
3. **Verify the laptop** before signing: check `server_sig` over the exact bytes of
   `signed_message("challenge", …)` against the pinned laptop public key and check
   `target_id`.
4. **Respond:** sign `signed_message("response", …)`, send `{"type":"response","nonce","signature"}`.
   Signature may be DER-hex or raw 64-byte r‖s hex.

Signed bytes (UTF-8): `remote-unlock/v2|<role>|<nonce>|<issued_ms>|<device_id>|<target_id>|unlock`

### Hardware factor

Generate the signing key in the Secure Enclave / Android StrongBox with *user
authentication required for every use* (`requireAuthentication` in `expo-secure-store`
was v1's approach; a hardware-backed key where each signature triggers the biometric is
stronger). Then a signature can't exist without a fingerprint/face check. A YubiKey/FIDO2
token as an additional factor would need server-side WebAuthn verification. That is a
sensible next step, but it isn't in this release.

## What this does NOT protect against

- **A compromised laptop OS or root.** Malware with root can bypass PAM, read process
  memory, or alter the audit log (before `chattr +a`). Use full-disk encryption.
- **A phone whose hardware key is extracted,** or a phone unlocked and handed to an
  attacker (biometric spoofing, coercion).
- **Someone who gets both the CA key and your passphrase.** That's why the CA key goes offline.
- **Failed TLS handshakes aren't counted by the lockout** (they never reach application
  code). They are harmless without a valid client cert but are also not logged by this
  service; use the firewall/Tailscale ACLs to limit who can reach the port.
- **Availability.** Someone holding a stolen client cert can trigger a device lockout.
  In `requisite` mode a locked-out or lost phone means *no login through that PAM
  service*. Keep at least one path without this module (a TTY `login`, or another root
  session) and keep the revoke/recovery steps handy. Test before you rely on it.

## Tests

`tests/test_flow.py` — 22 tests over real TLS 1.3 with mutual auth: happy path, replayed
response, burned nonces, wrong device key, expired challenge, no client cert, cert from
a foreign CA, instant revocation, impostor laptop (client refuses to sign), cert/hello
mismatch, lockout + alert + backoff doubling, PAM single-use grants, wrong user, wrong
uid on either side, grant expiry, audit tamper/truncation detection, wildcard-bind and
weak-passphrase refusal. Not covered: the systemd unit, a real PAM stack, and the phone app.

## Files

| File | Purpose |
|---|---|
| `listener.py` | mTLS WebSocket service, verification, lockout, PAM grant broker |
| `pair.py` | CA/PKI creation, device registration, revocation, renewal |
| `pam_unlock_helper.py` | Root helper called by `pam_exec`; asks the listener for a grant |
| `audit.py` | Hash-chained log + `verify` / `tail` CLI |
| `notify.py` | ntfy / Telegram / webhook alerts |
| `client_example.py` | Reference client = protocol spec, used for testing |
| `common.py` | Signed-message format, ECDSA helpers, config loader |
| `remote-unlock.service` | Hardened systemd unit |
