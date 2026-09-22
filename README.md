# Phone-unlock for your laptop — setup guide

## Is it secure?

Reasonably, for what it is — a *second factor* layered on top of your
existing login, not a replacement for disk encryption or a good password.
There's no such thing as "most secure" in absolute terms; every version
below closes a specific real weakness, and there are always more layers
(hardware security keys, mTLS, a dedicated auth server) you could add at
the cost of more moving parts. Treat this as a solid, honest baseline:

| Risk | Mitigation in this build |
|---|---|
| Captured challenge/response replayed later | Nonces are single-use, expire in 10s |
| Network eavesdropper on your Wi-Fi | Mandatory TLS 1.2+, listener **refuses to start** without a cert |
| Fake access point / MITM | Phone trusts a laptop-controlled local CA (verified via real TLS handshake) *and* verifies a signature from the laptop's own key — two independent checks |
| Stolen laptop disk / another local user reads your config | Unlock private key is encrypted at rest with a passphrase (scrypt-derived key); the passphrase is never stored |
| Brute-force attempts on the listener | Rate limiting (5 fails / 60s triggers cooldown) |
| A bug causing "fail open" | Every error path (timeout, bad signature, malformed JSON, unexpected exception) returns rejection |
| Local process spoofing a fake "unlock" signal to PAM | Timing sanity check rejects signals that arrive faster than a real network round-trip could |
| Someone finding your ntfy.sh alert channel | Topic name is a long random string, generated automatically, never a guessable default |

What this does **not** protect against: a fully compromised laptop OS
(malware with root can bypass PAM entirely, independent of this project),
or a compromised/jailbroken phone with the key physically extracted from
its secure enclave via hardware exploit. Nothing software-level fixes
those — that's what disk encryption (LUKS/FileVault) and keeping your
phone OS updated are for, and you should have both regardless of this
project.

## Setup

### 1. Install dependencies
```bash
pip install cryptography websockets --break-system-packages
```

### 2. Pair your phone and laptop
```bash
python3 pair.py
```
This will:
- Generate the laptop's ECDSA keypair
- Ask you to set a passphrase, and encrypt the private key with it
- Auto-generate a self-signed TLS certificate
- Auto-generate a random ntfy.sh alert topic
- Print the laptop's public key (paste into your phone app), the TLS cert
  fingerprint (pin it in the phone app), and the ntfy topic (subscribe to
  it in the ntfy app)
- Prompt you to paste in the phone's public key (shown on the phone app's
  own pairing screen)

Everything it writes lives in `~/.config/remote-unlock/`, permissions
`600`/`700`, owner-only.

### 3. (Optional but recommended) Set up Tailscale for cross-network unlock
Without this, unlock only works when phone and laptop share the same
Wi-Fi. Tailscale gives both devices a private, stable IP reachable over an
encrypted WireGuard tunnel from anywhere — no port forwarding, nothing
exposed to the public internet.

```bash
# Laptop (Linux):
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
tailscale ip -4    # note this — you'll enter it in pair.py
```
On the phone, install the Tailscale app from the App Store / Play Store
and sign in with the same account. That's it — no further app code is
needed, this is purely a network-layer tunnel underneath the same
listener/app you already have.

When you ran `pair.py` in step 2, you should have entered this Tailscale
IP (not your LAN IP) when it asked. If you already paired with a LAN IP
and want to switch, just re-run `pair.py` — it's not a destructive step
for anything except the certs, which regenerate anyway.

### 4. Set up the systemd service, hardened
```ini
# ~/.config/systemd/user/remote-unlock.service
[Unit]
Description=Remote unlock listener
# If using Tailscale, wait for it to be up before binding to its IP —
# otherwise the bind in step 3 below will fail on every boot.
After=tailscaled.service network-online.target
Wants=tailscaled.service network-online.target

[Service]
ExecStart=/usr/bin/python3 %h/remote-unlock/listener.py
Restart=on-failure
RestartSec=5

# Defense in depth: even though the process already avoids touching your
# files, these flags make the OS enforce it too.
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=%t

# The listener needs your passphrase at startup. Supplying it via
# systemd-ask-password keeps it out of shell history and process listings.
ExecStartPre=/bin/sh -c 'systemd-ask-password "Remote-unlock passphrase:" > %t/remote-unlock-pass'
Environment=REMOTE_UNLOCK_PASSPHRASE_FILE=%t/remote-unlock-pass

[Install]
WantedBy=default.target
```
```bash
systemctl --user enable --now remote-unlock.service
```
(If you'd rather not deal with `systemd-ask-password` plumbing, just run
`python3 listener.py` in a terminal you keep open — it'll prompt for the
passphrase directly. Less convenient, fewer moving parts.)

Note: `listener.py` now binds directly to the specific IP the cert was
issued for (Tailscale or LAN) instead of `0.0.0.0`. This means the service
is literally unreachable on any interface other than the one you paired
with — stronger than firewall rules alone, since there's no other
interface to accidentally leave open.

### 5. Scope the firewall (still worth doing, even with Tailscale)
**If you're using Tailscale:** the bind-to-specific-IP change above already
means nothing on your raw LAN or the public internet can reach the
listener — only traffic arriving through the Tailscale interface can. You
can optionally also restrict at the firewall level for defense in depth:
```bash
sudo ufw allow in on tailscale0 to any port 8765 proto tcp
sudo ufw deny 8765
```

**If you're NOT using Tailscale** (LAN-only setup): don't leave port 8765
open to the whole internet — confirm you haven't port-forwarded it, and
optionally scope to your home subnet:
```bash
sudo ufw allow from 192.168.0.0/16 to any port 8765 proto tcp
sudo ufw deny 8765
```
(adjust the subnet to match your actual home network range).

### 6. Wire up PAM (Linux)
Add this as an **additional** line — not a replacement for your password —
in `/etc/pam.d/gdm-password` or `/etc/pam.d/sudo`:
```
auth optional pam_exec.so /home/YOURUSER/remote-unlock/pam_unlock_helper.py
```
**Use `optional`, not `sufficient`.** `sufficient` lets a success here skip
your password entirely — meaning phone-key compromise becomes full account
compromise with zero other checks. `optional` just adds phone-unlock as
one more path PAM considers, on top of whatever your normal auth stack
already requires. If you deliberately want passwordless phone-only login,
understand exactly what you're trading away before flipping that switch.

### 7. Test before you rely on it
Run `listener.py` in a terminal (not as a service yet) and try an unlock
from your phone — first on the same Wi-Fi, then (if using Tailscale) with
your phone switched to cellular data entirely, to confirm cross-network
unlock actually works before you depend on it. Watch the terminal output.
Also confirm rejection works (cancel the phone's fingerprint prompt and
verify the laptop reports a rejected attempt). Only move to the systemd
service and PAM wiring once both paths are confirmed.

## Re-pairing / revocation
If you lose the phone, suspect the passphrase leaked, or just want to
rotate keys: delete `~/.config/remote-unlock/` entirely and run `pair.py`
again. There's no separate "revoke" step needed — the old keys simply stop
being accepted once the config that referenced them is gone.

## Phone app setup (Expo)

The `mobile-app/` folder is a working Expo app: pairing screen + unlock
screen, wired to real crypto (`src/crypto.js`, tested cross-compatible with
the laptop's Python signing/verification) and biometric-gated storage
(`src/secureStore.js`, via `expo-secure-store`'s `requireAuthentication`).

### Install and run
```bash
cd mobile-app
npm install
npx expo start
```
Scan the QR code with Expo Go (iOS/Android) to run it on your phone. No
App Store submission needed — this is for your own device only.

### Pairing flow, in order
1. Set up Tailscale first if you want cross-network unlock (see step 3 in
   the laptop setup above) — you need the IP before pairing.
2. On the laptop: `python3 pair.py`. When it asks for an IP, give the
   Tailscale IP (`tailscale ip -4`) for cross-network use, or the plain
   LAN IP (e.g. `192.168.1.42`) for same-Wi-Fi-only use.
3. `pair.py` writes `~/.config/remote-unlock/ca-cert.pem`. Transfer this
   file to your phone (AirDrop, email — it's a public certificate, not a
   secret) and install it as a trusted certificate:
   - **iOS**: open the file, follow the profile install prompt in
     Settings, then separately go to **Settings > General > About >
     Certificate Trust Settings** and toggle full trust for it — iOS
     requires this second step for custom CAs.
   - **Android**: **Settings > Security > Encryption & credentials >
     Install a certificate > CA certificate**.
4. Open the app on your phone. On the pairing screen: generate a keypair
   (this also confirms Face ID / fingerprint is set up — the app refuses
   to proceed without it), then paste the phone's printed public key into
   `pair.py` on the laptop when prompted.
5. `pair.py` will then print the laptop's public key — paste that into
   the app's pairing screen and save. Pairing is now complete on both
   sides.
6. On the unlock screen, enter the laptop's IP (Tailscale or LAN, matching
   what you gave `pair.py`) and tap "Unlock my laptop" to test the full
   flow end to end. It's remembered after the first successful attempt.

### Range and notifications
- **Without Tailscale**: unlock only works while phone and laptop share
  the same Wi-Fi (normal Wi-Fi range, ~30–50m indoors). Off that network,
  the app just times out — there's nothing internet-facing to reach.
- **With Tailscale**: unlock works from anywhere either device has
  internet access — home, mobile data, another country. The tunnel
  handles routing regardless of physical distance.
- **Push alerts always work anywhere**, independent of the above, since
  `notify.py` posts to ntfy.sh over the open internet. You'll only ever
  get an alert for an attempt that actually reached the listener, though
  — with Tailscale that includes attempts from anywhere; without it,
  only attempts from your own Wi-Fi (since nothing else could reach the
  listener to attempt in the first place).

### Why there's no certificate-pinning library in the app
A hand-rolled "pin this cert" check in app code is easy to write in a way
that looks right but silently does nothing — React Native's WebSocket
doesn't expose per-connection cert inspection without a native module, and
a naive implementation (like an earlier draft of this project had) can end
up not actually verifying anything. Installing the laptop's own CA as
trusted on the phone sidesteps that entirely: it's the same mechanism your
phone already uses to trust `https://` sites, just pointed at a CA you
control instead of a public one. Verified end-to-end in testing: a real
TLS handshake against the generated CA succeeds, and rejects anything not
signed by it.
