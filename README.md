# Remote-Unlock

**Unlock your laptop with your phone's fingerprint — securely, over your own network.**

Remote-Unlock is a small, self-hosted system that lets you approve a laptop login from your phone using Face ID / fingerprint, instead of (or alongside) typing a password. It's built around a few hard rules: no plaintext secrets on disk, no writes to your filesystem during normal operation, fail-closed on every error path, and every trust decision backed by real cryptography rather than a "looks secure" shortcut.

It is a **second factor layered on top of your existing login** — not a replacement for disk encryption or a strong password.

---

## Table of contents

- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Is it secure?](#is-it-secure)
- [Prerequisites](#prerequisites)
- [Setup guide](#setup-guide)
  1. [Install dependencies](#1-install-dependencies)
  2. [Pair your phone and laptop](#2-pair-your-phone-and-laptop)
  3. [Set up Tailscale (optional, recommended)](#3-set-up-tailscale-optional-recommended)
  4. [Install the systemd service](#4-install-the-systemd-service)
  5. [Scope the firewall](#5-scope-the-firewall)
  6. [Wire up PAM](#6-wire-up-pam)
  7. [Test before you rely on it](#7-test-before-you-rely-on-it)
- [Mobile app setup](#mobile-app-setup)
- [Re-pairing and revocation](#re-pairing-and-revocation)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Limitations](#limitations)
- [License](#license)

---

## How it works

1. Your phone opens a TLS (`wss://`) connection to a small Python listener running on your laptop.
2. The laptop sends back a **challenge**: a random nonce, a timestamp, and its own signature over both (proving the laptop, not an impostor, issued the challenge).
3. Your phone asks for Face ID / fingerprint, then signs the nonce with a private key that only exists inside its secure enclave.
4. The laptop verifies that signature against the phone's public key (exchanged once, during pairing). If it's valid, unused, and issued within the last 10 seconds, the laptop signals success over a local Unix socket.
5. A small PAM helper — invoked as an *additional* auth step, not a replacement — reads that signal and tells the OS login prompt to proceed.
6. A push notification fires either way, so you know about every unlock attempt in real time, successful or not.

```
 ┌──────────────┐        1. connect (wss://, TLS-pinned CA)        ┌───────────────┐
 │  Phone app   │ ───────────────────────────────────────────────▶ │  listener.py  │
 │ (Expo/React  │                                                   │ (background   │
 │   Native)    │ ◀─────────────────────────────────────────────── │  service)     │
 └──────┬───────┘        2. challenge {nonce, timestamp, sig}       └───────┬───────┘
        │                                                                    │
        │ 3. Face ID / fingerprint prompt                                   │
        │    sign(nonce, timestamp) with phone's private key                │
        ▼                                                                    ▼
 ┌──────────────┐        4. response {nonce, timestamp, signature}  ┌───────────────┐
 │  Phone app   │ ───────────────────────────────────────────────▶ │  listener.py  │
 └──────────────┘                                                   │  verify()     │
                                                                      └───────┬───────┘
                                                                              │ 5. Unix socket (/run, tmpfs)
                                                                              ▼
                                                          ┌────────────────────────────┐
                                                          │ pam_unlock_helper.py        │
                                                          │ (called by pam_exec.so)     │
                                                          └────────────┬───────────────┘
                                                                       │ exit 0 / exit 1
                                                                       ▼
                                                              OS login prompt (PAM)

                                                          6. notify.py → ntfy.sh push alert
```

## Repository layout

| File / folder | Purpose |
|---|---|
| `pair.py` | One-time setup script. Generates the laptop's ECDSA keypair, a local self-signed CA + TLS leaf certificate, an `ntfy.sh` alert topic, and exchanges public keys with the phone. Writes everything to `~/.config/remote-unlock/`. |
| `listener.py` | The background service. Listens for phone connections over `wss://`, issues challenges, verifies signed responses, rate-limits, and signals the result to PAM. This is what you run as a systemd service. |
| `pam_unlock_helper.py` | Called by `pam_exec.so` during login. Waits (up to 15s) on a local Unix socket for `listener.py` to signal success or failure, then exits `0` or `1` accordingly. |
| `notify.py` | Sends a push notification via [ntfy.sh](https://ntfy.sh) for every unlock attempt, successful or rejected. No account required. |
| `mobile-app/` | An Expo (React Native) app: pairing screen + unlock screen. Uses `src/crypto.js` for ECDSA signing (cross-compatible with the laptop's Python implementation) and `src/secureStore.js` (via `expo-secure-store`) to keep the phone's private key behind biometric authentication. |
| `README.md` | This guide. |

## Is it secure?

Reasonably — for what it is. There's no such thing as "most secure" in absolute terms; every measure below closes one specific, real weakness, and you could always add more layers (a hardware security key, mTLS, a dedicated auth server) at the cost of more moving parts. Treat this as a solid, honest baseline, not a silver bullet.

| Risk | Mitigation in this build |
|---|---|
| Captured challenge/response replayed later | Nonces are single-use and expire after 10 seconds |
| Network eavesdropper on your Wi-Fi | Mandatory TLS 1.2+; the listener **refuses to start** without a certificate |
| Fake access point / MITM | The phone trusts a laptop-controlled local CA (verified via a real TLS handshake) *and* independently verifies a signature from the laptop's own key — two unrelated checks |
| Stolen laptop disk / another local user reads your config | The unlock private key is encrypted at rest with a passphrase (scrypt-derived key); the passphrase itself is never stored |
| Brute-force attempts against the listener | Rate limiting — 5 failed attempts within 60 seconds triggers a cooldown |
| A bug causing "fail open" | Every error path (timeout, bad signature, malformed JSON, unexpected exception) is treated as a rejection |
| A local process spoofing a fake "unlock" signal to PAM | A timing sanity check rejects any signal that arrives faster than a real network round-trip + biometric prompt could plausibly take |
| Someone discovering your `ntfy.sh` alert channel | The topic name is a long, automatically-generated random string — never a guessable default |

**What this does *not* protect against:** a fully compromised laptop OS (malware running as root can bypass PAM entirely, independent of this project), or a compromised/jailbroken phone with the key physically extracted from its secure enclave via a hardware exploit. Nothing at this software layer fixes either of those — that's what full-disk encryption (LUKS / FileVault) and keeping your phone's OS up to date are for, and you should have both regardless of whether you use this project.

## Prerequisites

- A Linux laptop (PAM-based login — GDM, sudo, etc.). `pair.py` and `listener.py` are Python 3; PAM integration as written targets Linux specifically.
- Python 3.9+ and `pip`.
- A smartphone (iOS or Android) able to run an Expo Go app, with Face ID / fingerprint already configured.
- [Node.js](https://nodejs.org/) and `npm` on a machine to build/run the Expo app (can be the same laptop).
- Root/sudo access on the laptop, for the PAM and firewall steps only — the listener itself never runs as root.
- Optional but recommended: a [Tailscale](https://tailscale.com/) account, if you want unlock to work from outside your home Wi-Fi.

## Setup guide

### 1. Install dependencies

```bash
pip install cryptography websockets --break-system-packages
```

### 2. Pair your phone and laptop

```bash
python3 pair.py
```

This will:

- Generate the laptop's ECDSA (P-256) keypair.
- Ask you to set a passphrase (minimum 12 characters) and use it to encrypt the private key at rest via scrypt + Fernet.
- Auto-generate a local self-signed CA and a TLS leaf certificate for the IP you give it.
- Auto-generate a random, unguessable `ntfy.sh` alert topic.
- Print the laptop's public key (paste it into the phone app), and tell you where the CA certificate and `ntfy` topic are.
- Prompt you to paste in the phone's public key (shown on the phone app's own pairing screen — see [Mobile app setup](#mobile-app-setup) below to get that key first).

Everything it writes lives in `~/.config/remote-unlock/`, with directory permissions `700` and file permissions `600` — owner-only.

> You'll be asked for a laptop IP during this step. Enter your Tailscale IP if you're setting that up (see step 3), or your LAN IP for same-Wi-Fi-only use.

### 3. Set up Tailscale (optional, recommended)

Without this, unlock only works when your phone and laptop share the same Wi-Fi. [Tailscale](https://tailscale.com/) gives both devices a private, stable IP reachable over an encrypted WireGuard tunnel — from anywhere, with no port forwarding and nothing exposed to the public internet.

```bash
# On the laptop (Linux):
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
tailscale ip -4    # note this — you'll enter it in pair.py
```

On the phone, install the Tailscale app from the App Store / Play Store and sign in with the same account. No further app code is needed — Tailscale is purely a network-layer tunnel underneath the listener and app you already have.

If you already paired using a LAN IP and want to switch to Tailscale, just re-run `pair.py` — it regenerates the certificates for the new IP.

### 4. Install the systemd service

Create `~/.config/systemd/user/remote-unlock.service`:

```ini
[Unit]
Description=Remote unlock listener
# If using Tailscale, wait for it to be up before binding to its IP —
# otherwise the bind will fail on every boot.
After=tailscaled.service network-online.target
Wants=tailscaled.service network-online.target

[Service]
ExecStart=/usr/bin/python3 %h/remote-unlock/listener.py
Restart=on-failure
RestartSec=5

# Defense in depth: enforce at the OS level what the process already does.
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
ReadWritePaths=%t

# The listener needs your passphrase at startup. systemd-ask-password
# keeps it out of shell history and process listings.
ExecStartPre=/bin/sh -c 'systemd-ask-password "Remote-unlock passphrase:" > %t/remote-unlock-pass'
Environment=REMOTE_UNLOCK_PASSPHRASE_FILE=%t/remote-unlock-pass

[Install]
WantedBy=default.target
```

Then enable and start it:

```bash
systemctl --user enable --now remote-unlock.service
```

If you'd rather skip `systemd-ask-password` plumbing, just run `python3 listener.py` directly in a terminal you keep open — it will prompt for the passphrase interactively. Less convenient, but fewer moving parts.

> `listener.py` binds directly to the specific IP its certificate was issued for (Tailscale or LAN) — never `0.0.0.0`. That makes the service unreachable on any other interface, which is a stronger guarantee than firewall rules alone.

### 5. Scope the firewall

Still worth doing even with Tailscale, for defense in depth.

**Using Tailscale:**

```bash
sudo ufw allow in on tailscale0 to any port 8765 proto tcp
sudo ufw deny 8765
```

**LAN-only (no Tailscale):** confirm you haven't port-forwarded 8765, and optionally scope it to your home subnet:

```bash
sudo ufw allow from 192.168.0.0/16 to any port 8765 proto tcp
sudo ufw deny 8765
```

(Adjust the subnet to match your actual home network range.)

### 6. Wire up PAM

Add this as an **additional** line — not a replacement for your password — in `/etc/pam.d/gdm-password` or `/etc/pam.d/sudo`:

```
auth optional pam_exec.so /home/YOURUSER/remote-unlock/pam_unlock_helper.py
```

**Use `optional`, not `sufficient`.** `sufficient` lets a success here skip your password entirely, which means a compromised phone key becomes a full account compromise with zero other checks. `optional` just adds phone-unlock as one more path PAM considers, on top of whatever your normal auth stack already requires. If you deliberately want passwordless phone-only login, make sure you understand exactly what you're trading away before flipping that switch.

### 7. Test before you rely on it

Run `listener.py` in a terminal (not yet as a service) and try an unlock from your phone:

1. First on the same Wi-Fi.
2. Then, if using Tailscale, with your phone switched entirely to cellular data, to confirm cross-network unlock actually works.

Watch the terminal output. Also confirm rejection works — cancel the phone's fingerprint prompt and verify the laptop reports a rejected attempt.

Only move to the systemd service and PAM wiring (steps 4 and 6) once both the success and rejection paths are confirmed working.

## Mobile app setup

The `mobile-app/` folder is a working Expo app with a pairing screen and an unlock screen, wired to real cryptography (`src/crypto.js`, tested cross-compatible with the laptop's Python signing/verification) and biometric-gated key storage (`src/secureStore.js`, via `expo-secure-store`'s `requireAuthentication`).

### Install and run

```bash
cd mobile-app
npm install
npx expo start
```

Scan the QR code with the Expo Go app (iOS or Android) to run it on your phone. No App Store submission is needed — this is for your own device only.

### Pairing flow, in order

1. If you want cross-network unlock, set up Tailscale first (see [step 3](#3-set-up-tailscale-optional-recommended) above) — you'll need the IP before pairing.
2. On the laptop, run `python3 pair.py`. When it asks for an IP, give it the Tailscale IP (`tailscale ip -4`) for cross-network use, or the plain LAN IP (e.g. `192.168.1.42`) for same-Wi-Fi-only use.
3. `pair.py` writes `~/.config/remote-unlock/ca-cert.pem`. Transfer this file to your phone (AirDrop, email — it's a public certificate, not a secret) and install it as a trusted certificate:
   - **iOS:** open the file and follow the profile install prompt in Settings, then separately go to **Settings → General → About → Certificate Trust Settings** and enable full trust for it. iOS requires this second step for custom CAs.
   - **Android:** **Settings → Security → Encryption & credentials → Install a certificate → CA certificate.**
4. Open the app on your phone. On the pairing screen, generate a keypair — this also confirms Face ID / fingerprint is set up, since the app refuses to proceed without it — then paste the phone's printed public key into `pair.py` on the laptop when prompted.
5. `pair.py` then prints the laptop's public key. Paste that into the app's pairing screen and save. Pairing is now complete on both sides.
6. On the unlock screen, enter the laptop's IP (Tailscale or LAN — matching what you gave `pair.py`) and tap "Unlock my laptop" to test the full flow end to end. It's remembered after the first successful attempt.

### Range and notifications

- **Without Tailscale:** unlock only works while your phone and laptop share the same Wi-Fi (normal range, roughly 30–50m indoors). Off that network, the app simply times out — there's nothing internet-facing to reach.
- **With Tailscale:** unlock works from anywhere either device has internet access — home, mobile data, another country. The tunnel handles routing regardless of physical distance.
- **Push alerts always work anywhere**, independent of the above, since `notify.py` posts to `ntfy.sh` over the open internet. You'll only get an alert for an attempt that actually reached the listener, though — with Tailscale that includes attempts from anywhere; without it, only attempts from your own Wi-Fi, since nothing else could reach the listener in the first place.

### Why there's no certificate-pinning library in the app

A hand-rolled "pin this cert" check in app code is easy to write in a way that looks correct but silently verifies nothing — React Native's WebSocket doesn't expose per-connection certificate inspection without a native module. Installing the laptop's own CA as a trusted certificate on the phone sidesteps that entirely: it's the same mechanism your phone already uses to trust ordinary `https://` sites, just pointed at a CA you control instead of a public one. This has been verified end-to-end in testing: a real TLS handshake against the generated CA succeeds, and anything not signed by it is rejected.

## Re-pairing and revocation

If you lose the phone, suspect the passphrase leaked, or just want to rotate keys:

```bash
rm -rf ~/.config/remote-unlock/
python3 pair.py
```

There's no separate "revoke" step needed — the old keys simply stop being accepted once the config that referenced them is gone.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `listener.py` exits immediately with "No TLS certificate configured" | `pair.py` hasn't been run yet, or `pairing.json` is missing/corrupted. Re-run `pair.py`. |
| `listener.py` fails to bind on startup | The IP it's trying to bind to (Tailscale or LAN) isn't currently assigned to the machine. If using Tailscale, confirm `tailscaled` is running (`sudo tailscale status`). If your LAN IP changed, set a static DHCP reservation or re-run `pair.py` to reissue the cert for the new IP. |
| Phone times out trying to connect | Confirm phone and laptop are on the same Wi-Fi (non-Tailscale setup) or both connected to your tailnet (Tailscale setup). Check the firewall rule from [step 5](#5-scope-the-firewall) allows port 8765. |
| Phone connects but the unlock is always rejected | Re-check that the public keys pasted during pairing match exactly (no truncated lines). Also confirm your phone's clock is accurate — signatures include a timestamp and are rejected outside a small allowed skew. |
| Login prompt just times out without ever asking for the phone | Confirm the `pam_exec.so` line was added to the correct file (`gdm-password`, `sudo`, etc.) and that the path to `pam_unlock_helper.py` is correct and executable. |
| No push notification arrives | Confirm you're subscribed to the exact `ntfy_topic` printed by `pair.py`, in the ntfy app. Notification failures never block login — check `listener.py`'s logs for a "Notification failed" warning. |
| Passphrase prompt appears every time you `sudo` | That's expected if you're running `listener.py` manually in a terminal each boot — it decrypts the private key into memory once at service startup, not on every unlock attempt. Move to the systemd service in [step 4](#4-install-the-systemd-service) so it only asks once per boot. |

## FAQ

**Does this replace my password?**
No, by default it's wired in as `optional`, meaning it's an additional path, not a replacement. See the warning in [step 6](#6-wire-up-pam) if you want to change that.

**What happens if my phone is offline or dead?**
Nothing breaks — your normal password login still works exactly as before. This is purely additive.

**Does anything get written to disk during normal unlock attempts?**
No. `listener.py` reads `pairing.json` once at startup and otherwise only touches a Unix domain socket in `/run` (tmpfs, RAM-backed, wiped on reboot). The only files ever written are the one-time outputs of `pair.py`.

**Can I use this on macOS or Windows?**
The listener (`listener.py`), pairing script, and phone app are OS-agnostic Python/JS. The PAM integration described here is Linux-specific. macOS (Credential Provider-style hook) and Windows equivalents aren't included in this repo as written — you'd need to write an equivalent login hook for those platforms.

## Limitations

This project does **not** protect against:

- A fully compromised laptop OS — malware running with root can bypass PAM entirely, independent of anything this project does.
- A compromised or jailbroken phone with the private key physically extracted from its secure enclave via a hardware exploit.

Use full-disk encryption (LUKS / FileVault) and keep your phone's OS updated regardless of whether you use this project — those are the layers that address the risks above.

## License

MIT — see [LICENSE](LICENSE).
