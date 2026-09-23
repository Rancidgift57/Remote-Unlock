# Remote-Unlock

**Unlock your laptop with your phone's fingerprint — securely, over your own network.**

Remote-Unlock is a small, self-hosted system that lets you approve a laptop login from your phone using Face ID / fingerprint, instead of (or alongside) typing a password. It's built around a few hard rules: no plaintext secrets on disk, no writes to your filesystem during normal operation, fail-closed on every error path, and every trust decision backed by real cryptography rather than a "looks secure" shortcut.

It supports **Linux** (via PAM) and **Windows** (via a native Credential Provider), and on either platform you choose one of two authentication models:

- **Second factor** (Linux only, the original default): your password is *always* required — the phone is an additional check layered on top, never a replacement.
- **Fingerprint-primary** (both platforms): phone success logs you in with *no password prompt at all*; phone failure or timeout falls back to a normal password prompt. Only one factor is ever actually required.

If you want a guarantee that a password is always checked no matter what, stay on Linux's default `optional` mode. Windows can only run in fingerprint-primary mode — the reason why is explained in the [Windows setup guide](#windows-setup-guide).

---

## Table of contents

- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Is it secure?](#is-it-secure)
- [Choosing a mode](#choosing-a-mode)
- [Prerequisites](#prerequisites)
- [Setup guide (Linux)](#setup-guide-linux)
  1. [Install dependencies](#1-install-dependencies)
  2. [Pair your phone and laptop](#2-pair-your-phone-and-laptop)
  3. [Set up Tailscale (optional, recommended)](#3-set-up-tailscale-optional-recommended)
  4. [Install the systemd service](#4-install-the-systemd-service)
  5. [Scope the firewall](#5-scope-the-firewall)
  6. [Wire up PAM](#6-wire-up-pam)
  7. [Test before you rely on it](#7-test-before-you-rely-on-it)
- [Windows setup guide](#windows-setup-guide)
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
4. The laptop verifies that signature against the phone's public key (exchanged once, during pairing). If it's valid, unused, and issued within the last 10 seconds, the laptop signals success to the login screen.
5. **On Linux**, a PAM helper reads that signal off a local Unix socket and exits `0`/`1`; PAM either treats this as one more optional check (second-factor mode) or lets a success skip the password prompt entirely (fingerprint-primary mode) — see [step 6](#6-wire-up-pam).
   **On Windows**, a Credential Provider tile reads the signal off a named pipe and, on success, submits your Windows credential directly to LogonUI — see the [Windows setup guide](#windows-setup-guide) for why this platform only supports fingerprint-primary mode.
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
                                                                              │ 5a. Linux: Unix socket (/run, tmpfs)
                                                                              │ 5b. Windows: named pipe
                                                                              ▼
                                        ┌─────────────────────────────┐   ┌──────────────────────────────┐
                                        │ pam_unlock_helper.py (Linux) │   │ Credential Provider (Windows) │
                                        │ called by pam_exec.so        │   │ COM DLL, runs inside LogonUI   │
                                        └────────────┬─────────────────┘   └──────────────┬────────────────┘
                                                      │ exit 0 / exit 1                    │ submits credential or goes idle
                                                      ▼                                     ▼
                                          PAM auth stack (optional/sufficient)     LogonUI (tile alongside password tile)

                                                          6. notify.py → ntfy.sh push alert (both platforms)
```

## Repository layout

| File / folder | Purpose |
|---|---|
| `pair.py` | Linux one-time setup script. Generates the laptop's ECDSA keypair, a local self-signed CA + TLS leaf certificate, an `ntfy.sh` alert topic, and exchanges public keys with the phone. Writes everything to `~/.config/remote-unlock/`. |
| `listener.py` | Linux background service. Listens for phone connections over `wss://`, issues challenges, verifies signed responses, rate-limits, and signals the result to PAM. This is what you run as a systemd service. |
| `pam_unlock_helper.py` | Called by `pam_exec.so` during Linux login. Waits (up to 15s) on a local Unix socket for `listener.py` to signal success or failure, then exits `0` or `1`. Unchanged regardless of which PAM mode you choose. |
| `notify.py` | Sends a push notification via [ntfy.sh](https://ntfy.sh) for every unlock attempt, successful or rejected. No account required. Shared by both platforms. |
| `mobile-app/` | An Expo (React Native) app: pairing screen + unlock screen. Uses `src/crypto.js` for ECDSA signing (cross-compatible with the laptop's Python implementation) and `src/secureStore.js` (via `expo-secure-store`) to keep the phone's private key behind biometric authentication. Shared by both platforms. |
| `linux-fingerprint-primary/` | Scripts and docs for switching Linux from second-factor (`optional`) to fingerprint-primary (`sufficient`) mode, and back. See [Choosing a mode](#choosing-a-mode). |
| `windows/` | The full Windows port: `pair_windows.py`, `listener_windows.py`, and `credential-provider/` (the native Credential Provider C++/COM source, CMake build, and install/uninstall scripts). See the [Windows setup guide](#windows-setup-guide). |
| `README.md` | This guide. |

## Is it secure?

Reasonably — for what it is. There's no such thing as "most secure" in absolute terms; every measure below closes one specific, real weakness, and you could always add more layers (a hardware security key, mTLS, a dedicated auth server) at the cost of more moving parts. Treat this as a solid, honest baseline, not a silver bullet.

| Risk | Mitigation in this build |
|---|---|
| Captured challenge/response replayed later | Nonces are single-use and expire after 10 seconds |
| Network eavesdropper on your Wi-Fi | Mandatory TLS 1.2+; the listener **refuses to start** without a certificate |
| Fake access point / MITM | The phone trusts a laptop-controlled local CA (verified via a real TLS handshake) *and* independently verifies a signature from the laptop's own key — two unrelated checks |
| Stolen laptop disk / another local user reads your config | The unlock private key (and, on Windows, your Windows password) is encrypted at rest with a passphrase (scrypt-derived key); the passphrase itself is never stored |
| Brute-force attempts against the listener | Rate limiting — 5 failed attempts within 60 seconds triggers a cooldown |
| A bug causing "fail open" | Every error path (timeout, bad signature, malformed JSON, unexpected exception) is treated as a rejection |
| A local process spoofing a fake "unlock" signal | A timing sanity check rejects any signal that arrives faster than a real network round-trip + biometric prompt could plausibly take |
| Someone discovering your `ntfy.sh` alert channel | The topic name is a long, automatically-generated random string — never a guessable default |

**What this does *not* protect against:** a fully compromised laptop OS (malware running as root/admin can bypass this entirely, independent of this project), or a compromised/jailbroken phone with the key physically extracted from its secure enclave via a hardware exploit. Nothing at this software layer fixes either of those — that's what full-disk encryption (LUKS / BitLocker / FileVault) and keeping your phone's OS up to date are for, and you should have both regardless of whether you use this project.

**Additional risk if you use fingerprint-primary mode (Windows always, Linux optionally):** phone-key compromise becomes full account compromise on its own, since no password check runs when the phone succeeds. This isn't hidden in the fine print — see [Choosing a mode](#choosing-a-mode) before switching.

## Choosing a mode

| | Second factor (`optional`) | Fingerprint-primary (`sufficient` / Windows Credential Provider) |
|---|---|---|
| Available on | Linux only | Linux and Windows |
| Password required on phone success? | Yes, always | No |
| Password required on phone failure/timeout? | Yes | Yes — normal password prompt appears |
| What a stolen/cloned phone key gets an attacker | Nothing on its own — still needs your password | Full login, no password needed |
| Where it's configured | `/etc/pam.d/...`, `optional` keyword | `/etc/pam.d/...`, `sufficient` keyword (Linux) — or install the Windows Credential Provider |
| Setup docs | [Wire up PAM, step 6](#6-wire-up-pam) | `linux-fingerprint-primary/README-fingerprint-primary.md` (Linux) / [Windows setup guide](#windows-setup-guide) |

**Why Windows can't offer true second-factor mode:** PAM's `optional` keyword works because PAM's own password-checking module runs independently in the same stack regardless of what this project's module does. A Windows Credential Provider has no such stack to defer to — it must hand LogonUI a complete, working credential to finish a logon, with no "phone said yes, now let Windows' own password module finish the job" handoff available. So on Windows, a phone success necessarily *is* the whole login. Full detail is in the [Windows setup guide](#windows-setup-guide).

No code changes are needed to switch Linux modes — `pam_unlock_helper.py` and `listener.py` are identical either way; only the PAM keyword changes. Use the scripts in `linux-fingerprint-primary/` to apply or revert this safely, with backups.

## Prerequisites

- A Linux laptop (PAM-based login — GDM, sudo, etc.) and/or a Windows laptop (Windows 10/11).
- Python 3.9+ and `pip`, on whichever platform(s) you're setting up.
- A smartphone (iOS or Android) able to run an Expo Go app, with Face ID / fingerprint already configured.
- [Node.js](https://nodejs.org/) and `npm` on a machine to build/run the Expo app (can be the same laptop).
- **Linux:** root/sudo access, for the PAM and firewall steps only — the listener itself never runs as root.
- **Windows:** Administrator access, for registering the Credential Provider; Visual Studio 2022 (Desktop development with C++ workload) and CMake, to build it.
- Optional but recommended on either platform: a [Tailscale](https://tailscale.com/) account, if you want unlock to work from outside your home Wi-Fi.

## Setup guide (Linux)

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

Add this as an **additional** line in `/etc/pam.d/gdm-password` or `/etc/pam.d/sudo`, placed **before** the file's normal `pam_unix.so` password line:

```
auth optional pam_exec.so /home/YOURUSER/remote-unlock/pam_unlock_helper.py
```

This is **second-factor mode**: `optional` means a phone success or failure never independently grants or denies login — your password is always checked regardless. This is the safe default and needs nothing else.

**Want fingerprint-primary mode instead** (phone success skips the password prompt; phone failure/timeout falls through to a normal password prompt)? Change only the keyword:

```
auth sufficient pam_exec.so /home/YOURUSER/remote-unlock/pam_unlock_helper.py
```

No changes to `pam_unlock_helper.py` or `listener.py` are needed for this — their exit-code contract (`0` = phone approved, `1` = anything else) already means exactly what `sufficient` needs. Use the safety scripts instead of hand-editing, so you get a backup and a lockout-safe test procedure:

```bash
chmod +x linux-fingerprint-primary/*.sh

# Apply to sudo first — safest place to test:
sudo ./linux-fingerprint-primary/apply_fingerprint_primary.sh /etc/pam.d/sudo

# Test in a SECOND terminal, without closing your current session:
sudo -k; sudo true

# Only once phone-success AND phone-failure-falls-back-to-password both
# work, apply the same change to your display manager:
sudo ./linux-fingerprint-primary/apply_fingerprint_primary.sh /etc/pam.d/gdm-password
```

To revert to second-factor mode at any time:

```bash
sudo ./linux-fingerprint-primary/revert_fingerprint_primary.sh /etc/pam.d/sudo
sudo ./linux-fingerprint-primary/revert_fingerprint_primary.sh /etc/pam.d/gdm-password
```

**Whichever mode you pick, never use `requisite`** — that would let a phone *failure* immediately deny login with no password fallback at all, which neither mode here is meant to do. Full tradeoffs and PAM-ordering rules are in `linux-fingerprint-primary/README-fingerprint-primary.md`.

### 7. Test before you rely on it

Run `listener.py` in a terminal (not yet as a service) and try an unlock from your phone:

1. First on the same Wi-Fi.
2. Then, if using Tailscale, with your phone switched entirely to cellular data, to confirm cross-network unlock actually works.

Watch the terminal output. Also confirm rejection works — cancel the phone's fingerprint prompt and verify the laptop reports a rejected attempt.

Only move to the systemd service and PAM wiring (steps 4 and 6) once both the success and rejection paths are confirmed working.

## Windows setup guide

Windows has no PAM. The equivalent hook is a **Credential Provider** — a native COM DLL, registered with Windows, that adds a tile to the lock and login screen *alongside*, never replacing, the built-in password tile.

**This is fingerprint-primary mode only** — see [Choosing a mode](#choosing-a-mode) for why a true always-require-password second factor isn't achievable with Windows' Credential Provider architecture. Concretely: a phone success submits your Windows password (captured once at pairing, encrypted at rest, decrypted only in memory) directly to LogonUI; a phone failure or timeout leaves the tile idle and you use the untouched password tile right next to it.

### 1. Install Python dependencies

```powershell
pip install cryptography websockets pywin32
```

### 2. Pair your phone and this laptop

```powershell
python windows\pair_windows.py
```

Same flow as Linux `pair.py`, plus one extra prompt for your Windows account password (needed for the reason above). Everything lands in `%LOCALAPPDATA%\remote-unlock\pairing.json`, ACLed to your account + SYSTEM only.

### 3. Build the Credential Provider

Requires Visual Studio 2022 (Desktop development with C++ workload) and CMake.

```powershell
cd windows\credential-provider
cmake -B build -A x64
cmake --build build --config Release
```

### 4. Register it (as Administrator)

```powershell
.\install.ps1
```

**Test on the lock screen first** (`Win+L`), not by signing out or rebooting, so you can immediately `Ctrl+Alt+Del` back to the password tile if anything's off. Only rely on it for real sign-outs/reboots once a lock-screen test has actually succeeded end to end.

### 5. Run the listener

```powershell
python windows\listener_windows.py
```

For it to survive logoff/lock (which is exactly when you need it), set it up in Task Scheduler:
- Trigger: **At log on** (your user)
- Action: `python.exe windows\listener_windows.py`
- Check **"Run whether user is logged on or not"** if you want it alive through a full lock screen, not just a session-switch

The same Tailscale advice from [step 3 of the Linux guide](#3-set-up-tailscale-optional-recommended) applies unchanged — nothing about that part is Windows-specific.

### Uninstalling / falling back to password-only

```powershell
cd windows\credential-provider
.\uninstall.ps1
```

This is the safety valve. It only removes the tile registration — it never touches your actual Windows account password, and you're back to exactly stock Windows login.

### Hardening notes (read before relying on this)

- **The named pipe currently uses a default security descriptor.** Before trusting this beyond testing, give `CreateNamedPipeW` in `windows/credential-provider/RemoteUnlockCredential.cpp` an explicit `SECURITY_ATTRIBUTES` / `SECURITY_DESCRIPTOR` restricting connections to your account SID + `SYSTEM` (`S-1-5-18`) only — otherwise another local account could in principle attempt to connect to the pipe while it's open.
- **Local admin can still read the encrypted password file** if they also compromise your passphrase — same caveat the Linux private key has.
- **A fully compromised OS (malware with admin) bypasses this exactly like it bypasses PAM** — never in scope for either platform.
- The DLL is unsigned. Production use means getting an Authenticode certificate and signing it; understand SmartScreen/Defender warnings before dismissing them, rather than disabling them blindly.
- Not yet tested against a live Windows lock screen end to end — confirm `CredPackAuthenticationBufferW`'s `COMPUTER\user` format matches your setup (switch `GetLocalComputerNameW()` in `RemoteUnlockCredential.cpp` to your domain name if this machine is domain-joined), and complete the lock-screen dry run in step 4 before trusting it further.

Full detail: `windows/README-Windows.md`.

## Mobile app setup

The `mobile-app/` folder is a working Expo app with a pairing screen and an unlock screen, wired to real cryptography (`src/crypto.js`, tested cross-compatible with the laptop's Python signing/verification) and biometric-gated key storage (`src/secureStore.js`, via `expo-secure-store`'s `requireAuthentication`). It's shared unchanged between the Linux and Windows setups.

### Install and run

```bash
cd mobile-app
npm install
npx expo start
```

Scan the QR code with the Expo Go app (iOS or Android) to run it on your phone. No App Store submission is needed — this is for your own device only.

### Pairing flow, in order

1. If you want cross-network unlock, set up Tailscale first (see [step 3](#3-set-up-tailscale-optional-recommended) above) — you'll need the IP before pairing.
2. On the laptop, run `python3 pair.py` (Linux) or `python windows\pair_windows.py` (Windows). When it asks for an IP, give it the Tailscale IP (`tailscale ip -4`) for cross-network use, or the plain LAN IP (e.g. `192.168.1.42`) for same-Wi-Fi-only use.
3. Pairing writes a CA certificate (`~/.config/remote-unlock/ca-cert.pem` on Linux, `%LOCALAPPDATA%\remote-unlock\cert.pem` on Windows). Transfer this file to your phone (AirDrop, email — it's a public certificate, not a secret) and install it as a trusted certificate:
   - **iOS:** open the file and follow the profile install prompt in Settings, then separately go to **Settings → General → About → Certificate Trust Settings** and enable full trust for it. iOS requires this second step for custom CAs.
   - **Android:** **Settings → Security → Encryption & credentials → Install a certificate → CA certificate.**
4. Open the app on your phone. On the pairing screen, generate a keypair — this also confirms Face ID / fingerprint is set up, since the app refuses to proceed without it — then paste the phone's printed public key into the laptop's pairing script when prompted.
5. The pairing script then prints the laptop's public key. Paste that into the app's pairing screen and save. Pairing is now complete on both sides.
6. On the unlock screen, enter the laptop's IP (Tailscale or LAN — matching what you gave the pairing script) and tap "Unlock my laptop" to test the full flow end to end. It's remembered after the first successful attempt.

### Range and notifications

- **Without Tailscale:** unlock only works while your phone and laptop share the same Wi-Fi (normal range, roughly 30–50m indoors). Off that network, the app simply times out — there's nothing internet-facing to reach.
- **With Tailscale:** unlock works from anywhere either device has internet access — home, mobile data, another country. The tunnel handles routing regardless of physical distance.
- **Push alerts always work anywhere**, independent of the above, since `notify.py` posts to `ntfy.sh` over the open internet. You'll only get an alert for an attempt that actually reached the listener, though — with Tailscale that includes attempts from anywhere; without it, only attempts from your own Wi-Fi, since nothing else could reach the listener in the first place.

### Why there's no certificate-pinning library in the app

A hand-rolled "pin this cert" check in app code is easy to write in a way that looks correct but silently verifies nothing — React Native's WebSocket doesn't expose per-connection certificate inspection without a native module. Installing the laptop's own CA as a trusted certificate on the phone sidesteps that entirely: it's the same mechanism your phone already uses to trust ordinary `https://` sites, just pointed at a CA you control instead of a public one. This has been verified end-to-end in testing: a real TLS handshake against the generated CA succeeds, and anything not signed by it is rejected.

## Re-pairing and revocation

**Linux:** if you lose the phone, suspect the passphrase leaked, or just want to rotate keys:

```bash
rm -rf ~/.config/remote-unlock/
python3 pair.py
```

**Windows:** the equivalent is:

```powershell
Remove-Item -Recurse -Force $env:LOCALAPPDATA\remote-unlock\
python windows\pair_windows.py
```

There's no separate "revoke" step needed on either platform — the old keys (and, on Windows, the old stored password) simply stop being accepted once the config that referenced them is gone.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `listener.py` / `listener_windows.py` exits immediately with "No TLS certificate configured" | Pairing hasn't been run yet, or `pairing.json` is missing/corrupted. Re-run `pair.py` (Linux) or `pair_windows.py` (Windows). |
| Listener fails to bind on startup | The IP it's trying to bind to (Tailscale or LAN) isn't currently assigned to the machine. If using Tailscale, confirm `tailscaled` is running (`sudo tailscale status` / Tailscale app status on Windows). If your LAN IP changed, set a static DHCP reservation or re-run pairing to reissue the cert for the new IP. |
| Phone times out trying to connect | Confirm phone and laptop are on the same Wi-Fi (non-Tailscale setup) or both connected to your tailnet (Tailscale setup). On Linux, check the firewall rule from [step 5](#5-scope-the-firewall) allows port 8765. |
| Phone connects but the unlock is always rejected | Re-check that the public keys pasted during pairing match exactly (no truncated lines). Also confirm your phone's clock is accurate — signatures include a timestamp and are rejected outside a small allowed skew. |
| **(Linux)** Login prompt just times out without ever asking for the phone | Confirm the `pam_exec.so` line was added to the correct file (`gdm-password`, `sudo`, etc.), that it comes before the `pam_unix.so` line, and that the path to `pam_unlock_helper.py` is correct and executable. |
| **(Linux)** Phone succeeds but you're still asked for your password | You're on second-factor (`optional`) mode — this is expected. Switch to `sufficient` via `linux-fingerprint-primary/apply_fingerprint_primary.sh` if you want phone success alone to be enough. |
| **(Windows)** Tile shows "Timed out — use your password" | `listener_windows.py` isn't running, or isn't running under your own account (check Task Scheduler). The tile has nothing to connect to otherwise. |
| **(Windows)** Tile doesn't appear on the lock screen at all | `install.ps1` wasn't run as Administrator, or `regsvr32` failed silently — re-run `regsvr32 %SystemRoot%\System32\RemoteUnlockCredentialProvider.dll` without `/s` to see the actual error. |
| No push notification arrives | Confirm you're subscribed to the exact `ntfy_topic` printed during pairing, in the ntfy app. Notification failures never block login — check the listener's logs for a "Notification failed" warning. |
| Passphrase prompt appears every time you `sudo` | That's expected if you're running the listener manually in a terminal each boot — it decrypts secrets into memory once at service startup, not on every unlock attempt. Move to the systemd service ([step 4](#4-install-the-systemd-service)) or Task Scheduler so it only asks once per boot. |

## FAQ

**Does this replace my password?**
On Linux, only if you choose fingerprint-primary (`sufficient`) mode — by default it's wired in as `optional`, an additional path, not a replacement. On Windows, yes: a phone success submits your Windows password on your behalf, with no separate prompt — see [Choosing a mode](#choosing-a-mode) for why Windows can't offer the `optional` guarantee.

**What happens if my phone is offline or dead?**
Your normal password login still works exactly as before, on both platforms and in both modes — this is purely additive, never a lockout risk by itself.

**Does anything get written to disk during normal unlock attempts?**
No. The listener reads `pairing.json` once at startup and otherwise only touches a Unix domain socket in `/run` (Linux, tmpfs, RAM-backed) or a named pipe (Windows, not disk-backed at all). The only files ever written are the one-time outputs of pairing.

**Can I run both Linux and Windows Credential Provider setups from one pairing?**
No — pair separately per machine. Each device gets its own laptop keypair, TLS cert, and (on Windows) encrypted password, all stored locally to that machine.

**Which mode should I actually pick?**
If you want a hard guarantee that your password is always checked, use Linux with `optional` (the default). If your priority is speed/convenience and you're comfortable that phone-key compromise becomes full account compromise, use fingerprint-primary on either platform. See the comparison table in [Choosing a mode](#choosing-a-mode).

## Limitations

This project does **not** protect against:

- A fully compromised laptop OS — malware running with root/admin can bypass this entirely, independent of anything this project does.
- A compromised or jailbroken phone with the private key physically extracted from its secure enclave via a hardware exploit.
- (Fingerprint-primary mode, either platform) a stolen or cloned phone key on its own — that's the explicit tradeoff of the mode, see [Choosing a mode](#choosing-a-mode).
- (Windows) an unsigned DLL being flagged or blocked by SmartScreen/Defender in stricter environments — signing it yourself is on you for now.

Use full-disk encryption (LUKS / BitLocker / FileVault) and keep your phone's OS updated regardless of whether you use this project — those are the layers that address the risks above.

## License

MIT — see [LICENSE](LICENSE).
