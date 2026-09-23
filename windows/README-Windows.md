# Remote-Unlock for Windows

A Windows port of [Remote-Unlock](https://github.com/Rancidgift57/Remote-Unlock).
Same phone, same crypto, same pairing model — the login hook is rebuilt
for Windows because Windows has no PAM.

## How this differs from the Linux/PAM version

| | Linux (original) | Windows (this) |
|---|---|---|
| Login hook | `pam_exec.so` line in `/etc/pam.d/*` | A native **Credential Provider** COM DLL registered with Windows |
| Signal to the login screen | Unix domain socket in `/run` (tmpfs) | Named pipe (`\\.\pipe\remote-unlock-signal`) |
| What gets signaled | pass/fail byte only — your real password is handled separately by PAM's own stack | pass/fail **plus** your Windows password, because Windows has no equivalent stack to hand off to |
| Fallback to password | `optional` (not `sufficient`) in the PAM stack | The built-in Windows password tile is simply never hidden — both tiles sit side by side |

**The behavior you asked for — fingerprint as the lock, password as the
fallback if fingerprint fails — is what this already does, by default,
with no extra flag to set.** The Credential Provider adds one tile.
It never disables, hides, or overrides Windows' own password tile. If
your phone confirms, our tile submits your credential and you're in.
If it fails or times out, our tile just goes idle with a status message
— you click the password tile right next to it, same screen, no reboot,
no config change.

## Why your Windows password has to be stored (encrypted) at all

This is the one real architectural difference from Linux worth
understanding before you install it, not after:

PAM's `optional` keyword works because PAM's *own* password-checking
module runs independently, in the same stack, regardless of what our
module does. Windows Credential Providers don't sit inside a stack like
that — each one must independently hand LogonUI a **complete, working
credential** to finish a logon. There is no "phone said yes, now let
Windows' password module finish the job" handoff available to a
third-party provider.

So the only two honest options are:
1. Store your Windows password, encrypted at rest, unlocked only by the
   same passphrase that already protects your ECDSA private key
   (this build), or
2. Don't build a real unlock path at all, and just have the tile do
   nothing after "success" (not what you asked for).

This is the same trust model Windows Hello / USB fingerprint readers use
under the hood — they also keep a protected credential that biometric
success releases. `pair_windows.py` encrypts it with scrypt + Fernet,
exactly like the Linux build's private-key passphrase, and it's
decrypted only in `listener_windows.py`'s own memory, for the few
milliseconds it takes to relay it down the pipe on a successful phone
tap. It is never written to disk unencrypted.

## Setup

### 1. Install Python dependencies

```powershell
pip install cryptography websockets pywin32
```

### 2. Pair your phone and this laptop

```powershell
python pair_windows.py
```

Same flow as the Linux `pair.py`, plus one extra prompt for your Windows
account password. Everything lands in
`%LOCALAPPDATA%\remote-unlock\pairing.json`, ACLed to your account + SYSTEM.

### 3. Build the Credential Provider

Requires Visual Studio 2022 (Desktop development with C++ workload) and
CMake.

```powershell
cd credential-provider
cmake -B build -A x64
cmake --build build --config Release
```

### 4. Register it (as Administrator)

```powershell
.\install.ps1
```

**Test on the lock screen first** (`Win+L`), not by signing out or
rebooting, so you can immediately `Ctrl+Alt+Del` back to the password
tile if anything's off. Only rely on it for real once a lock-screen test
has actually succeeded end to end.

### 5. Run the listener

```powershell
python listener_windows.py
```

For it to survive logoff/lock (which is exactly when you need it),
set it up in Task Scheduler:
- Trigger: **At log on** (your user)
- Action: `python.exe listener_windows.py`
- Check **"Run whether user is logged on or not"** if you want it alive
  through a full lock screen, not just a session-switch

Same Tailscale-for-cross-network-unlock advice from the main README
applies unchanged — nothing about that part is Windows-specific.

## Uninstalling / falling back to password-only

```powershell
cd credential-provider
.\uninstall.ps1
```

This is the safety valve. It only removes the tile registration — it
never touches your actual Windows account password, and you're back to
exactly stock Windows login.

## Hardening notes (read before relying on this)

- **The named pipe currently uses a default security descriptor.**
  Before trusting this beyond testing, give `CreateNamedPipeW` in
  `RemoteUnlockCredential.cpp` an explicit `SECURITY_ATTRIBUTES` /
  `SECURITY_DESCRIPTOR` restricting connections to your account SID +
  `SYSTEM` (`S-1-5-18`) only — otherwise another local account could in
  principle attempt to connect to the pipe while it's open. The
  `_pipe_security_attributes`-style ACL shown in the Python listener is
  the pattern to mirror in C++; flagged here rather than silently shipped
  as "done," matching how the original README treats every mitigation as
  a named, specific one rather than a blanket "secure" claim.
- **Local admin can still read the DPAPI/Fernet-encrypted password file**
  if they also compromise your passphrase — same caveat the Linux
  version states for its private key.
- **A fully compromised OS (malware with admin) bypasses this exactly
  like it bypasses PAM** — this was never in scope for either platform.
- Treat the Credential Provider like any other native Windows component
  that runs during logon: keep the source auditable, and don't disable
  Windows Defender / SmartScreen warnings about an unsigned, unfamiliar
  DLL without understanding why they're appearing (this build is
  unsigned; production use would mean getting an Authenticode
  certificate and signing the DLL).

## What's unfinished / needs your testing

I can't compile or run this against a real Windows lock screen from here
— I don't have a Windows environment in this session. Before relying on
it:
- Build it, and check for compile errors specific to your Windows SDK
  version (COM interface signatures have shifted slightly across SDK
  releases in the past).
- Confirm `CredPackAuthenticationBufferW` accepts the `COMPUTER\user`
  format for your setup — if this laptop is domain-joined rather than a
  local account, change `GetLocalComputerNameW()` in
  `RemoteUnlockCredential.cpp` to use your domain name instead.
- Do the lock-screen dry run in step 4 above before trusting it on a
  real sign-out or reboot.
