#pragma once
#include <initguid.h>

// CLSID for the Remote-Unlock credential provider.
// Generated once for this project — do not reuse elsewhere, and do not
// regenerate unless you're intentionally re-registering from scratch,
// since re-registration under a new GUID orphans the old registry entry.
// {8F1E2B3C-6A4D-4E7F-9C2B-1A3D5E7F9B0C}
DEFINE_GUID(CLSID_RemoteUnlockProvider,
    0x8f1e2b3c, 0x6a4d, 0x4e7f, 0x9c, 0x2b, 0x1a, 0x3d, 0x5e, 0x7f, 0x9b, 0x0c);

#define REMOTEUNLOCK_PIPE_NAME  L"\\\\.\\pipe\\remote-unlock-signal"
#define REMOTEUNLOCK_WAIT_TIMEOUT_MS  15000   // matches WAIT_TIMEOUT in the Linux/Windows listener
