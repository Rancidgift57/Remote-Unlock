#include <windows.h>
#include <credentialprovider.h>
#include <strsafe.h>
#include "Guid.h"
#include "ClassFactory.h"

HINSTANCE g_hinst = nullptr;
LONG g_cRefModule = 0;
LONG g_cLocks = 0;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) g_hinst = hModule;
    return TRUE;
}

STDAPI DllCanUnloadNow()
{
    return (g_cRefModule == 0 && g_cLocks == 0) ? S_OK : S_FALSE;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    *ppv = nullptr;
    if (rclsid != CLSID_RemoteUnlockProvider) return CLASS_E_CLASSNOTAVAILABLE;

    CClassFactory* pcf = new(std::nothrow) CClassFactory();
    if (!pcf) return E_OUTOFMEMORY;

    HRESULT hr = pcf->QueryInterface(riid, ppv);
    pcf->Release();
    return hr;
}

// ---- Self registration -----------------------------------------------
// Registers this DLL both as a normal in-proc COM server (HKCR\CLSID\...)
// and, separately, under the OS's list of active Credential Providers
// (HKLM\...\Credential Providers\{CLSID}). Both keys are required —
// the first lets COM instantiate the object at all, the second is what
// tells LogonUI to actually load it as a tile provider.
//
// This does NOT touch the built-in password provider's registration in
// any way, and does not set any "exclusive"/hide-other-providers policy
// key. That silence is intentional — see RemoteUnlockProvider.h.

static const wchar_t* CLSID_STR = L"{8F1E2B3C-6A4D-4E7F-9C2B-1A3D5E7F9B0C}";
static const wchar_t* PROVIDER_NAME = L"Remote-Unlock Phone Credential Provider";

static HRESULT SetRegKeyValue(HKEY root, PCWSTR subkey, PCWSTR valueName, PCWSTR data)
{
    HKEY hKey;
    LONG res = RegCreateKeyExW(root, subkey, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr);
    if (res != ERROR_SUCCESS) return HRESULT_FROM_WIN32(res);
    res = RegSetValueExW(hKey, valueName, 0, REG_SZ, (const BYTE*)data,
                          (DWORD)((wcslen(data) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    return HRESULT_FROM_WIN32(res);
}

STDAPI DllRegisterServer()
{
    wchar_t modulePath[MAX_PATH];
    GetModuleFileNameW(g_hinst, modulePath, ARRAYSIZE(modulePath));

    wchar_t clsidKey[128];
    StringCchPrintfW(clsidKey, ARRAYSIZE(clsidKey), L"CLSID\\%s", CLSID_STR);
    wchar_t inprocKey[160];
    StringCchPrintfW(inprocKey, ARRAYSIZE(inprocKey), L"CLSID\\%s\\InProcServer32", CLSID_STR);

    HRESULT hr = SetRegKeyValue(HKEY_CLASSES_ROOT, clsidKey, nullptr, PROVIDER_NAME);
    if (FAILED(hr)) return hr;
    hr = SetRegKeyValue(HKEY_CLASSES_ROOT, inprocKey, nullptr, modulePath);
    if (FAILED(hr)) return hr;
    hr = SetRegKeyValue(HKEY_CLASSES_ROOT, inprocKey, L"ThreadingModel", L"Apartment");
    if (FAILED(hr)) return hr;

    wchar_t cpKey[256];
    StringCchPrintfW(cpKey, ARRAYSIZE(cpKey),
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s",
        CLSID_STR);
    return SetRegKeyValue(HKEY_LOCAL_MACHINE, cpKey, nullptr, PROVIDER_NAME);
}

STDAPI DllUnregisterServer()
{
    wchar_t clsidKey[128];
    StringCchPrintfW(clsidKey, ARRAYSIZE(clsidKey), L"CLSID\\%s", CLSID_STR);
    RegDeleteTreeW(HKEY_CLASSES_ROOT, clsidKey);

    wchar_t cpKey[256];
    StringCchPrintfW(cpKey, ARRAYSIZE(cpKey),
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\%s",
        CLSID_STR);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, cpKey);
    return S_OK;
}
