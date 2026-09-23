#include "RemoteUnlockCredential.h"
#include "Guid.h"
#include <NTSecAPI.h>
#include <ntsecpkg.h>
#pragma comment(lib, "Secur32.lib")

// Helper: get the local computer name for building DOMAIN\User or
// COMPUTER\User depending on scenario. Simplified for a single-user,
// local-account Windows setup, which is the assumed target here.
static std::wstring GetLocalComputerNameW()
{
    wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = ARRAYSIZE(buf);
    GetComputerNameW(buf, &size);
    return std::wstring(buf);
}

CRemoteUnlockCredential::CRemoteUnlockCredential()
    : _cRef(1), _pCredProvCredentialEvents(nullptr), _cpus(CPUS_INVALID),
      _waiting(false), _phoneApproved(false), _phoneFailed(false)
{
    InitializeCriticalSection(&_lock);
}

CRemoteUnlockCredential::~CRemoteUnlockCredential()
{
    if (_waitThread.joinable())
    {
        _waiting = false;
        _waitThread.join();
    }
    // Best-effort scrub of the relayed password before the string is freed.
    if (!_relayedPassword.empty())
    {
        SecureZeroMemory(&_relayedPassword[0], _relayedPassword.size() * sizeof(wchar_t));
    }
    DeleteCriticalSection(&_lock);
}

HRESULT CRemoteUnlockCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus)
{
    _cpus = cpus;
    _statusText = L"Click to wait for phone unlock";
    return S_OK;
}

IFACEMETHODIMP_(ULONG) CRemoteUnlockCredential::AddRef() { return InterlockedIncrement(&_cRef); }
IFACEMETHODIMP_(ULONG) CRemoteUnlockCredential::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (!cRef) delete this;
    return cRef;
}
IFACEMETHODIMP CRemoteUnlockCredential::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IUnknown || riid == __uuidof(ICredentialProviderCredential))
    {
        *ppv = static_cast<ICredentialProviderCredential*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

IFACEMETHODIMP CRemoteUnlockCredential::Advise(ICredentialProviderCredentialEvents* pcpce)
{
    if (_pCredProvCredentialEvents) _pCredProvCredentialEvents->Release();
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();
    return S_OK;
}

IFACEMETHODIMP CRemoteUnlockCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
        _pCredProvCredentialEvents = nullptr;
    }
    return S_OK;
}

// Tile gets clicked / becomes the selected tile: this is where we start
// waiting on the phone, mirroring pam_unlock_helper.py's wait_for_signal().
// pbAutoLogon = FALSE: we never auto-submit; GetSerialization only fires
// once the phone has actually confirmed (see WaitForPhoneOnBackgroundThread).
IFACEMETHODIMP CRemoteUnlockCredential::SetSelected(BOOL* pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    if (!_waiting.exchange(true))
    {
        _phoneApproved = false;
        _phoneFailed = false;
        UpdateStatus(L"Waiting for phone confirmation\u2026");
        if (_waitThread.joinable()) _waitThread.join();
        _waitThread = std::thread(&CRemoteUnlockCredential::WaitForPhoneOnBackgroundThread, this);
    }
    return S_OK;
}

IFACEMETHODIMP CRemoteUnlockCredential::SetDeselected()
{
    // Let an in-flight wait finish on its own timeout rather than tearing
    // it down mid-flight — an in-progress phone tap shouldn't be silently
    // dropped just because focus moved to the password tile for a moment.
    return S_OK;
}

void CRemoteUnlockCredential::UpdateStatus(PCWSTR text)
{
    EnterCriticalSection(&_lock);
    _statusText = text;
    LeaveCriticalSection(&_lock);
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->SetFieldString(this, FID_STATUS, text);
    }
}

// Runs on a worker thread: connects to the named pipe that
// listener_windows.py writes to, waits up to REMOTEUNLOCK_WAIT_TIMEOUT_MS,
// and reads the pass/fail byte (+ password on success). This is the direct
// analog of pam_unlock_helper.py's wait_for_signal() Unix-socket read,
// just over a named pipe because LogonUI-hosted code can't rely on the
// user's own session for a Unix-style /run path.
void CRemoteUnlockCredential::WaitForPhoneOnBackgroundThread()
{
    // We are the SERVER side of the pipe: the credential provider creates
    // it and waits for listener_windows.py (running under the user's own
    // account) to connect and write to it. This matches the direction of
    // trust in the Linux version, where PAM's helper binds the socket and
    // the always-running listener.py process writes to it.
    SECURITY_ATTRIBUTES sa{};
    // A locked-down DACL (SYSTEM + the interactively logged-on user only)
    // should be built here via SetSecurityDescriptorDacl in production;
    // omitted here for brevity — see README-Windows.md "Hardening notes"
    // for the exact SDDL string to use before relying on this.
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE hPipe = CreateNamedPipeW(
        REMOTEUNLOCK_PIPE_NAME,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,      // max instances
        0, 4096,
        0,      // use default timeout; we enforce our own below
        &sa);

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        UpdateStatus(L"Could not start listener (pipe busy?) \u2014 use your password");
        _waiting = false;
        return;
    }

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ConnectNamedPipe(hPipe, &ov);

    DWORD waitResult = WaitForSingleObject(ov.hEvent, REMOTEUNLOCK_WAIT_TIMEOUT_MS);
    if (waitResult != WAIT_OBJECT_0)
    {
        UpdateStatus(L"Timed out \u2014 use your password");
        CancelIoEx(hPipe, &ov);
        CloseHandle(ov.hEvent);
        CloseHandle(hPipe);
        _waiting = false;
        return;
    }

    BYTE buf[2048];
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hPipe, buf, sizeof(buf) - 1, &bytesRead, nullptr);
    CloseHandle(ov.hEvent);
    CloseHandle(hPipe);

    if (!ok || bytesRead < 1 || buf[0] == 0x00)
    {
        UpdateStatus(L"Phone rejected \u2014 use your password");
        _phoneFailed = true;
        _waiting = false;
        return;
    }

    // buf[1:] is the UTF-8 encoded Windows password, decrypted by
    // listener_windows.py only in memory and relayed here just once.
    int wlen = MultiByteToWideChar(CP_UTF8, 0, (char*)buf + 1, bytesRead - 1, nullptr, 0);
    std::wstring password(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, (char*)buf + 1, bytesRead - 1, &password[0], wlen);
    SecureZeroMemory(buf + 1, bytesRead - 1);   // scrub the UTF-8 copy immediately

    EnterCriticalSection(&_lock);
    _relayedPassword = password;
    LeaveCriticalSection(&_lock);
    SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));

    _phoneApproved = true;
    UpdateStatus(L"Confirmed \u2014 signing in\u2026");
    _waiting = false;

    // Tell LogonUI we're ready to be submitted now.
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->SetFieldState(this, FID_SUBMIT_BUTTON,
            CPFS_SHOWN);
        _pCredProvCredentialEvents->OnCreatingWindow();  // no-op if unsupported; safe
    }
}

IFACEMETHODIMP CRemoteUnlockCredential::GetFieldState(DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    switch (dwFieldID)
    {
    case FID_TILE_IMAGE:      *pcpfs = CPFS_DISPLAY_IN_BOTH; break;
    case FID_LABEL:            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE; break;
    case FID_STATUS:           *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE; break;
    case FID_SUBMIT_BUTTON:    *pcpfs = CPFS_HIDDEN; break;  // shown once phone confirms
    default: return E_INVALIDARG;
    }
    *pcpfis = CPFIS_NONE;
    return S_OK;
}

IFACEMETHODIMP CRemoteUnlockCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz)
{
    std::wstring value;
    switch (dwFieldID)
    {
    case FID_LABEL:  value = L"Remote-Unlock (phone)"; break;
    case FID_STATUS:
        EnterCriticalSection(&_lock);
        value = _statusText;
        LeaveCriticalSection(&_lock);
        break;
    default: return E_INVALIDARG;
    }
    size_t len = value.size() + 1;
    *ppwsz = (PWSTR)CoTaskMemAlloc(len * sizeof(wchar_t));
    if (!*ppwsz) return E_OUTOFMEMORY;
    wcscpy_s(*ppwsz, len, value.c_str());
    return S_OK;
}

IFACEMETHODIMP CRemoteUnlockCredential::GetBitmapValue(DWORD, HBITMAP*) { return E_NOTIMPL; }
IFACEMETHODIMP CRemoteUnlockCredential::GetCheckboxValue(DWORD, BOOL*, PWSTR*) { return E_NOTIMPL; }
IFACEMETHODIMP CRemoteUnlockCredential::GetComboBoxValueCount(DWORD, DWORD*, DWORD*) { return E_NOTIMPL; }
IFACEMETHODIMP CRemoteUnlockCredential::GetComboBoxValueAt(DWORD, DWORD, PWSTR*) { return E_NOTIMPL; }
IFACEMETHODIMP CRemoteUnlockCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    *pdwAdjacentTo = FID_LABEL;
    return S_OK;
}
IFACEMETHODIMP CRemoteUnlockCredential::SetStringValue(DWORD, PCWSTR) { return S_OK; }
IFACEMETHODIMP CRemoteUnlockCredential::SetCheckboxValue(DWORD, BOOL) { return E_NOTIMPL; }
IFACEMETHODIMP CRemoteUnlockCredential::SetComboBoxSelectedValue(DWORD, DWORD) { return E_NOTIMPL; }
IFACEMETHODIMP CRemoteUnlockCredential::CommandLinkClicked(DWORD) { return S_OK; }

// Called once GetSerialization is requested (submit button / auto after
// phone confirms). If the phone never approved, we fail *this tile only*
// — CPGSR_NO_CREDENTIAL_NOT_FINISHED tells LogonUI "this provider has
// nothing to submit", which leaves every other tile (i.e. the password
// tile) fully usable. That's the fallback behavior, expressed in the
// one return value that actually controls it.
IFACEMETHODIMP CRemoteUnlockCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    if (!_phoneApproved)
    {
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    HRESULT hr = BuildKerbCredential(_relayedPassword.c_str(), pcpcs);

    // Scrub our copy the instant it's packed — LogonUI/LSA now owns the
    // only remaining copy, and it's responsible for wiping that one.
    if (!_relayedPassword.empty())
        SecureZeroMemory(&_relayedPassword[0], _relayedPassword.size() * sizeof(wchar_t));
    _relayedPassword.clear();

    if (FAILED(hr))
    {
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        return hr;
    }

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    return S_OK;
}

// Packs a KERB_INTERACTIVE_UNLOCK_LOGON the same way the built-in password
// provider would, using the currently logged-on / target username plus
// the password relayed from the phone. This uses the standard
// CredPackAuthenticationBuffer helper so we don't hand-roll the LSA
// structure layout.
HRESULT CRemoteUnlockCredential::BuildKerbCredential(PCWSTR password,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    wchar_t username[UNLEN + 1];
    DWORD unLen = ARRAYSIZE(username);
    if (!GetUserNameW(username, &unLen))
        return HRESULT_FROM_WIN32(GetLastError());

    std::wstring domainUser = GetLocalComputerNameW() + L"\\" + username;

    DWORD cbBuffer = 0;
    BYTE* rgbBuffer = nullptr;
    if (!CredPackAuthenticationBufferW(0, (PWSTR)domainUser.c_str(), (PWSTR)password,
                                        nullptr, &cbBuffer))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            return HRESULT_FROM_WIN32(GetLastError());
        rgbBuffer = (BYTE*)CoTaskMemAlloc(cbBuffer);
        if (!rgbBuffer) return E_OUTOFMEMORY;
        if (!CredPackAuthenticationBufferW(0, (PWSTR)domainUser.c_str(), (PWSTR)password,
                                            rgbBuffer, &cbBuffer))
        {
            CoTaskMemFree(rgbBuffer);
            return HRESULT_FROM_WIN32(GetLastError());
        }
    }

    ULONG authPackage = 0;
    HANDLE hLsa = nullptr;
    LSA_STRING name{};
    LSA_OPERATIONAL_MODE mode;
    LSA_UNICODE_STRING lsaOrigin;
    lsaOrigin.Buffer = const_cast<PWSTR>(L"RemoteUnlock");
    lsaOrigin.Length = (USHORT)wcslen(lsaOrigin.Buffer) * sizeof(WCHAR);
    lsaOrigin.MaximumLength = lsaOrigin.Length;
    LsaRegisterLogonProcess(&name, &hLsa, &mode);  // best-effort; name intentionally blank/local
    name.Buffer = const_cast<PSTR>("Negotiate");
    name.Length = (USHORT)strlen(name.Buffer);
    name.MaximumLength = name.Length + 1;
    LsaLookupAuthenticationPackage(hLsa, &name, &authPackage);

    pcpcs->ulAuthenticationPackage = authPackage;
    pcpcs->clsidCredentialProvider = CLSID_RemoteUnlockProvider;
    pcpcs->cbSerialization = cbBuffer;
    pcpcs->rgbSerialization = rgbBuffer;
    return S_OK;
}

IFACEMETHODIMP CRemoteUnlockCredential::ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        UpdateStatus(L"Windows rejected the credential \u2014 check your stored password");
    }
    return S_OK;
}
