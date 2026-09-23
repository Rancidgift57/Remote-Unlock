#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include <string>
#include <thread>
#include <atomic>

// Field layout for our single tile.
enum FIELD_ID {
    FID_TILE_IMAGE = 0,
    FID_LABEL,               // "Remote-Unlock"
    FID_STATUS,               // "Waiting for phone..." / "Rejected" / "Timed out"
    FID_SUBMIT_BUTTON,
    FID_NUM_FIELDS
};

// ICredentialProviderCredential for the "phone fingerprint" tile.
//
// Behavior summary (this is the "fingerprint = lock, password = fallback"
// contract the user asked for):
//   - When this tile is selected, it opens the named pipe and waits (with
//     a visible "Waiting for phone..." status) for listener_windows.py to
//     relay a phone result.
//   - Success -> the Windows password captured at pairing time is handed
//     to LogonUI as a completed credential; the user is logged in without
//     ever typing anything.
//   - Failure or timeout -> this tile reports an error and goes idle.
//     It does NOT lock the user out or disable anything else: Windows'
//     own built-in password tile is still sitting right next to this one,
//     untouched, and the user can just click it. That's the fallback —
//     enforced by the OS's normal multi-tile behavior, not by any code
//     in this file.
class CRemoteUnlockCredential : public ICredentialProviderCredential
{
public:
    CRemoteUnlockCredential();
    ~CRemoteUnlockCredential();

    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
        CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus);

private:
    void WaitForPhoneOnBackgroundThread();
    void UpdateStatus(PCWSTR text);
    HRESULT BuildKerbCredential(PCWSTR password, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);

    LONG _cRef;
    ICredentialProviderCredentialEvents* _pCredProvCredentialEvents;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;

    std::wstring _statusText;
    std::thread _waitThread;
    std::atomic<bool> _waiting;
    std::atomic<bool> _phoneApproved;
    std::atomic<bool> _phoneFailed;
    std::wstring _relayedPassword;   // cleared immediately after use, see .cpp

    CRITICAL_SECTION _lock;
};
