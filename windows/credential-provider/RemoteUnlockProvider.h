#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include "RemoteUnlockCredential.h"

// ICredentialProvider: the factory-ish object LogonUI talks to first.
// We only ever expose ONE credential (the phone tile). We do NOT set
// CPUS_CREDUI-exclusive flags and we do NOT return
// CPE_FLAGS_HIDE_OTHER_CREDENTIALS from GetProviderFieldDescriptorCount /
// GetCredentialCount — deliberately, so Windows' own password provider
// keeps rendering next to ours. That's what makes the password a
// fallback instead of this being a hard replacement.
class CRemoteUnlockProvider : public ICredentialProvider
{
public:
    CRemoteUnlockProvider();
    ~CRemoteUnlockProvider();

    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);

    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc);

private:
    LONG _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    CRemoteUnlockCredential* _pCredential;
};
