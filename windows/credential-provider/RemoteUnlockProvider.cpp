#include "RemoteUnlockProvider.h"

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_fieldDescriptors[] =
{
    { FID_TILE_IMAGE,   CPFT_TILE_IMAGE,    L"Image" },
    { FID_LABEL,        CPFT_LARGE_TEXT,    L"Remote-Unlock" },
    { FID_STATUS,       CPFT_SMALL_TEXT,    L"Status" },
    { FID_SUBMIT_BUTTON,CPFT_SUBMIT_BUTTON, L"Submit" },
};
static_assert(ARRAYSIZE(s_fieldDescriptors) == FID_NUM_FIELDS, "field table out of sync with FIELD_ID");

CRemoteUnlockProvider::CRemoteUnlockProvider()
    : _cRef(1), _cpus(CPUS_INVALID), _pCredential(nullptr)
{
}

CRemoteUnlockProvider::~CRemoteUnlockProvider()
{
    if (_pCredential) _pCredential->Release();
}

IFACEMETHODIMP_(ULONG) CRemoteUnlockProvider::AddRef() { return InterlockedIncrement(&_cRef); }
IFACEMETHODIMP_(ULONG) CRemoteUnlockProvider::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (!cRef) delete this;
    return cRef;
}
IFACEMETHODIMP CRemoteUnlockProvider::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IUnknown || riid == __uuidof(ICredentialProvider))
    {
        *ppv = static_cast<ICredentialProvider*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

// We only make sense for interactive logon and workstation unlock — not
// CPUS_CREDUI (e.g. "Run as") and not CPUS_CHANGE_PASSWORD, where a phone
// tap can't supply what's actually being asked for.
IFACEMETHODIMP CRemoteUnlockProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD)
{
    _cpus = cpus;
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        return S_OK;
    default:
        return E_NOTIMPL;
    }
}

IFACEMETHODIMP CRemoteUnlockProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*)
{
    return E_NOTIMPL;
}

IFACEMETHODIMP CRemoteUnlockProvider::Advise(ICredentialProviderEvents*, UINT_PTR) { return S_OK; }
IFACEMETHODIMP CRemoteUnlockProvider::UnAdvise() { return S_OK; }

IFACEMETHODIMP CRemoteUnlockProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
    *pdwCount = FID_NUM_FIELDS;
    return S_OK;
}

IFACEMETHODIMP CRemoteUnlockProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    if (dwIndex >= FID_NUM_FIELDS) return E_INVALIDARG;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd =
        (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
    if (!pcpfd) return E_OUTOFMEMORY;
    *pcpfd = s_fieldDescriptors[dwIndex];
    size_t len = wcslen(s_fieldDescriptors[dwIndex].pszLabel) + 1;
    pcpfd->pszLabel = (PWSTR)CoTaskMemAlloc(len * sizeof(wchar_t));
    wcscpy_s(pcpfd->pszLabel, len, s_fieldDescriptors[dwIndex].pszLabel);
    *ppcpfd = pcpfd;
    return S_OK;
}

// Exactly one credential (our tile). pdwDefault / pbAutoLogonWithDefault
// both say "don't auto-pick us" — the OS decides tile order/default
// itself, typically remembering whichever tile you used last, which is
// exactly the multi-tile UX we want (no forced fingerprint-first).
IFACEMETHODIMP CRemoteUnlockProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault)
{
    *pdwCount = 1;
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;
    return S_OK;
}

IFACEMETHODIMP CRemoteUnlockProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc)
{
    if (dwIndex != 0) return E_INVALIDARG;
    if (!_pCredential)
    {
        _pCredential = new(std::nothrow) CRemoteUnlockCredential();
        if (!_pCredential) return E_OUTOFMEMORY;
        HRESULT hr = _pCredential->Initialize(_cpus);
        if (FAILED(hr)) { _pCredential->Release(); _pCredential = nullptr; return hr; }
    }
    return _pCredential->QueryInterface(IID_PPV_ARGS(ppcpc));
}
