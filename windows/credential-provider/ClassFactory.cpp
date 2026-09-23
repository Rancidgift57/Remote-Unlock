#include "ClassFactory.h"
#include "RemoteUnlockProvider.h"

extern LONG g_cLocks;   // declared in DllMain.cpp

IFACEMETHODIMP CClassFactory::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv)
{
    *ppv = nullptr;
    if (pUnkOuter) return CLASS_E_NOAGGREGATION;

    CRemoteUnlockProvider* pProvider = new(std::nothrow) CRemoteUnlockProvider();
    if (!pProvider) return E_OUTOFMEMORY;

    HRESULT hr = pProvider->QueryInterface(riid, ppv);
    pProvider->Release();
    return hr;
}

IFACEMETHODIMP CClassFactory::LockServer(BOOL bLock)
{
    if (bLock) InterlockedIncrement(&g_cLocks);
    else InterlockedDecrement(&g_cLocks);
    return S_OK;
}
