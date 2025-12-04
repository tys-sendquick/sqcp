#pragma once

#include <windows.h>
#include <credentialprovider.h>
#include <new>
#include <shlwapi.h>
#include <unknwn.h>
#include "dll.h"

// Credential Provider filter implementation declaration.
class CSampleProviderFilter : public ICredentialProviderFilter
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = InterlockedDecrement(&_cRef);
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void **ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CSampleProviderFilter, ICredentialProviderFilter), // IID_ICredentialProviderFilter
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

public:
    // ICredentialProviderFilter
    IFACEMETHODIMP Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                         DWORD dwFlags,
                         GUID *rgclsidProviders,
                         BOOL *rgbAllow,
                         DWORD cProviders);

    IFACEMETHODIMP UpdateRemoteCredential(_In_ const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsIn,
                                          _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsOut);

    friend HRESULT CSampleFilter_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv);

protected:
    CSampleProviderFilter() :
        _cRef(1)
    {
        DllAddRef();
    }

    virtual ~CSampleProviderFilter()
    {
        DllRelease();
    }

private:
    long _cRef;
};

// Boilerplate factory helper.
inline HRESULT CSampleFilter_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv)
{
    HRESULT hr;
    CSampleProviderFilter *pProviderFilter = new(std::nothrow) CSampleProviderFilter();

    if (pProviderFilter)
    {
        hr = pProviderFilter->QueryInterface(riid, ppv);
        pProviderFilter->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}
