//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// Standard dll required functions and class factory implementation.

#include <windows.h>
#include <unknwn.h>
#include "Dll.h"
#include "helpers.h"
#include "CSampleProviderFilter.h"

static long g_cRef = 0;   // global dll reference count
HINSTANCE g_hinst = NULL; // global dll hinstance

extern HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv);
extern HRESULT CSampleFilter_CreateInstance(__in REFIID riid, __deref_out void** ppv);
EXTERN_C GUID CLSID_CSample;
EXTERN_C GUID CLSID_CSampleFilter;

class CClassFactory : public IClassFactory
{
public:
    typedef HRESULT (*PFNCREATEINSTANCE)(__in REFIID riid, __deref_out void **ppv);

    CClassFactory(PFNCREATEINSTANCE pfnCreate) :
        _cRef(1),
        _pfnCreate(pfnCreate)
    {
    }

    // IUnknown
    IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void **ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CClassFactory, IClassFactory),
            { 0 },
        };
        return QISearch(this, qit, riid, ppv);
    }

    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return InterlockedIncrement(&_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = InterlockedDecrement(&_cRef);
        if (!cRef)
            delete this;
        return cRef;
    }

    // IClassFactory
    IFACEMETHODIMP CreateInstance(__in IUnknown* pUnkOuter, __in REFIID riid, __deref_out void **ppv)
    {
        HRESULT hr;
        if (!pUnkOuter)
        {
            hr = _pfnCreate ? _pfnCreate(riid, ppv) : E_POINTER;
        }
        else
        {
            *ppv = NULL;
            hr = CLASS_E_NOAGGREGATION;
        }
        return hr;
    }

    IFACEMETHODIMP LockServer(__in BOOL bLock)
    {
        if (bLock)
        {
            DllAddRef();
        }
        else
        {
            DllRelease();
        }
        return S_OK;
    }

private:
    ~CClassFactory()
    {
    }
    long _cRef;
    PFNCREATEINSTANCE _pfnCreate;
};

HRESULT CClassFactory_CreateInstance(__in REFCLSID rclsid, __in REFIID riid, __deref_out void **ppv)
{
    *ppv = NULL;

    HRESULT hr;
    CClassFactory::PFNCREATEINSTANCE pfnCreate = nullptr;

    if (CLSID_CSample == rclsid)
    {
        pfnCreate = CSample_CreateInstance;
    }
    else if (CLSID_CSampleFilter == rclsid)
    {
        pfnCreate = CSampleFilter_CreateInstance;
    }
    else
    {
        hr = CLASS_E_CLASSNOTAVAILABLE;
        return hr;
    }

    CClassFactory* pcf = new CClassFactory(pfnCreate);
    if (pcf)
    {
        hr = pcf->QueryInterface(riid, ppv);
        pcf->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    return hr;
}

void DllAddRef()
{
    InterlockedIncrement(&g_cRef);
}

void DllRelease()
{
    InterlockedDecrement(&g_cRef);
}

STDAPI DllCanUnloadNow()
{
    return (g_cRef > 0) ? S_FALSE : S_OK;
}

STDAPI DllGetClassObject(__in REFCLSID rclsid, __in REFIID riid, __deref_out void** ppv)
{
    return CClassFactory_CreateInstance(rclsid, riid, ppv);
}

STDAPI_(BOOL) DllMain(__in HINSTANCE hinstDll, __in DWORD dwReason, __in void *)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDll);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    g_hinst = hinstDll;
    return TRUE;
}

