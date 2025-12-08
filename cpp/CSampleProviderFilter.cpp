#include "CSampleProviderFilter.h"
#include "guid.h"
#include "utils.h"
#include <credentialprovider.h>
#include <strsafe.h>

#ifndef CPF_REMOTE_SESSION
#define CPF_REMOTE_SESSION 0x1
#endif
#ifndef CPF_REMOTE_CONNECTION
#define CPF_REMOTE_CONNECTION 0x2
#endif

namespace
{
    bool IsRemoteSession(DWORD flags)
    {
        return (flags & CPF_REMOTE_SESSION) != 0 ||
               (flags & CPF_REMOTE_CONNECTION) != 0;
    }

    void ApplyExclusiveFilter(GUID* rgclsidProviders,
                              BOOL* rgbAllow,
                              DWORD cProviders)
    {
        for (DWORD i = 0; i < cProviders; i++)
        {
            const GUID& clsid = rgclsidProviders[i];
            BOOL allow = IsEqualGUID(clsid, CLSID_CSample); // keep only our provider
            rgbAllow[i] = allow;
        }
    }
}

//
// Extra Checks
//
bool ShouldUseExclusiveMode()
{
    // return true to hide all other credential providers
    return false;
}

bool ShouldBlockWindowsHello()
{
    // return true to block Windows Hello / PIN providers
    return false;
}

bool ShouldBlockSmartCard()
{
    // return true to block Smart Card providers
    return false;
}

//
// Filter Implementation
//
HRESULT CSampleProviderFilter::Filter(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags,
    GUID* rgclsidProviders,
    BOOL* rgbAllow,
    DWORD cProviders)
{
    HRESULT hr = S_OK;

    // Log filter entry
    wchar_t logBuffer[256] = {};
    const wchar_t* scenarioName = L"UNKNOWN";
    switch (cpus)
    {
        case CPUS_LOGON: scenarioName = L"LOGON"; break;
        case CPUS_UNLOCK_WORKSTATION: scenarioName = L"UNLOCK"; break;
        case CPUS_CREDUI: scenarioName = L"CREDUI"; break;
        case CPUS_CHANGE_PASSWORD: scenarioName = L"CHANGE_PASSWORD"; break;
    }
    StringCchPrintfW(logBuffer, ARRAYSIZE(logBuffer), 
        L"[FILTER] Filter called: scenario=%s, providers=%u", scenarioName, cProviders);
    WriteLogMessage(logBuffer);

    // CredUI: allow only our provider in the RDP client dialog.
    if (cpus == CPUS_CREDUI)
    {
        ApplyExclusiveFilter(rgclsidProviders, rgbAllow, cProviders);
        WriteLogMessage(L"[FILTER] CredUI detected: applying exclusive filter to keep only CSample");
        return hr;
    }

    // Remote-only: block all other providers during RDP sessions. This is on host side
    if (IsRemoteSession(dwFlags))
    {
        ApplyExclusiveFilter(rgclsidProviders, rgbAllow, cProviders);
        WriteLogMessage(L"[FILTER] Remote session detected: applying exclusive filter to keep only CSample");
        return hr;
    }

    for (DWORD i = 0; i < cProviders; i++)
    {
        BOOL allow = TRUE;
        const GUID& clsid = rgclsidProviders[i];

        //
        // If EXCLUSIVE mode is enabled later, hide everything except our provider.
        //
        if (ShouldUseExclusiveMode())
        {
            allow = IsEqualGUID(clsid, CLSID_CSample);
            rgbAllow[i] = allow;
            
            if (!allow)
            {
                WriteLogMessage(L"[FILTER] Exclusive mode: Blocking non-CSample provider");
            }
            continue;
        }

        //
        // Handle OUR Credential Provider
        //
        if (IsEqualGUID(clsid, CLSID_CSample))
        {
            if (
                cpus == CPUS_LOGON ||
                cpus == CPUS_UNLOCK_WORKSTATION ||
                cpus == CPUS_CREDUI ||
                cpus == CPUS_CHANGE_PASSWORD // UAC ??
            )
            {
                allow = TRUE;
                StringCchPrintfW(logBuffer, ARRAYSIZE(logBuffer),
                    L"[FILTER] CSample provider: ALLOWED for scenario %s", scenarioName);
                WriteLogMessage(logBuffer);
            }
            else
            {
                allow = FALSE;
                StringCchPrintfW(logBuffer, ARRAYSIZE(logBuffer),
                    L"[FILTER] CSample provider: BLOCKED for scenario %s", scenarioName);
                WriteLogMessage(logBuffer);
            }

            rgbAllow[i] = allow;
            continue;
        }

        //
        // WINDOWS HELLO / PIN PROVIDERS (optional)
        //
        if (ShouldBlockWindowsHello())
        {
            if (IsEqualGUID(clsid, CLSID_WinBioCredentialProvider) ||
                IsEqualGUID(clsid, CLSID_PasswordCredentialProvider))
            {
                allow = FALSE;
                WriteLogMessage(L"[FILTER] Blocking Windows Hello/PIN provider");
            }
        }

        //
        // SMART CARD PROVIDER (optional)
        //
        if (ShouldBlockSmartCard())
        {
            if (IsEqualGUID(clsid, CLSID_SmartcardCredentialProvider) ||
                IsEqualGUID(clsid, CLSID_SmartcardPinProvider))
            {
                allow = FALSE;
                WriteLogMessage(L"[FILTER] Blocking Smart Card provider");
            }
        }

        rgbAllow[i] = allow;
    }

    WriteLogMessage(L"[FILTER] Filter completed");
    return hr;
}

//
// UpdateRemoteCredential — Leave as no-op
//
HRESULT CSampleProviderFilter::UpdateRemoteCredential(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* /*pcpcsIn*/,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* /*pcpcsOut*/)
{
    WriteLogMessage(L"[FILTER] UpdateRemoteCredential called (no-op)");
    // Your provider does not modify remote credentials.
    return S_OK;
}
