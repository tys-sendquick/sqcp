//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include <strsafe.h>
#include "CSampleCredential.h"
#include "guid.h"
#include "utils.h"

namespace
{
    void LogHr(_In_z_ LPCWSTR context, HRESULT hr)
    {
        wchar_t buffer[128] = {};
        if (SUCCEEDED(StringCchPrintfW(buffer, ARRAYSIZE(buffer), L"%s hr=0x%08X", context, hr)))
        {
            WriteLogMessage(buffer);
        }
    }
}

CSampleCredential::CSampleCredential():
    _cRef(1),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fChecked(false),
    _fShowControls(false),
    _dwComboIndex(0)
{
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CSampleCredential::~CSampleCredential()
{
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}


// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
HRESULT CSampleCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                      _In_ FIELD_STATE_PAIR const *rgfsp,
                                      _In_ ICredentialProviderUser *pcpUser)
{
    HRESULT hr = S_OK;
    _cpus = cpus;
    _fIsLocalUser = false;

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }
    if (FAILED(hr))
    {
        LogHr(L"Initialize FieldDescriptorCopy failed", hr);
        return hr;
    }

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Sample Credential", &_rgFieldStrings[SFI_LABEL]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Sample Credential Provider", &_rgFieldStrings[SFI_LARGE_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_USERNAME]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }

    if (SUCCEEDED(hr) && pcpUser != nullptr)
    {
        GUID guidProvider;
        pcpUser->GetProviderID(&guidProvider);
        _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);

        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
        if (SUCCEEDED(hr))
        {
            hr = pcpUser->GetSid(&_pszUserSid);
        }
    }
    else if (SUCCEEDED(hr))
    {
        // CredUI scenario has no bound user. Allow user to type a name.
        hr = SHStrDupW(L"", &_pszQualifiedUserName);
    }

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CSampleCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CSampleCredential::SetDeselected()
{
    HRESULT hr = S_OK;
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));

        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
        }
    }

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT CSampleCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT CSampleCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;

    if ((SFI_TILEIMAGE == dwFieldID))
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

    if (SFI_SUBMIT_BUTTON == dwFieldID)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to
        // appear next to.
        *pdwAdjacentTo = SFI_PASSWORD;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CSampleCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.
HRESULT CSampleCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    if (ppwszLabel)
    {
        *ppwszLabel = nullptr;
    }
    return E_NOTIMPL;
}

// Sets whether the specified checkbox is checked or not.
HRESULT CSampleCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);
    return E_NOTIMPL;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    *pcItems = 0;
    *pdwSelectedItem = 0;
    return E_NOTIMPL;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);
    *ppwszItem = nullptr;
    return E_NOTIMPL;
}

// Called when the user changes the selected item in the combobox.
HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwSelectedItem);
    return E_NOTIMPL;
}

// Called when the user clicks a command link.
HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    return E_NOTIMPL;
}

HRESULT CSampleCredential::GetSerialization(
    _Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
    _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    HRESULT hr = E_UNEXPECTED;

    // Initialize out params
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    // We will now use a single serialization path for:
    // LOGON, UNLOCK, and CREDUI.
    // This avoids KERB_* manual struct packing which is a common
    // source of LSASS/msv1_0 crashes when anything is mis-sized.
    if (_cpus == CPUS_LOGON || _cpus == CPUS_UNLOCK_WORKSTATION || _cpus == CPUS_CREDUI)
    {
        PWSTR pszUserNameForSerialization = nullptr;
        PWSTR pwzProtectedPassword = nullptr;
        WriteLogMessage(L"[CREDENTIAL] GetSerialization start");

        //
        // 1) Decide what username to serialize
        //
        // Prefer _pszQualifiedUserName (e.g. "DOMAIN\\user" or UPN) when available.
        // Otherwise, fall back to the typed username field.
        //
        if (_pszQualifiedUserName != nullptr && *_pszQualifiedUserName != L'\0')
        {
            pszUserNameForSerialization = _pszQualifiedUserName;
        }
        else
        {
            pszUserNameForSerialization = _rgFieldStrings[SFI_USERNAME];
        }

        if (pszUserNameForSerialization == nullptr || *pszUserNameForSerialization == L'\0')
        {
            hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            WriteLogMessage(L"GetSerialization: missing username");
            return hr;
        }

        //
        // 2) Protect/copy the password (your existing helper)
        //
        hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);
        if (FAILED(hr))
        {
            LogHr(L"GetSerialization: ProtectIfNecessaryAndCopyPassword failed", hr);
            return hr;
        }

        //
        // 3) Determine CredPack flags
        //
        DWORD dwAuthFlags = 0;

        // If password protection actually happened, it's typically safe to set CRED_PACK_PROTECTED_CREDENTIALS.
        // (If your helper sometimes returns the original pointer unchanged, you can refine this check.)
        if (pwzProtectedPassword != nullptr && pwzProtectedPassword != _rgFieldStrings[SFI_PASSWORD])
        {
            dwAuthFlags |= CRED_PACK_PROTECTED_CREDENTIALS;
        }

        // You were using CRED_PACK_ID_PROVIDER_CREDENTIALS for CREDUI; if you still
        // require that behavior specifically, you can conditionally OR it in here:
        // if (_cpus == CPUS_CREDUI) dwAuthFlags |= CRED_PACK_ID_PROVIDER_CREDENTIALS;

        //
        // 4) First CredPackAuthenticationBufferW call: get required size
        //
        DWORD cbSerialization = 0;

        if (CredPackAuthenticationBufferW(
                dwAuthFlags,
                pszUserNameForSerialization,
                pwzProtectedPassword,
                nullptr,
                &cbSerialization) ||
            (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
        {
            // We *expect* ERROR_INSUFFICIENT_BUFFER on this first call.
            hr = HRESULT_FROM_WIN32(GetLastError());
            LogHr(L"GetSerialization: First CredPackAuthenticationBufferW (size query) failed", hr);
            CoTaskMemFree(pwzProtectedPassword);
            return hr;
        }

        //
        // 5) Allocate buffer with CoTaskMemAlloc (required by CP contract)
        //
        pcpcs->rgbSerialization = static_cast<byte *>(CoTaskMemAlloc(cbSerialization));
        if (pcpcs->rgbSerialization == nullptr)
        {
            hr = E_OUTOFMEMORY;
            LogHr(L"GetSerialization: CoTaskMemAlloc for rgbSerialization failed", hr);
            CoTaskMemFree(pwzProtectedPassword);
            return hr;
        }

        pcpcs->cbSerialization = cbSerialization;

        //
        // 6) Second CredPackAuthenticationBufferW call: fill the buffer
        //
        if (!CredPackAuthenticationBufferW(
                dwAuthFlags,
                pszUserNameForSerialization,
                pwzProtectedPassword,
                pcpcs->rgbSerialization,
                &pcpcs->cbSerialization))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            LogHr(L"GetSerialization: Second CredPackAuthenticationBufferW (pack) failed", hr);

            CoTaskMemFree(pcpcs->rgbSerialization);
            pcpcs->rgbSerialization = nullptr;
            pcpcs->cbSerialization = 0;

            CoTaskMemFree(pwzProtectedPassword);
            return hr;
        }

        //
        // 7) Retrieve the Negotiate auth package and finish filling serialization
        //
        ULONG ulAuthPackage = 0;
        hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
        if (FAILED(hr))
        {
            LogHr(L"GetSerialization: RetrieveNegotiateAuthPackage failed", hr);

            CoTaskMemFree(pcpcs->rgbSerialization);
            pcpcs->rgbSerialization = nullptr;
            pcpcs->cbSerialization = 0;

            CoTaskMemFree(pwzProtectedPassword);
            return hr;
        }

        pcpcs->ulAuthenticationPackage = ulAuthPackage;
        pcpcs->clsidCredentialProvider = CLSID_CSample;

        //
        // 8) Tell LogonUI that we're done and it should submit these creds
        //
        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        hr = S_OK;
        WriteLogMessage(L"[CREDENTIAL] GetSerialization succeeded");

        //
        // 9) Cleanup
        //
        CoTaskMemFree(pwzProtectedPassword);
        return hr;
    }

    //
    // If we reach here, _cpus was not a scenario we handle.
    //
    WriteLogMessage(L"GetSerialization: unsupported CPUS value");
    return hr;
}


struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CSampleCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    // If we failed the logon, try to erase the password field.
    if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
        }
        LogHr(L"[CREDENTIAL] ReportResult logon failure", HRESULT_FROM_NT(ntsStatus));
    }
    else
    {
        WriteLogMessage(L"[CREDENTIAL] ReportResult success/continue");
    }

    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT CSampleCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
    *ppszSid = nullptr;
    HRESULT hr = S_FALSE;

    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    // Return S_FALSE with a null SID in ppszSid for the
    // credential to be associated with an empty user tile.

    return hr;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    else if (dwFieldID == SFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}
