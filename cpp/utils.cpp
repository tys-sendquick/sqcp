#include "utils.h"

#include <string>
#include <cwchar>

namespace
{
    const wchar_t kLogDirectory[] = L"C:\\ProgramData\\sqcp";
    const wchar_t kLogFile[] = L"C:\\ProgramData\\sqcp\\sqcp.log";
}

HRESULT WriteLogMessage(_In_z_ PCWSTR message)
{
    if (message == nullptr)
    {
        return E_INVALIDARG;
    }

    if (!CreateDirectoryW(kLogDirectory, nullptr))
    {
        DWORD createDirError = GetLastError();
        if (createDirError != ERROR_ALREADY_EXISTS)
        {
            return HRESULT_FROM_WIN32(createDirError);
        }
    }

    HANDLE fileHandle = CreateFileW(
        kLogFile,
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return HRESULT_FROM_WIN32(GetLastError());
    }

    SYSTEMTIME st = {};
    GetLocalTime(&st);

    wchar_t timeBuffer[32] = {};
    int written = swprintf_s(
        timeBuffer,
        sizeof(timeBuffer) / sizeof(timeBuffer[0]),
        L"%04u-%02u-%02u %02u:%02u:%02u",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond);

    if (written <= 0)
    {
        CloseHandle(fileHandle);
        return E_FAIL;
    }

    std::wstring line(timeBuffer);
    line.append(L"    ");
    line.append(message);
    line.append(L"\r\n");

    DWORD bytesToWrite = static_cast<DWORD>(line.size() * sizeof(wchar_t));
    DWORD bytesWritten = 0;
    BOOL writeResult = WriteFile(fileHandle, line.c_str(), bytesToWrite, &bytesWritten, nullptr);
    HRESULT hr = (writeResult && bytesWritten == bytesToWrite) ? S_OK : HRESULT_FROM_WIN32(GetLastError());

    CloseHandle(fileHandle);
    return hr;
}
