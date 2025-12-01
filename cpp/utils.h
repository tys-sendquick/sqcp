#pragma once

#include <windows.h>

// Writes a message to C:\ProgramData\sqcp\sqcp.log, creating the directory/file when missing.
HRESULT WriteLogMessage(_In_z_ PCWSTR message);
