#include "privilege.h"
#include <shellapi.h>
#include <iostream>

namespace mcguard {
namespace util {

bool IsElevatedAdministrator() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return isElevated != FALSE;
}

bool EnablePrivilege(LPCWSTR privilegeName) {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    return (ok && err == ERROR_SUCCESS);
}

bool RelaunchElevated(const std::wstring& additionalArgs) {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH) == 0) {
        return false;
    }

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = szPath;
    sei.lpParameters = additionalArgs.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_CANCELLED) {
            std::wcerr << L"[!] Elevation was cancelled by the user.\n";
        } else {
            std::wcerr << L"[!] ShellExecuteEx failed with error: " << dwError << L"\n";
        }
        return false;
    }
    return true;
}

} // namespace util
} // namespace mcguard
