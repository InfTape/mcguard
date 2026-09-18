#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <string>
#include "detours.h"

// -----------------------------------------------------------------------------
// IPC Named Pipe Client
// -----------------------------------------------------------------------------
static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_pipeCs;
static bool g_pipeCsInit = false;

static void EnsurePipeCs() {
    if (!g_pipeCsInit) {
        InitializeCriticalSection(&g_pipeCs);
        g_pipeCsInit = true;
    }
}

static bool SendIpcMessage(const std::string& msg) {
    EnsurePipeCs();
    EnterCriticalSection(&g_pipeCs);

    for (int retry = 0; retry < 2; ++retry) {
        if (g_hPipe == INVALID_HANDLE_VALUE) {
            g_hPipe = CreateFileW(
                L"\\\\.\\pipe\\mcguard_ipc",
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                0,
                NULL
            );
            if (g_hPipe == INVALID_HANDLE_VALUE) {
                break;
            }
            DWORD mode = PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(g_hPipe, &mode, NULL, NULL);
        }

        DWORD bytesWritten = 0;
        BOOL ok = WriteFile(g_hPipe, msg.c_str(), (DWORD)msg.length(), &bytesWritten, NULL);
        if (ok) {
            FlushFileBuffers(g_hPipe);
            char respBuf[256] = { 0 };
            DWORD bytesRead = 0;
            ReadFile(g_hPipe, respBuf, sizeof(respBuf) - 1, &bytesRead, NULL);
            LeaveCriticalSection(&g_pipeCs);
            return true;
        }

        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }

    LeaveCriticalSection(&g_pipeCs);
    return false;
}

// -----------------------------------------------------------------------------
// Hook 1: GetVolumeInformationW
// AppContainers / UWP cannot query GetVolumeInformationW on virtual/DOS drives
// directly due to internal security checks. Fallback to GetVolumeInformationByHandleW.
// -----------------------------------------------------------------------------
static BOOL (WINAPI* TrueGetVolumeInformationW)(
    LPCWSTR lpRootPathName,
    LPWSTR lpVolumeNameBuffer,
    DWORD nVolumeNameSize,
    LPDWORD lpVolumeSerialNumber,
    LPDWORD lpMaximumComponentLength,
    LPDWORD lpFileSystemFlags,
    LPWSTR lpFileSystemNameBuffer,
    DWORD nFileSystemNameSize
) = GetVolumeInformationW;

BOOL WINAPI GetVolumeInformationWPatch(
    LPCWSTR lpRootPathName,
    LPWSTR lpVolumeNameBuffer,
    DWORD nVolumeNameSize,
    LPDWORD lpVolumeSerialNumber,
    LPDWORD lpMaximumComponentLength,
    LPDWORD lpFileSystemFlags,
    LPWSTR lpFileSystemNameBuffer,
    DWORD nFileSystemNameSize
) {
    BOOL result = TrueGetVolumeInformationW(
        lpRootPathName,
        lpVolumeNameBuffer,
        nVolumeNameSize,
        lpVolumeSerialNumber,
        lpMaximumComponentLength,
        lpFileSystemFlags,
        lpFileSystemNameBuffer,
        nFileSystemNameSize
    );

    DWORD origErr = GetLastError();
    if (result || (origErr != ERROR_DIR_NOT_ROOT && origErr != ERROR_ACCESS_DENIED && origErr != ERROR_INVALID_PARAMETER)) {
        return result;
    }

    HANDLE hFile = INVALID_HANDLE_VALUE;

    // First attempt: open root directory directly with FILE_FLAG_BACKUP_SEMANTICS
    if (lpRootPathName && lpRootPathName[0] != L'\0') {
        hFile = CreateFileW(
            lpRootPathName,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            NULL
        );
    }

    // Second attempt: probe file .mcguard_vol
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wstring probePath;
        if (lpRootPathName == NULL || lpRootPathName[0] == L'\0') {
            probePath = L".";
        } else {
            probePath = lpRootPathName;
        }
        while (!probePath.empty() && (probePath.back() == L'\\' || probePath.back() == L'/')) {
            probePath.pop_back();
        }
        probePath += L"\\.mcguard_vol";

        hFile = CreateFileW(
            probePath.c_str(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
    }

    if (hFile == INVALID_HANDLE_VALUE) {
        SetLastError(origErr);
        return FALSE;
    }

    result = GetVolumeInformationByHandleW(
        hFile,
        lpVolumeNameBuffer,
        nVolumeNameSize,
        lpVolumeSerialNumber,
        lpMaximumComponentLength,
        lpFileSystemFlags,
        lpFileSystemNameBuffer,
        nFileSystemNameSize
    );

    CloseHandle(hFile);

    if (!result) {
        SetLastError(origErr);
    }
    return result;
}

// -----------------------------------------------------------------------------
// Hook 2: ClipCursor
// In AppContainers, ClipCursor fails with ERROR_ACCESS_DENIED. Forward to Host Broker.
// -----------------------------------------------------------------------------
static BOOL (WINAPI* TrueClipCursor)(const RECT*) = ClipCursor;

BOOL WINAPI ClipCursorPatch(const RECT* lpRect) {
    std::string msg;
    if (lpRect == NULL) {
        msg = "{\"action\":\"clip_cursor\",\"has_rect\":false}\n";
    } else {
        msg = "{\"action\":\"clip_cursor\",\"has_rect\":true,\"left\":" +
              std::to_string(lpRect->left) + ",\"top\":" +
              std::to_string(lpRect->top) + ",\"right\":" +
              std::to_string(lpRect->right) + ",\"bottom\":" +
              std::to_string(lpRect->bottom) + "}\n";
    }
    SendIpcMessage(msg);
    return TRUE;
}

// -----------------------------------------------------------------------------
// Hook 3: SetCursorPos
// In AppContainers, SetCursorPos fails. Forward to Host Broker.
// -----------------------------------------------------------------------------
static BOOL (WINAPI* TrueSetCursorPos)(int, int) = SetCursorPos;

BOOL WINAPI SetCursorPosPatch(int x, int y) {
    std::string msg = "{\"action\":\"set_cursor_pos\",\"x\":" +
                      std::to_string(x) + ",\"y\":" +
                      std::to_string(y) + "}\n";
    SendIpcMessage(msg);
    return TRUE;
}

// -----------------------------------------------------------------------------
// Hook Installation & Entrypoints
// -----------------------------------------------------------------------------
static void InstallHooks() {
    static bool s_installed = false;
    if (s_installed) return;
    s_installed = true;

    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueGetVolumeInformationW, (PVOID)GetVolumeInformationWPatch);
    DetourAttach(&(PVOID&)TrueClipCursor, (PVOID)ClipCursorPatch);
    DetourAttach(&(PVOID&)TrueSetCursorPos, (PVOID)SetCursorPosPatch);
    DetourTransactionCommit();
}

extern "C" __declspec(dllexport) int __stdcall Agent_OnLoad(void* vm, char* options, void* reserved) {
    InstallHooks();
    return 0; // JNI_OK
}

extern "C" __declspec(dllexport) int __stdcall Agent_OnAttach(void* vm, char* options, void* reserved) {
    InstallHooks();
    return 0; // JNI_OK
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        InstallHooks();
    } else if (dwReason == DLL_PROCESS_DETACH) {
        if (g_hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hPipe);
            g_hPipe = INVALID_HANDLE_VALUE;
        }
        if (g_pipeCsInit) {
            DeleteCriticalSection(&g_pipeCs);
            g_pipeCsInit = false;
        }
    }
    return TRUE;
}
