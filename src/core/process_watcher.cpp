#include "process_watcher.h"
#include "../util/string_util.h"
#include <tlhelp32.h>
#include <winternl.h>
#include <psapi.h>
#include <iostream>
#include <set>

#pragma comment(lib, "Ntdll.lib")

namespace mcguard {
namespace core {

typedef NTSTATUS(NTAPI* PFN_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

ProcessWatcher::ProcessWatcher() {}

ProcessWatcher::~ProcessWatcher() {
    StopWatching();
}

std::wstring ProcessWatcher::GetProcessCommandLine(HANDLE hProcess) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return L"";

    auto pfnQuery = (PFN_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!pfnQuery) return L"";

    // ProcessCommandLineInformation = 60
    const PROCESSINFOCLASS ProcessCommandLineInformation = (PROCESSINFOCLASS)60;

    ULONG bufferLength = 0;
    NTSTATUS status = pfnQuery(hProcess, ProcessCommandLineInformation, NULL, 0, &bufferLength);
    if (bufferLength == 0) {
        return L"";
    }

    std::vector<BYTE> buffer(bufferLength + sizeof(UNICODE_STRING));
    status = pfnQuery(hProcess, ProcessCommandLineInformation, buffer.data(), bufferLength, &bufferLength);
    if (status >= 0) {
        auto pUnicodeString = reinterpret_cast<PUNICODE_STRING>(buffer.data());
        if (pUnicodeString->Buffer && pUnicodeString->Length > 0) {
            return std::wstring(pUnicodeString->Buffer, pUnicodeString->Length / sizeof(wchar_t));
        }
    }
    return L"";
}

bool ProcessWatcher::InspectProcess(DWORD pid, MinecraftProcessInfo& outInfo) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        // Fall back to query limited information only
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) return false;
    }

    wchar_t exePath[MAX_PATH] = { 0 };
    DWORD pathLen = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProcess, 0, exePath, &pathLen)) {
        CloseHandle(hProcess);
        return false;
    }

    std::wstring exeStr(exePath);
    // Check if executable is javaw.exe or java.exe
    bool isJavaExe = util::ContainsIgnoreCase(exeStr, L"javaw.exe") || util::ContainsIgnoreCase(exeStr, L"java.exe");
    if (!isJavaExe) {
        CloseHandle(hProcess);
        return false;
    }

    std::wstring cmdLine = GetProcessCommandLine(hProcess);
    CloseHandle(hProcess);

    outInfo.pid = pid;
    outInfo.exePath = exeStr;
    outInfo.commandLine = cmdLine;

    // Derive javaHome from exeStr (e.g. C:\...\java\bin\java.exe -> C:\...\java)
    size_t lastSlash = exeStr.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        std::wstring binDir = exeStr.substr(0, lastSlash);
        size_t prevSlash = binDir.find_last_of(L"\\/");
        if (prevSlash != std::wstring::npos) {
            std::wstring folderName = binDir.substr(prevSlash + 1);
            if (util::EqualsIgnoreCase(folderName, L"bin")) {
                outInfo.javaHome = binDir.substr(0, prevSlash);
            } else {
                outInfo.javaHome = binDir;
            }
        } else {
            outInfo.javaHome = binDir;
        }
    }

    // Detect if this Java process is Minecraft
    bool hasMcMain = util::ContainsIgnoreCase(cmdLine, L"net.minecraft.client.main.Main") ||
                     util::ContainsIgnoreCase(cmdLine, L"net.minecraft.launchwrapper.Launch") ||
                     util::ContainsIgnoreCase(cmdLine, L"net.fabricmc.loader.impl.launch.knot.KnotClient") ||
                     util::ContainsIgnoreCase(cmdLine, L"cpw.mods.bootstraplauncher.BootstrapLauncher") ||
                     util::ContainsIgnoreCase(cmdLine, L"net.minecraftforge.bootstrap.ForgeBootstrap");

    bool hasMcArgs = util::ContainsIgnoreCase(cmdLine, L"--gameDir") ||
                     util::ContainsIgnoreCase(cmdLine, L"--version") ||
                     util::ContainsIgnoreCase(cmdLine, L".minecraft");

    outInfo.isMinecraft = hasMcMain || hasMcArgs;

    // 1. Parse --gameDir if present
    size_t gameDirPos = cmdLine.find(L"--gameDir");
    if (gameDirPos != std::wstring::npos) {
        size_t start = gameDirPos + 9;
        while (start < cmdLine.size() && (cmdLine[start] == L' ' || cmdLine[start] == L'=')) start++;
        if (start < cmdLine.size()) {
            if (cmdLine[start] == L'\"') {
                size_t end = cmdLine.find(L'\"', start + 1);
                if (end != std::wstring::npos) {
                    outInfo.gameDir = cmdLine.substr(start + 1, end - start - 1);
                }
            } else {
                size_t end = cmdLine.find(L' ', start);
                outInfo.gameDir = cmdLine.substr(start, end == std::wstring::npos ? end : end - start);
            }
        }
    }

    // 2. If empty, check for -Dminecraft.client.jar= or -Djava.library.path= or -Djna.tmpdir=
    if (outInfo.gameDir.empty()) {
        const std::wstring keys[] = {
            L"-Dminecraft.client.jar=",
            L"-Djava.library.path=",
            L"-Djna.tmpdir=",
            L"-Dio.netty.native.workdir="
        };
        for (const auto& key : keys) {
            size_t pos = cmdLine.find(key);
            if (pos != std::wstring::npos) {
                size_t start = pos + key.length();
                if (start < cmdLine.size() && cmdLine[start] == L'\"') start++;
                size_t end = cmdLine.find_first_of(L"\" \t\r\n", start);
                std::wstring val = cmdLine.substr(start, end == std::wstring::npos ? end : end - start);

                // Find .minecraft in this path
                size_t mcPos = val.find(L".minecraft");
                if (mcPos != std::wstring::npos) {
                    outInfo.gameDir = val.substr(0, mcPos + 10);
                    break;
                }
            }
        }
    }

    // 3. If still empty, search for any token containing ".minecraft"
    if (outInfo.gameDir.empty()) {
        size_t mcPos = cmdLine.find(L".minecraft");
        if (mcPos != std::wstring::npos) {
            size_t tokenStart = cmdLine.rfind(L" ", mcPos);
            tokenStart = (tokenStart == std::wstring::npos) ? 0 : tokenStart + 1;
            if (tokenStart < cmdLine.size() && cmdLine[tokenStart] == L'\"') tokenStart++;
            outInfo.gameDir = cmdLine.substr(tokenStart, (mcPos + 10) - tokenStart);
        }
    }

    // 4. Default fallback: %APPDATA%\.minecraft
    if (outInfo.gameDir.empty()) {
        wchar_t appData[MAX_PATH] = { 0 };
        if (GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH)) {
            outInfo.gameDir = std::wstring(appData) + L"\\.minecraft";
        }
    }

    // Clean and normalize outInfo.gameDir
    while (!outInfo.gameDir.empty() && (outInfo.gameDir.back() == L'\\' || outInfo.gameDir.back() == L'/' || outInfo.gameDir.back() == L'\"')) {
        outInfo.gameDir.pop_back();
    }
    while (!outInfo.gameDir.empty() && (outInfo.gameDir.front() == L'\"')) {
        outInfo.gameDir.erase(outInfo.gameDir.begin());
    }

    // Parse version if present
    size_t verPos = cmdLine.find(L"--version");
    if (verPos != std::wstring::npos) {
        size_t start = verPos + 9;
        while (start < cmdLine.size() && (cmdLine[start] == L' ' || cmdLine[start] == L'=')) start++;
        if (start < cmdLine.size()) {
            if (cmdLine[start] == L'\"') {
                size_t end = cmdLine.find(L'\"', start + 1);
                if (end != std::wstring::npos) {
                    outInfo.version = cmdLine.substr(start + 1, end - start - 1);
                }
            } else {
                size_t end = cmdLine.find(L' ', start);
                outInfo.version = cmdLine.substr(start, end == std::wstring::npos ? end : end - start);
            }
        }
    }

    return true;
}

std::vector<MinecraftProcessInfo> ProcessWatcher::FindMinecraftProcesses() {
    std::vector<MinecraftProcessInfo> results;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return results;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            std::wstring procName(pe.szExeFile);
            if (util::EqualsIgnoreCase(procName, L"javaw.exe") || util::EqualsIgnoreCase(procName, L"java.exe")) {
                MinecraftProcessInfo info;
                info.parentPid = pe.th32ParentProcessID;
                if (InspectProcess(pe.th32ProcessID, info) && info.isMinecraft) {
                    info.parentPid = pe.th32ParentProcessID;
                    results.push_back(info);
                }
            }
        } while (Process32NextW(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return results;
}

void ProcessWatcher::StartWatching(ProcessCallback callback, uint32_t pollIntervalMs) {
    if (m_running) return;
    m_running = true;
    m_watchThread = std::thread(&ProcessWatcher::WatcherLoop, this, callback, pollIntervalMs);
}

void ProcessWatcher::StopWatching() {
    if (!m_running) return;
    m_running = false;
    if (m_watchThread.joinable()) {
        m_watchThread.join();
    }
}

void ProcessWatcher::WatcherLoop(ProcessCallback callback, uint32_t pollIntervalMs) {
    std::set<DWORD> activePids;

    while (m_running) {
        auto currentList = FindMinecraftProcesses();
        std::set<DWORD> currentPids;

        for (const auto& mc : currentList) {
            currentPids.insert(mc.pid);
            if (activePids.find(mc.pid) == activePids.end()) {
                // New process detected
                if (callback) {
                    callback(mc, true);
                }
            }
        }

        for (DWORD oldPid : activePids) {
            if (currentPids.find(oldPid) == currentPids.end()) {
                // Process exited
                MinecraftProcessInfo info;
                info.pid = oldPid;
                if (callback) {
                    callback(info, false);
                }
            }
        }

        activePids = std::move(currentPids);
        Sleep(pollIntervalMs);
    }
}

} // namespace core
} // namespace mcguard
