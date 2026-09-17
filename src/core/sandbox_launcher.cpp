#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include "sandbox_launcher.h"
#include "../util/string_util.h"
#include <iostream>
#include <vector>

#pragma comment(lib, "Advapi32.lib")

namespace mcguard {
namespace core {

HANDLE SandboxLauncher::CreateLowIntegrityRestrictedToken(bool stripPrivileges, bool lowIntegrity, std::string& outError) {
    HANDLE hCurrentToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &hCurrentToken)) {
        outError = "Failed to open current process token: " + std::to_string(GetLastError());
        return NULL;
    }

    HANDLE hTargetToken = NULL;
    if (stripPrivileges) {
        // Create restricted token stripping administrative and sensitive privileges
        if (!CreateRestrictedToken(hCurrentToken, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 0, NULL, &hTargetToken)) {
            outError = "CreateRestrictedToken failed: " + std::to_string(GetLastError());
            CloseHandle(hCurrentToken);
            return NULL;
        }
    } else {
        // Duplicate token if privilege stripping is not requested
        if (!DuplicateTokenEx(hCurrentToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hTargetToken)) {
            outError = "DuplicateTokenEx failed: " + std::to_string(GetLastError());
            CloseHandle(hCurrentToken);
            return NULL;
        }
    }
    CloseHandle(hCurrentToken);

    if (lowIntegrity) {
        // Demote to Low Integrity Level (S-1-16-4096)
        PSID pLowSid = NULL;
        if (ConvertStringSidToSidW(L"S-1-16-4096", &pLowSid)) {
            TOKEN_MANDATORY_LABEL tml = { 0 };
            tml.Label.Attributes = SE_GROUP_INTEGRITY;
            tml.Label.Sid = pLowSid;

            if (!SetTokenInformation(hTargetToken, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(pLowSid))) {
                outError = "SetTokenInformation(TokenIntegrityLevel) failed: " + std::to_string(GetLastError());
            }
            LocalFree(pLowSid);
        }
    }

    return hTargetToken;
}

bool SandboxLauncher::GrantLowIntegrityAccessToFolder(const std::wstring& folderPath) {
    if (folderPath.empty()) return false;

    // S:(ML;OICI;NW;;;LW)
    // ML = Mandatory Label
    // OICI = Object Inherit + Container Inherit
    // NW = No-Write-Up (allows Low Integrity processes to write)
    // LW = Low Mandatory Level (S-1-16-4096)
    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"S:(ML;OICI;NW;;;LW)",
            SDDL_REVISION_1,
            &pSD,
            NULL)) {
        return false;
    }

    PACL pSacl = NULL;
    BOOL saclPresent = FALSE, saclDefaulted = FALSE;
    GetSecurityDescriptorSacl(pSD, &saclPresent, &pSacl, &saclDefaulted);

    DWORD res = SetNamedSecurityInfoW(
        (LPWSTR)folderPath.c_str(),
        SE_FILE_OBJECT,
        LABEL_SECURITY_INFORMATION,
        NULL,
        NULL,
        NULL,
        pSacl
    );

    LocalFree(pSD);
    return (res == ERROR_SUCCESS);
}

static std::wstring ExpandEnvironmentPath(const std::wstring& inPath) {
    wchar_t buf[MAX_PATH * 4] = { 0 };
    DWORD len = ExpandEnvironmentStringsW(inPath.c_str(), buf, sizeof(buf) / sizeof(buf[0]));
    std::wstring result = (len > 0 && len < sizeof(buf) / sizeof(buf[0])) ? std::wstring(buf) : inPath;
    for (auto& ch : result) {
        if (ch == L'/') ch = L'\\';
    }
    return result;
}

bool SandboxLauncher::ProtectPathFromLowIntegrity(const std::wstring& targetPath) {
    if (targetPath.empty()) return false;

    std::wstring expanded = ExpandEnvironmentPath(targetPath);
    DWORD attr = GetFileAttributesW(expanded.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    bool isDir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    // For directories: inherit to child files and containers (OICI)
    // For files: no inheritance needed
    const wchar_t* sddl = isDir ? L"S:(ML;OICI;NRNW;;;ME)" : L"S:(ML;;NRNW;;;ME)";

    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, NULL)) {
        return false;
    }

    PACL pSacl = NULL;
    BOOL saclPresent = FALSE, saclDefaulted = FALSE;
    GetSecurityDescriptorSacl(pSD, &saclPresent, &pSacl, &saclDefaulted);

    DWORD res = SetNamedSecurityInfoW(
        (LPWSTR)expanded.c_str(),
        SE_FILE_OBJECT,
        LABEL_SECURITY_INFORMATION,
        NULL,
        NULL,
        NULL,
        pSacl
    );

    LocalFree(pSD);
    return (res == ERROR_SUCCESS);
}

void SandboxLauncher::ApplyProtectedPaths(const std::vector<std::string>& paths, std::vector<std::wstring>& outApplied) {
    for (const auto& p : paths) {
        if (p.empty()) continue;
        std::wstring wPath = util::Utf8ToWide(p);
        std::wstring expanded = ExpandEnvironmentPath(wPath);
        if (ProtectPathFromLowIntegrity(expanded)) {
            outApplied.push_back(expanded);
        }
    }
}

bool SandboxLauncher::LaunchSandboxedProcess(
    const std::wstring& applicationPath,
    const std::wstring& commandLine,
    const SandboxOptions& options,
    SandboxProcessInfo& outInfo,
    std::string& outError
) {
    // 1. Grant Low-Integrity access to target game directory and temp folder
    if (options.lowIntegrity) {
        if (!options.gameDir.empty()) {
            GrantLowIntegrityAccessToFolder(options.gameDir);
        }
        wchar_t tempPath[MAX_PATH] = { 0 };
        if (GetTempPathW(MAX_PATH, tempPath)) {
            GrantLowIntegrityAccessToFolder(tempPath);
        }

        // Apply No-Read-Up & No-Write-Up protection to protected paths
        for (const auto& p : options.protectedPaths) {
            ProtectPathFromLowIntegrity(p);
        }
    }

    // 2. Prepare ProcThreadAttributeList for Mitigation Policy
    STARTUPINFOEXW siex = { 0 };
    siex.StartupInfo.cb = sizeof(siex);

    std::vector<BYTE> attrBuffer;
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = NULL;

    if (options.blockChildProcesses) {
        SIZE_T attrSize = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
        if (attrSize > 0) {
            attrBuffer.resize(attrSize);
            attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)attrBuffer.data();
            if (InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
                DWORD policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
                if (UpdateProcThreadAttribute(
                        attrList,
                        0,
                        PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                        &policy,
                        sizeof(policy),
                        NULL,
                        NULL)) {
                    siex.lpAttributeList = attrList;
                }
            }
        }
    }

    // 3. Obtain restricted primary token
    HANDLE hToken = NULL;
    if (options.stripPrivileges || options.lowIntegrity) {
        hToken = CreateLowIntegrityRestrictedToken(options.stripPrivileges, options.lowIntegrity, outError);
    }

    // 4. Configure process creation flags
    DWORD creationFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
    if (options.startSuspended) {
        creationFlags |= CREATE_SUSPENDED;
    }

    std::vector<wchar_t> cmdLineBuf(commandLine.begin(), commandLine.end());
    cmdLineBuf.push_back(L'\0');

    PROCESS_INFORMATION pi = { 0 };
    BOOL success = FALSE;

    if (hToken != NULL) {
        success = CreateProcessAsUserW(
            hToken,
            applicationPath.empty() ? NULL : applicationPath.c_str(),
            cmdLineBuf.data(),
            NULL,
            NULL,
            FALSE,
            creationFlags,
            NULL,
            NULL,
            &siex.StartupInfo,
            &pi
        );
        if (!success) {
            DWORD err = GetLastError();
            outError = "CreateProcessAsUserW failed (code " + std::to_string(err) + "). Trying CreateProcessW fallback...";
        }
    }

    if (!success) {
        // Fallback to CreateProcessW with mitigation policies
        success = CreateProcessW(
            applicationPath.empty() ? NULL : applicationPath.c_str(),
            cmdLineBuf.data(),
            NULL,
            NULL,
            FALSE,
            creationFlags,
            NULL,
            NULL,
            &siex.StartupInfo,
            &pi
        );
        if (!success) {
            outError = "CreateProcessW failed (code " + std::to_string(GetLastError()) + ")";
            if (attrList) DeleteProcThreadAttributeList(attrList);
            if (hToken) CloseHandle(hToken);
            return false;
        }
    }

    if (attrList) {
        DeleteProcThreadAttributeList(attrList);
    }
    if (hToken) {
        CloseHandle(hToken);
    }

    outInfo.hProcess = pi.hProcess;
    outInfo.hThread = pi.hThread;
    outInfo.processId = pi.dwProcessId;
    outInfo.threadId = pi.dwThreadId;

    // 5. Assign to Job Object with ActiveProcessLimit = 1
    if (options.useJobObject) {
        HANDLE hJob = CreateJobObjectW(NULL, NULL);
        if (hJob) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
            jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            jeli.BasicLimitInformation.ActiveProcessLimit = 1;
            SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
            AssignProcessToJobObject(hJob, pi.hProcess);
            outInfo.hJob = hJob;
        }
    }

    return true;
}

bool SandboxLauncher::ResumeSandboxedProcess(SandboxProcessInfo& procInfo) {
    if (procInfo.hThread) {
        DWORD res = ResumeThread(procInfo.hThread);
        return (res != (DWORD)-1);
    }
    return false;
}

void SandboxLauncher::CleanupProcessInfo(SandboxProcessInfo& procInfo) {
    if (procInfo.hThread) {
        CloseHandle(procInfo.hThread);
        procInfo.hThread = NULL;
    }
    if (procInfo.hProcess) {
        CloseHandle(procInfo.hProcess);
        procInfo.hProcess = NULL;
    }
    if (procInfo.hJob) {
        CloseHandle(procInfo.hJob);
        procInfo.hJob = NULL;
    }
    procInfo.processId = 0;
    procInfo.threadId = 0;
}

static bool CheckFileExists(const std::wstring& path) {
    DWORD dwAttrib = GetFileAttributesW(path.c_str());
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

std::wstring SandboxLauncher::AutoDetectRealJava(const std::string& configuredPath, bool preferConsole) {
    // 1. If configuredPath is provided and valid, use it
    if (!configuredPath.empty()) {
        std::wstring wPath = util::Utf8ToWide(configuredPath);
        if (CheckFileExists(wPath)) {
            if (preferConsole) {
                // If it ends with javaw.exe, try sibling java.exe so console probes produce stdout
                size_t pos = wPath.rfind(L"javaw.exe");
                if (pos != std::wstring::npos) {
                    std::wstring consoleJava = wPath.substr(0, pos) + L"java.exe";
                    if (CheckFileExists(consoleJava)) return consoleJava;
                }
            } else {
                // If it ends with java.exe, try sibling javaw.exe
                size_t pos = wPath.rfind(L"java.exe");
                if (pos != std::wstring::npos && (pos == 0 || wPath[pos - 1] != L'w')) {
                    std::wstring guiJava = wPath.substr(0, pos) + L"javaw.exe";
                    if (CheckFileExists(guiJava)) return guiJava;
                }
            }
            return wPath;
        }
    }

    // 2. Check JAVA_HOME environment variable
    wchar_t javaHome[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"JAVA_HOME", javaHome, MAX_PATH) > 0) {
        std::wstring target = std::wstring(javaHome) + (preferConsole ? L"\\bin\\java.exe" : L"\\bin\\javaw.exe");
        if (CheckFileExists(target)) return target;
        std::wstring fallback = std::wstring(javaHome) + (preferConsole ? L"\\bin\\javaw.exe" : L"\\bin\\java.exe");
        if (CheckFileExists(fallback)) return fallback;
    }

    // 3. Scan common standard JDK installation locations
    const std::wstring searchRoots[] = {
        L"C:\\Program Files\\Microsoft\\",
        L"C:\\Program Files\\Eclipse Adoptium\\",
        L"C:\\Program Files\\Java\\",
        L"C:\\Program Files\\BellSoft\\",
        L"C:\\Program Files\\Zulu\\"
    };

    std::wstring bestCandidate;
    int bestVersion = 0;

    for (const auto& root : searchRoots) {
        std::wstring searchPattern = root + L"*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                    std::wstring candidate = root + fd.cFileName + (preferConsole ? L"\\bin\\java.exe" : L"\\bin\\javaw.exe");
                    if (CheckFileExists(candidate)) {
                        int ver = 0;
                        const wchar_t* p = wcsstr(fd.cFileName, L"jdk-");
                        if (!p) p = wcsstr(fd.cFileName, L"jdk");
                        if (p) {
                            while (*p && (*p < L'0' || *p > L'9')) p++;
                            if (*p) ver = _wtoi(p);
                        }
                        if (ver == 21) {
                            // Java 21 is modern Minecraft's target LTS version
                            FindClose(hFind);
                            return candidate;
                        }
                        if (ver > bestVersion || bestCandidate.empty()) {
                            bestVersion = ver;
                            bestCandidate = candidate;
                        }
                    }
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    if (!bestCandidate.empty()) {
        return bestCandidate;
    }

    // 4. Check system PATH
    wchar_t pathBuf[MAX_PATH] = { 0 };
    if (SearchPathW(NULL, preferConsole ? L"java.exe" : L"javaw.exe", NULL, MAX_PATH, pathBuf, NULL) > 0) {
        wchar_t currentExe[MAX_PATH] = { 0 };
        GetModuleFileNameW(NULL, currentExe, MAX_PATH);
        if (_wcsicmp(pathBuf, currentExe) != 0) {
            return std::wstring(pathBuf);
        }
    }

    return preferConsole ? L"java.exe" : L"javaw.exe";
}

int SandboxLauncher::RunJavaProbe(const std::wstring& javaExe, int argc, char* argv[]) {
    std::wstring cmdLine = L"\"" + javaExe + L"\"";
    for (int i = 1; i < argc; ++i) {
        std::wstring wArg = util::Utf8ToWide(argv[i]);
        if (wArg.find(L' ') != std::wstring::npos) {
            cmdLine += L" \"" + wArg + L"\"";
        } else {
            cmdLine += L" " + wArg;
        }
    }

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    GetStartupInfoW(&si);

    PROCESS_INFORMATION pi = { 0 };
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    // Launch real java with handle inheritance enabled so output streams directly to caller (HMCL)
    BOOL ok = CreateProcessW(
        NULL,
        cmdBuf.data(),
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!ok) {
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (int)exitCode;
}

} // namespace core
} // namespace mcguard
