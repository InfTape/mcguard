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

} // namespace core
} // namespace mcguard
