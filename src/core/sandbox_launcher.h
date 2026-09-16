#pragma once
#include "../common.h"
#include <string>
#include <vector>
#include <sddl.h>
#include <aclapi.h>

namespace mcguard {
namespace core {

struct SandboxOptions {
    bool blockChildProcesses = true;  // PROCESS_CREATION_CHILD_PROCESS_RESTRICTED
    bool lowIntegrity = true;         // Demote to Low Integrity Level (S-1-16-4096)
    bool stripPrivileges = true;      // DISABLE_MAX_PRIVILEGE via CreateRestrictedToken
    bool useJobObject = true;         // ActiveProcessLimit = 1
    bool startSuspended = true;       // Launch in suspended state to allow pre-flight WFP binding
    std::wstring gameDir;             // Minecraft game directory to grant Low Integrity write access to
};

struct SandboxProcessInfo {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    DWORD processId = 0;
    DWORD threadId = 0;
    HANDLE hJob = NULL;
};

class SandboxLauncher {
public:
    // Launch a target application inside a Windows Restricted Sandbox
    static bool LaunchSandboxedProcess(
        const std::wstring& applicationPath,
        const std::wstring& commandLine,
        const SandboxOptions& options,
        SandboxProcessInfo& outInfo,
        std::string& outError
    );

    // Grant Low-Integrity write/modify access to a directory (e.g. .minecraft or temp)
    static bool GrantLowIntegrityAccessToFolder(const std::wstring& folderPath);

    // Resume a suspended sandboxed process thread after WFP/ETW attachment
    static bool ResumeSandboxedProcess(SandboxProcessInfo& procInfo);

    // Cleanup handles associated with the sandbox process
    static void CleanupProcessInfo(SandboxProcessInfo& procInfo);

private:
    static HANDLE CreateLowIntegrityRestrictedToken(bool stripPrivileges, bool lowIntegrity, std::string& outError);
};

} // namespace core
} // namespace mcguard
