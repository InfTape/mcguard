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
    bool allowInsecureFallback = false; // If CreateProcessAsUserW fails, abort instead of silently falling back
    bool denyUserSid = true;          // Mark Primary User SID as Deny-Only (Default-Deny on user files, zero SACL tagging)
    std::wstring gameDir;             // Minecraft game directory to grant Low Integrity write access to
    std::vector<std::wstring> protectedPaths; // Paths protected with No-Read-Up & No-Write-Up
};

struct SandboxProcessInfo {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    DWORD processId = 0;
    DWORD threadId = 0;
    HANDLE hJob = NULL;
    HANDLE hStdOutRead = NULL;
    HANDLE hStdErrRead = NULL;
    bool isLowIntegrity = false;
    bool privilegesStripped = false;
    bool userSidDenied = false;
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

    // Grant Full Access (BUILTIN\Users) to a folder so sandboxed process has read/write rights
    static bool GrantFullAccessToFolder(const std::wstring& folderPath);

    // Derive Java Home directory (parent of bin/) from Java executable path
    static std::wstring GetJavaHomeFromPath(const std::wstring& exePath);

    // Grant non-inheritable read/traverse access to ancestor directories of gameDir so Java toRealPath() can resolve path
    static bool GrantTraverseAccessToAncestor(const std::wstring& folderPath);
    static void GrantAncestorsTraverseAccess(const std::wstring& targetPath);

    // Grant Low-Integrity write/modify access to a directory (e.g. .minecraft or temp)
    static bool GrantLowIntegrityAccessToFolder(const std::wstring& folderPath);

    // Apply Windows Mandatory Integrity Control (MIC) No-Read-Up & No-Write-Up (NRNW) label
    // to prevent Low-Integrity processes from reading and writing to this path.
    // If targetPath is a directory, pre-existing files in it are also protected, skipping excludeDir.
    static bool ProtectPathFromLowIntegrity(const std::wstring& targetPath, const std::wstring& excludeDir = L"");

    // Apply NRNW protection to a list of paths (supports environment variables e.g. %APPDATA%)
    static void ApplyProtectedPaths(const std::vector<std::string>& paths, std::vector<std::wstring>& outApplied, const std::wstring& excludeDir = L"");

    // Restore Windows Mandatory Integrity Control (MIC) to default Medium (NW),
    // removing No-Read-Up (NR) restriction upon process exit.
    static bool RestorePathIntegrity(const std::wstring& targetPath, const std::wstring& excludeDir = L"");

    // Restore all protected paths upon exit (Clean Exit)
    static void RestoreProtectedPaths(const std::vector<std::wstring>& paths, const std::wstring& excludeDir = L"");

    // Resume a suspended sandboxed process thread after WFP/ETW attachment
    static bool ResumeSandboxedProcess(SandboxProcessInfo& procInfo);

    // Cleanup handles associated with the sandbox process
    static void CleanupProcessInfo(SandboxProcessInfo& procInfo);

    // Auto-detect system installed Java runtime
    static std::wstring AutoDetectRealJava(const std::string& configuredPath, bool preferConsole);

    // Forward a Java probe/info command synchronously with direct handle inheritance
    static int RunJavaProbe(const std::wstring& javaExe, int argc, char* argv[]);

private:
    static HANDLE CreateLowIntegrityRestrictedToken(bool stripPrivileges, bool lowIntegrity, bool denyUserSid, std::string& outError);
};

} // namespace core
} // namespace mcguard
