#pragma once
#include "../common.h"
#include <string>
#include <vector>
#include <sddl.h>
#include <aclapi.h>

namespace mcguard {
namespace core {

struct SandboxOptions {
    bool useAppContainer = true;                    // Use Windows AppContainer Isolation
    std::wstring appContainerName = L"MCGuard.Sandbox";
    std::wstring appContainerDisplayName = L"MCGuard Sandbox Isolation Profile";
    std::vector<std::wstring> allowedHkcuSubkeys = { L"Software\\JavaSoft" }; // Tier B: Specific HKCU subkeys
    bool enableBroker = true;                       // Tier C: IPC Broker
    std::string brokerPipeName = "\\\\.\\pipe\\mcguard_ipc";

    bool blockChildProcesses = true;               // Restrict cmd.exe/powershell breakout
    bool useJobObject = true;                      // ActiveProcessLimit = 1
    bool startSuspended = true;                    // Suspend to bind WFP prior to first instruction
    std::wstring gameDir;                          // Minecraft game directory
    std::vector<std::wstring> additionalAllowedFolders;
};

struct SandboxProcessInfo {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    DWORD processId = 0;
    DWORD threadId = 0;
    HANDLE hJob = NULL;
    HANDLE hStdOutRead = NULL;
    HANDLE hStdErrRead = NULL;

    PSID pAppContainerSid = NULL;
    std::wstring appContainerSidStr;
    std::wstring appContainerFolder;
    std::vector<std::wstring> grantedRegistryKeys;

    std::wstring virtualDriveLetter;       // e.g. L"Z:"
    std::wstring virtualDriveTargetPath;   // e.g. L"C:\Users\Admin\Desktop\HMCL\.minecraft"
};

class SandboxLauncher {
public:
    // Virtual Drive Helpers to bypass Windows parent directory traverse checks for AppContainer
    static std::wstring FindAvailableVirtualDrive();
    static bool MapVirtualDrive(const std::wstring& targetPath, std::wstring& outDriveLetter);
    static void UnmapVirtualDrive(const std::wstring& driveLetter, const std::wstring& targetPath);
    static std::wstring ReplacePathPrefixCaseInsensitive(
        const std::wstring& text,
        const std::wstring& oldPrefix,
        const std::wstring& newPrefix
    );
    // Launch a target application inside Windows AppContainer Sandbox
    static bool LaunchSandboxedProcess(
        const std::wstring& applicationPath,
        const std::wstring& commandLine,
        const SandboxOptions& options,
        SandboxProcessInfo& outInfo,
        std::string& outError
    );

    // Resume a suspended sandboxed process thread after WFP/ETW attachment
    static bool ResumeSandboxedProcess(SandboxProcessInfo& procInfo);

    // Cleanup handles and restore registry permissions on process termination
    static void CleanupProcessInfo(SandboxProcessInfo& procInfo);

    // Derive Java Home directory (parent of bin/) from Java executable path
    static std::wstring GetJavaHomeFromPath(const std::wstring& exePath);

    // Auto-detect system installed Java runtime
    static std::wstring AutoDetectRealJava(const std::string& configuredPath, bool preferConsole);

    // Forward a Java probe/info command synchronously
    static int RunJavaProbe(const std::wstring& javaExe, int argc, char* argv[]);

    // AppContainer Profile & SID Management
    static bool CreateOrGetAppContainer(
        const std::wstring& profileName,
        const std::wstring& displayName,
        PSID* ppSid,
        std::wstring& outSidStr,
        std::wstring& outFolder,
        std::string& outError
    );

    // Tier B: Granular HKCU Subkey Access Control
    static bool GrantAppContainerRegistryAccess(
        HKEY hRoot,
        const std::wstring& subKey,
        PSID pSid,
        REGSAM access = KEY_READ
    );

    static bool RevokeAppContainerRegistryAccess(
        HKEY hRoot,
        const std::wstring& subKey,
        PSID pSid
    );

    // File Access Management for AppContainer SID
    static bool GrantAppContainerFileAccess(
        const std::wstring& targetPath,
        PSID pSid,
        DWORD accessMask,
        bool inherit = true
    );
};

} // namespace core
} // namespace mcguard
