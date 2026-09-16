#pragma once
#include "etw_watcher.h"
#include "wfp_guard.h"
#include "module_tracker.h"
#include <string>
#include <vector>
#include <functional>

namespace mcguard {
namespace core {

enum class AuditAction {
    ALLOW,
    BLOCK,
    AUDIT,
    ALERT
};

struct AuditRecord {
    std::string timestamp;
    DWORD pid = 0;
    std::string type;     // "TCP_OUT", "FILE_READ", "FILE_WRITE", "FILE_CREATE", "FILE_DELETE", "DLL_LOAD"
    std::string target;   // "1.2.3.4:25565", "C:\...", "suspicious.dll"
    AuditAction action;   // ALLOW, BLOCK, AUDIT, ALERT
    std::string source;   // "Minecraft Network", "Minecraft Game Data", "Suspicious Native Access", etc.
    std::string details;
    bool isSensitive = false;
};

class Correlator {
public:
    using AuditCallback = std::function<void(const AuditRecord& record)>;

    Correlator();
    ~Correlator();

    void SetSensitivePatterns(const std::vector<std::string>& patterns);
    void SetWhitelistRules(const std::vector<WhitelistRule>& whitelist);
    void AddWhitelistRule(const WhitelistRule& rule);
    void SetAuditCallback(AuditCallback cb) { m_callback = cb; }

    // Feed events from ETW
    void OnEtwEvent(const EtwEvent& ev);

    // Feed events from Module Tracker
    void OnModuleLoaded(DWORD pid, const LoadedModuleInfo& mod);

    // Feed events from Game Directory Watcher
    void OnFolderEvent(DWORD pid, const std::wstring& filePath, const std::string& opTypeStr);

    // Feed events from Active Network Tracker
    void OnNetworkConnection(DWORD pid, const std::string& remoteIp, uint16_t remotePort);

    // Feed synthetic or test event
    void PostAuditRecord(const AuditRecord& record);

    bool IsTargetWhitelisted(const std::string& target);
    bool IsSensitiveFile(const std::string& path);

    // Folder whitelist API
    void SetFolderWhitelistEnforced(bool enforced);
    void AddAllowedFolder(const std::wstring& folderPath, const std::string& description = "Allowed Folder");
    void ClearAllowedFolders();
    bool IsPathInFolderWhitelist(const std::wstring& filePath, std::string& outCategory);

private:
    std::string ClassifyFileSource(const std::string& path);

    struct FolderWhitelistEntry {
        std::wstring normalizedPrefix;
        std::string description;
    };

    std::vector<std::string> m_sensitivePatterns;
    std::vector<WhitelistRule> m_whitelist;
    std::vector<FolderWhitelistEntry> m_folderWhitelist;
    std::mutex m_rulesMutex;
    std::mutex m_folderMutex;
    bool m_enforceFolderWhitelist = true;
    AuditCallback m_callback;
};

} // namespace core
} // namespace mcguard
