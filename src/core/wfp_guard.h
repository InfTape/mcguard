#pragma once
#include "../common.h"
#include <fwpmu.h>
#include <string>
#include <vector>
#include <mutex>
#include <cstdint>

namespace mcguard {
namespace core {

struct WhitelistRule {
    std::string description;
    std::string ip;        // e.g. "127.0.0.1" or "1.2.3.4" or empty for all IPs
    uint16_t port = 0;     // 0 means any port
    std::string protocol;  // "TCP", "UDP", "ANY"
};

class WfpGuard {
public:
    WfpGuard();
    ~WfpGuard();

    // Initialize WFP session (FWPM_SESSION_FLAG_DYNAMIC ensures automatic teardown if process exits)
    bool Initialize();

    // Attach WFP ALE rules to a specific application executable path (e.g. javaw.exe)
    bool ProtectApplication(const std::wstring& appPath, const std::vector<WhitelistRule>& whitelist);

    // Add a single runtime whitelist rule for the protected application
    bool AddWhitelistRule(const WhitelistRule& rule);

    // Remove all rules and detach from application
    void Detach();

    // Check if WFP guard is currently active
    bool IsActive() const { return m_engineHandle != NULL && m_isProtecting; }

    // Get current protected application path
    std::wstring GetProtectedAppPath() const { return m_protectedAppPath; }

    // Close WFP session
    void Shutdown();

private:
    bool CreateSubLayer();
    bool AddPermitRule(const WhitelistRule& rule, uint8_t weight);
    bool AddDefaultBlockRule(uint8_t weight);
    void RemoveInstalledFilters();

    HANDLE m_engineHandle = NULL;
    GUID m_subLayerKey = { 0 };
    FWP_BYTE_BLOB* m_appId = NULL;
    std::wstring m_protectedAppPath;
    std::vector<UINT64> m_installedFilterIds;
    std::mutex m_mutex;
    bool m_isProtecting = false;
};

} // namespace core
} // namespace mcguard
