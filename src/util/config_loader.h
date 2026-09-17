#pragma once
#include "../common.h"
#include "../core/wfp_guard.h"
#include <string>
#include <vector>

namespace mcguard {
namespace util {

struct SandboxConfig {
    bool enabled = true;
    bool blockChildProcesses = true;
    bool lowIntegrity = true;
    bool stripPrivileges = true;
    bool useJobObject = true;
    std::string realJavaPath;
};

struct ConfigData {
    std::vector<core::WhitelistRule> whitelist;
    std::vector<std::string> sensitivePatterns;
    std::vector<std::string> allowedDomainSuffixes;
    std::vector<std::string> allowedFolders;
    std::vector<std::string> protectedPaths;
    bool allowLocalhost = true;
    bool allowLan = true;
    bool allowDns = true;
    bool autoWhitelistGameDir = true;
    bool autoCloseOnExit = false;
    int autoCloseDelaySeconds = 5;
    SandboxConfig sandbox;
};

class ConfigLoader {
public:
    // Try to load config from config/mcguard.json or mcguard.json
    static bool LoadConfig(const std::string& customPath, ConfigData& outConfig);

    // Resolve a hostname (or IP) to IPv4 string
    static std::string ResolveHostToIp(const std::string& hostOrIp);
};

} // namespace util
} // namespace mcguard
