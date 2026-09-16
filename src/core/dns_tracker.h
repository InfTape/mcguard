#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <cstdint>
#include <functional>

namespace mcguard {
namespace core {

struct KnownSubnet {
    uint32_t network;
    uint32_t mask;
    std::string orgName;
};

class DnsTracker {
public:
    using WhitelistIpCallback = std::function<void(const std::string& domain, const std::string& ip)>;

    static DnsTracker& Instance();

    // Whitelisted domain suffixes (e.g. "mojang.com", "minecraft.net", "minecraftservices.com")
    void AddAllowedDomainSuffix(const std::string& suffix);
    void ClearAllowedDomainSuffixes();
    bool IsDomainWhitelisted(const std::string& domain) const;
    const std::vector<std::string>& GetAllowedDomainSuffixes() const { return m_allowedSuffixes; }

    // Register dynamic whitelist callback
    void SetWhitelistIpCallback(WhitelistIpCallback cb) { m_whitelistCb = cb; }

    // Register a domain-to-IP resolution mapping
    void RegisterResolution(const std::string& domain, const std::string& ip);
    void RegisterResolution(const std::string& domain, const std::vector<std::string>& ips);

    // Parse ETW QueryResults string (e.g. "type: 1 108.160.172.204;") and register
    void ParseAndRegisterDnsResults(const std::string& domain, const std::string& queryResults);

    // Format target (e.g. "108.160.172.204:443 (client.v.dropbox.com)" or "150.171.110.136:80 [Microsoft]")
    std::string FormatTarget(const std::string& ip, uint16_t port);

    // Query domain for IP if known
    std::string GetDomain(const std::string& ip);

    // Query organization / ASN for IP if known
    std::string GetOrganization(const std::string& ip);

    // Asynchronously trigger reverse DNS (PTR) lookup
    void AsyncResolvePtr(const std::string& ip);

    // Pre-resolve common Mojang & Minecraft services at startup
    void PreResolveCommonEndpoints();

private:
    DnsTracker();
    ~DnsTracker();

    void InitKnownSubnets();
    void AddSubnet(const std::string& cidr, const std::string& org);
    uint32_t Ipv4ToUint(const std::string& ip) const;

    std::unordered_map<std::string, std::string> m_ipToDomain;
    std::unordered_set<std::string> m_whitelistedIps;
    std::unordered_set<std::string> m_pendingQueries;
    std::vector<std::string> m_allowedSuffixes;
    std::vector<KnownSubnet> m_subnets;
    WhitelistIpCallback m_whitelistCb;
    mutable std::mutex m_mutex;
};

} // namespace core
} // namespace mcguard
