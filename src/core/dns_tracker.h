#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <cstdint>

namespace mcguard {
namespace core {

struct KnownSubnet {
    uint32_t network;
    uint32_t mask;
    std::string orgName;
};

class DnsTracker {
public:
    static DnsTracker& Instance();

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

private:
    DnsTracker();
    ~DnsTracker();

    void InitKnownSubnets();
    void AddSubnet(const std::string& cidr, const std::string& org);
    uint32_t Ipv4ToUint(const std::string& ip) const;

    std::unordered_map<std::string, std::string> m_ipToDomain;
    std::unordered_set<std::string> m_pendingQueries;
    std::vector<KnownSubnet> m_subnets;
    std::mutex m_mutex;
};

} // namespace core
} // namespace mcguard
