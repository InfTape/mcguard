#include "dns_tracker.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "Ws2_32.lib")

namespace mcguard {
namespace core {

DnsTracker& DnsTracker::Instance() {
    static DnsTracker instance;
    return instance;
}

static std::string ToLowerString(const std::string& str) {
    std::string s = str;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

DnsTracker::DnsTracker() {
    InitKnownSubnets();

    // Default allowed domain suffixes as requested
    AddAllowedDomainSuffix("mojang.com");
    AddAllowedDomainSuffix("minecraft.net");
    AddAllowedDomainSuffix("minecraftservices.com");
}

DnsTracker::~DnsTracker() {}

void DnsTracker::AddAllowedDomainSuffix(const std::string& suffix) {
    if (suffix.empty()) return;
    std::string s = ToLowerString(suffix);
    if (s.front() == '.') s = s.substr(1);
    if (!s.empty() && s.back() == '.') s.pop_back();

    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& existing : m_allowedSuffixes) {
        if (existing == s) return;
    }
    m_allowedSuffixes.push_back(s);
}

void DnsTracker::ClearAllowedDomainSuffixes() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_allowedSuffixes.clear();
}

bool DnsTracker::IsDomainWhitelisted(const std::string& domain) const {
    if (domain.empty()) return false;
    std::string lowerDomain = ToLowerString(domain);
    if (!lowerDomain.empty() && lowerDomain.back() == '.') lowerDomain.pop_back();

    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& suffix : m_allowedSuffixes) {
        if (lowerDomain == suffix) return true;

        // Subdomain check with dot boundary (e.g. "api.minecraftservices.com" ends with ".minecraftservices.com")
        if (lowerDomain.length() > suffix.length()) {
            size_t offset = lowerDomain.length() - suffix.length();
            if (lowerDomain[offset - 1] == '.' && lowerDomain.substr(offset) == suffix) {
                return true;
            }
        }
    }
    return false;
}

uint32_t DnsTracker::Ipv4ToUint(const std::string& ip) const {
    in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
        return ntohl(addr.s_addr);
    }
    return 0;
}

void DnsTracker::AddSubnet(const std::string& cidr, const std::string& org) {
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) return;

    std::string baseIp = cidr.substr(0, slash);
    int prefixLen = std::stoi(cidr.substr(slash + 1));
    if (prefixLen <= 0 || prefixLen > 32) return;

    uint32_t mask = (prefixLen == 32) ? 0xFFFFFFFF : ~((1ULL << (32 - prefixLen)) - 1);
    uint32_t net = Ipv4ToUint(baseIp) & mask;
    m_subnets.push_back({ net, mask, org });
}

void DnsTracker::InitKnownSubnets() {
    // 1. Microsoft / Azure / Mojang Telemetry & Services
    AddSubnet("150.171.0.0/16", "Microsoft");
    AddSubnet("13.64.0.0/11", "Microsoft / Azure");
    AddSubnet("20.0.0.0/8", "Microsoft / Azure");
    AddSubnet("40.64.0.0/10", "Microsoft / Azure");
    AddSubnet("52.96.0.0/12", "Microsoft / Azure");
    AddSubnet("52.145.0.0/16", "Microsoft / Azure");
    AddSubnet("104.40.0.0/13", "Microsoft / Azure");
    AddSubnet("204.79.197.0/24", "Microsoft / Bing");
    AddSubnet("51.103.0.0/16", "Microsoft / Azure");
    AddSubnet("51.104.0.0/16", "Microsoft / Azure");
    AddSubnet("51.105.0.0/16", "Microsoft / Azure");

    // 2. Dropbox (Cloud sync / Mod updater hosting)
    AddSubnet("108.160.160.0/20", "Dropbox");
    AddSubnet("162.125.0.0/16", "Dropbox");

    // 3. Cloudflare (Hypixel, CurseForge, Skin CDNs, Mod Author Domains)
    AddSubnet("104.16.0.0/13", "Cloudflare");
    AddSubnet("104.24.0.0/14", "Cloudflare");
    AddSubnet("172.64.0.0/13", "Cloudflare");
    AddSubnet("162.158.0.0/15", "Cloudflare");
    AddSubnet("108.162.192.0/18", "Cloudflare");
    AddSubnet("198.41.128.0/17", "Cloudflare");
    AddSubnet("141.101.64.0/18", "Cloudflare");
    AddSubnet("190.93.240.0/20", "Cloudflare");
    AddSubnet("188.114.96.0/20", "Cloudflare");
    AddSubnet("197.234.240.0/22", "Cloudflare");

    // 4. Amazon Web Services / CloudFront CDN
    AddSubnet("13.32.0.0/15", "AWS / CloudFront");
    AddSubnet("13.35.0.0/16", "AWS / CloudFront");
    AddSubnet("13.224.0.0/14", "AWS / CloudFront");
    AddSubnet("18.0.0.0/9", "AWS");
    AddSubnet("3.0.0.0/9", "AWS");
    AddSubnet("52.0.0.0/11", "AWS");
    AddSubnet("54.0.0.0/11", "AWS");
    AddSubnet("99.84.0.0/16", "AWS / CloudFront");
    AddSubnet("143.204.0.0/16", "AWS / CloudFront");

    // 5. Fastly CDN (GitHub releases, Fabric/Quilt maven mirrors)
    AddSubnet("151.101.0.0/16", "Fastly CDN");
    AddSubnet("199.232.0.0/16", "Fastly CDN");
    AddSubnet("146.75.0.0/16", "Fastly CDN");

    // 6. Google Cloud
    AddSubnet("142.250.0.0/15", "Google");
    AddSubnet("172.217.0.0/16", "Google");
    AddSubnet("216.58.192.0/19", "Google");
    AddSubnet("34.0.0.0/9", "Google Cloud");
    AddSubnet("35.184.0.0/13", "Google Cloud");

    // 7. Alibaba Cloud / Tencent Cloud
    AddSubnet("47.74.0.0/15", "Alibaba Cloud");
    AddSubnet("47.88.0.0/14", "Alibaba Cloud");
    AddSubnet("120.0.0.0/8", "Alibaba Cloud");
    AddSubnet("106.14.0.0/15", "Alibaba Cloud");
    AddSubnet("43.128.0.0/12", "Tencent Cloud");
    AddSubnet("119.28.0.0/15", "Tencent Cloud");
    AddSubnet("129.226.0.0/16", "Tencent Cloud");
}

void DnsTracker::RegisterResolution(const std::string& domain, const std::string& ip) {
    if (ip.empty() || domain.empty()) return;

    std::string cleanDomain = domain;
    if (!cleanDomain.empty() && cleanDomain.back() == '.') {
        cleanDomain.pop_back();
    }

    bool shouldWhitelist = IsDomainWhitelisted(cleanDomain);
    bool isNewWhitelistedIp = false;

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_ipToDomain[ip] = cleanDomain;

        if (shouldWhitelist && m_whitelistedIps.find(ip) == m_whitelistedIps.end()) {
            m_whitelistedIps.insert(ip);
            isNewWhitelistedIp = true;
        }
    }

    if (isNewWhitelistedIp && m_whitelistCb) {
        m_whitelistCb(cleanDomain, ip);
    }
}

void DnsTracker::RegisterResolution(const std::string& domain, const std::vector<std::string>& ips) {
    for (const auto& ip : ips) {
        RegisterResolution(domain, ip);
    }
}

void DnsTracker::ParseAndRegisterDnsResults(const std::string& domain, const std::string& queryResults) {
    if (domain.empty() || queryResults.empty()) return;

    // Tokens in QueryResults are separated by spaces or semicolons
    std::string token;
    std::stringstream ss(queryResults);
    while (std::getline(ss, token, ';')) {
        std::stringstream inner(token);
        std::string part;
        while (inner >> part) {
            // Check if part looks like an IPv4 address (contains 3 dots and only digits)
            size_t dotCount = 0;
            bool validIpv4 = true;
            for (char c : part) {
                if (c == '.') dotCount++;
                else if (!std::isdigit((unsigned char)c)) {
                    validIpv4 = false;
                    break;
                }
            }
            if (validIpv4 && dotCount == 3) {
                in_addr addr;
                if (inet_pton(AF_INET, part.c_str(), &addr) == 1) {
                    RegisterResolution(domain, part);
                }
            }
        }
    }
}

std::string DnsTracker::GetDomain(const std::string& ip) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_ipToDomain.find(ip);
    if (it != m_ipToDomain.end()) {
        return it->second;
    }
    return "";
}

std::string DnsTracker::GetOrganization(const std::string& ip) {
    uint32_t ipVal = Ipv4ToUint(ip);
    if (ipVal == 0) return "";

    for (const auto& sub : m_subnets) {
        if ((ipVal & sub.mask) == sub.network) {
            return sub.orgName;
        }
    }
    return "";
}

void DnsTracker::AsyncResolvePtr(const std::string& ip) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_pendingQueries.find(ip) != m_pendingQueries.end()) return;
        m_pendingQueries.insert(ip);
    }

    std::thread([this, ip]() {
        sockaddr_in sa = { 0 };
        sa.sin_family = AF_INET;
        if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) == 1) {
            char host[NI_MAXHOST] = { 0 };
            if (getnameinfo((sockaddr*)&sa, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD) == 0) {
                std::string domain(host);
                if (!domain.empty()) {
                    RegisterResolution(domain, ip);
                }
            }
        }
    }).detach();
}

std::string DnsTracker::FormatTarget(const std::string& ip, uint16_t port) {
    if (ip == "127.0.0.1" || ip == "localhost") {
        return ip + ":" + std::to_string(port) + " (Localhost)";
    }

    std::string domain = GetDomain(ip);
    if (!domain.empty()) {
        return ip + ":" + std::to_string(port) + " (" + domain + ")";
    }

    // Try Organization / ASN
    std::string org = GetOrganization(ip);

    // Trigger async PTR resolution in the background
    AsyncResolvePtr(ip);

    if (!org.empty()) {
        return ip + ":" + std::to_string(port) + " [" + org + "]";
    }

    return ip + ":" + std::to_string(port);
}

void DnsTracker::PreResolveCommonEndpoints() {
    std::vector<std::string> endpoints = {
        "api.minecraftservices.com",
        "sessionserver.mojang.com",
        "authserver.mojang.com",
        "launchermeta.mojang.com",
        "pc.realms.minecraft.net",
        "libraries.minecraft.net",
        "textures.minecraft.net",
        "skins.minecraft.net",
        "piston-meta.mojang.com",
        "launcher.mojang.com"
    };

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (const auto& suffix : m_allowedSuffixes) {
            bool exists = false;
            for (const auto& ep : endpoints) {
                if (ep == suffix) { exists = true; break; }
            }
            if (!exists) {
                endpoints.push_back(suffix);
            }
        }
    }

    std::thread([this, endpoints]() {
        struct addrinfo hints = { 0 };
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        for (const auto& ep : endpoints) {
            struct addrinfo* pRes = NULL;
            int err = getaddrinfo(ep.c_str(), NULL, &hints, &pRes);
            if (err == 0 && pRes) {
                for (auto p = pRes; p != NULL; p = p->ai_next) {
                    char ipStr[INET_ADDRSTRLEN] = { 0 };
                    auto sIn = reinterpret_cast<sockaddr_in*>(p->ai_addr);
                    if (inet_ntop(AF_INET, &sIn->sin_addr, ipStr, sizeof(ipStr))) {
                        RegisterResolution(ep, std::string(ipStr));
                    }
                }
                freeaddrinfo(pRes);
            }
        }
    }).detach();
}

} // namespace core
} // namespace mcguard
