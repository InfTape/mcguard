#include "config_loader.h"
#include "string_util.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <ws2tcpip.h>

namespace mcguard {
namespace util {

std::string ConfigLoader::ResolveHostToIp(const std::string& hostOrIp) {
    if (hostOrIp.empty()) return "";

    // Check if it's already an IPv4 address
    IN_ADDR inAddr;
    if (inet_pton(AF_INET, hostOrIp.c_str(), &inAddr) == 1) {
        return hostOrIp;
    }

    // Resolve domain name via DNS
    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* pRes = NULL;
    int err = getaddrinfo(hostOrIp.c_str(), NULL, &hints, &pRes);
    if (err == 0 && pRes) {
        char ipBuffer[INET_ADDRSTRLEN] = { 0 };
        auto sockaddr_ipv4 = reinterpret_cast<struct sockaddr_in*>(pRes->ai_addr);
        if (inet_ntop(AF_INET, &(sockaddr_ipv4->sin_addr), ipBuffer, sizeof(ipBuffer))) {
            std::string resolvedIp(ipBuffer);
            freeaddrinfo(pRes);
            return resolvedIp;
        }
        freeaddrinfo(pRes);
    }
    return hostOrIp;
}

static std::string FindJsonFieldValue(const std::string& block, const std::string& key) {
    std::string pattern = "\"" + key + "\"";
    size_t pos = block.find(pattern);
    if (pos == std::string::npos) return "";

    pos += pattern.length();
    while (pos < block.length() && (block[pos] == ' ' || block[pos] == ':' || block[pos] == '\t')) {
        pos++;
    }
    if (pos >= block.length()) return "";

    if (block[pos] == '\"') {
        pos++;
        size_t end = block.find('\"', pos);
        if (end != std::string::npos) {
            return block.substr(pos, end - pos);
        }
    } else {
        size_t end = block.find_first_of(",}\r\n ", pos);
        if (end != std::string::npos) {
            return block.substr(pos, end - pos);
        }
    }
    return "";
}

bool ConfigLoader::LoadConfig(const std::string& customPath, ConfigData& outConfig) {
    std::vector<std::string> candidates;
    if (!customPath.empty()) {
        candidates.push_back(customPath);
    }

    // Check next to exe
    wchar_t exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        std::wstring wExe(exePath);
        size_t lastSlash = wExe.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            std::string dir = util::WideToUtf8(wExe.substr(0, lastSlash + 1));
            candidates.push_back(dir + "config\\mcguard.json");
            candidates.push_back(dir + "mcguard.json");
        }
    }

    // Check current directory
    candidates.push_back("config/mcguard.json");
    candidates.push_back("mcguard.json");

    std::string configContent;
    std::string loadedPath;

    for (const auto& path : candidates) {
        std::ifstream file(path);
        if (file.is_open()) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            configContent = buffer.str();
            loadedPath = path;
            break;
        }
    }

    if (configContent.empty()) {
        return false;
    }

    // Parse allow_dns
    std::string allowDnsStr = FindJsonFieldValue(configContent, "allow_dns");
    if (!allowDnsStr.empty()) {
        outConfig.allowDns = (allowDnsStr == "true");
    }

    // Parse allow_localhost
    std::string allowLocalStr = FindJsonFieldValue(configContent, "allow_localhost");
    if (!allowLocalStr.empty()) {
        outConfig.allowLocalhost = (allowLocalStr == "true");
    }

    // Parse whitelist array
    size_t wlPos = configContent.find("\"whitelist\"");
    if (wlPos != std::string::npos) {
        size_t arrStart = configContent.find('[', wlPos);
        size_t arrEnd = configContent.find(']', arrStart);
        if (arrStart != std::string::npos && arrEnd != std::string::npos) {
            std::string arrStr = configContent.substr(arrStart, arrEnd - arrStart + 1);
            size_t objStart = 0;
            while ((objStart = arrStr.find('{', objStart)) != std::string::npos) {
                size_t objEnd = arrStr.find('}', objStart);
                if (objEnd == std::string::npos) break;

                std::string objStr = arrStr.substr(objStart, objEnd - objStart + 1);

                core::WhitelistRule rule;
                rule.description = FindJsonFieldValue(objStr, "description");
                rule.protocol = FindJsonFieldValue(objStr, "protocol");
                if (rule.protocol.empty()) rule.protocol = "TCP";

                std::string hostVal = FindJsonFieldValue(objStr, "host");
                std::string ipVal = FindJsonFieldValue(objStr, "ip");
                std::string portStr = FindJsonFieldValue(objStr, "port");

                if (!portStr.empty()) {
                    try { rule.port = (uint16_t)std::stoi(portStr); } catch (...) { rule.port = 25565; }
                } else {
                    rule.port = 25565;
                }

                // If host specified, resolve it; or if ip is a domain, resolve it
                std::string targetHost = !hostVal.empty() ? hostVal : ipVal;
                if (!targetHost.empty()) {
                    std::string resolved = ResolveHostToIp(targetHost);
                    rule.ip = resolved;
                    if (rule.description.empty()) {
                        rule.description = targetHost;
                    } else if (resolved != targetHost) {
                        rule.description += " (" + targetHost + " -> " + resolved + ")";
                    }
                    outConfig.whitelist.push_back(rule);
                }

                objStart = objEnd + 1;
            }
        }
    }

    // Parse sensitive_patterns
    size_t spPos = configContent.find("\"sensitive_patterns\"");
    if (spPos != std::string::npos) {
        size_t arrStart = configContent.find('[', spPos);
        size_t arrEnd = configContent.find(']', arrStart);
        if (arrStart != std::string::npos && arrEnd != std::string::npos) {
            std::string arrStr = configContent.substr(arrStart, arrEnd - arrStart + 1);
            size_t strPos = 0;
            while ((strPos = arrStr.find('\"', strPos)) != std::string::npos) {
                size_t end = arrStr.find('\"', strPos + 1);
                if (end == std::string::npos) break;
                std::string pattern = arrStr.substr(strPos + 1, end - strPos - 1);
                if (!pattern.empty()) {
                    outConfig.sensitivePatterns.push_back(pattern);
                }
                strPos = end + 1;
            }
        }
    }

    // Parse allowed_domain_suffixes
    size_t dsPos = configContent.find("\"allowed_domain_suffixes\"");
    if (dsPos == std::string::npos) {
        dsPos = configContent.find("\"domain_suffixes\"");
    }
    if (dsPos != std::string::npos) {
        size_t arrStart = configContent.find('[', dsPos);
        size_t arrEnd = configContent.find(']', arrStart);
        if (arrStart != std::string::npos && arrEnd != std::string::npos) {
            std::string arrStr = configContent.substr(arrStart, arrEnd - arrStart + 1);
            size_t strPos = 0;
            while ((strPos = arrStr.find('\"', strPos)) != std::string::npos) {
                size_t end = arrStr.find('\"', strPos + 1);
                if (end == std::string::npos) break;
                std::string suffix = arrStr.substr(strPos + 1, end - strPos - 1);
                if (!suffix.empty()) {
                    outConfig.allowedDomainSuffixes.push_back(suffix);
                }
                strPos = end + 1;
            }
        }
    }

    return true;
}

} // namespace util
} // namespace mcguard
