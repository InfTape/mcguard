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

    // Ensure Winsock initialized
    WSADATA wsaData;
    bool wsaInit = (WSAStartup(MAKEWORD(2, 2), &wsaData) == 0);

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
            if (wsaInit) WSACleanup();
            return resolvedIp;
        }
        freeaddrinfo(pRes);
    }
    if (wsaInit) WSACleanup();
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

    // Parse allow_lan
    std::string allowLanStr = FindJsonFieldValue(configContent, "allow_lan");
    if (!allowLanStr.empty()) {
        outConfig.allowLan = (allowLanStr == "true");
    }

    // Parse allowed_domain_suffixes first
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

                std::string hostVal = FindJsonFieldValue(objStr, "host");
                std::string ipVal = FindJsonFieldValue(objStr, "ip");
                std::string portStr = FindJsonFieldValue(objStr, "port");

                // Check if ipVal is a valid IPv4 address or CIDR subnet
                uint32_t subnetHost = 0, maskHost = 0;
                bool isCidr = false;
                bool ipValValid = !ipVal.empty() && util::ParseIpOrCidr(ipVal, subnetHost, maskHost, isCidr);

                if (!portStr.empty()) {
                    try { rule.port = (uint16_t)std::stoi(portStr); } catch (...) { rule.port = isCidr ? 0 : 25565; }
                } else {
                    rule.port = isCidr ? 0 : 25565;
                }

                if (rule.protocol.empty()) {
                    rule.protocol = isCidr ? "ANY" : "TCP";
                }

                if (ipValValid) {
                    rule.ip = ipVal;
                    if (rule.description.empty()) {
                        rule.description = !hostVal.empty() ? hostVal : ipVal;
                    }
                    if (!hostVal.empty() && rule.description.find(hostVal) == std::string::npos) {
                        rule.description += " (" + hostVal + " -> " + ipVal + ")";
                    }
                } else {
                    std::string targetHost = !hostVal.empty() ? hostVal : ipVal;
                    if (!targetHost.empty()) {
                        std::string resolved = ResolveHostToIp(targetHost);
                        rule.ip = resolved;
                        if (rule.description.empty()) {
                            rule.description = targetHost;
                        } else if (resolved != targetHost) {
                            rule.description += " (" + targetHost + " -> " + resolved + ")";
                        }
                    }
                }

                if (!rule.ip.empty()) {
                    outConfig.whitelist.push_back(rule);
                }

                // If hostVal is provided, also ensure it's in allowedDomainSuffixes so dynamic DNS / SRV / ports are whitelisted
                if (!hostVal.empty()) {
                    bool exists = false;
                    for (const auto& s : outConfig.allowedDomainSuffixes) {
                        if (s == hostVal) { exists = true; break; }
                    }
                    if (!exists) {
                        outConfig.allowedDomainSuffixes.push_back(hostVal);
                    }
                }

                objStart = objEnd + 1;
            }
        }
    }

    // If allowLan is enabled, ensure RFC 1918 private subnets are in whitelist
    if (outConfig.allowLan) {
        const std::pair<std::string, std::string> lanSubnets[] = {
            {"192.168.0.0/16", "LAN Private Subnet (192.168.0.0/16)"},
            {"10.0.0.0/8", "LAN Private Subnet (10.0.0.0/8)"},
            {"172.16.0.0/12", "LAN Private Subnet (172.16.0.0/12)"}
        };
        for (const auto& item : lanSubnets) {
            bool exists = false;
            for (const auto& r : outConfig.whitelist) {
                if (r.ip == item.first) { exists = true; break; }
            }
            if (!exists) {
                core::WhitelistRule rule;
                rule.description = item.second;
                rule.ip = item.first;
                rule.port = 0;
                rule.protocol = "ANY";
                outConfig.whitelist.push_back(rule);
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

    // Parse auto_whitelist_game_dir
    std::string autoWlStr = FindJsonFieldValue(configContent, "auto_whitelist_game_dir");
    if (!autoWlStr.empty()) {
        outConfig.autoWhitelistGameDir = (autoWlStr == "true");
    }

    // Parse allowed_folders
    size_t afPos = configContent.find("\"allowed_folders\"");
    if (afPos != std::string::npos) {
        size_t arrStart = configContent.find('[', afPos);
        size_t arrEnd = configContent.find(']', arrStart);
        if (arrStart != std::string::npos && arrEnd != std::string::npos) {
            std::string arrStr = configContent.substr(arrStart, arrEnd - arrStart + 1);
            size_t strPos = 0;
            while ((strPos = arrStr.find('\"', strPos)) != std::string::npos) {
                size_t end = arrStr.find('\"', strPos + 1);
                if (end == std::string::npos) break;
                std::string folder = arrStr.substr(strPos + 1, end - strPos - 1);
                if (!folder.empty()) {
                    outConfig.allowedFolders.push_back(folder);
                }
                strPos = end + 1;
            }
        }
    }

    // Parse sandbox settings
    size_t sbPos = configContent.find("\"sandbox\"");
    if (sbPos != std::string::npos) {
        size_t objStart = configContent.find('{', sbPos);
        size_t objEnd = configContent.find('}', objStart);
        if (objStart != std::string::npos && objEnd != std::string::npos) {
            std::string sbStr = configContent.substr(objStart, objEnd - objStart + 1);
            std::string en = FindJsonFieldValue(sbStr, "enabled");
            if (!en.empty()) outConfig.sandbox.enabled = (en == "true");

            std::string bcp = FindJsonFieldValue(sbStr, "block_child_processes");
            if (!bcp.empty()) outConfig.sandbox.blockChildProcesses = (bcp == "true");

            std::string ujo = FindJsonFieldValue(sbStr, "use_job_object");
            if (!ujo.empty()) outConfig.sandbox.useJobObject = (ujo == "true");

            std::string rjp = FindJsonFieldValue(sbStr, "real_java_path");
            if (!rjp.empty()) outConfig.sandbox.realJavaPath = rjp;
        }
    }

    // Parse appcontainer settings
    size_t acPos = configContent.find("\"appcontainer\"");
    if (acPos == std::string::npos) {
        acPos = configContent.find("\"app_container\"");
    }
    if (acPos != std::string::npos) {
        size_t objStart = configContent.find('{', acPos);
        size_t objEnd = configContent.find('}', objStart);
        if (objStart != std::string::npos && objEnd != std::string::npos) {
            std::string acStr = configContent.substr(objStart, objEnd - objStart + 1);
            std::string en = FindJsonFieldValue(acStr, "enabled");
            if (!en.empty()) outConfig.appContainer.enabled = (en == "true");

            std::string pn = FindJsonFieldValue(acStr, "profile_name");
            if (!pn.empty()) outConfig.appContainer.profileName = pn;

            std::string eb = FindJsonFieldValue(acStr, "enable_broker");
            if (!eb.empty()) outConfig.appContainer.enableBroker = (eb == "true");

            // Parse allowed_hkcu_keys
            size_t hkPos = acStr.find("\"allowed_hkcu_keys\"");
            if (hkPos != std::string::npos) {
                size_t arrStart = acStr.find('[', hkPos);
                size_t arrEnd = acStr.find(']', arrStart);
                if (arrStart != std::string::npos && arrEnd != std::string::npos) {
                    outConfig.appContainer.allowedHkcuKeys.clear();
                    std::string arrStr = acStr.substr(arrStart, arrEnd - arrStart + 1);
                    size_t strPos = 0;
                    while ((strPos = arrStr.find('\"', strPos)) != std::string::npos) {
                        size_t end = arrStr.find('\"', strPos + 1);
                        if (end == std::string::npos) break;
                        std::string k = arrStr.substr(strPos + 1, end - strPos - 1);
                        if (!k.empty()) outConfig.appContainer.allowedHkcuKeys.push_back(k);
                        strPos = end + 1;
                    }
                }
            }

            // Parse broker_allowed_keys
            size_t bakPos = acStr.find("\"broker_allowed_keys\"");
            if (bakPos != std::string::npos) {
                size_t arrStart = acStr.find('[', bakPos);
                size_t arrEnd = acStr.find(']', arrStart);
                if (arrStart != std::string::npos && arrEnd != std::string::npos) {
                    outConfig.appContainer.brokerAllowedKeys.clear();
                    std::string arrStr = acStr.substr(arrStart, arrEnd - arrStart + 1);
                    size_t strPos = 0;
                    while ((strPos = arrStr.find('\"', strPos)) != std::string::npos) {
                        size_t end = arrStr.find('\"', strPos + 1);
                        if (end == std::string::npos) break;
                        std::string k = arrStr.substr(strPos + 1, end - strPos - 1);
                        if (!k.empty()) outConfig.appContainer.brokerAllowedKeys.push_back(k);
                        strPos = end + 1;
                    }
                }
            }
        }
    }

    // Parse auto_close settings
    std::string autoCloseStr = FindJsonFieldValue(configContent, "auto_close_on_exit");
    if (autoCloseStr.empty()) {
        autoCloseStr = FindJsonFieldValue(configContent, "auto_close");
    }
    if (!autoCloseStr.empty()) {
        outConfig.autoCloseOnExit = (autoCloseStr == "true");
    }

    std::string autoCloseDelayStr = FindJsonFieldValue(configContent, "auto_close_delay");
    if (autoCloseDelayStr.empty()) {
        autoCloseDelayStr = FindJsonFieldValue(configContent, "auto_close_delay_seconds");
    }
    if (!autoCloseDelayStr.empty()) {
        try {
            outConfig.autoCloseDelaySeconds = std::stoi(autoCloseDelayStr);
        } catch (...) {}
    }

    return true;
}

} // namespace util
} // namespace mcguard
