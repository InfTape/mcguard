#include "correlator.h"
#include "dns_tracker.h"
#include "../util/string_util.h"
#include <algorithm>

namespace mcguard {
namespace core {

static std::wstring NormalizeFolderPath(const std::wstring& raw) {
    std::wstring p = raw;
    for (auto& c : p) {
        if (c == L'/') c = L'\\';
        c = (wchar_t)towlower(c);
    }
    while (p.length() > 3 && p.back() == L'\\') {
        p.pop_back();
    }
    return p;
}

Correlator::Correlator() {
    m_sensitivePatterns = {
        ".ssh", "id_rsa", "id_ed25519", "servers.dat", "launcher_profiles.json",
        "Cookies", "Login Data", "Local State", "tokens.json", "Discord",
        "Chrome\\User Data", "Edge\\User Data"
    };

    // Standard Windows runtime folders in whitelist
    wchar_t winDir[MAX_PATH] = { 0 };
    if (GetWindowsDirectoryW(winDir, MAX_PATH)) {
        AddAllowedFolder(winDir, "Windows System");
    }
    wchar_t progFiles[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"ProgramFiles", progFiles, MAX_PATH)) {
        AddAllowedFolder(progFiles, "Program Files");
    }
    wchar_t progFilesX86[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"ProgramFiles(x86)", progFilesX86, MAX_PATH)) {
        AddAllowedFolder(progFilesX86, "Program Files (x86)");
    }
    wchar_t tempDir[MAX_PATH] = { 0 };
    if (GetTempPathW(MAX_PATH, tempDir)) {
        AddAllowedFolder(tempDir, "Temp / Native Cache");
    }
}

Correlator::~Correlator() {}

void Correlator::SetFolderWhitelistEnforced(bool enforced) {
    m_enforceFolderWhitelist = enforced;
}

void Correlator::ClearAllowedFolders() {
    std::lock_guard<std::mutex> lock(m_folderMutex);
    m_folderWhitelist.clear();
}

void Correlator::AddAllowedFolder(const std::wstring& folderPath, const std::string& description) {
    if (folderPath.empty()) return;
    std::wstring norm = NormalizeFolderPath(folderPath);

    std::lock_guard<std::mutex> lock(m_folderMutex);
    for (const auto& entry : m_folderWhitelist) {
        if (entry.normalizedPrefix == norm) return;
    }
    m_folderWhitelist.push_back({ norm, description.empty() ? "Allowed Folder" : description });
}

bool Correlator::IsPathInFolderWhitelist(const std::wstring& filePath, std::string& outCategory) {
    if (filePath.empty()) return true;

    // Special handles or device paths
    if (filePath.find(L"[Unknown") != std::wstring::npos) {
        outCategory = "Win32 Handle";
        return true;
    }

    std::wstring normFile = NormalizeFolderPath(filePath);

    std::lock_guard<std::mutex> lock(m_folderMutex);
    for (const auto& entry : m_folderWhitelist) {
        if (entry.normalizedPrefix.empty()) continue;

        if (normFile.rfind(entry.normalizedPrefix, 0) == 0) {
            // Check boundary: exact match or followed by backslash
            if (normFile.length() == entry.normalizedPrefix.length() ||
                normFile[entry.normalizedPrefix.length()] == L'\\') {
                outCategory = entry.description;
                return true;
            }
        }
    }
    return false;
}

void Correlator::SetSensitivePatterns(const std::vector<std::string>& patterns) {
    m_sensitivePatterns = patterns;
}

void Correlator::SetWhitelistRules(const std::vector<WhitelistRule>& whitelist) {
    std::lock_guard<std::mutex> lock(m_rulesMutex);
    m_whitelist = whitelist;
}

void Correlator::AddWhitelistRule(const WhitelistRule& rule) {
    std::lock_guard<std::mutex> lock(m_rulesMutex);
    for (const auto& r : m_whitelist) {
        if (r.ip == rule.ip && r.port == rule.port && r.protocol == rule.protocol) {
            return;
        }
    }
    m_whitelist.push_back(rule);
}

bool Correlator::IsSensitiveFile(const std::string& path) {
    for (const auto& pattern : m_sensitivePatterns) {
        if (util::ContainsIgnoreCase(path, pattern)) {
            return true;
        }
    }
    return false;
}

bool Correlator::IsTargetWhitelisted(const std::string& target) {
    size_t colon = target.rfind(':');
    std::string targetIp = (colon != std::string::npos) ? target.substr(0, colon) : target;
    uint16_t targetPort = 0;
    if (colon != std::string::npos) {
        try { targetPort = (uint16_t)std::stoi(target.substr(colon + 1)); } catch (...) { targetPort = 0; }
    }

    // Localhost always allowed
    if (targetIp == "127.0.0.1" || targetIp == "localhost" || target.find("127.0.0.1") != std::string::npos) {
        return true;
    }

    {
        std::lock_guard<std::mutex> lock(m_rulesMutex);
        for (const auto& rule : m_whitelist) {
            if (rule.ip.empty() && rule.port == 0) continue;

            bool ipMatch = false;
            if (rule.ip.empty()) {
                ipMatch = true;
            } else if (rule.ip.find('/') != std::string::npos) {
                // CIDR subnet match
                ipMatch = util::IsIpInCidr(targetIp, rule.ip);
            } else {
                // Exact IP or substring match
                ipMatch = (targetIp == rule.ip) || (target.find(rule.ip) != std::string::npos);
            }

            bool portMatch = (rule.port == 0) || (targetPort > 0 && targetPort == rule.port) || (target.find(":" + std::to_string(rule.port)) != std::string::npos);

            if (ipMatch && portMatch) {
                return true;
            }
        }
    }

    // Secondary check: Has DnsTracker recorded a whitelisted domain for this IP?
    std::string domain = DnsTracker::Instance().GetDomain(targetIp);
    if (!domain.empty() && DnsTracker::Instance().IsDomainWhitelisted(domain)) {
        return true;
    }

    return false;
}

std::string Correlator::ClassifyFileSource(const std::string& path) {
    if (IsSensitiveFile(path)) {
        return "Suspicious File Access";
    }
    if (util::ContainsIgnoreCase(path, ".minecraft\\assets") ||
        util::ContainsIgnoreCase(path, ".minecraft\\libraries") ||
        util::ContainsIgnoreCase(path, ".minecraft\\versions")) {
        return "Minecraft Assets/Lib";
    }
    if (util::ContainsIgnoreCase(path, ".minecraft\\logs") ||
        util::ContainsIgnoreCase(path, ".minecraft\\crash-reports")) {
        return "Minecraft Logs";
    }
    if (util::ContainsIgnoreCase(path, ".minecraft\\options.txt") ||
        util::ContainsIgnoreCase(path, ".minecraft\\servers.dat") ||
        util::ContainsIgnoreCase(path, ".minecraft\\saves") ||
        util::ContainsIgnoreCase(path, ".minecraft\\config")) {
        return "Minecraft Game Data";
    }
    if (util::ContainsIgnoreCase(path, ".minecraft\\mods")) {
        return "Minecraft Mod I/O";
    }
    if (util::ContainsIgnoreCase(path, "\\AppData\\Local\\Temp\\")) {
        return "Temp I/O (Unpacked Native)";
    }
    return "Win32/JNI I/O";
}

void Correlator::OnEtwEvent(const EtwEvent& ev) {
    AuditRecord record;
    record.timestamp = ev.timestamp;
    record.pid = ev.pid;
    std::string targetUtf8 = util::WideToUtf8(ev.target);
    record.target = targetUtf8;

    switch (ev.type) {
        case EtwEventType::TCP_CONNECT:
        case EtwEventType::TCP_SEND:
        case EtwEventType::TCP_RECV: {
            record.type = (ev.type == EtwEventType::TCP_CONNECT) ? "TCP_OUT" : "TCP_IO";
            bool isAllowed = IsTargetWhitelisted(targetUtf8);
            if (isAllowed) {
                record.action = AuditAction::ALLOW;
                record.source = "Minecraft (Allowed)";
            } else {
                record.action = AuditAction::BLOCK;
                record.source = "Unauthorized (Blocked)";
            }
            // Format target with domain name / ASN organization if available
            size_t colon = targetUtf8.rfind(':');
            if (colon != std::string::npos) {
                std::string ip = targetUtf8.substr(0, colon);
                try {
                    uint16_t port = (uint16_t)std::stoi(targetUtf8.substr(colon + 1));
                    record.target = DnsTracker::Instance().FormatTarget(ip, port);
                } catch (...) {
                    record.target = targetUtf8;
                }
            }
            break;
        }

        case EtwEventType::FILE_ACCESS_DENIED: {
            record.type = "FILE_BLOCK";
            record.action = AuditAction::BLOCK;
            record.isSensitive = true;
            bool isSens = IsSensitiveFile(targetUtf8);
            if (isSens) {
                record.source = "Sensitive File Blocked (Denied)";
                record.details = "Protected sensitive file access blocked by kernel (STATUS_ACCESS_DENIED 0xC0000022)";
            } else {
                record.source = "Sandbox Blocked (Denied)";
                record.details = "File access blocked by kernel sandbox (STATUS_ACCESS_DENIED 0xC0000022)";
            }
            break;
        }

        case EtwEventType::FILE_CREATE:
        case EtwEventType::FILE_READ:
        case EtwEventType::FILE_WRITE:
        case EtwEventType::FILE_DELETE: {
            if (ev.type == EtwEventType::FILE_CREATE) record.type = "FILE_CREATE";
            else if (ev.type == EtwEventType::FILE_READ) record.type = "FILE_READ";
            else if (ev.type == EtwEventType::FILE_WRITE) record.type = "FILE_WRITE";
            else record.type = "FILE_DELETE";

            bool isSens = IsSensitiveFile(targetUtf8);
            std::string folderDesc;
            bool inFolderWhitelist = IsPathInFolderWhitelist(ev.target, folderDesc);

            // If the file is inside the whitelisted game folder, ignore sensitive flag if it only matched a parent directory path
            if (inFolderWhitelist && isSens) {
                bool specificallySensitive = false;
                for (const auto& pat : m_sensitivePatterns) {
                    if (pat.find('\\') == std::string::npos && pat.find('/') == std::string::npos) {
                        if (util::ContainsIgnoreCase(targetUtf8, pat)) {
                            specificallySensitive = true;
                            break;
                        }
                    }
                }
                isSens = specificallySensitive;
            }
            record.isSensitive = isSens;

            if (isSens) {
                record.action = AuditAction::ALERT;
                record.source = "Suspicious File Access (Sensitive)";
            } else if (inFolderWhitelist || !m_enforceFolderWhitelist) {
                record.action = AuditAction::AUDIT;
                record.source = ClassifyFileSource(targetUtf8);
                if (record.source == "Win32/JNI I/O" && !folderDesc.empty()) {
                    record.source = folderDesc;
                }
            } else {
                record.action = AuditAction::ALERT;
                record.source = "Out-of-Bounds File Access";
                record.isSensitive = true;
                record.details = "Accessed file outside whitelisted folders";
            }
            break;
        }

        default:
            record.type = "I/O";
            record.source = "System";
            record.action = AuditAction::AUDIT;
            break;
    }

    if (m_callback) {
        m_callback(record);
    }
}

void Correlator::OnModuleLoaded(DWORD pid, const LoadedModuleInfo& mod) {
    AuditRecord record;
    record.timestamp = util::GetCurrentTimeString();
    record.pid = pid;
    record.type = "DLL_LOAD";
    record.target = util::WideToUtf8(mod.moduleName);
    record.details = util::WideToUtf8(mod.modulePath);

    if (mod.category == ModuleCategory::SUSPICIOUS_THIRD_PARTY) {
        record.action = AuditAction::ALERT;
        record.source = "Third-Party Native DLL";
        record.isSensitive = true;
    } else if (mod.category == ModuleCategory::MINECRAFT_NATIVE) {
        record.action = AuditAction::AUDIT;
        record.source = "Minecraft Core Native";
    } else {
        record.action = AuditAction::AUDIT;
        record.source = "Runtime System DLL";
    }

    if (m_callback) {
        m_callback(record);
    }
}

void Correlator::OnFolderEvent(DWORD pid, const std::wstring& filePath, const std::string& opTypeStr) {
    std::string pathUtf8 = util::WideToUtf8(filePath);
    AuditRecord record;
    record.timestamp = util::GetCurrentTimeString();
    record.pid = pid;
    record.type = opTypeStr;
    record.target = pathUtf8;
    record.isSensitive = IsSensitiveFile(pathUtf8);
    record.source = ClassifyFileSource(pathUtf8);
    record.action = record.isSensitive ? AuditAction::ALERT : AuditAction::AUDIT;

    if (m_callback) {
        m_callback(record);
    }
}

void Correlator::OnNetworkConnection(DWORD pid, const std::string& remoteIp, uint16_t remotePort) {
    std::string rawTarget = remoteIp + ":" + std::to_string(remotePort);
    AuditRecord record;
    record.timestamp = util::GetCurrentTimeString();
    record.pid = pid;
    record.type = "TCP_OUT";
    record.target = DnsTracker::Instance().FormatTarget(remoteIp, remotePort);
    bool isAllowed = IsTargetWhitelisted(rawTarget);
    if (isAllowed) {
        record.action = AuditAction::ALLOW;
        record.source = "Minecraft (Allowed)";
    } else {
        if (m_wfpActive) {
            record.action = AuditAction::BLOCK;
            record.source = "Unauthorized (Blocked by WFP)";
        } else {
            record.action = AuditAction::ALERT;
            record.source = "Unauthorized (WFP Inactive)";
        }
    }

    if (m_callback) {
        m_callback(record);
    }
}

void Correlator::PostAuditRecord(const AuditRecord& record) {
    if (m_callback) {
        m_callback(record);
    }
}

} // namespace core
} // namespace mcguard
