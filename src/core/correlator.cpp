#include "correlator.h"
#include "dns_tracker.h"
#include "../util/string_util.h"
#include <algorithm>

namespace mcguard {
namespace core {

Correlator::Correlator() {
    m_sensitivePatterns = {
        ".ssh", "id_rsa", "id_ed25519", "servers.dat", "launcher_profiles.json",
        "Cookies", "Login Data", "Local State", "tokens.json", "Discord",
        "Chrome\\User Data", "Edge\\User Data"
    };
}

Correlator::~Correlator() {}

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
    // Localhost always allowed
    if (target.find("127.0.0.1") != std::string::npos || target.find("localhost") != std::string::npos) {
        return true;
    }

    std::lock_guard<std::mutex> lock(m_rulesMutex);
    for (const auto& rule : m_whitelist) {
        if (rule.ip.empty() && rule.port == 0) continue;

        bool ipMatch = rule.ip.empty() || (target.find(rule.ip) != std::string::npos);
        bool portMatch = (rule.port == 0) || (target.find(":" + std::to_string(rule.port)) != std::string::npos);

        if (ipMatch && portMatch) {
            return true;
        }
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

        case EtwEventType::FILE_CREATE:
            record.type = "FILE_CREATE";
            record.isSensitive = IsSensitiveFile(targetUtf8);
            record.source = ClassifyFileSource(targetUtf8);
            record.action = record.isSensitive ? AuditAction::ALERT : AuditAction::AUDIT;
            break;

        case EtwEventType::FILE_READ:
            record.type = "FILE_READ";
            record.isSensitive = IsSensitiveFile(targetUtf8);
            record.source = ClassifyFileSource(targetUtf8);
            record.action = record.isSensitive ? AuditAction::ALERT : AuditAction::AUDIT;
            break;

        case EtwEventType::FILE_WRITE:
            record.type = "FILE_WRITE";
            record.isSensitive = IsSensitiveFile(targetUtf8);
            record.source = ClassifyFileSource(targetUtf8);
            record.action = record.isSensitive ? AuditAction::ALERT : AuditAction::AUDIT;
            break;

        case EtwEventType::FILE_DELETE:
            record.type = "FILE_DELETE";
            record.isSensitive = IsSensitiveFile(targetUtf8);
            record.source = ClassifyFileSource(targetUtf8);
            record.action = record.isSensitive ? AuditAction::ALERT : AuditAction::AUDIT;
            break;

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
        record.action = AuditAction::BLOCK;
        record.source = "Unauthorized (Blocked)";
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
