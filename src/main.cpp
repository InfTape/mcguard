#include "common.h"
#include <iostream>
#include <vector>
#include <string>
#include <csignal>
#include <atomic>

#include "util/privilege.h"
#include "util/string_util.h"
#include "util/config_loader.h"
#include "core/process_watcher.h"
#include "core/wfp_guard.h"
#include "core/etw_watcher.h"
#include "core/network_tracker.h"
#include "core/folder_watcher.h"
#include "core/module_tracker.h"
#include "core/correlator.h"
#include "core/dns_tracker.h"
#include "ui/console_view.h"

using namespace mcguard;

// Global shutdown flag
static std::atomic<bool> g_exitRequested{false};
static core::WfpGuard* g_pWfp = nullptr;
static core::EtwWatcher* g_pEtw = nullptr;
static core::NetworkTracker* g_pNetTracker = nullptr;
static core::FolderWatcher* g_pFolderWatcher = nullptr;

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        std::cout << "\n[*] Shutting down MCGuard cleanly...\n";
        g_exitRequested = true;
        if (g_pWfp) g_pWfp->Shutdown();
        if (g_pEtw) g_pEtw->Stop();
        if (g_pNetTracker) g_pNetTracker->StopPolling();
        if (g_pFolderWatcher) g_pFolderWatcher->StopWatching();
        return TRUE;
    }
    return FALSE;
}

void PrintUsage() {
    std::cout << "MCGuard v1.0 - Standalone Pure User-Mode Minecraft Sandbox Auditor\n"
              << "Zero-configuration, no Java Agent or JVM arguments required.\n\n"
              << "Usage: MCGuard.exe <command> [options]\n\n"
              << "Commands:\n"
              << "  watch              Auto-discover Minecraft (javaw.exe) and attach WFP + ETW + Module Audit\n"
              << "  test-wfp           Test WFP ALE dynamic engine and rule installation\n"
              << "  demo               Run live demonstration of WFP blocking and native I/O audit\n\n"
              << "Options:\n"
              << "  --whitelist <ip:port>  Add custom IP and Port to the network whitelist\n"
              << "  --elevate              Automatically request Administrator privileges via UAC\n"
              << "  --help                 Show this help message\n";
}

int main(int argc, char* argv[]) {
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    // Initialize Winsock
    WSADATA wsaData;
    int wsaRes = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaRes != 0) {
        std::cerr << "[-] WSAStartup failed: " << wsaRes << "\n";
    }

    std::string command = "watch";
    std::vector<core::WhitelistRule> whitelist;

    // Try loading configuration from config/mcguard.json
    util::ConfigData cfg;
    bool hasConfig = util::ConfigLoader::LoadConfig("", cfg);

    if (hasConfig) {
        whitelist = cfg.whitelist;
    } else {
        // Fallback default: only local server 127.0.0.1:25565
        core::WhitelistRule rLocal;
        rLocal.description = "Local Server";
        rLocal.ip = "127.0.0.1";
        rLocal.port = 25565;
        rLocal.protocol = "TCP";
        whitelist.push_back(rLocal);
    }

    // Always allow DNS queries (port 53 UDP) so Minecraft can resolve server hostnames
    core::WhitelistRule rDns;
    rDns.description = "DNS Resolution";
    rDns.port = 53;
    rDns.protocol = "UDP";
    whitelist.push_back(rDns);

    bool requestElevate = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            PrintUsage();
            return 0;
        } else if (arg == "--elevate") {
            requestElevate = true;
        } else if (arg == "--whitelist" && i + 1 < argc) {
            std::string wp = argv[++i];
            size_t colon = wp.find(':');
            core::WhitelistRule r;
            r.protocol = "TCP";
            std::string hostOrIp;
            if (colon != std::string::npos) {
                hostOrIp = wp.substr(0, colon);
                r.port = (uint16_t)std::stoi(wp.substr(colon + 1));
            } else {
                hostOrIp = wp;
                r.port = 25565;
            }
            // Automatically resolve domain name to IP if host provided
            r.ip = util::ConfigLoader::ResolveHostToIp(hostOrIp);
            r.description = "User Whitelist (" + hostOrIp + (r.ip != hostOrIp ? " -> " + r.ip : "") + ")";
            whitelist.push_back(r);
        } else if (arg[0] != '-') {
            command = arg;
        }
    }

    // Check Administrator Privilege
    bool isElevated = util::IsElevatedAdministrator();
    if (!isElevated) {
        std::cout << "\n[!] Notice: MCGuard is running with standard user rights.\n"
                  << "[!] Full WFP firewall blocking and system-wide ETW require Administrator privileges.\n";

        if (requestElevate) {
            std::cout << "[*] Requesting UAC elevation...\n";
            std::wstring args;
            for (int i = 1; i < argc; ++i) {
                args += util::Utf8ToWide(argv[i]) + L" ";
            }
            if (util::RelaunchElevated(args)) {
                return 0;
            }
        } else {
            std::cout << "[!] Pro-tip: For 100% WFP kernel network block, right-click MCGuard.exe -> 'Run as administrator' (or pass --elevate).\n\n";
        }
    } else {
        // Enable SeDebugPrivilege
        util::EnablePrivilege(SE_DEBUG_NAME);
    }

    ui::ConsoleView view("mcguard_audit.jsonl");

    // Command: test-wfp
    if (command == "test-wfp") {
        view.Initialize();
        view.PrintStatus("Running WFP ALE engine self-test...");

        core::WfpGuard wfp;
        if (!wfp.Initialize()) {
            view.PrintError("WFP Engine failed to open. Check Administrator permissions.");
            return 1;
        }
        view.PrintSuccess("WFP Engine opened successfully with FWPM_SESSION_FLAG_DYNAMIC.");

        wchar_t currentExe[MAX_PATH];
        GetModuleFileNameW(NULL, currentExe, MAX_PATH);

        view.PrintStatus("Testing ALE filter installation for: " + util::WideToUtf8(currentExe));
        if (wfp.ProtectApplication(currentExe, whitelist)) {
            view.PrintSuccess("Successfully installed ALE Outbound Permit & Default-Block filters!");
            wfp.Detach();
            view.PrintSuccess("Detached filters cleanly.");
        } else {
            view.PrintError("Failed to install ALE filters (Requires Administrator).");
        }

        wfp.Shutdown();
        view.PrintSuccess("WFP test complete. All dynamic rules safely removed.");
        return 0;
    }

    // Command: demo
    if (command == "demo") {
        view.Initialize();
        view.PrintStatus("Starting Standalone MCGuard live demonstration mode...");

        core::Correlator correlator;
        correlator.SetWhitelistRules(whitelist);
        correlator.SetAuditCallback([&view](const core::AuditRecord& rec) {
            view.DisplayRecord(rec);
        });

        view.PrintStatus("Simulating Minecraft (PID 18432) startup and operations...\n");

        Sleep(400);
        // 1. Allowed Minecraft server connection
        core::AuditRecord r1;
        r1.timestamp = util::GetCurrentTimeString();
        r1.pid = 18432;
        r1.type = "TCP_OUT";
        r1.target = "127.0.0.1:25565";
        r1.action = core::AuditAction::ALLOW;
        r1.source = "Minecraft Network";
        correlator.PostAuditRecord(r1);

        Sleep(400);
        // 2. Normal game data write
        core::AuditRecord r2;
        r2.timestamp = util::GetCurrentTimeString();
        r2.pid = 18432;
        r2.type = "FILE_WRITE";
        r2.target = "C:\\Users\\Admin\\.minecraft\\options.txt";
        r2.action = core::AuditAction::AUDIT;
        r2.source = "Minecraft Game Data";
        correlator.PostAuditRecord(r2);

        Sleep(400);
        // 3. Suspicious native DLL loaded
        core::LoadedModuleInfo mod;
        mod.moduleName = L"native_stealer.dll";
        mod.modulePath = L"C:\\Users\\Admin\\AppData\\Local\\Temp\\native_stealer.dll";
        mod.category = core::ModuleCategory::SUSPICIOUS_THIRD_PARTY;
        correlator.OnModuleLoaded(18432, mod);

        Sleep(400);
        // 4. Unauthorized connection from native DLL (Blocked by WFP!)
        core::AuditRecord r3;
        r3.timestamp = util::GetCurrentTimeString();
        r3.pid = 18432;
        r3.type = "TCP_OUT";
        r3.target = "104.18.1.2:443";
        r3.action = core::AuditAction::BLOCK;
        r3.source = "Native/JNI (WFP Blocked)";
        correlator.PostAuditRecord(r3);

        Sleep(400);
        // 5. Sensitive file read from native DLL (Flagged by ETW!)
        core::AuditRecord r4;
        r4.timestamp = util::GetCurrentTimeString();
        r4.pid = 18432;
        r4.type = "FILE_READ";
        r4.target = "C:\\Users\\Admin\\.ssh\\id_rsa";
        r4.action = core::AuditAction::ALERT;
        r4.source = "Suspicious File Access";
        r4.isSensitive = true;
        correlator.PostAuditRecord(r4);

        Sleep(400);
        // 6. Normal Mod log output
        core::AuditRecord r5;
        r5.timestamp = util::GetCurrentTimeString();
        r5.pid = 18432;
        r5.type = "FILE_WRITE";
        r5.target = "C:\\Users\\Admin\\.minecraft\\logs\\latest.log";
        r5.action = core::AuditAction::AUDIT;
        r5.source = "Minecraft Logs";
        correlator.PostAuditRecord(r5);

        std::cout << "\n[+] Demonstration completed. Audit records recorded to mcguard_audit.jsonl.\n";
        return 0;
    }

    // Command: watch (Default)
    view.Initialize();
    view.PrintStatus("Starting MCGuard Standalone Watcher (Zero-Configuration)...");

    core::WfpGuard wfp;
    g_pWfp = &wfp;

    core::EtwWatcher etw;
    g_pEtw = &etw;

    core::NetworkTracker netTracker;
    g_pNetTracker = &netTracker;

    core::FolderWatcher folderWatcher;
    g_pFolderWatcher = &folderWatcher;

    core::ModuleTracker moduleTracker;

    core::Correlator correlator;
    correlator.SetWhitelistRules(whitelist);
    correlator.SetAuditCallback([&view](const core::AuditRecord& rec) {
        view.DisplayRecord(rec);
    });

    for (const auto& r : whitelist) {
        std::string info = "Rule: " + r.ip + ":" + std::to_string(r.port) + " [" + r.protocol + "]";
        if (!r.description.empty()) info += " (" + r.description + ")";
        view.PrintStatus("Loaded " + info);
    }

    // Configure DnsTracker with domain suffixes and dynamic WFP whitelisting callback
    auto& dnsTracker = core::DnsTracker::Instance();
    if (hasConfig && !cfg.allowedDomainSuffixes.empty()) {
        dnsTracker.ClearAllowedDomainSuffixes();
        for (const auto& suffix : cfg.allowedDomainSuffixes) {
            dnsTracker.AddAllowedDomainSuffix(suffix);
        }
    }

    dnsTracker.SetWhitelistIpCallback([&wfp, &correlator, &view, &whitelist, isElevated](const std::string& domain, const std::string& ip) {
        core::WhitelistRule rule;
        rule.description = "Allowed Domain (" + domain + ")";
        rule.ip = ip;
        rule.port = 0; // Any port (HTTPS 443 / HTTP 80)
        rule.protocol = "TCP";

        correlator.AddWhitelistRule(rule);
        whitelist.push_back(rule);

        if (isElevated && wfp.IsActive()) {
            wfp.AddWhitelistRule(rule);
        }
        view.PrintSuccess("Dynamically Whitelisted Domain IP: " + ip + " (" + domain + ")");
    });

    // Pre-resolve common Mojang & Minecraft services at startup
    dnsTracker.PreResolveCommonEndpoints();

    // Start active TCP socket connection poller
    netTracker.StartPolling([&correlator](DWORD pid, const std::string& remoteIp, uint16_t remotePort, bool isNew) {
        correlator.OnNetworkConnection(pid, remoteIp, remotePort);
    }, 500);
    view.PrintSuccess("Active TCP Connection Tracker active (GetExtendedTcpTable).");

    // Initialize WFP if elevated
    if (isElevated) {
        if (wfp.Initialize()) {
            view.PrintSuccess("WFP Dynamic ALE Engine initialized.");
        } else {
            view.PrintWarning("Could not initialize WFP Engine.");
        }

        // Start ETW Trace Session
        if (etw.Start([&correlator](const core::EtwEvent& ev) {
            correlator.OnEtwEvent(ev);
        })) {
            view.PrintSuccess("ETW Kernel File & Network I/O Tracer started.");
        } else {
            view.PrintWarning("Could not start ETW session. Ensure running as Administrator.");
        }
    } else {
        view.PrintWarning("Running in Standard User mode. Active TCP & Folder watcher enabled.");
        view.PrintWarning("For kernel-level WFP connection BLOCK, run as Administrator.");
    }

    // Start Process Watcher to find Minecraft
    core::ProcessWatcher procWatcher;
    view.PrintStatus("Waiting for Minecraft (javaw.exe) to start...");

    std::vector<DWORD> monitoredPids;
    std::mutex pidListMutex;

    procWatcher.StartWatching([&](const core::MinecraftProcessInfo& mc, bool isStarted) {
        if (isStarted) {
            view.PrintSuccess("Detected Minecraft instance! PID: " + std::to_string(mc.pid));
            view.PrintStatus("JVM Path: " + util::WideToUtf8(mc.exePath));
            if (!mc.version.empty()) {
                view.PrintStatus("Version: " + util::WideToUtf8(mc.version));
            }

            {
                std::lock_guard<std::mutex> lock(pidListMutex);
                monitoredPids.push_back(mc.pid);
            }

            // Register target PID in active Network Tracker and ETW
            netTracker.AddMonitoredPid(mc.pid);
            etw.AddTargetPid(mc.pid);

            // Start directory watcher on Minecraft game folder
            std::wstring watchDir = mc.gameDir;
            if (watchDir.empty()) {
                wchar_t appData[MAX_PATH];
                if (GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH)) {
                    watchDir = std::wstring(appData) + L"\\.minecraft";
                }
            }
            if (!watchDir.empty()) {
                folderWatcher.StartWatching(watchDir, mc.pid, [&correlator](const core::FileChangeEvent& ev) {
                    std::string opStr = "FILE_WRITE";
                    if (ev.opType == core::FileOpType::OP_CREATE) opStr = "FILE_CREATE";
                    else if (ev.opType == core::FileOpType::OP_DELETE) opStr = "FILE_DELETE";
                    correlator.OnFolderEvent(ev.pid, ev.filePath, opStr);
                });
                view.PrintStatus("Active Directory Watcher monitoring: " + util::WideToUtf8(watchDir));
            }

            // Audit loaded modules
            auto thirdPartyMods = moduleTracker.GetThirdPartyModules(mc.pid);
            for (const auto& m : thirdPartyMods) {
                correlator.OnModuleLoaded(mc.pid, m);
            }

            // Apply WFP rules to this javaw.exe
            if (isElevated && wfp.IsActive() == false) {
                view.PrintStatus("Installing WFP ALE Outbound Whitelist + Block rules...");
                if (wfp.ProtectApplication(mc.exePath, whitelist)) {
                    view.PrintSuccess("WFP Protection Active for: " + util::WideToUtf8(mc.exePath));
                } else {
                    view.PrintError("Failed to apply WFP rules to javaw.exe.");
                }
            }
        } else {
            view.PrintWarning("Minecraft process exited (PID: " + std::to_string(mc.pid) + ")");
            netTracker.RemoveMonitoredPid(mc.pid);
            folderWatcher.StopWatching();
            etw.RemoveTargetPid(mc.pid);

            {
                std::lock_guard<std::mutex> lock(pidListMutex);
                auto it = std::find(monitoredPids.begin(), monitoredPids.end(), mc.pid);
                if (it != monitoredPids.end()) {
                    monitoredPids.erase(it);
                }
            }
            if (isElevated && monitoredPids.empty()) {
                wfp.Detach();
                view.PrintStatus("WFP rules detached cleanly.");
            }
        }
    }, 1000);

    // Keep running until exit requested, periodically auditing modules
    uint32_t loopCounter = 0;
    while (!g_exitRequested) {
        Sleep(500);
        loopCounter++;

        // Every 3 seconds, check for newly loaded native DLLs
        if (loopCounter % 6 == 0) {
            std::vector<DWORD> pidsCopy;
            {
                std::lock_guard<std::mutex> lock(pidListMutex);
                pidsCopy = monitoredPids;
            }
            for (DWORD pid : pidsCopy) {
                moduleTracker.CheckForNewModules(pid, [&](DWORD p, const core::LoadedModuleInfo& mod) {
                    correlator.OnModuleLoaded(p, mod);
                });
            }
        }
    }

    procWatcher.StopWatching();
    folderWatcher.StopWatching();
    netTracker.StopPolling();
    etw.Stop();
    wfp.Shutdown();

    view.PrintSuccess("MCGuard terminated cleanly. Audit logs saved.");
    WSACleanup();
    return 0;
}
