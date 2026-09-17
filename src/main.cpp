#include "common.h"
#include <iostream>
#include <vector>
#include <string>
#include <csignal>
#include <atomic>
#include <conio.h>
#include <shellapi.h>

#include "util/privilege.h"
#include "util/string_util.h"
#include "util/config_loader.h"
#include "core/process_watcher.h"
#include "core/wfp_guard.h"
#include "core/sandbox_launcher.h"
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
    std::cout << "MCGuard v1.1 - Standalone Pure User-Mode Minecraft Sandbox & Security Auditor\n"
              << "Zero-configuration, no Java Agent or kernel drivers required.\n\n"
              << "Usage: MCGuard.exe <command> [options]\n\n"
              << "Commands:\n"
              << "  watch              Auto-discover Minecraft (javaw.exe) and attach WFP + ETW + Module Audit\n"
              << "  run -- <exe> [args] Launch target inside Windows Kernel Restricted Sandbox (Low Integrity + Block Child Proc)\n"
              << "  sandbox [args]     Alias for 'run'\n"
              << "  monitor            Real-time interactive security console window\n"
              << "  test-wfp           Test WFP ALE dynamic engine and rule installation\n"
              << "  demo               Run live demonstration of WFP blocking and native I/O audit\n\n"
              << "Options:\n"
              << "  --whitelist <ip:port>  Add custom IP and Port to the network whitelist\n"
              << "  --elevate              Automatically request Administrator privileges via UAC\n"
              << "  --help                 Show this help message\n";
}

void LogLauncherDiag(const std::string& msg) {
    wchar_t exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        std::wstring wExe(exePath);
        size_t lastSlash = wExe.find_last_of(L"\\/");
        std::wstring logPath = (lastSlash != std::wstring::npos ? wExe.substr(0, lastSlash + 1) : L"") + L"mcguard_launcher_diag.log";
        std::ofstream ofs(logPath, std::ios::app);
        if (ofs.is_open()) {
            ofs << "[" << util::GetCurrentTimeString() << "] " << msg << std::endl;
        }
    }
}

static std::wstring BuildProxyCommandLine(const std::wstring& realJava) {
    const wchar_t* cmdLine = GetCommandLineW();
    if (!cmdLine) return L"\"" + realJava + L"\"";

    const wchar_t* p = cmdLine;
    while (*p == L' ' || *p == L'\t') p++;
    if (*p == L'\"') {
        p++;
        while (*p && *p != L'\"') p++;
        if (*p == L'\"') p++;
    } else {
        while (*p && *p != L' ' && *p != L'\t') p++;
    }
    while (*p == L' ' || *p == L'\t') p++;

    std::wstring result = L"\"" + realJava + L"\"";
    if (*p) {
        result += L" ";
        result += p;
    }
    return result;
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
    std::string targetExe;
    std::string targetCmdLine;
    DWORD targetPid = 0;
    std::string auditFilePath;
    bool monitorWfpActive = false;

    // Determine whether MCGuard is being invoked with an explicit MCGuard subcommand
    // or as a Java executable proxy (by HMCL, PCL, or launcher)
    bool isExplicitCommand = false;
    if (argc > 1) {
        std::string firstArg = argv[1];
        if (firstArg == "watch" || firstArg == "run" || firstArg == "sandbox" ||
            firstArg == "monitor" || firstArg == "test-wfp" || firstArg == "demo" ||
            firstArg == "--help" || firstArg == "-h" ||
            firstArg == "--elevate" || firstArg == "--whitelist" ||
            firstArg == "--wfp-service") {
            isExplicitCommand = true;
        }
    }

    if (!isExplicitCommand && argc > 1) {
        // Invoked as Java proxy!
        LogLauncherDiag("Invoked as Java proxy with " + std::to_string(argc) + " arguments.");

        // 1. Check if this is a Minecraft Game Launch!
        bool isMinecraftLaunch = false;
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--gameDir" || a == "--assetsDir" || a == "--accessToken" ||
                a == "--username" || a == "--uuid" || a == "--versionType" ||
                a.rfind("-Dminecraft.", 0) == 0 ||
                a.find("net.minecraft") != std::string::npos ||
                a.find("net.fabricmc") != std::string::npos ||
                a.find("cpw.mods") != std::string::npos ||
                a.find("net.neoforged") != std::string::npos) {
                isMinecraftLaunch = true;
                break;
            }
        }

        // 2. Check if this is a Java information / probe query (e.g. HMCL or CLI probing version/properties)
        bool isProbe = false;
        if (!isMinecraftLaunch) {
            for (int i = 1; i < argc; ++i) {
                std::string a = argv[i];
                if (a == "org.glavo.info.Main" ||
                    a == "-version" || a == "--version" ||
                    a == "-showversion" || a == "-fullversion" ||
                    a.rfind("-XshowSettings", 0) == 0 ||
                    a == "-help" || a == "-?") {
                    isProbe = true;
                    break;
                }
            }
        }

        if (isProbe) {
            LogLauncherDiag("Detected Java probe query. Forwarding directly to real java.exe via RunJavaProbe.");
            std::wstring realJava = core::SandboxLauncher::AutoDetectRealJava(cfg.sandbox.realJavaPath, true /* prefer console java.exe */);
            return core::SandboxLauncher::RunJavaProbe(realJava, argc, argv);
        }

        // 3. Otherwise, this is a Minecraft Game Launch!
        LogLauncherDiag("Confirmed Minecraft Game Launch! Routing to sandbox supervisor.");
        command = "sandbox";
        std::wstring realJava = core::SandboxLauncher::AutoDetectRealJava(cfg.sandbox.realJavaPath, false /* prefer javaw.exe */);
        targetExe = util::WideToUtf8(realJava);
        targetCmdLine = util::WideToUtf8(BuildProxyCommandLine(realJava));
    } else if (isExplicitCommand) {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--help" || arg == "-h") {
                PrintUsage();
                return 0;
            } else if (arg == "--elevate") {
                requestElevate = true;
            } else if (arg == "monitor") {
                command = "monitor";
                for (int m = i + 1; m < argc; ++m) {
                    std::string mArg = argv[m];
                    if (mArg == "--pid" && m + 1 < argc) {
                        targetPid = (DWORD)std::stoul(argv[++m]);
                    } else if (mArg == "--audit" && m + 1 < argc) {
                        auditFilePath = argv[++m];
                    } else if (mArg == "--wfp" && m + 1 < argc) {
                        monitorWfpActive = (std::string(argv[++m]) == "1");
                    }
                }
                break;
            } else if (arg == "--wfp-service") {
                command = "--wfp-service";
                break;
            } else if (arg == "run" || arg == "sandbox") {
                command = "sandbox";
                int targetIdx = i + 1;
                if (targetIdx < argc && std::string(argv[targetIdx]) == "--") {
                    targetIdx++;
                }
                if (targetIdx < argc) {
                    targetExe = argv[targetIdx];
                    for (int k = targetIdx; k < argc; ++k) {
                        std::string a = argv[k];
                        if (a.find(' ') != std::string::npos) {
                            targetCmdLine += "\"" + a + "\" ";
                        } else {
                            targetCmdLine += a + " ";
                        }
                    }
                }
                break;
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
    }

    // If running in an already interactive console, set title
    HWND hConsole = GetConsoleWindow();
    if (hConsole != NULL && IsWindowVisible(hConsole)) {
        SetConsoleTitleW(L"MCGuard v1.1 - Minecraft Security Sandbox & Real-Time Monitor");
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

    // Command: --wfp-service (Elevated WFP ALE helper service)
    if (command == "--wfp-service") {
        if (!isElevated) {
            return 1;
        }

        std::string appPath;
        DWORD parentPid = 0;
        std::string configPath;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--app" && i + 1 < argc) {
                appPath = argv[++i];
            } else if (arg == "--parent-pid" && i + 1 < argc) {
                parentPid = (DWORD)std::stoul(argv[++i]);
            } else if (arg == "--config" && i + 1 < argc) {
                configPath = argv[++i];
            }
        }

        if (appPath.empty() || parentPid == 0) {
            return 1;
        }

        util::ConfigData helperCfg;
        util::ConfigLoader::LoadConfig(configPath, helperCfg);

        std::vector<core::WhitelistRule> helperWhitelist = helperCfg.whitelist;

        core::WfpGuard wfpService;
        if (!wfpService.Initialize()) {
            return 1;
        }

        std::wstring wAppPath = util::Utf8ToWide(appPath);
        if (!wfpService.ProtectApplication(wAppPath, helperWhitelist)) {
            wfpService.Shutdown();
            return 1;
        }

        // Setup dynamic DNS tracking
        auto& dnsTracker = core::DnsTracker::Instance();
        if (!helperCfg.allowedDomainSuffixes.empty()) {
            dnsTracker.ClearAllowedDomainSuffixes();
            for (const auto& suffix : helperCfg.allowedDomainSuffixes) {
                dnsTracker.AddAllowedDomainSuffix(suffix);
            }
        }
        dnsTracker.SetWhitelistIpCallback([&wfpService](const std::string& domain, const std::string& ip) {
            core::WhitelistRule rule;
            rule.description = "Allowed Domain (" + domain + ")";
            rule.ip = ip;
            rule.port = 0;
            rule.protocol = "TCP";
            wfpService.AddWhitelistRule(rule);
        });
        dnsTracker.PreResolveCommonEndpoints();

        // Signal ready event to parent
        std::wstring eventName = L"Local\\MCGuard_WFP_Ready_" + std::to_wstring(parentPid);
        HANDLE hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, eventName.c_str());
        if (hEvent) {
            SetEvent(hEvent);
            CloseHandle(hEvent);
        }

        // Connect to named pipes for dynamic updates & drop event reporting
        std::wstring cmdPipeName = L"\\\\.\\pipe\\MCGuard_WFP_Cmd_" + std::to_wstring(parentPid);
        HANDLE hCmdPipe = CreateFileW(cmdPipeName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

        std::wstring evtPipeName = L"\\\\.\\pipe\\MCGuard_WFP_Evt_" + std::to_wstring(parentPid);
        HANDLE hEvtPipe = CreateFileW(evtPipeName.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        if (hEvtPipe != INVALID_HANDLE_VALUE) {
            wfpService.SetDropCallback([hEvtPipe](const std::string& remoteIp, uint16_t remotePort) {
                std::string line = "DROP " + remoteIp + " " + std::to_string(remotePort) + "\n";
                DWORD written = 0;
                WriteFile(hEvtPipe, line.c_str(), (DWORD)line.size(), &written, NULL);
            });
        }

        if (hCmdPipe != INVALID_HANDLE_VALUE) {
            std::thread pipeThread([hCmdPipe, &wfpService]() {
                char buf[512];
                DWORD bytesRead = 0;
                std::string pending;
                while (ReadFile(hCmdPipe, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
                    buf[bytesRead] = '\0';
                    pending += buf;
                    size_t nl;
                    while ((nl = pending.find('\n')) != std::string::npos) {
                        std::string line = pending.substr(0, nl);
                        pending.erase(0, nl + 1);
                        if (line.rfind("ADD ", 0) == 0) {
                            std::string ip = line.substr(4);
                            while (!ip.empty() && (ip.back() == '\r' || ip.back() == ' ')) ip.pop_back();
                            core::WhitelistRule r;
                            r.ip = ip;
                            r.port = 0;
                            r.protocol = "TCP";
                            r.description = "Dynamic Parent Rule";
                            wfpService.AddWhitelistRule(r);
                        }
                    }
                }
                CloseHandle(hCmdPipe);
            });
            pipeThread.detach();
        }

        // Wait for parent process to exit
        HANDLE hParent = OpenProcess(SYNCHRONIZE, FALSE, parentPid);
        if (hParent) {
            WaitForSingleObject(hParent, INFINITE);
            CloseHandle(hParent);
        }

        if (hEvtPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hEvtPipe);
        }

        wfpService.Shutdown();
        return 0;
    }

    // Command: monitor (Dedicated real-time GUI / interactive console monitor)
    if (command == "monitor") {
        std::string logPath = auditFilePath.empty() ? "mcguard_audit.jsonl" : auditFilePath;
        ui::ConsoleView monView(logPath);
        monView.Initialize(monitorWfpActive);
        if (monitorWfpActive) {
            monView.PrintSuccess("WFP Kernel Firewall: ACTIVE (Unauthorized connections dropped at packet level)");
        } else {
            monView.PrintWarning("WFP Kernel Firewall: INACTIVE (Admin declined / Pure audit mode)");
        }

        if (targetPid != 0) {
            SetConsoleTitleW((L"MCGuard v1.1 - Minecraft Security Monitor & Real-Time Defense [PID: " + std::to_wstring(targetPid) + L"]").c_str());
        } else {
            SetConsoleTitleW(L"MCGuard v1.1 - Minecraft Security Monitor & Real-Time Defense");
        }

        monView.PrintStatus("MCGuard Interactive Security Console attached.");
        if (targetPid != 0) {
            monView.PrintStatus("Observing Sandboxed Minecraft Process (PID: " + std::to_string(targetPid) + ")");
        }

        HANDLE hProc = NULL;
        if (targetPid != 0) {
            hProc = OpenProcess(SYNCHRONIZE, FALSE, targetPid);
        }

        std::ifstream file;
        std::streampos lastPos = 0;
        uint64_t totalRecords = 0;

        while (!g_exitRequested) {
            if (!file.is_open()) {
                file.open(monView.GetLogFilePath(), std::ios::in);
            }

            if (file.is_open()) {
                file.clear();
                file.seekg(lastPos);
                std::string line;
                while (std::getline(file, line)) {
                    if (!line.empty()) {
                        core::AuditRecord rec;
                        if (ui::ConsoleView::ParseJsonRecord(line, rec)) {
                            monView.DisplayRecord(rec, false /* do not re-write to file */);
                            totalRecords++;
                        }
                    }
                    lastPos = file.tellg();
                }
            }

            // Check if target process has exited
            if (hProc != NULL) {
                DWORD waitRes = WaitForSingleObject(hProc, 250);
                if (waitRes == WAIT_OBJECT_0) {
                    // Drain any remaining records
                    if (file.is_open()) {
                        file.clear();
                        file.seekg(lastPos);
                        std::string line;
                        while (std::getline(file, line)) {
                            if (!line.empty()) {
                                core::AuditRecord rec;
                                if (ui::ConsoleView::ParseJsonRecord(line, rec)) {
                                    monView.DisplayRecord(rec, false);
                                    totalRecords++;
                                }
                            }
                        }
                    }

                    monView.PrintSuccess("Minecraft Process (PID: " + std::to_string(targetPid) + ") has terminated.");
                    monView.PrintStatus("Session summary: " + std::to_string(totalRecords) + " total security events recorded.");
                    monView.PrintStatus("Window will close automatically in 5 seconds (or press any key)...");

                    for (int s = 0; s < 50; ++s) {
                        if (_kbhit()) {
                            _getch();
                            break;
                        }
                        Sleep(100);
                    }
                    break;
                }
            } else {
                Sleep(250);
            }
        }

        if (hProc) CloseHandle(hProc);
        return 0;
    }

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

    // Command: sandbox / run
    if (command == "sandbox") {
        view.Initialize();
        view.PrintStatus("Initializing MCGuard Kernel Restricted Sandbox...");

        if (targetExe.empty()) {
            std::wstring realJava = core::SandboxLauncher::AutoDetectRealJava(cfg.sandbox.realJavaPath, false);
            targetExe = util::WideToUtf8(realJava);
            if (targetCmdLine.empty()) {
                targetCmdLine = "\"" + targetExe + "\"";
            }
            view.PrintStatus("Auto-detected Real Java: " + targetExe);
        }

        std::wstring wTargetExe = util::Utf8ToWide(targetExe);
        std::wstring wCmdLine = util::Utf8ToWide(targetCmdLine);

        // 1. Detect gameDir from command line
        std::wstring gameDir;
        size_t gameDirPos = wCmdLine.find(L"--gameDir");
        if (gameDirPos != std::wstring::npos) {
            size_t start = gameDirPos + 9;
            while (start < wCmdLine.size() && (wCmdLine[start] == L' ' || wCmdLine[start] == L'=')) start++;
            if (start < wCmdLine.size()) {
                if (wCmdLine[start] == L'\"') {
                    size_t end = wCmdLine.find(L'\"', start + 1);
                    if (end != std::wstring::npos) gameDir = wCmdLine.substr(start + 1, end - start - 1);
                } else {
                    size_t end = wCmdLine.find(L' ', start);
                    gameDir = wCmdLine.substr(start, end == std::wstring::npos ? end : end - start);
                }
            }
        }
        if (gameDir.empty()) {
            size_t mcPos = wCmdLine.find(L".minecraft");
            if (mcPos != std::wstring::npos) {
                size_t start = wCmdLine.rfind(L'\"', mcPos);
                if (start == std::wstring::npos) start = wCmdLine.rfind(L' ', mcPos);
                start = (start == std::wstring::npos) ? 0 : start + 1;
                gameDir = wCmdLine.substr(start, (mcPos + 10) - start);
            }
        }

        if (!gameDir.empty()) {
            view.PrintStatus("Target Game Directory: " + util::WideToUtf8(gameDir));
        }

        // 2. Prepare Sandbox Options
        core::SandboxOptions sbOptions;
        sbOptions.blockChildProcesses = cfg.sandbox.blockChildProcesses;
        sbOptions.lowIntegrity = cfg.sandbox.lowIntegrity;
        sbOptions.stripPrivileges = cfg.sandbox.stripPrivileges;
        sbOptions.useJobObject = cfg.sandbox.useJobObject;
        sbOptions.startSuspended = true;
        sbOptions.gameDir = gameDir;

        // Apply kernel-level No-Read-Up & No-Write-Up (NRNW) Mandatory Label protection
        if (!cfg.protectedPaths.empty()) {
            std::vector<std::wstring> appliedPaths;
            core::SandboxLauncher::ApplyProtectedPaths(cfg.protectedPaths, appliedPaths);
            sbOptions.protectedPaths = appliedPaths;

            for (const auto& appPath : appliedPaths) {
                std::string u8Path = util::WideToUtf8(appPath);
                LogLauncherDiag("Kernel NRNW Protection applied: " + u8Path);
                view.PrintSuccess("Protected Path [NRNW Active]: " + u8Path);

                // Add to sensitivePatterns for ETW detection and alerting
                cfg.sensitivePatterns.push_back(u8Path);
                size_t lastSlash = u8Path.find_last_of("\\/");
                if (lastSlash != std::string::npos && lastSlash + 1 < u8Path.size()) {
                    cfg.sensitivePatterns.push_back(u8Path.substr(lastSlash + 1));
                }
            }
        }

        // 3. Initialize WFP ALE engine
        core::WfpGuard wfp;
        g_pWfp = &wfp;
        bool wfpActive = false;
        HANDLE hWfpHelperProcess = NULL;
        HANDLE hWfpPipe = INVALID_HANDLE_VALUE;
        HANDLE hPipeEvtServer = INVALID_HANDLE_VALUE;

        if (isElevated) {
            if (wfp.Initialize()) {
                wfpActive = true;
                LogLauncherDiag("Administrator privileges detected. WFP ALE Engine initialized directly.");
            }
        } else {
            // Standard user rights: Request UAC elevation to activate WFP ALE Engine
            LogLauncherDiag("Standard user rights detected. Requesting UAC elevation for WFP ALE Engine...");

            DWORD myPid = GetCurrentProcessId();
            std::wstring eventName = L"Local\\MCGuard_WFP_Ready_" + std::to_wstring(myPid);
            HANDLE hReadyEvent = CreateEventW(NULL, TRUE, FALSE, eventName.c_str());

            std::wstring cmdPipeName = L"\\\\.\\pipe\\MCGuard_WFP_Cmd_" + std::to_wstring(myPid);
            HANDLE hPipeCmdServer = CreateNamedPipeW(
                cmdPipeName.c_str(),
                PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1, 4096, 4096, 0, NULL
            );

            std::wstring evtPipeName = L"\\\\.\\pipe\\MCGuard_WFP_Evt_" + std::to_wstring(myPid);
            hPipeEvtServer = CreateNamedPipeW(
                evtPipeName.c_str(),
                PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1, 4096, 4096, 0, NULL
            );

            OVERLAPPED ovCmd = { 0 };
            ovCmd.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (hPipeCmdServer != INVALID_HANDLE_VALUE) {
                ConnectNamedPipe(hPipeCmdServer, &ovCmd);
            }

            OVERLAPPED ovEvt = { 0 };
            ovEvt.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (hPipeEvtServer != INVALID_HANDLE_VALUE) {
                ConnectNamedPipe(hPipeEvtServer, &ovEvt);
            }

            wchar_t currentExe[MAX_PATH];
            GetModuleFileNameW(NULL, currentExe, MAX_PATH);

            std::wstring wfpArgs = L"--wfp-service --app \"" + wTargetExe + L"\" --parent-pid " +
                                   std::to_wstring(myPid);

            SHELLEXECUTEINFOW sei = { sizeof(sei) };
            sei.lpVerb = L"runas";
            sei.lpFile = currentExe;
            sei.lpParameters = wfpArgs.c_str();
            sei.nShow = SW_HIDE;
            sei.fMask = SEE_MASK_NOCLOSEPROCESS;

            if (ShellExecuteExW(&sei)) {
                hWfpHelperProcess = sei.hProcess;
                LogLauncherDiag("UAC prompt accepted by user. Waiting for WFP service to arm...");

                if (hReadyEvent && WaitForSingleObject(hReadyEvent, 5000) == WAIT_OBJECT_0) {
                    wfpActive = true;
                    hWfpPipe = hPipeCmdServer;
                    LogLauncherDiag("Elevated WFP ALE Engine successfully activated and armed!");
                } else {
                    LogLauncherDiag("Elevated WFP service timed out waiting for ready signal.");
                }
            } else {
                DWORD uacErr = GetLastError();
                if (uacErr == ERROR_CANCELLED) {
                    LogLauncherDiag("User DECLINED UAC administrator prompt. WFP ALE will be INACTIVE (Audit Only).");
                } else {
                    LogLauncherDiag("ShellExecuteExW failed: error " + std::to_string(uacErr));
                }
                if (hPipeCmdServer != INVALID_HANDLE_VALUE) {
                    CloseHandle(hPipeCmdServer);
                }
                if (hPipeEvtServer != INVALID_HANDLE_VALUE) {
                    CloseHandle(hPipeEvtServer);
                    hPipeEvtServer = INVALID_HANDLE_VALUE;
                }
            }

            if (ovCmd.hEvent) CloseHandle(ovCmd.hEvent);
            if (ovEvt.hEvent) CloseHandle(ovEvt.hEvent);
            if (hReadyEvent) CloseHandle(hReadyEvent);
        }

        // 4. Launch in suspended state
        core::SandboxProcessInfo procInfo;
        std::string launchErr;
        LogLauncherDiag("Launching Sandboxed Process: " + targetExe);
        LogLauncherDiag("Target Command Line (truncated): " + (targetCmdLine.size() > 300 ? targetCmdLine.substr(0, 300) + "..." : targetCmdLine));
        bool launched = core::SandboxLauncher::LaunchSandboxedProcess(
            wTargetExe, wCmdLine, sbOptions, procInfo, launchErr
        );

        if (!launched) {
            LogLauncherDiag("Sandbox launch FAILED: " + launchErr);
            view.PrintError("Sandbox launch failed: " + launchErr);
            return 1;
        }

        LogLauncherDiag("Sandbox launch SUCCESS. Sandboxed PID=" + std::to_string(procInfo.processId));
        view.PrintSuccess("Process created inside Sandbox (PID: " + std::to_string(procInfo.processId) + ")");
        if (sbOptions.lowIntegrity) {
            view.PrintStatus("Integrity Level: LOW (S-1-16-4096) - Write access denied to system/user folders");
        }
        if (sbOptions.blockChildProcesses) {
            view.PrintStatus("Child Process Policy: RESTRICTED - Kernel forbids cmd.exe/powershell creation");
        }
        if (sbOptions.useJobObject) {
            view.PrintStatus("Job Object Limit: ActiveProcessLimit = 1 (Breakout blocked)");
        }

        // 5. Pre-flight arm WFP firewall before any instruction executes
        if (isElevated && wfp.IsActive()) {
            if (wfp.ProtectApplication(wTargetExe, whitelist)) {
                view.PrintSuccess("WFP Firewall rules armed before first CPU instruction!");
            }
        }

        // 6. Setup Correlator & Handlers
        core::Correlator correlator;
        correlator.SetWfpActive(wfpActive);
        correlator.SetWhitelistRules(whitelist);
        correlator.SetSensitivePatterns(cfg.sensitivePatterns);
        if (!gameDir.empty()) {
            correlator.AddAllowedFolder(gameDir, "Minecraft Game Dir");
        }
        correlator.SetAuditCallback([&view](const core::AuditRecord& rec) {
            view.DisplayRecord(rec);
        });

        // Register drop listeners to capture real kernel drops!
        DWORD sandboxedPid = procInfo.processId;
        if (isElevated && wfp.IsActive()) {
            wfp.SetDropCallback([&correlator, sandboxedPid](const std::string& remoteIp, uint16_t remotePort) {
                correlator.OnNetworkConnection(sandboxedPid, remoteIp, remotePort);
            });
        } else if (wfpActive && hPipeEvtServer != INVALID_HANDLE_VALUE) {
            HANDLE hEvtToRead = hPipeEvtServer;
            std::thread evtThread([hEvtToRead, &correlator, sandboxedPid]() {
                OVERLAPPED ovRead = { 0 };
                ovRead.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
                char buf[512];
                std::string pending;

                while (!g_exitRequested) {
                    ResetEvent(ovRead.hEvent);
                    DWORD bytesRead = 0;
                    BOOL ok = ReadFile(hEvtToRead, buf, sizeof(buf) - 1, &bytesRead, &ovRead);
                    if (!ok && GetLastError() == ERROR_IO_PENDING) {
                        if (GetOverlappedResult(hEvtToRead, &ovRead, &bytesRead, TRUE) && bytesRead > 0) {
                            ok = TRUE;
                        } else {
                            break;
                        }
                    } else if (!ok || bytesRead == 0) {
                        break;
                    }

                    buf[bytesRead] = '\0';
                    pending += buf;
                    size_t nl;
                    while ((nl = pending.find('\n')) != std::string::npos) {
                        std::string line = pending.substr(0, nl);
                        pending.erase(0, nl + 1);
                        if (line.rfind("DROP ", 0) == 0) {
                            std::string rest = line.substr(5);
                            while (!rest.empty() && (rest.back() == '\r' || rest.back() == ' ')) rest.pop_back();
                            size_t sp = rest.find(' ');
                            if (sp != std::string::npos) {
                                std::string ip = rest.substr(0, sp);
                                uint16_t port = 0;
                                try { port = (uint16_t)std::stoul(rest.substr(sp + 1)); } catch (...) { port = 0; }
                                correlator.OnNetworkConnection(sandboxedPid, ip, port);
                            }
                        }
                    }
                }
                if (ovRead.hEvent) CloseHandle(ovRead.hEvent);
                CloseHandle(hEvtToRead);
            });
            evtThread.detach();
        }

        // Configure DnsTracker with domain suffixes and dynamic WFP whitelisting callback
        auto& dnsTracker = core::DnsTracker::Instance();
        if (hasConfig && !cfg.allowedDomainSuffixes.empty()) {
            dnsTracker.ClearAllowedDomainSuffixes();
            for (const auto& suffix : cfg.allowedDomainSuffixes) {
                dnsTracker.AddAllowedDomainSuffix(suffix);
            }
        }
        dnsTracker.SetWhitelistIpCallback([&wfp, &correlator, &view, &whitelist, isElevated, wfpActive, hWfpPipe](const std::string& domain, const std::string& ip) {
            core::WhitelistRule rule;
            rule.description = "Allowed Domain (" + domain + ")";
            rule.ip = ip;
            rule.port = 0; // Any port
            rule.protocol = "TCP";

            correlator.AddWhitelistRule(rule);
            whitelist.push_back(rule);

            if (isElevated && wfp.IsActive()) {
                wfp.AddWhitelistRule(rule);
            } else if (wfpActive && hWfpPipe != INVALID_HANDLE_VALUE) {
                std::string msg = "ADD " + ip + "\n";
                DWORD written = 0;
                WriteFile(hWfpPipe, msg.c_str(), (DWORD)msg.size(), &written, NULL);
            }
            view.PrintSuccess("Dynamically Whitelisted Domain IP: " + ip + " (" + domain + ")");
        });
        dnsTracker.PreResolveCommonEndpoints();

        // 7. If running without a visible console window (e.g. launched by HMCL / PCL with CREATE_NO_WINDOW),
        // spawn a dedicated monitor process with CREATE_NEW_CONSOLE to display an independent, authentic monitor window on the desktop!
        HWND hCurrentConsole = GetConsoleWindow();
        bool isConsoleVisible = (hCurrentConsole != NULL && IsWindowVisible(hCurrentConsole));
        LogLauncherDiag("Console check: hCurrentConsole=" + std::to_string((uintptr_t)hCurrentConsole) +
                        ", isVisible=" + std::to_string(isConsoleVisible));

        if (!isConsoleVisible) {
            wchar_t exePath[MAX_PATH];
            GetModuleFileNameW(NULL, exePath, MAX_PATH);

            std::wstring monCmd = L"\"" + std::wstring(exePath) + L"\" monitor --pid " +
                                  std::to_wstring(procInfo.processId) + L" --audit \"" +
                                  util::Utf8ToWide(view.GetLogFilePath()) + L"\" --wfp " +
                                  (wfpActive ? L"1" : L"0");
            std::vector<wchar_t> monCmdBuf(monCmd.begin(), monCmd.end());
            monCmdBuf.push_back(L'\0');

            STARTUPINFOW monSi = { sizeof(monSi) };
            monSi.dwFlags = STARTF_USESHOWWINDOW;
            monSi.wShowWindow = SW_SHOWNORMAL;
            PROCESS_INFORMATION monPi = { 0 };

            // Direct invocation with CREATE_NEW_CONSOLE to pop up an independent interactive desktop console
            BOOL monOk = CreateProcessW(
                exePath,
                monCmdBuf.data(),
                NULL, NULL, FALSE,
                CREATE_NEW_CONSOLE,
                NULL, NULL,
                &monSi, &monPi
            );

            if (monOk) {
                LogLauncherDiag("Dedicated Security Monitor console launched successfully. Monitor PID=" + std::to_string(monPi.dwProcessId));
                CloseHandle(monPi.hProcess);
                CloseHandle(monPi.hThread);
                view.PrintSuccess("Dedicated Security Monitor console window launched.");
            } else {
                DWORD err = GetLastError();
                LogLauncherDiag("Failed to launch monitor console: error " + std::to_string(err));
                view.PrintError("Failed to launch monitor console: error " + std::to_string(err));
            }
        }

        // Resume sandboxed process thread
        core::SandboxLauncher::ResumeSandboxedProcess(procInfo);
        view.PrintSuccess("Sandboxed Minecraft is now running safely!\n");
        view.PrintStatus("Audit Log File: " + view.GetLogFilePath() + "\n");

        // Post Process Start event to Audit Log (matches Procmon)
        core::AuditRecord startRec;
        startRec.timestamp = util::GetCurrentTimeString();
        startRec.pid = procInfo.processId;
        startRec.type = "PROC_START";
        startRec.target = util::WideToUtf8(wTargetExe);
        startRec.action = core::AuditAction::AUDIT;
        startRec.source = "Process Start";
        startRec.details = "Sandboxed PID: " + std::to_string(procInfo.processId) + ", Integrity: LOW, ChildProcess: RESTRICTED";
        correlator.PostAuditRecord(startRec);

        core::AuditRecord sbRec;
        sbRec.timestamp = util::GetCurrentTimeString();
        sbRec.pid = procInfo.processId;
        sbRec.type = "SANDBOX_INIT";
        sbRec.target = "Windows Kernel SRM";
        sbRec.action = core::AuditAction::AUDIT;
        sbRec.source = "Sandbox Mitigation";
        sbRec.details = "Job Object ActiveProcessLimit=1, Token Privileges Stripped";
        correlator.PostAuditRecord(sbRec);

        // 8. Start File / Directory Watcher on Minecraft game directory
        core::FolderWatcher folderWatcher;
        g_pFolderWatcher = &folderWatcher;
        std::wstring watchDir = gameDir;
        if (watchDir.empty()) {
            wchar_t appData[MAX_PATH];
            if (GetEnvironmentVariableW(L"APPDATA", appData, MAX_PATH)) {
                watchDir = std::wstring(appData) + L"\\.minecraft";
            }
        }
        if (!watchDir.empty()) {
            folderWatcher.StartWatching(watchDir, procInfo.processId, [&correlator](const core::FileChangeEvent& ev) {
                std::string opStr = "FILE_WRITE";
                if (ev.opType == core::FileOpType::OP_CREATE) opStr = "FILE_CREATE";
                else if (ev.opType == core::FileOpType::OP_DELETE) opStr = "FILE_DELETE";
                correlator.OnFolderEvent(ev.pid, ev.filePath, opStr);
            });
            view.PrintStatus("Active Directory Watcher monitoring: " + util::WideToUtf8(watchDir));
        }

        // 9. Start ETW & Network tracking
        core::EtwWatcher etw;
        g_pEtw = &etw;
        if (isElevated) {
            etw.Start([&correlator](const core::EtwEvent& ev) {
                correlator.OnEtwEvent(ev);
            });
            etw.AddTargetPid(procInfo.processId);
        }

        core::NetworkTracker netTracker;
        g_pNetTracker = &netTracker;
        netTracker.StartPolling([&correlator](DWORD pid, const std::string& remoteIp, uint16_t remotePort, bool isNew) {
            correlator.OnNetworkConnection(pid, remoteIp, remotePort);
        }, 500);
        netTracker.AddMonitoredPid(procInfo.processId);

        core::ModuleTracker modTracker;
        auto initialMods = modTracker.GetThirdPartyModules(procInfo.processId);
        for (const auto& m : initialMods) {
            correlator.OnModuleLoaded(procInfo.processId, m);
        }

        // Loop until process exits or user exits
        uint32_t loopCounter = 0;
        while (!g_exitRequested) {
            DWORD waitRes = WaitForSingleObject(procInfo.hProcess, 500);
            if (waitRes == WAIT_OBJECT_0) {
                DWORD exitCode = 0;
                GetExitCodeProcess(procInfo.hProcess, &exitCode);
                view.PrintStatus("Sandboxed process exited with code " + std::to_string(exitCode));
                break;
            }

            loopCounter++;
            // Every 3 seconds, check for newly loaded native DLLs
            if (loopCounter % 6 == 0) {
                modTracker.CheckForNewModules(procInfo.processId, [&correlator](DWORD pid, const core::LoadedModuleInfo& mod) {
                    correlator.OnModuleLoaded(pid, mod);
                });
            }
        }

        folderWatcher.StopWatching();
        netTracker.StopPolling();
        if (isElevated) etw.Stop();
        if (hWfpPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hWfpPipe);
            hWfpPipe = INVALID_HANDLE_VALUE;
        }
        if (hWfpHelperProcess != NULL) {
            CloseHandle(hWfpHelperProcess);
            hWfpHelperProcess = NULL;
        }
        wfp.Detach();
        wfp.Shutdown();
        core::SandboxLauncher::CleanupProcessInfo(procInfo);
        view.PrintSuccess("MCGuard Sandbox session ended cleanly.");
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

    for (const auto& folder : cfg.allowedFolders) {
        correlator.AddAllowedFolder(util::Utf8ToWide(folder), "Custom Allowed Folder");
        view.PrintStatus("Loaded Allowed Folder: " + folder);
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
            if (!mc.gameDir.empty()) {
                view.PrintSuccess("Whitelisted Game Directory: " + util::WideToUtf8(mc.gameDir));
                correlator.AddAllowedFolder(mc.gameDir, "Minecraft Game Dir");
            }
            if (!mc.javaHome.empty()) {
                correlator.AddAllowedFolder(mc.javaHome, "Java Runtime");
            }

            // Post Process Start event to Audit Log (matches Procmon)
            core::AuditRecord startRec;
            startRec.timestamp = util::GetCurrentTimeString();
            startRec.pid = mc.pid;
            startRec.type = "PROC_START";
            startRec.target = util::WideToUtf8(mc.exePath);
            startRec.action = core::AuditAction::AUDIT;
            startRec.source = "Process Start";
            startRec.details = "Parent PID: " + std::to_string(mc.parentPid) + ", Command line: " + util::WideToUtf8(mc.commandLine);
            correlator.PostAuditRecord(startRec);

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
