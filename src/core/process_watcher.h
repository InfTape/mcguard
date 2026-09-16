#pragma once
#include "../common.h"
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>

namespace mcguard {
namespace core {

struct MinecraftProcessInfo {
    DWORD pid = 0;
    std::wstring exePath;
    std::wstring commandLine;
    std::wstring gameDir;
    std::wstring version;
    bool isMinecraft = false;
};

class ProcessWatcher {
public:
    using ProcessCallback = std::function<void(const MinecraftProcessInfo& info, bool isStarted)>;

    ProcessWatcher();
    ~ProcessWatcher();

    // Enumerate currently running processes and return any detected Minecraft instance
    std::vector<MinecraftProcessInfo> FindMinecraftProcesses();

    // Inspect a specific process by PID
    bool InspectProcess(DWORD pid, MinecraftProcessInfo& outInfo);

    // Start background monitoring for Minecraft process launch / termination
    void StartWatching(ProcessCallback callback, uint32_t pollIntervalMs = 1000);

    // Stop background monitoring
    void StopWatching();

    bool IsWatching() const { return m_running; }

private:
    void WatcherLoop(ProcessCallback callback, uint32_t pollIntervalMs);
    static std::wstring GetProcessCommandLine(HANDLE hProcess);

    std::atomic<bool> m_running{false};
    std::thread m_watchThread;
};

} // namespace core
} // namespace mcguard
