#pragma once
#include "../common.h"
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <functional>
#include <thread>
#include <atomic>

#pragma comment(lib, "Iphlpapi.lib")

namespace mcguard {
namespace core {

struct ActiveTcpConnection {
    DWORD pid = 0;
    std::string localAddr;
    uint16_t localPort = 0;
    std::string remoteAddr;
    uint16_t remotePort = 0;
    DWORD state = 0; // MIB_TCP_STATE_...
};

class NetworkTracker {
public:
    using ConnectionCallback = std::function<void(DWORD pid, const std::string& remoteIp, uint16_t remotePort, bool isNew)>;

    NetworkTracker();
    ~NetworkTracker();

    // Query active TCP connections for a specific PID
    std::vector<ActiveTcpConnection> GetProcessTcpConnections(DWORD pid);

    // Start background poller to detect any active/new TCP connections for monitored PIDs
    void StartPolling(ConnectionCallback callback, uint32_t intervalMs = 500);
    void StopPolling();

    void AddMonitoredPid(DWORD pid);
    void RemoveMonitoredPid(DWORD pid);
    void ClearMonitoredPids();

private:
    void PollingLoop(ConnectionCallback callback, uint32_t intervalMs);

    std::atomic<bool> m_running{false};
    std::thread m_thread;
    std::set<DWORD> m_monitoredPids;
    std::set<std::string> m_knownConnections;
    std::mutex m_mutex;
};

} // namespace core
} // namespace mcguard
