#include "network_tracker.h"
#include "../util/string_util.h"
#include <ws2tcpip.h>
#include <iostream>

namespace mcguard {
namespace core {

NetworkTracker::NetworkTracker() {}

NetworkTracker::~NetworkTracker() {
    StopPolling();
}

void NetworkTracker::AddMonitoredPid(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_monitoredPids.insert(pid);
}

void NetworkTracker::RemoveMonitoredPid(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_monitoredPids.erase(pid);
}

void NetworkTracker::ClearMonitoredPids() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_monitoredPids.clear();
    m_knownConnections.clear();
}

std::vector<ActiveTcpConnection> NetworkTracker::GetProcessTcpConnections(DWORD pid) {
    std::vector<ActiveTcpConnection> results;

    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return results;

    std::vector<BYTE> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        auto pTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
            const auto& row = pTable->table[i];
            if (row.dwOwningPid == pid) {
                ActiveTcpConnection conn;
                conn.pid = pid;
                conn.localAddr = util::Ipv4ToString(row.dwLocalAddr);
                conn.localPort = ntohs((u_short)row.dwLocalPort);
                conn.remoteAddr = util::Ipv4ToString(row.dwRemoteAddr);
                conn.remotePort = ntohs((u_short)row.dwRemotePort);
                conn.state = row.dwState;

                // Ignore listening or 0.0.0.0 remote connections
                if (conn.remoteAddr != "0.0.0.0" && conn.remotePort != 0) {
                    results.push_back(conn);
                }
            }
        }
    }

    return results;
}

void NetworkTracker::StartPolling(ConnectionCallback callback, uint32_t intervalMs) {
    if (m_running) return;
    m_running = true;
    m_thread = std::thread(&NetworkTracker::PollingLoop, this, callback, intervalMs);
}

void NetworkTracker::StopPolling() {
    if (!m_running) return;
    m_running = false;
    if (m_thread.joinable()) {
        m_thread.join();
    }
}

void NetworkTracker::PollingLoop(ConnectionCallback callback, uint32_t intervalMs) {
    while (m_running) {
        std::set<DWORD> pidsCopy;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            pidsCopy = m_monitoredPids;
        }

        for (DWORD pid : pidsCopy) {
            auto connections = GetProcessTcpConnections(pid);
            for (const auto& conn : connections) {
                std::string connKey = std::to_string(pid) + "_" + conn.remoteAddr + ":" + std::to_string(conn.remotePort);
                bool isNew = false;

                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_knownConnections.find(connKey) == m_knownConnections.end()) {
                        m_knownConnections.insert(connKey);
                        isNew = true;
                    }
                }

                if (isNew && callback) {
                    callback(pid, conn.remoteAddr, conn.remotePort, true);
                }
            }
        }

        Sleep(intervalMs);
    }
}

} // namespace core
} // namespace mcguard
