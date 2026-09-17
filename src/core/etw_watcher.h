#pragma once
#include "../common.h"
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <string>
#include <vector>
#include <set>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <cstdint>
#include <unordered_map>

namespace mcguard {
namespace core {

enum class EtwEventType {
    FILE_CREATE,
    FILE_READ,
    FILE_WRITE,
    FILE_DELETE,
    FILE_RENAME,
    FILE_ACCESS_DENIED,
    TCP_CONNECT,
    TCP_SEND,
    TCP_RECV,
    UNKNOWN
};

struct EtwEvent {
    DWORD pid = 0;
    DWORD tid = 0;
    EtwEventType type = EtwEventType::UNKNOWN;
    std::wstring target; // File path or IP:Port
    uint16_t port = 0;
    uint32_t status = 0; // NTSTATUS code (e.g. 0xC0000022 STATUS_ACCESS_DENIED)
    std::string timestamp;
};

class EtwWatcher {
public:
    using EventCallback = std::function<void(const EtwEvent& ev)>;

    EtwWatcher();
    ~EtwWatcher();

    // Add / remove target PIDs to monitor
    void AddTargetPid(DWORD pid);
    void RemoveTargetPid(DWORD pid);
    void ClearTargetPids();

    // Start ETW real-time trace session
    bool Start(EventCallback callback);

    // Stop ETW session
    void Stop();

    bool IsRunning() const { return m_running; }

private:
    void TraceWorkerThread(EventCallback callback);
    static VOID WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord);

    std::atomic<bool> m_running{false};
    std::thread m_workerThread;
    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = 0;
    std::wstring m_sessionName;

    std::set<DWORD> m_targetPids;
    std::mutex m_pidMutex;

    struct PendingFileOp {
        DWORD pid = 0;
        DWORD tid = 0;
        std::wstring target;
        std::string timestamp;
    };
    std::unordered_map<ULONGLONG, PendingFileOp> m_pendingCreates;
    std::mutex m_pendingMutex;

    static EtwWatcher* s_instance;
    EventCallback m_callback;
};

} // namespace core
} // namespace mcguard
