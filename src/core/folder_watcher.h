#pragma once
#include "../common.h"
#include <string>
#include <functional>
#include <thread>
#include <atomic>

namespace mcguard {
namespace core {

enum class FileOpType {
    OP_CREATE,
    OP_MODIFY,
    OP_DELETE,
    OP_RENAME
};

struct FileChangeEvent {
    DWORD pid = 0;
    FileOpType opType = FileOpType::OP_MODIFY;
    std::wstring filePath;
    std::string timestamp;
};

class FolderWatcher {
public:
    using FileChangeCallback = std::function<void(const FileChangeEvent& ev)>;

    FolderWatcher();
    ~FolderWatcher();

    // Start watching a folder (e.g. .minecraft) recursively
    bool StartWatching(const std::wstring& directoryPath, DWORD targetPid, FileChangeCallback callback);
    void StopWatching();

    bool IsWatching() const { return m_running; }

private:
    void WatchLoop(std::wstring dirPath, DWORD targetPid, FileChangeCallback callback);

    std::atomic<bool> m_running{false};
    std::thread m_thread;
    HANDLE m_hDir = INVALID_HANDLE_VALUE;
};

} // namespace core
} // namespace mcguard
