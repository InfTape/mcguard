#include "folder_watcher.h"
#include "../util/string_util.h"
#include <iostream>
#include <vector>

namespace mcguard {
namespace core {

FolderWatcher::FolderWatcher() {}

FolderWatcher::~FolderWatcher() {
    StopWatching();
}

bool FolderWatcher::StartWatching(const std::wstring& directoryPath, DWORD targetPid, FileChangeCallback callback) {
    if (m_running) StopWatching();

    m_hDir = CreateFileW(
        directoryPath.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (m_hDir == INVALID_HANDLE_VALUE) {
        return false;
    }

    m_running = true;
    m_thread = std::thread(&FolderWatcher::WatchLoop, this, directoryPath, targetPid, callback);
    return true;
}

void FolderWatcher::StopWatching() {
    if (!m_running) return;
    m_running = false;

    if (m_thread.joinable()) {
        CancelSynchronousIo(m_thread.native_handle());
    }

    if (m_hDir != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDir);
        m_hDir = INVALID_HANDLE_VALUE;
    }

    if (m_thread.joinable()) {
        m_thread.join();
    }
}

void FolderWatcher::WatchLoop(std::wstring dirPath, DWORD targetPid, FileChangeCallback callback) {
    std::vector<BYTE> buffer(64 * 1024); // 64 KB notification buffer

    // Ensure dirPath does not have trailing slash
    if (!dirPath.empty() && (dirPath.back() == L'\\' || dirPath.back() == L'/')) {
        dirPath.pop_back();
    }

    while (m_running && m_hDir != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned = 0;
        BOOL ok = ReadDirectoryChangesW(
            m_hDir,
            buffer.data(),
            (DWORD)buffer.size(),
            TRUE, // Recursive
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
            &bytesReturned,
            NULL,
            NULL
        );

        if (!ok || bytesReturned == 0 || !m_running) {
            break;
        }

        BYTE* pCurrent = buffer.data();
        while (pCurrent) {
            auto pNotify = reinterpret_cast<PFILE_NOTIFY_INFORMATION>(pCurrent);
            std::wstring relPath(pNotify->FileName, pNotify->FileNameLength / sizeof(wchar_t));
            std::wstring fullPath = dirPath + L"\\" + relPath;

            FileChangeEvent ev;
            ev.pid = targetPid;
            ev.filePath = fullPath;
            ev.timestamp = util::GetCurrentTimeString();

            switch (pNotify->Action) {
                case FILE_ACTION_ADDED:
                    ev.opType = FileOpType::OP_CREATE;
                    break;
                case FILE_ACTION_REMOVED:
                    ev.opType = FileOpType::OP_DELETE;
                    break;
                case FILE_ACTION_MODIFIED:
                    ev.opType = FileOpType::OP_MODIFY;
                    break;
                case FILE_ACTION_RENAMED_NEW_NAME:
                    ev.opType = FileOpType::OP_RENAME;
                    break;
                default:
                    ev.opType = FileOpType::OP_MODIFY;
                    break;
            }

            if (callback) {
                callback(ev);
            }

            if (pNotify->NextEntryOffset == 0) {
                break;
            }
            pCurrent += pNotify->NextEntryOffset;
        }
    }
}

} // namespace core
} // namespace mcguard
