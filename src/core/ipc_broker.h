#pragma once
#include "../common.h"
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <sddl.h>

namespace mcguard {
namespace core {

class IpcBroker {
public:
    IpcBroker();
    ~IpcBroker();

    // Start the IPC Broker server on the specified named pipe.
    // Configures pipe DACL to grant read/write access to the AppContainer SID.
    bool Start(
        PSID appContainerSid,
        const std::string& pipeName,
        const std::vector<std::string>& allowedHkcuKeys
    );

    // Stop the broker server and close pipes
    void Stop();

    // Check if broker is actively running
    bool IsRunning() const { return m_running; }

    // Get the pipe name
    std::string GetPipeName() const { return m_pipeName; }

private:
    void ServerLoop();
    void HandleClient(HANDLE hPipe);
    std::string ProcessRequest(const std::string& requestStr);

    bool IsKeyAllowed(const std::string& subKey) const;
    std::string QueryRegistryValue(HKEY hRoot, const std::wstring& subKey, const std::wstring& valueName);

    std::atomic<bool> m_running{false};
    std::thread m_serverThread;
    std::string m_pipeName;
    std::vector<std::string> m_allowedHkcuKeys;
    PSID m_appContainerSid = NULL;
    HANDLE m_hStopEvent = NULL;
};

} // namespace core
} // namespace mcguard
