#pragma once
#include "../common.h"
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <functional>

namespace mcguard {
namespace core {

enum class ModuleCategory {
    WINDOWS_SYSTEM,
    JAVA_RUNTIME,
    MINECRAFT_NATIVE,   // e.g. lwjgl, glfw, OpenAL
    SUSPICIOUS_THIRD_PARTY
};

struct LoadedModuleInfo {
    std::wstring moduleName;
    std::wstring modulePath;
    uintptr_t baseAddress = 0;
    size_t moduleSize = 0;
    ModuleCategory category = ModuleCategory::SUSPICIOUS_THIRD_PARTY;
};

class ModuleTracker {
public:
    using ModuleCallback = std::function<void(DWORD pid, const LoadedModuleInfo& mod)>;

    ModuleTracker();
    ~ModuleTracker();

    // Enumerate all loaded modules for a target process
    std::vector<LoadedModuleInfo> ScanProcessModules(DWORD pid);

    // Filter only third-party / non-system / non-standard modules
    std::vector<LoadedModuleInfo> GetThirdPartyModules(DWORD pid);

    // Check for newly loaded modules since last scan
    void CheckForNewModules(DWORD pid, ModuleCallback onNewModule);

    // Classify a module path
    static ModuleCategory ClassifyModule(const std::wstring& path);

private:
    std::mutex m_mutex;
    std::set<std::wstring> m_knownModules;
};

} // namespace core
} // namespace mcguard
