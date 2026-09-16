#include "module_tracker.h"
#include "../util/string_util.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>

namespace mcguard {
namespace core {

ModuleTracker::ModuleTracker() {}

ModuleTracker::~ModuleTracker() {}

ModuleCategory ModuleTracker::ClassifyModule(const std::wstring& path) {
    if (util::ContainsIgnoreCase(path, L"\\Windows\\System32\\") ||
        util::ContainsIgnoreCase(path, L"\\Windows\\SysWOW64\\") ||
        util::ContainsIgnoreCase(path, L"\\Windows\\WinSxS\\")) {
        return ModuleCategory::WINDOWS_SYSTEM;
    }

    if (util::ContainsIgnoreCase(path, L"jvm.dll") ||
        util::ContainsIgnoreCase(path, L"java.dll") ||
        util::ContainsIgnoreCase(path, L"net.dll") ||
        util::ContainsIgnoreCase(path, L"nio.dll") ||
        util::ContainsIgnoreCase(path, L"zip.dll") ||
        util::ContainsIgnoreCase(path, L"awt.dll") ||
        util::ContainsIgnoreCase(path, L"management.dll") ||
        util::ContainsIgnoreCase(path, L"attach.dll")) {
        return ModuleCategory::JAVA_RUNTIME;
    }

    if (util::ContainsIgnoreCase(path, L"lwjgl") ||
        util::ContainsIgnoreCase(path, L"glfw") ||
        util::ContainsIgnoreCase(path, L"openal") ||
        util::ContainsIgnoreCase(path, L"jemalloc")) {
        return ModuleCategory::MINECRAFT_NATIVE;
    }

    return ModuleCategory::SUSPICIOUS_THIRD_PARTY;
}

std::vector<LoadedModuleInfo> ModuleTracker::ScanProcessModules(DWORD pid) {
    std::vector<LoadedModuleInfo> result;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return result;
    }

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    if (Module32FirstW(hSnapshot, &me)) {
        do {
            LoadedModuleInfo info;
            info.moduleName = me.szModule;
            info.modulePath = me.szExePath;
            info.baseAddress = (uintptr_t)me.modBaseAddr;
            info.moduleSize = me.modBaseSize;
            info.category = ClassifyModule(info.modulePath);
            result.push_back(info);
        } while (Module32NextW(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
    return result;
}

std::vector<LoadedModuleInfo> ModuleTracker::GetThirdPartyModules(DWORD pid) {
    auto all = ScanProcessModules(pid);
    std::vector<LoadedModuleInfo> thirdParty;
    for (const auto& mod : all) {
        if (mod.category == ModuleCategory::SUSPICIOUS_THIRD_PARTY) {
            thirdParty.push_back(mod);
        }
    }
    return thirdParty;
}

void ModuleTracker::CheckForNewModules(DWORD pid, ModuleCallback onNewModule) {
    auto currentMods = ScanProcessModules(pid);
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto& mod : currentMods) {
        if (m_knownModules.find(mod.modulePath) == m_knownModules.end()) {
            m_knownModules.insert(mod.modulePath);
            if (onNewModule) {
                onNewModule(pid, mod);
            }
        }
    }
}

} // namespace core
} // namespace mcguard
