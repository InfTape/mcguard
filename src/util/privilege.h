#pragma once
#include "../common.h"
#include <string>

namespace mcguard {
namespace util {

// Check whether the current process is running with elevated Administrator privileges
bool IsElevatedAdministrator();

// Enable a specific privilege on the current process token (e.g. SeDebugPrivilege)
bool EnablePrivilege(LPCWSTR privilegeName);

// Relaunch the current process elevated using the "runas" UAC verb
bool RelaunchElevated(const std::wstring& additionalArgs = L"");

} // namespace util
} // namespace mcguard
