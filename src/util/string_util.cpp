#include "string_util.h"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <map>
#include <mutex>

namespace mcguard {
namespace util {

std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), NULL, 0, NULL, NULL);
    if (sizeNeeded <= 0) return {};
    std::string result(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &result[0], sizeNeeded, NULL, NULL);
    return result;
}

std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return {};
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), NULL, 0);
    if (sizeNeeded <= 0) return {};
    std::wstring result(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &result[0], sizeNeeded);
    return result;
}

bool EqualsIgnoreCase(const std::wstring& s1, const std::wstring& s2) {
    if (s1.size() != s2.size()) return false;
    return _wcsicmp(s1.c_str(), s2.c_str()) == 0;
}

bool ContainsIgnoreCase(const std::wstring& hay, const std::wstring& needle) {
    if (needle.empty()) return true;
    auto it = std::search(
        hay.begin(), hay.end(),
        needle.begin(), needle.end(),
        [](wchar_t ch1, wchar_t ch2) { return towlower(ch1) == towlower(ch2); }
    );
    return it != hay.end();
}

bool ContainsIgnoreCase(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return true;
    auto it = std::search(
        hay.begin(), hay.end(),
        needle.begin(), needle.end(),
        [](char ch1, char ch2) { return tolower((unsigned char)ch1) == tolower((unsigned char)ch2); }
    );
    return it != hay.end();
}

static std::map<std::wstring, std::wstring> g_deviceToDriveMap;
static std::mutex g_deviceMapMutex;
static bool g_deviceMapInitialized = false;

static void RefreshDeviceMap() {
    std::lock_guard<std::mutex> lock(g_deviceMapMutex);
    g_deviceToDriveMap.clear();

    wchar_t szDrives[512];
    if (GetLogicalDriveStringsW(sizeof(szDrives) / sizeof(wchar_t) - 1, szDrives)) {
        wchar_t* pDrive = szDrives;
        while (*pDrive) {
            wchar_t driveLetter[3] = { pDrive[0], L':', L'\0' };
            wchar_t targetPath[MAX_PATH] = { 0 };
            if (QueryDosDeviceW(driveLetter, targetPath, MAX_PATH)) {
                g_deviceToDriveMap[targetPath] = driveLetter;
            }
            pDrive += wcslen(pDrive) + 1;
        }
    }
    g_deviceMapInitialized = true;
}

std::wstring ResolveNtDevicePath(const std::wstring& ntPath) {
    if (ntPath.empty()) return ntPath;
    if (ntPath.size() >= 2 && ntPath[1] == L':') {
        return ntPath; // Already standard DOS path
    }

    if (!g_deviceMapInitialized) {
        RefreshDeviceMap();
    }

    std::lock_guard<std::mutex> lock(g_deviceMapMutex);
    for (const auto& [devicePrefix, driveLetter] : g_deviceToDriveMap) {
        if (ntPath.rfind(devicePrefix, 0) == 0) {
            return driveLetter + ntPath.substr(devicePrefix.length());
        }
    }
    return ntPath;
}

std::string Ipv4ToString(uint32_t ipBigEndian) {
    IN_ADDR addr;
    addr.S_un.S_addr = ipBigEndian;
    char buffer[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, &addr, buffer, sizeof(buffer))) {
        return std::string(buffer);
    }
    return "0.0.0.0";
}

uint32_t StringToIpv4(const std::string& ipStr) {
    IN_ADDR addr;
    if (inet_pton(AF_INET, ipStr.c_str(), &addr) == 1) {
        return addr.S_un.S_addr;
    }
    return 0;
}

std::string Ipv6ToString(const uint8_t* ipv6Bytes) {
    if (!ipv6Bytes) return "::";
    char buffer[INET6_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET6, (void*)ipv6Bytes, buffer, sizeof(buffer))) {
        return std::string(buffer);
    }
    return "::";
}

std::string GetCurrentTimeString() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm bt;
    localtime_s(&bt, &in_time_t);

    std::ostringstream ss;
    ss << std::setfill('0')
       << std::setw(2) << bt.tm_hour << ":"
       << std::setw(2) << bt.tm_min << ":"
       << std::setw(2) << bt.tm_sec << "."
       << std::setw(3) << ms.count();
    return ss.str();
}

} // namespace util
} // namespace mcguard
