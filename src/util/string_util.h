#pragma once
#include "../common.h"
#include <string>
#include <vector>
#include <cstdint>

namespace mcguard {
namespace util {

// String conversions
std::string WideToUtf8(const std::wstring& wstr);
std::wstring Utf8ToWide(const std::string& str);

// Case-insensitive comparisons
bool EqualsIgnoreCase(const std::wstring& s1, const std::wstring& s2);
bool ContainsIgnoreCase(const std::wstring& hay, const std::wstring& needle);
bool ContainsIgnoreCase(const std::string& hay, const std::string& needle);

// Device path resolver: converts \Device\HarddiskVolumeX\path to C:\path
std::wstring ResolveNtDevicePath(const std::wstring& ntPath);

// IP address helpers
std::string Ipv4ToString(uint32_t ipBigEndian);
uint32_t StringToIpv4(const std::string& ipStr);
std::string Ipv6ToString(const uint8_t* ipv6Bytes);

// Current timestamp formatting
std::string GetCurrentTimeString();

} // namespace util
} // namespace mcguard
