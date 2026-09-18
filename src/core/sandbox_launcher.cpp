#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include "sandbox_launcher.h"
#include "../util/string_util.h"
#include <iostream>
#include <vector>
#include <map>
#include <userenv.h>
#include <combaseapi.h>

#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ole32.lib")

namespace mcguard {
namespace core {

std::wstring SandboxLauncher::FindAvailableVirtualDrive() {
    DWORD drives = GetLogicalDrives();
    for (wchar_t letter = L'Z'; letter >= L'E'; --letter) {
        int bit = letter - L'A';
        if ((drives & (1 << bit)) == 0) {
            return std::wstring(1, letter) + L":";
        }
    }
    return L"";
}

bool SandboxLauncher::MapVirtualDrive(const std::wstring& targetPath, std::wstring& outDriveLetter) {
    if (targetPath.empty()) return false;
    outDriveLetter = FindAvailableVirtualDrive();
    if (outDriveLetter.empty()) return false;

    std::wstring ntTarget = L"\\??\\" + targetPath;
    while (!ntTarget.empty() && ntTarget.back() == L'\\') {
        ntTarget.pop_back();
    }

    BOOL ok = DefineDosDeviceW(DDD_RAW_TARGET_PATH, outDriveLetter.c_str(), ntTarget.c_str());
    return (ok != FALSE);
}

void SandboxLauncher::UnmapVirtualDrive(const std::wstring& driveLetter, const std::wstring& targetPath) {
    if (driveLetter.empty()) return;
    std::wstring ntTarget = L"\\??\\" + targetPath;
    while (!ntTarget.empty() && ntTarget.back() == L'\\') {
        ntTarget.pop_back();
    }
    DefineDosDeviceW(
        DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE,
        driveLetter.c_str(),
        ntTarget.c_str()
    );
}

std::wstring SandboxLauncher::ReplacePathPrefixCaseInsensitive(
    const std::wstring& text,
    const std::wstring& oldPrefix,
    const std::wstring& newPrefix
) {
    if (oldPrefix.empty() || text.empty()) return text;

    std::wstring normOld = oldPrefix;
    for (auto& ch : normOld) { if (ch == L'/') ch = L'\\'; ch = towlower(ch); }
    while (!normOld.empty() && normOld.back() == L'\\') normOld.pop_back();

    std::wstring normText = text;
    for (auto& ch : normText) { if (ch == L'/') ch = L'\\'; ch = towlower(ch); }

    std::wstring result;
    size_t lastPos = 0;
    size_t pos = 0;

    while ((pos = normText.find(normOld, lastPos)) != std::wstring::npos) {
        result.append(text, lastPos, pos - lastPos);
        result.append(newPrefix);
        size_t afterOld = pos + normOld.length();
        if (afterOld >= text.length() || (text[afterOld] != L'\\' && text[afterOld] != L'/')) {
            result.push_back(L'\\');
        }
        lastPos = afterOld;
    }
    result.append(text, lastPos, text.length() - lastPos);
    return result;
}

std::wstring SandboxLauncher::GetJavaHomeFromPath(const std::wstring& exePath) {
    if (exePath.empty()) return L"";
    std::wstring path = exePath;
    for (auto& ch : path) { if (ch == L'/') ch = L'\\'; }
    while (!path.empty() && path.back() == L'\\') path.pop_back();

    size_t lastSlash = path.find_last_of(L'\\');
    if (lastSlash == std::wstring::npos) return L"";
    std::wstring parent = path.substr(0, lastSlash);

    size_t pSlash = parent.find_last_of(L'\\');
    std::wstring binName = (pSlash != std::wstring::npos) ? parent.substr(pSlash + 1) : parent;
    std::wstring binLower = binName;
    for (auto& ch : binLower) ch = towlower(ch);

    if (binLower == L"bin" && pSlash != std::wstring::npos) {
        return parent.substr(0, pSlash);
    }
    return parent;
}

bool SandboxLauncher::CreateOrGetAppContainer(
    const std::wstring& profileName,
    const std::wstring& displayName,
    PSID* ppSid,
    std::wstring& outSidStr,
    std::wstring& outFolder,
    std::string& outError
) {
    if (!ppSid) return false;
    *ppSid = NULL;

    HRESULT hr = CreateAppContainerProfile(
        profileName.c_str(),
        displayName.c_str(),
        L"MCGuard Standalone Sandbox Profile",
        NULL, 0,
        ppSid
    );

    if (hr == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) || !SUCCEEDED(hr)) {
        // Already exists or create returned code, derive the deterministic AppContainer SID
        HRESULT hrDerive = DeriveAppContainerSidFromAppContainerName(profileName.c_str(), ppSid);
        if (!SUCCEEDED(hrDerive) || !*ppSid) {
            outError = "Failed to create or derive AppContainer SID (HRESULT: " + std::to_string(hrDerive) + ")";
            return false;
        }
    }

    LPWSTR pStrSid = NULL;
    if (ConvertSidToStringSidW(*ppSid, &pStrSid) && pStrSid) {
        outSidStr = pStrSid;

        LPWSTR pFolder = NULL;
        if (SUCCEEDED(GetAppContainerFolderPath(pStrSid, &pFolder)) && pFolder) {
            outFolder = pFolder;
            CoTaskMemFree(pFolder);
        }
        LocalFree(pStrSid);
    }

    // Ensure AppContainer AC Temp folder exists (Tier A)
    if (!outFolder.empty()) {
        std::wstring tempDir = outFolder + L"\\Temp";
        CreateDirectoryW(tempDir.c_str(), NULL);
        std::wstring roamingDir = outFolder + L"\\Roaming";
        CreateDirectoryW(roamingDir.c_str(), NULL);
    }

    return true;
}

bool SandboxLauncher::GrantAppContainerRegistryAccess(
    HKEY hRoot,
    const std::wstring& subKey,
    PSID pSid,
    REGSAM access
) {
    if (!pSid || subKey.empty()) return false;

    // Safety check: Never allow granting entire HKCU or HKCU\Software root!
    std::wstring lowerKey = subKey;
    for (auto& ch : lowerKey) ch = towlower(ch);
    while (!lowerKey.empty() && (lowerKey.back() == L'\\' || lowerKey.back() == L'/')) lowerKey.pop_back();

    if (lowerKey.empty() || lowerKey == L"software") {
        return false; // Strictly rejected
    }

    HKEY hKey = NULL;
    LSTATUS status = RegOpenKeyExW(hRoot, subKey.c_str(), 0, READ_CONTROL | WRITE_DAC, &hKey);
    if (status != ERROR_SUCCESS) {
        // Try creating the key if it does not exist
        DWORD disp = 0;
        status = RegCreateKeyExW(hRoot, subKey.c_str(), 0, NULL, 0, KEY_READ | WRITE_DAC, NULL, &hKey, &disp);
        if (status != ERROR_SUCCESS) return false;
    }

    PACL pOldDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD res = GetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDacl, NULL, &pSD);
    if (res != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    EXPLICIT_ACCESS_W ea = { 0 };
    ea.grfAccessPermissions = access;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea.Trustee.ptstrName = (LPWSTR)pSid;

    PACL pNewDacl = NULL;
    res = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
    if (res == ERROR_SUCCESS && pNewDacl) {
        res = SetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);
        LocalFree(pNewDacl);
    }

    if (pSD) LocalFree(pSD);
    RegCloseKey(hKey);

    return (res == ERROR_SUCCESS);
}

bool SandboxLauncher::RevokeAppContainerRegistryAccess(
    HKEY hRoot,
    const std::wstring& subKey,
    PSID pSid
) {
    if (!pSid || subKey.empty()) return false;

    HKEY hKey = NULL;
    LSTATUS status = RegOpenKeyExW(hRoot, subKey.c_str(), 0, READ_CONTROL | WRITE_DAC, &hKey);
    if (status != ERROR_SUCCESS) return false;

    PACL pOldDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD res = GetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDacl, NULL, &pSD);
    if (res != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }

    EXPLICIT_ACCESS_W ea = { 0 };
    ea.grfAccessPermissions = KEY_ALL_ACCESS;
    ea.grfAccessMode = REVOKE_ACCESS;
    ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea.Trustee.ptstrName = (LPWSTR)pSid;

    PACL pNewDacl = NULL;
    res = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
    if (res == ERROR_SUCCESS && pNewDacl) {
        SetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);
        LocalFree(pNewDacl);
    }

    if (pSD) LocalFree(pSD);
    RegCloseKey(hKey);

    return (res == ERROR_SUCCESS);
}

bool SandboxLauncher::GrantAppContainerFileAccess(
    const std::wstring& targetPath,
    PSID pSid,
    DWORD accessMask,
    bool inherit
) {
    if (targetPath.empty() || !pSid) return false;

    PACL pOldDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD res = GetNamedSecurityInfoW(
        (LPWSTR)targetPath.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL,
        &pOldDacl,
        NULL,
        &pSD
    );
    if (res != ERROR_SUCCESS) return false;

    EXPLICIT_ACCESS_W ea = { 0 };
    ea.grfAccessPermissions = accessMask;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = inherit ? (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) : NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea.Trustee.ptstrName = (LPWSTR)pSid;

    PACL pNewDacl = NULL;
    res = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
    if (res == ERROR_SUCCESS && pNewDacl) {
        SetNamedSecurityInfoW(
            (LPWSTR)targetPath.c_str(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            NULL, NULL,
            pNewDacl,
            NULL
        );
        LocalFree(pNewDacl);
    }

    if (pSD) LocalFree(pSD);
    return (res == ERROR_SUCCESS);
}

void SandboxLauncher::GrantAncestorsTraverseAccess(
    const std::wstring& targetPath,
    PSID pSid
) {
    if (targetPath.empty() || !pSid) return;

    wchar_t userProfileBuf[MAX_PATH] = { 0 };
    std::wstring wProfile;
    if (GetEnvironmentVariableW(L"USERPROFILE", userProfileBuf, MAX_PATH) > 0) {
        wProfile = userProfileBuf;
        for (auto& ch : wProfile) { if (ch == L'/') ch = L'\\'; ch = towlower(ch); }
        while (!wProfile.empty() && wProfile.back() == L'\\') wProfile.pop_back();
    }

    std::wstring path = targetPath;
    while (!path.empty() && path.length() > 3) {
        size_t lastSlash = path.find_last_of(L"\\/");
        if (lastSlash == std::wstring::npos || lastSlash <= 2) break;
        path = path.substr(0, lastSlash);

        std::wstring norm = path;
        for (auto& ch : norm) { if (ch == L'/') ch = L'\\'; ch = towlower(ch); }
        while (!norm.empty() && norm.back() == L'\\') norm.pop_back();

        // Boundary: Do not grant on C:\ or C:\Users
        if (norm.length() <= 3 || norm.rfind(L"\\users") == norm.length() - 6) {
            break;
        }

        // Grant traverse (non-inheritable)
        GrantAppContainerFileAccess(path, pSid, FILE_GENERIC_READ | FILE_TRAVERSE, false);

        if (!wProfile.empty() && norm == wProfile) {
            break;
        }
    }
}

// Build environment block redirecting LOCALAPPDATA, TEMP, TMP to AppContainer storage (Tier A)
static std::vector<wchar_t> CreateAppContainerEnvironmentBlock(const std::wstring& acFolder) {
    std::vector<wchar_t> result;
    if (acFolder.empty()) return result;

    std::wstring tempDir = acFolder + L"\\Temp";
    std::wstring roamingDir = acFolder + L"\\Roaming";

    LPWCH envStrings = GetEnvironmentStringsW();
    if (!envStrings) return result;

    struct CaseInsensitiveWCompare {
        bool operator()(const std::wstring& a, const std::wstring& b) const {
            return _wcsicmp(a.c_str(), b.c_str()) < 0;
        }
    };

    std::map<std::wstring, std::wstring, CaseInsensitiveWCompare> envMap;

    LPWCH curr = envStrings;
    while (*curr) {
        std::wstring line(curr);
        size_t eqPos = line.find(L'=');
        if (eqPos != std::wstring::npos && eqPos > 0) {
            std::wstring key = line.substr(0, eqPos);
            std::wstring val = line.substr(eqPos + 1);
            envMap[key] = val;
        }
        curr += line.length() + 1;
    }
    FreeEnvironmentStringsW(envStrings);

    // Tier A Overrides:
    envMap[L"LOCALAPPDATA"] = acFolder;
    envMap[L"TEMP"] = tempDir;
    envMap[L"TMP"] = tempDir;
    envMap[L"APPDATA"] = roamingDir;

    // Flatten to double-null-terminated block
    for (const auto& kv : envMap) {
        std::wstring entry = kv.first + L"=" + kv.second;
        result.insert(result.end(), entry.begin(), entry.end());
        result.push_back(L'\0');
    }
    result.push_back(L'\0'); // Final terminator

    return result;
}

bool SandboxLauncher::LaunchSandboxedProcess(
    const std::wstring& applicationPath,
    const std::wstring& commandLine,
    const SandboxOptions& options,
    SandboxProcessInfo& outInfo,
    std::string& outError
) {
    std::wstring resolvedAppPath = applicationPath;
    if (!resolvedAppPath.empty() && resolvedAppPath.find(L'\\') == std::wstring::npos && resolvedAppPath.find(L'/') == std::wstring::npos) {
        wchar_t searchBuf[MAX_PATH] = { 0 };
        DWORD found = SearchPathW(NULL, resolvedAppPath.c_str(), L".exe", MAX_PATH, searchBuf, NULL);
        if (found > 0 && found < MAX_PATH) {
            resolvedAppPath = searchBuf;
        }
    }

    // 1. Initialize or obtain AppContainer profile & SID
    PSID pAppContainerSid = NULL;
    std::wstring sidStr, acFolder;
    if (!CreateOrGetAppContainer(
            options.appContainerName,
            options.appContainerDisplayName,
            &pAppContainerSid,
            sidStr,
            acFolder,
            outError)) {
        return false;
    }

    outInfo.pAppContainerSid = pAppContainerSid;
    outInfo.appContainerSidStr = sidStr;
    outInfo.appContainerFolder = acFolder;

    // 2. Tier B: Grant Granular Access to Specific HKCU Subkeys
    for (const auto& subKey : options.allowedHkcuSubkeys) {
        if (GrantAppContainerRegistryAccess(HKEY_CURRENT_USER, subKey, pAppContainerSid, KEY_READ)) {
            outInfo.grantedRegistryKeys.push_back(subKey);
        }
    }

    // 3. Grant File Access to Game Directory & Java Runtime for AppContainer SID
    // Auto-detect .minecraft root
    std::wstring mcRoot;
    if (!options.gameDir.empty()) {
        std::wstring lowerGameDir = options.gameDir;
        for (auto& ch : lowerGameDir) { if (ch == L'/') ch = L'\\'; ch = towlower(ch); }
        size_t mcPos = lowerGameDir.find(L".minecraft");
        if (mcPos != std::wstring::npos) {
            mcRoot = options.gameDir.substr(0, mcPos + 10);
        }
    }
    if (mcRoot.empty() && !commandLine.empty()) {
        std::wstring lowerCmd = commandLine;
        for (auto& ch : lowerCmd) { if (ch == L'/') ch = L'\\'; ch = towlower(ch); }
        size_t cmdMcPos = lowerCmd.find(L".minecraft");
        if (cmdMcPos != std::wstring::npos) {
            size_t start = commandLine.rfind(L'\"', cmdMcPos);
            if (start == std::wstring::npos) start = commandLine.rfind(L' ', cmdMcPos);
            start = (start == std::wstring::npos) ? 0 : start + 1;
            mcRoot = commandLine.substr(start, (cmdMcPos + 10) - start);
        }
    }
    if (mcRoot.empty()) {
        mcRoot = options.gameDir;
    }

    if (!options.gameDir.empty()) {
        GrantAncestorsTraverseAccess(options.gameDir, pAppContainerSid);
        GrantAppContainerFileAccess(options.gameDir, pAppContainerSid, GENERIC_ALL, true);
    }

    if (!mcRoot.empty()) {
        GrantAncestorsTraverseAccess(mcRoot, pAppContainerSid);
        GrantAppContainerFileAccess(mcRoot, pAppContainerSid, GENERIC_ALL, true);

        // Explicitly ensure critical subdirectories have inherited full access
        static const std::vector<std::wstring> s_mcSubDirs = {
            L"libraries", L"assets", L"versions", L"mods", L"config",
            L".fabric", L"logs", L"saves", L".mixin.out"
        };
        for (const auto& sub : s_mcSubDirs) {
            std::wstring subPath = mcRoot;
            if (subPath.back() != L'\\') subPath += L'\\';
            subPath += sub;
            if (GetFileAttributesW(subPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                GrantAppContainerFileAccess(subPath, pAppContainerSid, GENERIC_ALL, true);
            }
        }
    }

    // Map Virtual Drive for mcRoot to bypass Windows parent traverse limitations for AppContainers
    std::wstring effectiveCmdLine = commandLine;
    std::wstring effectiveWorkingDir;
    if (!mcRoot.empty()) {
        std::wstring mappedDrive;
        if (MapVirtualDrive(mcRoot, mappedDrive)) {
            outInfo.virtualDriveLetter = mappedDrive;
            outInfo.virtualDriveTargetPath = mcRoot;

            effectiveCmdLine = ReplacePathPrefixCaseInsensitive(effectiveCmdLine, mcRoot, mappedDrive);
            if (!options.gameDir.empty()) {
                effectiveWorkingDir = ReplacePathPrefixCaseInsensitive(options.gameDir, mcRoot, mappedDrive);
            } else {
                effectiveWorkingDir = mappedDrive + L"\\";
            }
        }
    }

    // Grant Java runtime access
    if (!resolvedAppPath.empty()) {
        GrantAncestorsTraverseAccess(resolvedAppPath, pAppContainerSid);
        std::wstring javaHome = GetJavaHomeFromPath(resolvedAppPath);
        if (!javaHome.empty()) {
            GrantAppContainerFileAccess(javaHome, pAppContainerSid, GENERIC_READ | GENERIC_EXECUTE, true);
        }
        size_t lastSlash = resolvedAppPath.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            std::wstring binDir = resolvedAppPath.substr(0, lastSlash);
            GrantAppContainerFileAccess(binDir, pAppContainerSid, GENERIC_READ | GENERIC_EXECUTE, true);
        }
    }

    // Additional user-configured folders
    for (const auto& extraFolder : options.additionalAllowedFolders) {
        GrantAncestorsTraverseAccess(extraFolder, pAppContainerSid);
        GrantAppContainerFileAccess(extraFolder, pAppContainerSid, GENERIC_READ, true);
    }

    // 4. Prepare stdout & stderr redirection pipes with AppContainer access
    SECURITY_DESCRIPTOR pipeSd;
    InitializeSecurityDescriptor(&pipeSd, SECURITY_DESCRIPTOR_REVISION);

    EXPLICIT_ACCESS_W pipeEa[2] = { 0 };
    pipeEa[0].grfAccessPermissions = GENERIC_ALL;
    pipeEa[0].grfAccessMode = GRANT_ACCESS;
    pipeEa[0].grfInheritance = NO_INHERITANCE;
    pipeEa[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    pipeEa[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    PSID pWorldSid = NULL;
    ConvertStringSidToSidW(L"S-1-1-0", &pWorldSid);
    pipeEa[0].Trustee.ptstrName = (LPWSTR)pWorldSid;

    pipeEa[1].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
    pipeEa[1].grfAccessMode = GRANT_ACCESS;
    pipeEa[1].grfInheritance = NO_INHERITANCE;
    pipeEa[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    pipeEa[1].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    pipeEa[1].Trustee.ptstrName = (LPWSTR)pAppContainerSid;

    PACL pPipeDacl = NULL;
    SetEntriesInAclW(2, pipeEa, NULL, &pPipeDacl);
    if (pPipeDacl) {
        SetSecurityDescriptorDacl(&pipeSd, TRUE, pPipeDacl, FALSE);
    }

    SECURITY_ATTRIBUTES saPipe = { sizeof(saPipe), &pipeSd, TRUE };

    HANDLE hChildStdOutRead = NULL, hChildStdOutWrite = NULL;
    HANDLE hChildStdErrRead = NULL, hChildStdErrWrite = NULL;
    bool pipesCreated = false;

    if (CreatePipe(&hChildStdOutRead, &hChildStdOutWrite, &saPipe, 0) &&
        CreatePipe(&hChildStdErrRead, &hChildStdErrWrite, &saPipe, 0)) {
        SetHandleInformation(hChildStdOutRead, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(hChildStdErrRead, HANDLE_FLAG_INHERIT, 0);
        pipesCreated = true;
    }

    if (pPipeDacl) LocalFree(pPipeDacl);
    if (pWorldSid) LocalFree(pWorldSid);

    // 5. Configure STARTUPINFOEXW & AppContainer Security Capabilities
    STARTUPINFOEXW siex = { 0 };
    siex.StartupInfo.cb = sizeof(siex);
    std::wstring desktopName = L"winsta0\\default";
    siex.StartupInfo.lpDesktop = (LPWSTR)desktopName.c_str();

    std::vector<HANDLE> handlesToInherit;
    if (pipesCreated) {
        handlesToInherit.push_back(hChildStdOutWrite);
        handlesToInherit.push_back(hChildStdErrWrite);
        siex.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        siex.StartupInfo.hStdOutput = hChildStdOutWrite;
        siex.StartupInfo.hStdError = hChildStdErrWrite;
        siex.StartupInfo.hStdInput = NULL;
    }

    // AppContainer Network Capabilities (internetClient & privateNetworkClientServer)
    PSID pInternetClientSid = NULL;
    PSID pPrivateNetworkSid = NULL;
    ConvertStringSidToSidW(L"S-1-15-3-1", &pInternetClientSid);
    ConvertStringSidToSidW(L"S-1-15-3-3", &pPrivateNetworkSid);

    SID_AND_ATTRIBUTES caps[2] = { 0 };
    DWORD capCount = 0;
    if (pInternetClientSid) {
        caps[capCount].Sid = pInternetClientSid;
        caps[capCount].Attributes = SE_GROUP_ENABLED;
        capCount++;
    }
    if (pPrivateNetworkSid) {
        caps[capCount].Sid = pPrivateNetworkSid;
        caps[capCount].Attributes = SE_GROUP_ENABLED;
        capCount++;
    }

    SECURITY_CAPABILITIES sc = { 0 };
    sc.AppContainerSid = pAppContainerSid;
    sc.Capabilities = caps;
    sc.CapabilityCount = capCount;

    DWORD attrCount = 1; // PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
    if (options.blockChildProcesses) attrCount++;
    if (!handlesToInherit.empty()) attrCount++;

    std::vector<BYTE> attrBuffer;
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = NULL;
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, attrCount, 0, &attrSize);

    if (attrSize > 0) {
        attrBuffer.resize(attrSize);
        attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)attrBuffer.data();
        if (InitializeProcThreadAttributeList(attrList, attrCount, 0, &attrSize)) {
            // Attribute 1: AppContainer Security Capabilities
            UpdateProcThreadAttribute(
                attrList, 0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                &sc, sizeof(sc),
                NULL, NULL
            );

            // Attribute 2: Child process restriction
            if (options.blockChildProcesses) {
                DWORD policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
                UpdateProcThreadAttribute(
                    attrList, 0,
                    PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                    &policy, sizeof(policy),
                    NULL, NULL
                );
            }

            // Attribute 3: Handle inheritance list
            if (!handlesToInherit.empty()) {
                UpdateProcThreadAttribute(
                    attrList, 0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    handlesToInherit.data(),
                    handlesToInherit.size() * sizeof(HANDLE),
                    NULL, NULL
                );
            }

            siex.lpAttributeList = attrList;
        }
    }

    // 6. Tier A: Prepare isolated environment block
    std::vector<wchar_t> envBlock = CreateAppContainerEnvironmentBlock(acFolder);

    // 7. Process Creation Flags
    DWORD creationFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
    if (options.startSuspended) {
        creationFlags |= CREATE_SUSPENDED;
    }

    std::vector<wchar_t> cmdLineBuf(effectiveCmdLine.begin(), effectiveCmdLine.end());
    cmdLineBuf.push_back(L'\0');

    PROCESS_INFORMATION pi = { 0 };

    BOOL success = CreateProcessW(
        resolvedAppPath.empty() ? NULL : resolvedAppPath.c_str(),
        cmdLineBuf.data(),
        NULL,
        NULL,
        pipesCreated ? TRUE : FALSE,
        creationFlags,
        envBlock.empty() ? NULL : envBlock.data(),
        effectiveWorkingDir.empty() ? NULL : effectiveWorkingDir.c_str(),
        &siex.StartupInfo,
        &pi
    );

    // Clean up temporary setup objects
    if (attrList) DeleteProcThreadAttributeList(attrList);
    if (hChildStdOutWrite) CloseHandle(hChildStdOutWrite);
    if (hChildStdErrWrite) CloseHandle(hChildStdErrWrite);
    if (pInternetClientSid) LocalFree(pInternetClientSid);
    if (pPrivateNetworkSid) LocalFree(pPrivateNetworkSid);

    if (!success) {
        DWORD err = GetLastError();
        outError = "CreateProcessW failed: " + std::to_string(err);
        if (!outInfo.virtualDriveLetter.empty()) {
            UnmapVirtualDrive(outInfo.virtualDriveLetter, outInfo.virtualDriveTargetPath);
            outInfo.virtualDriveLetter.clear();
            outInfo.virtualDriveTargetPath.clear();
        }
        if (hChildStdOutRead) CloseHandle(hChildStdOutRead);
        if (hChildStdErrRead) CloseHandle(hChildStdErrRead);
        return false;
    }

    // 8. Assign to Job Object if requested
    HANDLE hJob = NULL;
    if (options.useJobObject) {
        hJob = CreateJobObjectW(NULL, NULL);
        if (hJob) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
            jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            jeli.BasicLimitInformation.ActiveProcessLimit = 1;
            SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
            AssignProcessToJobObject(hJob, pi.hProcess);
        }
    }

    outInfo.hProcess = pi.hProcess;
    outInfo.hThread = pi.hThread;
    outInfo.processId = pi.dwProcessId;
    outInfo.threadId = pi.dwThreadId;
    outInfo.hJob = hJob;
    outInfo.hStdOutRead = hChildStdOutRead;
    outInfo.hStdErrRead = hChildStdErrRead;

    return true;
}

bool SandboxLauncher::ResumeSandboxedProcess(SandboxProcessInfo& procInfo) {
    if (procInfo.hThread == NULL) return false;
    DWORD res = ResumeThread(procInfo.hThread);
    return (res != (DWORD)-1);
}

void SandboxLauncher::CleanupProcessInfo(SandboxProcessInfo& procInfo) {
    // Unmap virtual drive if mapped
    if (!procInfo.virtualDriveLetter.empty()) {
        UnmapVirtualDrive(procInfo.virtualDriveLetter, procInfo.virtualDriveTargetPath);
        procInfo.virtualDriveLetter.clear();
        procInfo.virtualDriveTargetPath.clear();
    }

    // Revoke granted registry subkeys cleanly upon termination (Tier B cleanup)
    if (procInfo.pAppContainerSid) {
        for (const auto& subKey : procInfo.grantedRegistryKeys) {
            RevokeAppContainerRegistryAccess(HKEY_CURRENT_USER, subKey, procInfo.pAppContainerSid);
        }
        procInfo.grantedRegistryKeys.clear();
        free(procInfo.pAppContainerSid);
        procInfo.pAppContainerSid = NULL;
    }

    if (procInfo.hStdOutRead) {
        CloseHandle(procInfo.hStdOutRead);
        procInfo.hStdOutRead = NULL;
    }
    if (procInfo.hStdErrRead) {
        CloseHandle(procInfo.hStdErrRead);
        procInfo.hStdErrRead = NULL;
    }
    if (procInfo.hThread) {
        CloseHandle(procInfo.hThread);
        procInfo.hThread = NULL;
    }
    if (procInfo.hJob) {
        CloseHandle(procInfo.hJob);
        procInfo.hJob = NULL;
    }
    if (procInfo.hProcess) {
        CloseHandle(procInfo.hProcess);
        procInfo.hProcess = NULL;
    }
}

std::wstring SandboxLauncher::AutoDetectRealJava(const std::string& configuredPath, bool preferConsole) {
    if (!configuredPath.empty()) {
        std::wstring wConfigured = util::Utf8ToWide(configuredPath);
        if (GetFileAttributesW(wConfigured.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return wConfigured;
        }
    }

    std::wstring targetBinary = preferConsole ? L"java.exe" : L"javaw.exe";

    wchar_t javaHomeBuf[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"JAVA_HOME", javaHomeBuf, MAX_PATH) > 0) {
        std::wstring candidate = std::wstring(javaHomeBuf) + L"\\bin\\" + targetBinary;
        if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return candidate;
        }
    }

    std::vector<std::wstring> wellKnownRoots = {
        L"C:\\Program Files\\Java",
        L"C:\\Program Files\\Eclipse Adoptium",
        L"C:\\Program Files\\Microsoft",
        L"C:\\Program Files\\BellSoft",
        L"C:\\Program Files\\Amazon Corretto",
        L"C:\\Program Files\\Zulu"
    };

    for (const auto& root : wellKnownRoots) {
        std::wstring searchPattern = root + L"\\*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                    std::wstring candidate = root + L"\\" + fd.cFileName + L"\\bin\\" + targetBinary;
                    if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES) {
                        FindClose(hFind);
                        return candidate;
                    }
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    return targetBinary;
}

int SandboxLauncher::RunJavaProbe(const std::wstring& javaExe, int argc, char* argv[]) {
    std::wstring cmdLine = L"\"" + javaExe + L"\"";
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg != "run" && arg != "sandbox" && arg != "--") {
            cmdLine += L" " + util::Utf8ToWide(arg);
        }
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    if (!CreateProcessW(NULL, cmdBuf.data(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return (int)exitCode;
}

} // namespace core
} // namespace mcguard
