#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#include "sandbox_launcher.h"
#include "../util/string_util.h"
#include <iostream>
#include <vector>

#pragma comment(lib, "Advapi32.lib")

namespace mcguard {
namespace core {

HANDLE SandboxLauncher::CreateLowIntegrityRestrictedToken(bool stripPrivileges, bool lowIntegrity, bool denyUserSid, std::string& outError) {
    HANDLE hCurrentToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &hCurrentToken)) {
        outError = "Failed to open current process token: " + std::to_string(GetLastError());
        return NULL;
    }

    DWORD flags = stripPrivileges ? DISABLE_MAX_PRIVILEGE : 0;
    std::vector<SID_AND_ATTRIBUTES> sidsToDisable;

    if (denyUserSid) {
        DWORD len = 0;
        GetTokenInformation(hCurrentToken, TokenUser, NULL, 0, &len);
        if (len > 0) {
            std::vector<BYTE> userBuf(len);
            PTOKEN_USER pUser = (PTOKEN_USER)userBuf.data();
            if (GetTokenInformation(hCurrentToken, TokenUser, pUser, len, &len)) {
                SID_AND_ATTRIBUTES sa = { 0 };
                sa.Sid = pUser->User.Sid;
                sa.Attributes = 0; // SE_GROUP_USE_FOR_DENY_ONLY
                sidsToDisable.push_back(sa);
            }
        }
    }

    HANDLE hTargetToken = NULL;
    // Always call CreateRestrictedToken so the resulting token is marked as a restricted token
    // of the caller, exempting standard non-administrator users from SeAssignPrimaryTokenPrivilege.
    if (!CreateRestrictedToken(
            hCurrentToken,
            flags,
            (DWORD)sidsToDisable.size(),
            sidsToDisable.empty() ? NULL : sidsToDisable.data(),
            0, NULL,
            0, NULL,
            &hTargetToken)) {
        outError = "CreateRestrictedToken failed: " + std::to_string(GetLastError());
        CloseHandle(hCurrentToken);
        return NULL;
    }
    CloseHandle(hCurrentToken);

    if (lowIntegrity) {
        // Demote to Low Integrity Level (S-1-16-4096)
        PSID pLowSid = NULL;
        if (ConvertStringSidToSidW(L"S-1-16-4096", &pLowSid)) {
            TOKEN_MANDATORY_LABEL tml = { 0 };
            tml.Label.Attributes = SE_GROUP_INTEGRITY;
            tml.Label.Sid = pLowSid;

            if (!SetTokenInformation(hTargetToken, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(pLowSid))) {
                outError = "SetTokenInformation(TokenIntegrityLevel) failed: " + std::to_string(GetLastError());
                LocalFree(pLowSid);
                CloseHandle(hTargetToken);
                return NULL;
            }
            LocalFree(pLowSid);
        } else {
            outError = "ConvertStringSidToSidW failed: " + std::to_string(GetLastError());
            CloseHandle(hTargetToken);
            return NULL;
        }
    }

    return hTargetToken;
}

bool SandboxLauncher::GrantFullAccessToFolder(const std::wstring& folderPath) {
    if (folderPath.empty()) return false;

    PACL pOldDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD res = GetNamedSecurityInfoW(
        (LPWSTR)folderPath.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL,
        &pOldDacl,
        NULL,
        &pSD
    );
    if (res != ERROR_SUCCESS) return false;

    PSID pUsersSid = NULL;
    if (!ConvertStringSidToSidW(L"S-1-5-32-545", &pUsersSid)) { // BUILTIN\Users
        if (pSD) LocalFree(pSD);
        return false;
    }

    // Fast check: if BUILTIN\Users already has FullControl with inheritance, no update needed
    if (pOldDacl) {
        for (WORD i = 0; i < pOldDacl->AceCount; ++i) {
            LPVOID pAce = NULL;
            if (GetAce(pOldDacl, i, &pAce)) {
                PACE_HEADER pHeader = (PACE_HEADER)pAce;
                if (pHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                    PACCESS_ALLOWED_ACE pAllowedAce = (PACCESS_ALLOWED_ACE)pAce;
                    PSID pSid = (PSID)&pAllowedAce->SidStart;
                    if (EqualSid(pSid, pUsersSid)) {
                        bool hasFullControl = ((pAllowedAce->Mask & GENERIC_ALL) == GENERIC_ALL || 
                                               (pAllowedAce->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS);
                        bool hasInheritance = ((pHeader->AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) == 
                                               (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE));
                        if (hasFullControl && hasInheritance) {
                            LocalFree(pUsersSid);
                            LocalFree(pSD);
                            return true;
                        }
                    }
                }
            }
        }
    }

    EXPLICIT_ACCESS_W ea = { 0 };
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)pUsersSid;

    PACL pNewDacl = NULL;
    res = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
    if (res == ERROR_SUCCESS && pNewDacl) {
        SECURITY_DESCRIPTOR sd;
        if (InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
            if (SetSecurityDescriptorDacl(&sd, TRUE, pNewDacl, FALSE)) {
                SECURITY_DESCRIPTOR_CONTROL control = 0;
                DWORD revision = 0;
                if (pSD && GetSecurityDescriptorControl(pSD, &control, &revision)) {
                    SECURITY_DESCRIPTOR_CONTROL mask = SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED;
                    SetSecurityDescriptorControl(&sd, mask, control & mask);
                }
                if (!SetFileSecurityW(folderPath.c_str(), DACL_SECURITY_INFORMATION, &sd)) {
                    SetNamedSecurityInfoW(
                        (LPWSTR)folderPath.c_str(),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        NULL, NULL,
                        pNewDacl,
                        NULL
                    );
                }
            }
        }
    }

    if (pNewDacl) LocalFree(pNewDacl);
    if (pUsersSid) LocalFree(pUsersSid);
    if (pSD) LocalFree(pSD);

    return (res == ERROR_SUCCESS);
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

bool SandboxLauncher::GrantTraverseAccessToAncestor(const std::wstring& folderPath) {
    if (folderPath.empty() || folderPath.length() <= 3) return true;

    std::wstring norm(folderPath);
    for (auto& ch : norm) { if (ch == L'/') ch = L'\\'; ch = towlower(ch); }
    while (!norm.empty() && norm.back() == L'\\') norm.pop_back();

    // Boundary check: never modify root drive or C:\Users
    if (norm.length() <= 3 || norm.rfind(L"\\users") == norm.length() - 6) {
        return true;
    }

    // Never modify ancestors strictly above User Profile root (e.g. C:\Users, C:\)
    wchar_t userProfileBuf[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"USERPROFILE", userProfileBuf, MAX_PATH) > 0) {
        std::wstring wProfile(userProfileBuf);
        for (auto& ch : wProfile) { if (ch == L'/') ch = L'\\'; ch = towlower(ch); }
        while (!wProfile.empty() && wProfile.back() == L'\\') wProfile.pop_back();

        if (wProfile.rfind(norm + L"\\", 0) == 0) {
            return true;
        }
    }

    PACL pOldDacl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD res = GetNamedSecurityInfoW(
        (LPWSTR)folderPath.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        NULL, NULL,
        &pOldDacl,
        NULL,
        &pSD
    );
    if (res != ERROR_SUCCESS) return false;

    PSID pUsersSid = NULL;
    if (!ConvertStringSidToSidW(L"S-1-5-32-545", &pUsersSid)) { // BUILTIN\Users
        if (pSD) LocalFree(pSD);
        return false;
    }

    // Fast check: if BUILTIN\Users already has traverse / read permission, return immediately
    if (pOldDacl) {
        for (WORD i = 0; i < pOldDacl->AceCount; ++i) {
            LPVOID pAce = NULL;
            if (GetAce(pOldDacl, i, &pAce)) {
                PACE_HEADER pHeader = (PACE_HEADER)pAce;
                if (pHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                    PACCESS_ALLOWED_ACE pAllowedAce = (PACCESS_ALLOWED_ACE)pAce;
                    PSID pSid = (PSID)&pAllowedAce->SidStart;
                    if (EqualSid(pSid, pUsersSid)) {
                        if ((pAllowedAce->Mask & (FILE_TRAVERSE | GENERIC_READ | GENERIC_ALL | FILE_GENERIC_READ)) != 0) {
                            LocalFree(pUsersSid);
                            LocalFree(pSD);
                            return true;
                        }
                    }
                }
            }
        }
    }

    EXPLICIT_ACCESS_W ea = { 0 };
    ea.grfAccessPermissions = FILE_GENERIC_READ | FILE_TRAVERSE;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = NO_INHERITANCE; // Crucial: NEVER inherit to children/files (so desktop files remain blocked!)
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)pUsersSid;

    PACL pNewDacl = NULL;
    res = SetEntriesInAclW(1, &ea, pOldDacl, &pNewDacl);
    if (res == ERROR_SUCCESS && pNewDacl) {
        SECURITY_DESCRIPTOR sd;
        if (InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
            if (SetSecurityDescriptorDacl(&sd, TRUE, pNewDacl, FALSE)) {
                SECURITY_DESCRIPTOR_CONTROL control = 0;
                DWORD revision = 0;
                if (pSD && GetSecurityDescriptorControl(pSD, &control, &revision)) {
                    SECURITY_DESCRIPTOR_CONTROL mask = SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED;
                    SetSecurityDescriptorControl(&sd, mask, control & mask);
                }
                if (!SetFileSecurityW(folderPath.c_str(), DACL_SECURITY_INFORMATION, &sd)) {
                    SetNamedSecurityInfoW(
                        (LPWSTR)folderPath.c_str(),
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION,
                        NULL, NULL,
                        pNewDacl,
                        NULL
                    );
                }
            }
        }
    }

    if (pNewDacl) LocalFree(pNewDacl);
    if (pUsersSid) LocalFree(pUsersSid);
    if (pSD) LocalFree(pSD);

    return (res == ERROR_SUCCESS);
}

void SandboxLauncher::GrantAncestorsTraverseAccess(const std::wstring& targetPath) {
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

        // Normalize path for boundary check
        std::wstring norm = path;
        for (auto& ch : norm) { if (ch == L'/') ch = L'\\'; ch = towlower(ch); }
        while (!norm.empty() && norm.back() == L'\\') norm.pop_back();

        // Boundary: strictly above user profile root (e.g. C:\Users or C:\) or root path
        if (!wProfile.empty()) {
            if (wProfile.rfind(norm + L"\\", 0) == 0) {
                break;
            }
        }
        if (norm.length() <= 3 || norm.rfind(L"\\users") == norm.length() - 6) {
            break;
        }

        GrantTraverseAccessToAncestor(path);

        // Once we have granted traverse access to user profile root (norm == wProfile),
        // we stop going further up into C:\Users or C:\ drive root.
        if (!wProfile.empty() && norm == wProfile) {
            break;
        }
    }
}

bool SandboxLauncher::GrantLowIntegrityAccessToFolder(const std::wstring& folderPath) {
    if (folderPath.empty()) return false;

    DWORD attr = GetFileAttributesW(folderPath.c_str());
    bool isDir = (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
    const wchar_t* sddl = isDir ? L"S:(ML;OICI;NW;;;LW)" : L"S:(ML;;NW;;;LW)";

    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            SDDL_REVISION_1,
            &pSD,
            NULL)) {
        return false;
    }

    PACL pSacl = NULL;
    BOOL saclPresent = FALSE, saclDefaulted = FALSE;
    GetSecurityDescriptorSacl(pSD, &saclPresent, &pSacl, &saclDefaulted);

    DWORD res = SetNamedSecurityInfoW(
        (LPWSTR)folderPath.c_str(),
        SE_FILE_OBJECT,
        LABEL_SECURITY_INFORMATION,
        NULL,
        NULL,
        NULL,
        pSacl
    );

    LocalFree(pSD);
    return (res == ERROR_SUCCESS);
}

static std::wstring ExpandEnvironmentPath(const std::wstring& inPath) {
    wchar_t buf[MAX_PATH * 4] = { 0 };
    DWORD len = ExpandEnvironmentStringsW(inPath.c_str(), buf, sizeof(buf) / sizeof(buf[0]));
    std::wstring result = (len > 0 && len < sizeof(buf) / sizeof(buf[0])) ? std::wstring(buf) : inPath;
    for (auto& ch : result) {
        if (ch == L'/') ch = L'\\';
    }
    return result;
}

static bool IsPathOverlapping(const std::wstring& pathA, const std::wstring& pathB) {
    if (pathA.empty() || pathB.empty()) return false;
    std::wstring a = pathA;
    std::wstring b = pathB;
    for (auto& ch : a) { if (ch == L'/') ch = L'\\'; ch = towlower(ch); }
    for (auto& ch : b) { if (ch == L'/') ch = L'\\'; ch = towlower(ch); }
    while (!a.empty() && a.back() == L'\\') a.pop_back();
    while (!b.empty() && b.back() == L'\\') b.pop_back();

    if (a == b) return true;
    if (a.length() > b.length() && a.rfind(b + L'\\', 0) == 0) return true;
    if (b.length() > a.length() && b.rfind(a + L'\\', 0) == 0) return true;
    return false;
}

bool SandboxLauncher::ProtectPathFromLowIntegrity(const std::wstring& targetPath, const std::wstring& excludeDir) {
    if (targetPath.empty()) return false;

    std::wstring expanded = ExpandEnvironmentPath(targetPath);
    DWORD attr = GetFileAttributesW(expanded.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    bool isDir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    // For directories: inherit to child files and containers (OICI)
    // For files: no inheritance needed
    const wchar_t* sddl = isDir ? L"S:(ML;OICI;NRNW;;;ME)" : L"S:(ML;;NRNW;;;ME)";

    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, NULL)) {
        return false;
    }

    PACL pSacl = NULL;
    BOOL saclPresent = FALSE, saclDefaulted = FALSE;
    GetSecurityDescriptorSacl(pSD, &saclPresent, &pSacl, &saclDefaulted);

    DWORD res = SetNamedSecurityInfoW(
        (LPWSTR)expanded.c_str(),
        SE_FILE_OBJECT,
        LABEL_SECURITY_INFORMATION,
        NULL,
        NULL,
        NULL,
        pSacl
    );

    LocalFree(pSD);

    // If it's a directory, also protect existing files directly under this directory
    // because SetNamedSecurityInfo does not automatically propagate to pre-existing child files.
    if (res == ERROR_SUCCESS && isDir) {
        PSECURITY_DESCRIPTOR pSDFile = NULL;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NRNW;;;ME)", SDDL_REVISION_1, &pSDFile, NULL)) {
            PACL pFileSacl = NULL;
            GetSecurityDescriptorSacl(pSDFile, &saclPresent, &pFileSacl, &saclDefaulted);

            std::wstring searchPattern = expanded;
            if (searchPattern.back() != L'\\') searchPattern += L'\\';
            searchPattern += L"*";

            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

                    std::wstring childPath = expanded;
                    if (childPath.back() != L'\\') childPath += L'\\';
                    childPath += fd.cFileName;

                    // Skip any item that contains or is inside excludeDir (e.g. gameDir or HMCL)
                    if (!excludeDir.empty() && IsPathOverlapping(childPath, excludeDir)) {
                        continue;
                    }

                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        // Apply NRNW to pre-existing file
                        SetNamedSecurityInfoW(
                            (LPWSTR)childPath.c_str(),
                            SE_FILE_OBJECT,
                            LABEL_SECURITY_INFORMATION,
                            NULL, NULL, NULL,
                            pFileSacl
                        );
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }

            LocalFree(pSDFile);
        }
    }

    return (res == ERROR_SUCCESS);
}

void SandboxLauncher::ApplyProtectedPaths(
    const std::vector<std::string>& paths,
    std::vector<std::wstring>& outApplied,
    const std::wstring& excludeDir
) {
    for (const auto& p : paths) {
        if (p.empty()) continue;
        std::wstring wPath = util::Utf8ToWide(p);
        std::wstring expanded = ExpandEnvironmentPath(wPath);
        if (ProtectPathFromLowIntegrity(expanded, excludeDir)) {
            outApplied.push_back(expanded);
        }
    }
}

bool SandboxLauncher::RestorePathIntegrity(const std::wstring& targetPath, const std::wstring& excludeDir) {
    if (targetPath.empty()) return false;

    std::wstring expanded = ExpandEnvironmentPath(targetPath);
    DWORD attr = GetFileAttributesW(expanded.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    bool isDir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    // Restore to standard default: Medium Mandatory Level with No-Write-Up (NW)
    const wchar_t* sddl = isDir ? L"S:(ML;OICI;NW;;;ME)" : L"S:(ML;;NW;;;ME)";

    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSD, NULL)) {
        return false;
    }

    PACL pSacl = NULL;
    BOOL saclPresent = FALSE, saclDefaulted = FALSE;
    GetSecurityDescriptorSacl(pSD, &saclPresent, &pSacl, &saclDefaulted);

    DWORD res = SetNamedSecurityInfoW(
        (LPWSTR)expanded.c_str(),
        SE_FILE_OBJECT,
        LABEL_SECURITY_INFORMATION,
        NULL,
        NULL,
        NULL,
        pSacl
    );

    LocalFree(pSD);

    if (res == ERROR_SUCCESS && isDir) {
        // Also restore files under this directory
        PSECURITY_DESCRIPTOR pSDFile = NULL;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;;NW;;;ME)", SDDL_REVISION_1, &pSDFile, NULL)) {
            PACL pFileSacl = NULL;
            GetSecurityDescriptorSacl(pSDFile, &saclPresent, &pFileSacl, &saclDefaulted);

            std::wstring searchPattern = expanded;
            if (searchPattern.back() != L'\\') searchPattern += L'\\';
            searchPattern += L"*";

            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

                    std::wstring childPath = expanded;
                    if (childPath.back() != L'\\') childPath += L'\\';
                    childPath += fd.cFileName;

                    if (!excludeDir.empty() && IsPathOverlapping(childPath, excludeDir)) {
                        continue;
                    }

                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                        SetNamedSecurityInfoW(
                            (LPWSTR)childPath.c_str(),
                            SE_FILE_OBJECT,
                            LABEL_SECURITY_INFORMATION,
                            NULL, NULL, NULL,
                            pFileSacl
                        );
                    }
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }

            LocalFree(pSDFile);
        }
    }

    return (res == ERROR_SUCCESS);
}

void SandboxLauncher::RestoreProtectedPaths(const std::vector<std::wstring>& paths, const std::wstring& excludeDir) {
    for (const auto& p : paths) {
        RestorePathIntegrity(p, excludeDir);
    }
}

static void GrantSubdirectoriesAccess(const std::wstring& rootDir, int maxDepth = 5) {
    if (rootDir.empty() || maxDepth <= 0) return;
    std::wstring searchPattern = rootDir;
    if (searchPattern.back() != L'\\') searchPattern += L'\\';
    searchPattern += L"*";

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            std::wstring itemPath = rootDir;
            if (itemPath.back() != L'\\') itemPath += L'\\';
            itemPath += fd.cFileName;

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                SandboxLauncher::GrantFullAccessToFolder(itemPath);
                SandboxLauncher::GrantLowIntegrityAccessToFolder(itemPath);

                std::wstring nameLower = fd.cFileName;
                for (auto& ch : nameLower) ch = towlower(ch);
                if (nameLower != L"libraries" && nameLower != L"assets") {
                    GrantSubdirectoriesAccess(itemPath, maxDepth - 1);
                }
            } else {
                std::wstring fileName = fd.cFileName;
                if (fileName.length() >= 4 && fileName.rfind(L".tmp") == fileName.length() - 4) {
                    SetFileAttributesW(itemPath.c_str(), FILE_ATTRIBUTE_NORMAL);
                    DeleteFileW(itemPath.c_str());
                } else {
                    SandboxLauncher::GrantLowIntegrityAccessToFolder(itemPath);
                }
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
}

bool SandboxLauncher::LaunchSandboxedProcess(
    const std::wstring& applicationPath,
    const std::wstring& commandLine,
    const SandboxOptions& options,
    SandboxProcessInfo& outInfo,
    std::string& outError
) {
    // Helper to grant necessary directory access for sandboxed Minecraft
    auto grantDirAccess = [&options](const std::wstring& dir) {
        if (dir.empty()) return;
        DWORD attr = GetFileAttributesW(dir.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) return;
        if (options.denyUserSid) {
            GrantAncestorsTraverseAccess(dir);
            GrantFullAccessToFolder(dir);
            GrantSubdirectoriesAccess(dir);
        }
        if (options.lowIntegrity) {
            GrantLowIntegrityAccessToFolder(dir);
        }
    };

    // 1. Configure Mandatory Integrity Control & DACL Access
    if (!options.gameDir.empty()) {
        grantDirAccess(options.gameDir);
    }

    // Auto-detect .minecraft root and grant access to its standard structure (libraries, assets, versions, mods, config)
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

    if (!mcRoot.empty() && mcRoot != options.gameDir) {
        grantDirAccess(mcRoot);
    }
    if (!mcRoot.empty()) {
        // Pre-create .fabric directory if it does not exist so it is properly initialized
        std::wstring fabricDir = mcRoot;
        if (fabricDir.back() != L'\\') fabricDir += L'\\';
        fabricDir += L".fabric";
        CreateDirectoryW(fabricDir.c_str(), NULL);
        grantDirAccess(fabricDir);

        static const std::vector<std::wstring> s_mcSubDirs = {
            L"libraries", L"assets", L"versions", L"mods", L"config",
            L".fabric", L"logs", L"saves", L".mixin.out"
        };
        for (const auto& sub : s_mcSubDirs) {
            std::wstring subPath = mcRoot;
            if (subPath.back() != L'\\') subPath += L'\\';
            subPath += sub;
            grantDirAccess(subPath);
        }
    }

    // Grant access to Java executable directory and Java Home runtime
    if (!applicationPath.empty()) {
        if (options.denyUserSid) {
            GrantAncestorsTraverseAccess(applicationPath);
        }
        std::wstring javaHome = GetJavaHomeFromPath(applicationPath);
        if (!javaHome.empty()) {
            grantDirAccess(javaHome);
        }
        size_t lastSlash = applicationPath.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            std::wstring binDir = applicationPath.substr(0, lastSlash);
            grantDirAccess(binDir);
        }
    }

    wchar_t tempPath[MAX_PATH] = { 0 };
    if (GetTempPathW(MAX_PATH, tempPath)) {
        if (options.denyUserSid) {
            GrantAncestorsTraverseAccess(tempPath);
            GrantFullAccessToFolder(tempPath);
        }
        if (options.lowIntegrity) {
            GrantLowIntegrityAccessToFolder(tempPath);
        }
    }

    // Only apply NRNW disk labels if denyUserSid is disabled (legacy fallback)
    if (options.lowIntegrity && !options.denyUserSid) {
        std::wstring excludeDir = !mcRoot.empty() ? mcRoot : options.gameDir;
        for (const auto& p : options.protectedPaths) {
            ProtectPathFromLowIntegrity(p, excludeDir);
        }
    }

    // 2. Prepare stdout & stderr redirection pipes
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    PSECURITY_DESCRIPTOR pPipeSD = NULL;
    if (options.lowIntegrity) {
        // Grant write permissions to World and mark with Low Mandatory Level (NW)
        // so that a Low Integrity child process can write to stdout/stderr pipes without ERROR_ACCESS_DENIED.
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:(A;;GA;;;WD)S:(ML;;NW;;;LW)",
                SDDL_REVISION_1,
                &pPipeSD,
                NULL)) {
            sa.lpSecurityDescriptor = pPipeSD;
        }
    }

    HANDLE hChildStdOutRead = NULL, hChildStdOutWrite = NULL;
    HANDLE hChildStdErrRead = NULL, hChildStdErrWrite = NULL;

    bool pipesCreated = false;
    if (CreatePipe(&hChildStdOutRead, &hChildStdOutWrite, &sa, 0) &&
        CreatePipe(&hChildStdErrRead, &hChildStdErrWrite, &sa, 0)) {
        SetHandleInformation(hChildStdOutRead, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(hChildStdErrRead, HANDLE_FLAG_INHERIT, 0);
        pipesCreated = true;
    }
    if (pPipeSD) {
        LocalFree(pPipeSD);
        pPipeSD = NULL;
    }

    // Prepare ProcThreadAttributeList for Mitigation Policy and Handle Inheritance
    STARTUPINFOEXW siex = { 0 };
    siex.StartupInfo.cb = sizeof(siex);
    std::wstring desktopName = L"winsta0\\default";
    siex.StartupInfo.lpDesktop = (LPWSTR)desktopName.c_str();

    std::vector<BYTE> attrBuffer;
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = NULL;

    DWORD attrCount = 0;
    if (options.blockChildProcesses) attrCount++;
    if (pipesCreated) attrCount++;

    std::vector<HANDLE> handlesToInherit;
    if (pipesCreated) {
        handlesToInherit.push_back(hChildStdOutWrite);
        handlesToInherit.push_back(hChildStdErrWrite);
        siex.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        siex.StartupInfo.hStdOutput = hChildStdOutWrite;
        siex.StartupInfo.hStdError = hChildStdErrWrite;
        siex.StartupInfo.hStdInput = NULL;
    }

    if (attrCount > 0) {
        SIZE_T attrSize = 0;
        InitializeProcThreadAttributeList(NULL, attrCount, 0, &attrSize);
        if (attrSize > 0) {
            attrBuffer.resize(attrSize);
            attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)attrBuffer.data();
            if (InitializeProcThreadAttributeList(attrList, attrCount, 0, &attrSize)) {
                if (options.blockChildProcesses) {
                    DWORD policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
                    UpdateProcThreadAttribute(
                        attrList,
                        0,
                        PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                        &policy,
                        sizeof(policy),
                        NULL,
                        NULL);
                }
                if (!handlesToInherit.empty()) {
                    UpdateProcThreadAttribute(
                        attrList,
                        0,
                        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                        handlesToInherit.data(),
                        handlesToInherit.size() * sizeof(HANDLE),
                        NULL,
                        NULL);
                }
                siex.lpAttributeList = attrList;
            }
        }
    }

    // 3. Obtain restricted primary token
    HANDLE hToken = NULL;
    bool tokenRequested = (options.stripPrivileges || options.lowIntegrity || options.denyUserSid);
    if (tokenRequested) {
        hToken = CreateLowIntegrityRestrictedToken(options.stripPrivileges, options.lowIntegrity, options.denyUserSid, outError);
        if (!hToken) {
            // Token creation failed. Refuse to launch un-sandboxed process.
            if (attrList) DeleteProcThreadAttributeList(attrList);
            if (hChildStdOutWrite) CloseHandle(hChildStdOutWrite);
            if (hChildStdErrWrite) CloseHandle(hChildStdErrWrite);
            if (hChildStdOutRead) CloseHandle(hChildStdOutRead);
            if (hChildStdErrRead) CloseHandle(hChildStdErrRead);
            return false;
        }
    }

    // 4. Configure process creation flags
    DWORD creationFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT;
    if (options.startSuspended) {
        creationFlags |= CREATE_SUSPENDED;
    }

    std::vector<wchar_t> cmdLineBuf(commandLine.begin(), commandLine.end());
    cmdLineBuf.push_back(L'\0');

    PROCESS_INFORMATION pi = { 0 };
    BOOL success = FALSE;

    if (hToken != NULL) {
        success = CreateProcessAsUserW(
            hToken,
            applicationPath.empty() ? NULL : applicationPath.c_str(),
            cmdLineBuf.data(),
            NULL,
            NULL,
            pipesCreated ? TRUE : FALSE,
            creationFlags,
            NULL,
            NULL,
            &siex.StartupInfo,
            &pi
        );
        if (!success) {
            DWORD err = GetLastError();
            outError = "CreateProcessAsUserW failed (code " + std::to_string(err) + ")";
            if (!options.allowInsecureFallback) {
                // Fail-Closed: Abort launch to prevent running with Medium/High IL
                outError += ". Sandbox launch aborted to prevent untrusted process from running outside Low-Integrity sandbox.";
                if (attrList) DeleteProcThreadAttributeList(attrList);
                CloseHandle(hToken);
                if (hChildStdOutWrite) CloseHandle(hChildStdOutWrite);
                if (hChildStdErrWrite) CloseHandle(hChildStdErrWrite);
                if (hChildStdOutRead) CloseHandle(hChildStdOutRead);
                if (hChildStdErrRead) CloseHandle(hChildStdErrRead);
                return false;
            }
            outError += ". [WARNING] Insecure fallback to CreateProcessW (Medium/High IL) allowed by configuration!";
        } else {
            outInfo.isLowIntegrity = options.lowIntegrity;
            outInfo.privilegesStripped = options.stripPrivileges;
            outInfo.userSidDenied = options.denyUserSid;
        }
    }

    if (!success) {
        // Fallback to CreateProcessW only if token was not requested OR insecure fallback was explicitly permitted
        success = CreateProcessW(
            applicationPath.empty() ? NULL : applicationPath.c_str(),
            cmdLineBuf.data(),
            NULL,
            NULL,
            pipesCreated ? TRUE : FALSE,
            creationFlags,
            NULL,
            NULL,
            &siex.StartupInfo,
            &pi
        );
        if (!success) {
            outError = "CreateProcessW failed (code " + std::to_string(GetLastError()) + ")";
            if (attrList) DeleteProcThreadAttributeList(attrList);
            if (hToken) CloseHandle(hToken);
            if (hChildStdOutWrite) CloseHandle(hChildStdOutWrite);
            if (hChildStdErrWrite) CloseHandle(hChildStdErrWrite);
            if (hChildStdOutRead) CloseHandle(hChildStdOutRead);
            if (hChildStdErrRead) CloseHandle(hChildStdErrRead);
            return false;
        }
        outInfo.isLowIntegrity = false;
        outInfo.privilegesStripped = false;
    }

    // Close parent's copies of write handles so EOF unblocks when child terminates
    if (hChildStdOutWrite) {
        CloseHandle(hChildStdOutWrite);
        hChildStdOutWrite = NULL;
    }
    if (hChildStdErrWrite) {
        CloseHandle(hChildStdErrWrite);
        hChildStdErrWrite = NULL;
    }

    if (attrList) {
        DeleteProcThreadAttributeList(attrList);
    }
    if (hToken) {
        CloseHandle(hToken);
    }

    outInfo.hProcess = pi.hProcess;
    outInfo.hThread = pi.hThread;
    outInfo.processId = pi.dwProcessId;
    outInfo.threadId = pi.dwThreadId;
    outInfo.hStdOutRead = hChildStdOutRead;
    outInfo.hStdErrRead = hChildStdErrRead;

    // 5. Assign to Job Object with ActiveProcessLimit = 1
    if (options.useJobObject) {
        HANDLE hJob = CreateJobObjectW(NULL, NULL);
        if (hJob) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
            jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            jeli.BasicLimitInformation.ActiveProcessLimit = 1;
            SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
            AssignProcessToJobObject(hJob, pi.hProcess);
            outInfo.hJob = hJob;
        }
    }

    return true;
}

bool SandboxLauncher::ResumeSandboxedProcess(SandboxProcessInfo& procInfo) {
    if (procInfo.hThread) {
        DWORD res = ResumeThread(procInfo.hThread);
        return (res != (DWORD)-1);
    }
    return false;
}

void SandboxLauncher::CleanupProcessInfo(SandboxProcessInfo& procInfo) {
    if (procInfo.hThread) {
        CloseHandle(procInfo.hThread);
        procInfo.hThread = NULL;
    }
    if (procInfo.hProcess) {
        CloseHandle(procInfo.hProcess);
        procInfo.hProcess = NULL;
    }
    if (procInfo.hJob) {
        CloseHandle(procInfo.hJob);
        procInfo.hJob = NULL;
    }
    if (procInfo.hStdOutRead) {
        CloseHandle(procInfo.hStdOutRead);
        procInfo.hStdOutRead = NULL;
    }
    if (procInfo.hStdErrRead) {
        CloseHandle(procInfo.hStdErrRead);
        procInfo.hStdErrRead = NULL;
    }
    procInfo.processId = 0;
    procInfo.threadId = 0;
}

static bool CheckFileExists(const std::wstring& path) {
    DWORD dwAttrib = GetFileAttributesW(path.c_str());
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

std::wstring SandboxLauncher::AutoDetectRealJava(const std::string& configuredPath, bool preferConsole) {
    // 1. If configuredPath is provided and valid, use it
    if (!configuredPath.empty()) {
        std::wstring wPath = util::Utf8ToWide(configuredPath);
        if (CheckFileExists(wPath)) {
            if (preferConsole) {
                // If it ends with javaw.exe, try sibling java.exe so console probes produce stdout
                size_t pos = wPath.rfind(L"javaw.exe");
                if (pos != std::wstring::npos) {
                    std::wstring consoleJava = wPath.substr(0, pos) + L"java.exe";
                    if (CheckFileExists(consoleJava)) return consoleJava;
                }
            } else {
                // If it ends with java.exe, try sibling javaw.exe
                size_t pos = wPath.rfind(L"java.exe");
                if (pos != std::wstring::npos && (pos == 0 || wPath[pos - 1] != L'w')) {
                    std::wstring guiJava = wPath.substr(0, pos) + L"javaw.exe";
                    if (CheckFileExists(guiJava)) return guiJava;
                }
            }
            return wPath;
        }
    }

    // 2. Check JAVA_HOME environment variable
    wchar_t javaHome[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"JAVA_HOME", javaHome, MAX_PATH) > 0) {
        std::wstring target = std::wstring(javaHome) + (preferConsole ? L"\\bin\\java.exe" : L"\\bin\\javaw.exe");
        if (CheckFileExists(target)) return target;
        std::wstring fallback = std::wstring(javaHome) + (preferConsole ? L"\\bin\\javaw.exe" : L"\\bin\\java.exe");
        if (CheckFileExists(fallback)) return fallback;
    }

    // 3. Scan common standard JDK installation locations
    const std::wstring searchRoots[] = {
        L"C:\\Program Files\\Microsoft\\",
        L"C:\\Program Files\\Eclipse Adoptium\\",
        L"C:\\Program Files\\Java\\",
        L"C:\\Program Files\\BellSoft\\",
        L"C:\\Program Files\\Zulu\\"
    };

    std::wstring bestCandidate;
    int bestVersion = 0;

    for (const auto& root : searchRoots) {
        std::wstring searchPattern = root + L"*";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                    std::wstring candidate = root + fd.cFileName + (preferConsole ? L"\\bin\\java.exe" : L"\\bin\\javaw.exe");
                    if (CheckFileExists(candidate)) {
                        int ver = 0;
                        const wchar_t* p = wcsstr(fd.cFileName, L"jdk-");
                        if (!p) p = wcsstr(fd.cFileName, L"jdk");
                        if (p) {
                            while (*p && (*p < L'0' || *p > L'9')) p++;
                            if (*p) ver = _wtoi(p);
                        }
                        if (ver == 21) {
                            // Java 21 is modern Minecraft's target LTS version
                            FindClose(hFind);
                            return candidate;
                        }
                        if (ver > bestVersion || bestCandidate.empty()) {
                            bestVersion = ver;
                            bestCandidate = candidate;
                        }
                    }
                }
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    if (!bestCandidate.empty()) {
        return bestCandidate;
    }

    // 4. Check system PATH
    wchar_t pathBuf[MAX_PATH] = { 0 };
    if (SearchPathW(NULL, preferConsole ? L"java.exe" : L"javaw.exe", NULL, MAX_PATH, pathBuf, NULL) > 0) {
        wchar_t currentExe[MAX_PATH] = { 0 };
        GetModuleFileNameW(NULL, currentExe, MAX_PATH);
        if (_wcsicmp(pathBuf, currentExe) != 0) {
            return std::wstring(pathBuf);
        }
    }

    return preferConsole ? L"java.exe" : L"javaw.exe";
}

int SandboxLauncher::RunJavaProbe(const std::wstring& javaExe, int argc, char* argv[]) {
    std::wstring cmdLine = L"\"" + javaExe + L"\"";
    for (int i = 1; i < argc; ++i) {
        std::wstring wArg = util::Utf8ToWide(argv[i]);
        if (wArg.find(L' ') != std::wstring::npos) {
            cmdLine += L" \"" + wArg + L"\"";
        } else {
            cmdLine += L" " + wArg;
        }
    }

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    GetStartupInfoW(&si);

    PROCESS_INFORMATION pi = { 0 };
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(L'\0');

    // Launch real java with handle inheritance enabled so output streams directly to caller (HMCL)
    BOOL ok = CreateProcessW(
        NULL,
        cmdBuf.data(),
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!ok) {
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return (int)exitCode;
}

} // namespace core
} // namespace mcguard
