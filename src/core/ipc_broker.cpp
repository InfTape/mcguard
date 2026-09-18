#include "ipc_broker.h"
#include "../util/string_util.h"
#include <iostream>
#include <sstream>
#include <aclapi.h>

#pragma comment(lib, "Advapi32.lib")

namespace mcguard {
namespace core {

IpcBroker::IpcBroker() {}

IpcBroker::~IpcBroker() {
    Stop();
}

bool IpcBroker::Start(
    PSID appContainerSid,
    const std::string& pipeName,
    const std::vector<std::string>& allowedHkcuKeys
) {
    if (m_running) return true;

    m_pipeName = pipeName.empty() ? "\\\\.\\pipe\\mcguard_ipc" : pipeName;
    m_allowedHkcuKeys = allowedHkcuKeys;

    if (appContainerSid) {
        DWORD sidLen = GetLengthSid(appContainerSid);
        m_appContainerSid = (PSID)malloc(sidLen);
        if (m_appContainerSid) {
            CopySid(sidLen, m_appContainerSid, appContainerSid);
        }
    }

    m_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!m_hStopEvent) return false;

    m_running = true;
    m_serverThread = std::thread(&IpcBroker::ServerLoop, this);
    return true;
}

void IpcBroker::Stop() {
    if (!m_running) return;
    m_running = false;

    if (m_hStopEvent) {
        SetEvent(m_hStopEvent);
    }

    // Connect to unblock ConnectNamedPipe if waiting
    std::wstring wPipeName = util::Utf8ToWide(m_pipeName);
    HANDLE hWake = CreateFileW(
        wPipeName.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL
    );
    if (hWake != INVALID_HANDLE_VALUE) {
        CloseHandle(hWake);
    }

    if (m_serverThread.joinable()) {
        m_serverThread.join();
    }

    if (m_hStopEvent) {
        CloseHandle(m_hStopEvent);
        m_hStopEvent = NULL;
    }

    if (m_appContainerSid) {
        free(m_appContainerSid);
        m_appContainerSid = NULL;
    }
}

bool IpcBroker::IsKeyAllowed(const std::string& subKey) const {
    std::string norm = subKey;
    for (auto& ch : norm) {
        if (ch == '/') ch = '\\';
        ch = (char)tolower(ch);
    }
    while (!norm.empty() && norm.back() == '\\') norm.pop_back();

    for (const auto& allowed : m_allowedHkcuKeys) {
        std::string aNorm = allowed;
        for (auto& ch : aNorm) {
            if (ch == '/') ch = '\\';
            ch = (char)tolower(ch);
        }
        while (!aNorm.empty() && aNorm.back() == '\\') aNorm.pop_back();

        // Exact match or subkey match
        if (norm == aNorm) return true;
        if (norm.rfind(aNorm + "\\", 0) == 0) return true;
    }
    return false;
}

std::string IpcBroker::QueryRegistryValue(HKEY hRoot, const std::wstring& subKey, const std::wstring& valueName) {
    HKEY hKey = NULL;
    LSTATUS status = RegOpenKeyExW(hRoot, subKey.c_str(), 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) {
        return "{\"status\":\"not_found\",\"error\":\"Key open failed: " + std::to_string(status) + "\"}";
    }

    DWORD dwType = 0;
    DWORD cbData = 0;
    status = RegQueryValueExW(hKey, valueName.empty() ? NULL : valueName.c_str(), NULL, &dwType, NULL, &cbData);
    if (status != ERROR_SUCCESS || cbData == 0) {
        RegCloseKey(hKey);
        return "{\"status\":\"not_found\",\"error\":\"Value not found\"}";
    }

    std::vector<BYTE> data(cbData + 2, 0);
    status = RegQueryValueExW(hKey, valueName.empty() ? NULL : valueName.c_str(), NULL, &dwType, data.data(), &cbData);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS) {
        return "{\"status\":\"error\",\"error\":\"Query failed\"}";
    }

    if (dwType == REG_SZ || dwType == REG_EXPAND_SZ) {
        std::wstring wVal((wchar_t*)data.data());
        return "{\"status\":\"ok\",\"type\":\"REG_SZ\",\"value\":\"" + util::WideToUtf8(wVal) + "\"}";
    } else if (dwType == REG_DWORD && cbData >= sizeof(DWORD)) {
        DWORD dwVal = *(DWORD*)data.data();
        return "{\"status\":\"ok\",\"type\":\"REG_DWORD\",\"value\":" + std::to_string(dwVal) + "}";
    }

    return "{\"status\":\"ok\",\"type\":\"BINARY\",\"bytes\":" + std::to_string(cbData) + "}";
}

std::string IpcBroker::ProcessRequest(const std::string& req) {
    if (req.find("\"action\":\"ping\"") != std::string::npos || req.find("\"action\": \"ping\"") != std::string::npos) {
        return "{\"status\":\"ok\",\"service\":\"MCGuard IPC Broker\",\"version\":\"2.0\"}\n";
    }

    // Check for query_reg action
    if (req.find("\"query_reg\"") != std::string::npos) {
        // Extract root, key, value
        auto extractJsonField = [](const std::string& src, const std::string& field) -> std::string {
            std::string pat = "\"" + field + "\"";
            size_t p = src.find(pat);
            if (p == std::string::npos) return "";
            size_t col = src.find(':', p);
            if (col == std::string::npos) return "";
            size_t q1 = src.find('\"', col);
            if (q1 == std::string::npos) return "";
            size_t q2 = src.find('\"', q1 + 1);
            if (q2 == std::string::npos) return "";
            return src.substr(q1 + 1, q2 - q1 - 1);
        };

        std::string rootStr = extractJsonField(req, "root");
        std::string keyStr = extractJsonField(req, "key");
        std::string valStr = extractJsonField(req, "value");

        HKEY hRoot = HKEY_CURRENT_USER;
        if (rootStr == "HKLM" || rootStr == "HKEY_LOCAL_MACHINE") {
            hRoot = HKEY_LOCAL_MACHINE;
        }

        // Enforce policy: check if key is allowed
        if (!IsKeyAllowed(keyStr)) {
            return "{\"status\":\"denied\",\"error\":\"Registry key access prohibited by MCGuard Broker policy: " + keyStr + "\"}\n";
        }

        std::string res = QueryRegistryValue(hRoot, util::Utf8ToWide(keyStr), util::Utf8ToWide(valStr));
        return res + "\n";
    }

    return "{\"status\":\"bad_request\",\"error\":\"Unknown action\"}\n";
}

void IpcBroker::HandleClient(HANDLE hPipe) {
    char buf[4096] = { 0 };
    DWORD bytesRead = 0;

    if (ReadFile(hPipe, buf, sizeof(buf) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buf[bytesRead] = '\0';
        std::string response = ProcessRequest(buf);
        DWORD bytesWritten = 0;
        WriteFile(hPipe, response.c_str(), (DWORD)response.length(), &bytesWritten, NULL);
        FlushFileBuffers(hPipe);
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}

void IpcBroker::ServerLoop() {
    std::wstring wPipeName = util::Utf8ToWide(m_pipeName);

    // Create Security Descriptor granting access to Current User and AppContainer SID
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);

    EXPLICIT_ACCESS_W ea[2] = { 0 };
    DWORD eaCount = 1;

    // 1. Current user full control
    PSID pUserSid = NULL;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD len = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
        if (len > 0) {
            std::vector<BYTE> buf(len);
            if (GetTokenInformation(hToken, TokenUser, buf.data(), len, &len)) {
                PTOKEN_USER pTU = (PTOKEN_USER)buf.data();
                ea[0].grfAccessPermissions = GENERIC_ALL;
                ea[0].grfAccessMode = GRANT_ACCESS;
                ea[0].grfInheritance = NO_INHERITANCE;
                ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
                ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
                ea[0].Trustee.ptstrName = (LPWSTR)pTU->User.Sid;
            }
        }
        CloseHandle(hToken);
    }

    // 2. AppContainer SID Read/Write access
    if (m_appContainerSid) {
        ea[1].grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
        ea[1].grfAccessMode = GRANT_ACCESS;
        ea[1].grfInheritance = NO_INHERITANCE;
        ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[1].Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
        ea[1].Trustee.ptstrName = (LPWSTR)m_appContainerSid;
        eaCount = 2;
    }

    PACL pAcl = NULL;
    SetEntriesInAclW(eaCount, ea, NULL, &pAcl);
    if (pAcl) {
        SetSecurityDescriptorDacl(&sd, TRUE, pAcl, FALSE);
    }

    SECURITY_ATTRIBUTES sa = { sizeof(sa), &sd, FALSE };

    while (m_running) {
        HANDLE hPipe = CreateNamedPipeW(
            wPipeName.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096, 4096, 0, &sa
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(500);
            continue;
        }

        OVERLAPPED ov = { 0 };
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

        BOOL connected = ConnectNamedPipe(hPipe, &ov);
        if (!connected) {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING) {
                HANDLE waitHandles[2] = { ov.hEvent, m_hStopEvent };
                DWORD waitRes = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
                if (waitRes == WAIT_OBJECT_0 + 1 || !m_running) {
                    // Stop requested
                    CancelIo(hPipe);
                    CloseHandle(ov.hEvent);
                    CloseHandle(hPipe);
                    break;
                }
            } else if (err != ERROR_PIPE_CONNECTED) {
                CloseHandle(ov.hEvent);
                CloseHandle(hPipe);
                continue;
            }
        }

        CloseHandle(ov.hEvent);

        if (!m_running) {
            CloseHandle(hPipe);
            break;
        }

        // Handle client connection in a separate thread to keep server responsive
        std::thread([this, hPipe]() {
            this->HandleClient(hPipe);
        }).detach();
    }

    if (pAcl) {
        LocalFree(pAcl);
    }
}

} // namespace core
} // namespace mcguard
