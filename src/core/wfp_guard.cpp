#include "wfp_guard.h"
#include "../util/string_util.h"
#include <iostream>
#include <objbase.h>

#pragma comment(lib, "Fwpuclnt.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Ole32.lib")

namespace mcguard {
namespace core {

// Static GUID for the MCGuard Sublayer
static const GUID MCGUARD_SUBLAYER_GUID = 
    { 0xb03b7431, 0x12dc, 0x47d9, { 0x8b, 0x4f, 0x6e, 0x93, 0x8a, 0x51, 0x22, 0xd0 } };

WfpGuard::WfpGuard() : m_subLayerKey(MCGUARD_SUBLAYER_GUID) {}

WfpGuard::~WfpGuard() {
    Shutdown();
}

bool WfpGuard::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_engineHandle != NULL) return true;

    FWPM_SESSION0 session = { 0 };
    session.displayData.name = L"MCGuard Dynamic WFP Session";
    session.displayData.description = L"Dynamic ALE filtering for Minecraft sandboxing";
    // FWPM_SESSION_FLAG_DYNAMIC ensures all added objects are destroyed if MCGuard closes/crashes
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    DWORD res = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &m_engineHandle);
    if (res != ERROR_SUCCESS) {
        std::wcerr << L"[-] Failed to open WFP engine: 0x" << std::hex << res 
                   << L" (Requires Administrator privileges)\n";
        m_engineHandle = NULL;
        return false;
    }

    if (!CreateSubLayer()) {
        FwpmEngineClose0(m_engineHandle);
        m_engineHandle = NULL;
        return false;
    }

    return true;
}

bool WfpGuard::CreateSubLayer() {
    FWPM_SUBLAYER0 subLayer = { 0 };
    subLayer.subLayerKey = m_subLayerKey;
    subLayer.displayData.name = L"MCGuard ALE Sublayer";
    subLayer.displayData.description = L"Sublayer for Minecraft process network confinement";
    subLayer.flags = 0;
    subLayer.weight = 0x8000;

    DWORD res = FwpmSubLayerAdd0(m_engineHandle, &subLayer, NULL);
    if (res != ERROR_SUCCESS && res != FWP_E_ALREADY_EXISTS) {
        std::wcerr << L"[-] Failed to create WFP sublayer: 0x" << std::hex << res << L"\n";
        return false;
    }
    return true;
}

bool WfpGuard::ProtectApplication(const std::wstring& appPath, const std::vector<WhitelistRule>& whitelist) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_engineHandle) {
        if (!Initialize()) return false;
    }

    // Detach any previous rules
    RemoveInstalledFilters();

    // Generate AppId for the specified application path
    if (m_appId) {
        FwpmFreeMemory0((void**)&m_appId);
        m_appId = NULL;
    }

    DWORD res = FwpmGetAppIdFromFileName0(appPath.c_str(), &m_appId);
    if (res != ERROR_SUCCESS || !m_appId) {
        std::wcerr << L"[-] FwpmGetAppIdFromFileName0 failed for " << appPath 
                   << L", error: 0x" << std::hex << res << L"\n";
        return false;
    }

    m_protectedAppPath = appPath;

    // 1. Add Default Block Rule (Lowest priority within our sublayer: weight = 1)
    // Any outbound connection from this AppId not matching an earlier permit rule will be blocked!
    if (!AddDefaultBlockRule(1)) {
        std::wcerr << L"[-] Failed to add default block rule for AppId.\n";
        RemoveInstalledFilters();
        return false;
    }

    // 2. Add Whitelist Permit Rules (Higher priority: weight = 10)
    uint8_t permitWeight = 10;
    for (const auto& rule : whitelist) {
        if (!AddPermitRule(rule, permitWeight)) {
            std::wcerr << L"[!] Warning: Failed to add whitelist rule: " 
                       << util::Utf8ToWide(rule.description) << L"\n";
        }
    }

    // Always permit Localhost (127.0.0.1)
    WhitelistRule loopbackRule;
    loopbackRule.description = "Loopback 127.0.0.1";
    loopbackRule.ip = "127.0.0.1";
    loopbackRule.port = 0; // Any port
    loopbackRule.protocol = "ANY";
    AddPermitRule(loopbackRule, permitWeight + 1);

    m_isProtecting = true;
    return true;
}

bool WfpGuard::AddDefaultBlockRule(uint8_t weight) {
    if (!m_engineHandle || !m_appId) return false;

    // Layers to block: IPv4 and IPv6 outbound connect
    const GUID layers[] = {
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6
    };

    for (const auto& layer : layers) {
        FWPM_FILTER0 filter = { 0 };
        filter.layerKey = layer;
        filter.subLayerKey = m_subLayerKey;
        filter.displayData.name = L"MCGuard_Default_Block";
        filter.displayData.description = L"Block all non-whitelisted outbound connections for target process";
        filter.action.type = FWP_ACTION_BLOCK;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = weight;

        // Condition: FWPM_CONDITION_ALE_APP_ID == m_appId
        FWPM_FILTER_CONDITION0 cond[1] = { 0 };
        cond[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        cond[0].matchType = FWP_MATCH_EQUAL;
        cond[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        cond[0].conditionValue.byteBlob = m_appId;

        filter.numFilterConditions = 1;
        filter.filterCondition = cond;

        UINT64 filterId = 0;
        DWORD res = FwpmFilterAdd0(m_engineHandle, &filter, NULL, &filterId);
        if (res != ERROR_SUCCESS) {
            std::wcerr << L"[-] FwpmFilterAdd0 (BLOCK) failed: 0x" << std::hex << res << L"\n";
            return false;
        }
        m_installedFilterIds.push_back(filterId);
    }

    return true;
}

bool WfpGuard::AddPermitRule(const WhitelistRule& rule, uint8_t weight) {
    if (!m_engineHandle || !m_appId) return false;

    FWPM_FILTER0 filter = { 0 };
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = m_subLayerKey;
    std::wstring name = L"MCGuard_Permit_" + util::Utf8ToWide(rule.description);
    filter.displayData.name = (PWSTR)name.c_str();
    filter.action.type = FWP_ACTION_PERMIT;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;

    std::vector<FWPM_FILTER_CONDITION0> conditions;

    // Condition 0: ALE_APP_ID
    FWPM_FILTER_CONDITION0 condApp = { 0 };
    condApp.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    condApp.matchType = FWP_MATCH_EQUAL;
    condApp.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    condApp.conditionValue.byteBlob = m_appId;
    conditions.push_back(condApp);

    // Condition 1: Remote IP
    if (!rule.ip.empty()) {
        uint32_t ipNetworkOrder = util::StringToIpv4(rule.ip);
        if (ipNetworkOrder != 0) {
            FWPM_FILTER_CONDITION0 condIp = { 0 };
            condIp.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            condIp.matchType = FWP_MATCH_EQUAL;
            condIp.conditionValue.type = FWP_UINT32;
            condIp.conditionValue.uint32 = ntohl(ipNetworkOrder); // Host byte order required by WFP
            conditions.push_back(condIp);
        }
    }

    // Condition 2: Remote Port
    if (rule.port > 0) {
        FWPM_FILTER_CONDITION0 condPort = { 0 };
        condPort.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        condPort.matchType = FWP_MATCH_EQUAL;
        condPort.conditionValue.type = FWP_UINT16;
        condPort.conditionValue.uint16 = rule.port;
        conditions.push_back(condPort);
    }

    // Condition 3: Protocol
    if (rule.protocol == "TCP") {
        FWPM_FILTER_CONDITION0 condProto = { 0 };
        condProto.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        condProto.matchType = FWP_MATCH_EQUAL;
        condProto.conditionValue.type = FWP_UINT8;
        condProto.conditionValue.uint8 = IPPROTO_TCP;
        conditions.push_back(condProto);
    } else if (rule.protocol == "UDP") {
        FWPM_FILTER_CONDITION0 condProto = { 0 };
        condProto.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        condProto.matchType = FWP_MATCH_EQUAL;
        condProto.conditionValue.type = FWP_UINT8;
        condProto.conditionValue.uint8 = IPPROTO_UDP;
        conditions.push_back(condProto);
    }

    filter.numFilterConditions = (UINT32)conditions.size();
    filter.filterCondition = conditions.data();

    UINT64 filterId = 0;
    DWORD res = FwpmFilterAdd0(m_engineHandle, &filter, NULL, &filterId);
    if (res != ERROR_SUCCESS) {
        std::wcerr << L"[-] FwpmFilterAdd0 (PERMIT) failed: 0x" << std::hex << res << L"\n";
        return false;
    }

    m_installedFilterIds.push_back(filterId);
    return true;
}

bool WfpGuard::AddWhitelistRule(const WhitelistRule& rule) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_isProtecting) return false;
    return AddPermitRule(rule, 15);
}

void WfpGuard::RemoveInstalledFilters() {
    if (!m_engineHandle) return;

    for (UINT64 filterId : m_installedFilterIds) {
        FwpmFilterDeleteById0(m_engineHandle, filterId);
    }
    m_installedFilterIds.clear();
    m_isProtecting = false;
}

void WfpGuard::Detach() {
    std::lock_guard<std::mutex> lock(m_mutex);
    RemoveInstalledFilters();
    if (m_appId) {
        FwpmFreeMemory0((void**)&m_appId);
        m_appId = NULL;
    }
    m_protectedAppPath.clear();
}

void WfpGuard::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    RemoveInstalledFilters();
    if (m_appId) {
        FwpmFreeMemory0((void**)&m_appId);
        m_appId = NULL;
    }
    if (m_engineHandle) {
        FwpmSubLayerDeleteByKey0(m_engineHandle, &m_subLayerKey);
        FwpmEngineClose0(m_engineHandle);
        m_engineHandle = NULL;
    }
}

} // namespace core
} // namespace mcguard
