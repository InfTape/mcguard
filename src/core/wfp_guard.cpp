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

    // 3. Subscribe to Net Events (Classification Drops)
    if (m_netEventSubHandle) {
        FwpmNetEventUnsubscribe0(m_engineHandle, m_netEventSubHandle);
        m_netEventSubHandle = NULL;
    }
    FWPM_NET_EVENT_SUBSCRIPTION0 sub = { 0 };
    DWORD subRes = FwpmNetEventSubscribe0(m_engineHandle, &sub, &WfpGuard::NetEventCallback, this, &m_netEventSubHandle);
    if (subRes != ERROR_SUCCESS) {
        m_netEventSubHandle = NULL;
    }

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

    // Condition 1: Remote IP or CIDR Subnet
    FWP_V4_ADDR_AND_MASK addrMask = { 0 };
    if (!rule.ip.empty()) {
        uint32_t ipHost = 0, maskHost = 0;
        bool isCidr = false;
        if (util::ParseIpOrCidr(rule.ip, ipHost, maskHost, isCidr)) {
            FWPM_FILTER_CONDITION0 condIp = { 0 };
            condIp.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            condIp.matchType = FWP_MATCH_EQUAL;

            if (isCidr) {
                addrMask.addr = ipHost;
                addrMask.mask = maskHost;
                condIp.conditionValue.type = FWP_V4_ADDR_MASK;
                condIp.conditionValue.v4AddrMask = &addrMask;
            } else {
                condIp.conditionValue.type = FWP_UINT32;
                condIp.conditionValue.uint32 = ipHost; // Host byte order required by WFP
            }
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

    if (m_netEventSubHandle) {
        FwpmNetEventUnsubscribe0(m_engineHandle, m_netEventSubHandle);
        m_netEventSubHandle = NULL;
    }

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

void CALLBACK WfpGuard::NetEventCallback(void* context, const FWPM_NET_EVENT1* event) {
    if (!context || !event) return;
    auto pThis = reinterpret_cast<WfpGuard*>(context);

    if (event->type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP) {
        bool isOurDrop = false;
        if (event->classifyDrop) {
            std::lock_guard<std::mutex> lock(pThis->m_mutex);
            for (UINT64 fId : pThis->m_installedFilterIds) {
                if (event->classifyDrop->filterId == fId) {
                    isOurDrop = true;
                    break;
                }
            }
        }
        if (!isOurDrop && pThis->m_appId && event->header.appId.size == pThis->m_appId->size &&
            memcmp(event->header.appId.data, pThis->m_appId->data, pThis->m_appId->size) == 0) {
            isOurDrop = true;
        }

        if (isOurDrop && event->header.ipVersion == FWP_IP_VERSION_V4) {
            uint32_t netIp = htonl(event->header.remoteAddrV4);
            std::string remoteIp = util::Ipv4ToString(netIp);
            uint16_t remotePort = event->header.remotePort;

            // Deduplicate drops for the same target within 1000ms
            std::string key = remoteIp + ":" + std::to_string(remotePort);
            uint64_t nowMs = GetTickCount64();
            {
                std::lock_guard<std::mutex> lock(pThis->m_dropDedupeMutex);
                auto it = pThis->m_lastDropTimeMs.find(key);
                if (it != pThis->m_lastDropTimeMs.end() && (nowMs - it->second) < 1000) {
                    return;
                }
                pThis->m_lastDropTimeMs[key] = nowMs;
            }

            if (pThis->m_dropCallback) {
                pThis->m_dropCallback(remoteIp, remotePort);
            }
        }
    }
}

} // namespace core
} // namespace mcguard
