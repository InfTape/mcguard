#include "etw_watcher.h"
#include "dns_tracker.h"
#include "../util/string_util.h"
#include <iostream>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace mcguard {
namespace core {

// Provider GUIDs
static const GUID KernelFileProviderGuid = 
    { 0xedd08927, 0x9cc4, 0x4e65, { 0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89 } };

static const GUID KernelNetworkProviderGuid = 
    { 0x7dd42a49, 0x5329, 0x4832, { 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88 } };

static const GUID DnsClientProviderGuid = 
    { 0x1c95126e, 0x7eea, 0x49a9, { 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d } };

EtwWatcher* EtwWatcher::s_instance = nullptr;

EtwWatcher::EtwWatcher() : m_sessionName(L"MCGuard_ETW_Session") {
    s_instance = this;
}

EtwWatcher::~EtwWatcher() {
    Stop();
    if (s_instance == this) {
        s_instance = nullptr;
    }
}

void EtwWatcher::AddTargetPid(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_pidMutex);
    m_targetPids.insert(pid);
}

void EtwWatcher::RemoveTargetPid(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_pidMutex);
    m_targetPids.erase(pid);
}

void EtwWatcher::ClearTargetPids() {
    std::lock_guard<std::mutex> lock(m_pidMutex);
    m_targetPids.clear();
}

bool EtwWatcher::Start(EventCallback callback) {
    if (m_running) return true;
    m_callback = callback;

    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 512;
    std::vector<BYTE> propsBuffer(bufferSize, 0);
    auto pProps = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propsBuffer.data());
    pProps->Wnode.BufferSize = bufferSize;
    pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pProps->Wnode.ClientContext = 1; // QPC
    pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    // Stop any stale session with the same name
    ControlTraceW(0, m_sessionName.c_str(), pProps, EVENT_TRACE_CONTROL_STOP);

    ULONG status = StartTraceW(&m_sessionHandle, m_sessionName.c_str(), pProps);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"[-] Failed to start ETW trace session: " << status 
                   << L" (Ensure running as Administrator for kernel providers)\n";
        return false;
    }

    ENABLE_TRACE_PARAMETERS params = { 0 };
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

    // Enable File I/O provider (all keywords)
    EnableTraceEx2(
        m_sessionHandle,
        &KernelFileProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        (ULONGLONG)~0ULL, 0, 0, &params
    );

    // Enable Network provider (all keywords)
    EnableTraceEx2(
        m_sessionHandle,
        &KernelNetworkProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        (ULONGLONG)~0ULL, 0, 0, &params
    );

    // Enable DNS Client provider (Operational keyword: 0x8000000000000000)
    EnableTraceEx2(
        m_sessionHandle,
        &DnsClientProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0x8000000000000000ULL, 0, 0, &params
    );

    m_running = true;
    m_workerThread = std::thread(&EtwWatcher::TraceWorkerThread, this, callback);
    return true;
}

void EtwWatcher::Stop() {
    if (!m_running) return;
    m_running = false;

    if (m_traceHandle != 0 && m_traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(m_traceHandle);
        m_traceHandle = 0;
    }

    if (m_sessionHandle != 0) {
        ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 512;
        std::vector<BYTE> propsBuffer(bufferSize, 0);
        auto pProps = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propsBuffer.data());
        pProps->Wnode.BufferSize = bufferSize;
        pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(m_sessionHandle, m_sessionName.c_str(), pProps, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = 0;
    }

    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }
}

void EtwWatcher::TraceWorkerThread(EventCallback callback) {
    EVENT_TRACE_LOGFILEW logFile = { 0 };
    logFile.LoggerName = const_cast<LPWSTR>(m_sessionName.c_str());
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = &EtwWatcher::EventRecordCallback;

    m_traceHandle = OpenTraceW(&logFile);
    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        std::wcerr << L"[-] OpenTraceW failed.\n";
        m_running = false;
        return;
    }

    // ProcessTrace blocks until CloseTrace is called
    ProcessTrace(&m_traceHandle, 1, NULL, NULL);
    m_running = false;
}

static bool GetTdhPropertyPointer(PEVENT_RECORD pEventRecord, PTRACE_EVENT_INFO pInfo, const wchar_t* targetName, ULONGLONG& outVal) {
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
        LPWSTR propName = (LPWSTR)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
        if (_wcsicmp(propName, targetName) == 0) {
            PROPERTY_DATA_DESCRIPTOR desc = { 0 };
            desc.PropertyName = (ULONGLONG)propName;
            desc.ArrayIndex = ULONG_MAX;
            DWORD propSize = 0;
            TdhGetPropertySize(pEventRecord, 0, NULL, 1, &desc, &propSize);
            if (propSize == sizeof(ULONGLONG)) {
                return TdhGetProperty(pEventRecord, 0, NULL, 1, &desc, propSize, (PBYTE)&outVal) == ERROR_SUCCESS;
            } else if (propSize == sizeof(DWORD)) {
                DWORD d = 0;
                if (TdhGetProperty(pEventRecord, 0, NULL, 1, &desc, propSize, (PBYTE)&d) == ERROR_SUCCESS) {
                    outVal = d;
                    return true;
                }
            }
            break;
        }
    }
    return false;
}

static bool GetTdhPropertyUInt32(PEVENT_RECORD pEventRecord, PTRACE_EVENT_INFO pInfo, const wchar_t* targetName, uint32_t& outVal) {
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
        LPWSTR propName = (LPWSTR)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
        if (_wcsicmp(propName, targetName) == 0) {
            PROPERTY_DATA_DESCRIPTOR desc = { 0 };
            desc.PropertyName = (ULONGLONG)propName;
            desc.ArrayIndex = ULONG_MAX;
            DWORD propSize = 0;
            TdhGetPropertySize(pEventRecord, 0, NULL, 1, &desc, &propSize);
            if (propSize == sizeof(uint32_t)) {
                return TdhGetProperty(pEventRecord, 0, NULL, 1, &desc, propSize, (PBYTE)&outVal) == ERROR_SUCCESS;
            }
            break;
        }
    }
    return false;
}

static bool GetTdhPropertyString(PEVENT_RECORD pEventRecord, PTRACE_EVENT_INFO pInfo, const wchar_t* targetName, std::wstring& outVal) {
    for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
        LPWSTR propName = (LPWSTR)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
        if (_wcsicmp(propName, targetName) == 0) {
            PROPERTY_DATA_DESCRIPTOR desc = { 0 };
            desc.PropertyName = (ULONGLONG)propName;
            desc.ArrayIndex = ULONG_MAX;
            DWORD propSize = 0;
            TdhGetPropertySize(pEventRecord, 0, NULL, 1, &desc, &propSize);
            if (propSize > 0) {
                std::vector<BYTE> buf(propSize + 2, 0);
                if (TdhGetProperty(pEventRecord, 0, NULL, 1, &desc, propSize, buf.data()) == ERROR_SUCCESS) {
                    outVal = (LPWSTR)buf.data();
                    return true;
                }
            }
            break;
        }
    }
    return false;
}

VOID WINAPI EtwWatcher::EventRecordCallback(PEVENT_RECORD pEventRecord) {
    if (!s_instance || !pEventRecord) return;

    const GUID& providerId = pEventRecord->EventHeader.ProviderId;

    // 0. Check DNS Client Provider first (System-wide & Game DNS resolutions)
    if (IsEqualGUID(providerId, DnsClientProviderGuid)) {
        DWORD bufferSize = 0;
        TdhGetEventInformation(pEventRecord, 0, NULL, NULL, &bufferSize);
        if (bufferSize > 0) {
            std::vector<BYTE> infoBuffer(bufferSize);
            auto pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
            if (TdhGetEventInformation(pEventRecord, 0, NULL, pInfo, &bufferSize) == ERROR_SUCCESS) {
                std::wstring queryName;
                std::wstring queryResults;
                for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
                    LPWSTR propName = (LPWSTR)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
                    if (_wcsicmp(propName, L"QueryName") == 0) {
                        PROPERTY_DATA_DESCRIPTOR desc = { 0 };
                        desc.PropertyName = (ULONGLONG)propName;
                        desc.ArrayIndex = ULONG_MAX;
                        DWORD propSize = 0;
                        TdhGetPropertySize(pEventRecord, 0, NULL, 1, &desc, &propSize);
                        if (propSize > 0) {
                            std::vector<BYTE> propVal(propSize + 2, 0);
                            if (TdhGetProperty(pEventRecord, 0, NULL, 1, &desc, propSize, propVal.data()) == ERROR_SUCCESS) {
                                queryName = (LPWSTR)propVal.data();
                            }
                        }
                    } else if (_wcsicmp(propName, L"QueryResults") == 0) {
                        PROPERTY_DATA_DESCRIPTOR desc = { 0 };
                        desc.PropertyName = (ULONGLONG)propName;
                        desc.ArrayIndex = ULONG_MAX;
                        DWORD propSize = 0;
                        TdhGetPropertySize(pEventRecord, 0, NULL, 1, &desc, &propSize);
                        if (propSize > 0) {
                            std::vector<BYTE> propVal(propSize + 2, 0);
                            if (TdhGetProperty(pEventRecord, 0, NULL, 1, &desc, propSize, propVal.data()) == ERROR_SUCCESS) {
                                queryResults = (LPWSTR)propVal.data();
                            }
                        }
                    }
                }
                if (!queryName.empty() && !queryResults.empty()) {
                    DnsTracker::Instance().ParseAndRegisterDnsResults(
                        util::WideToUtf8(queryName),
                        util::WideToUtf8(queryResults)
                    );
                }
            }
        }
        return;
    }

    DWORD pid = pEventRecord->EventHeader.ProcessId;
    bool isFileProvider = IsEqualGUID(providerId, KernelFileProviderGuid);
    USHORT eventId = pEventRecord->EventHeader.EventDescriptor.Id;

    // 1. Check File Events (Microsoft-Windows-Kernel-File)
    if (isFileProvider) {
        // Special Case: Event ID 24 (OperationEnd) signals completion of an I/O request (Create/Open)
        // Correlate with pending IRP regardless of which thread/context completes the IRP
        if (eventId == 24) {
            DWORD bufferSize = 0;
            TdhGetEventInformation(pEventRecord, 0, NULL, NULL, &bufferSize);
            if (bufferSize > 0) {
                std::vector<BYTE> infoBuffer(bufferSize);
                auto pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
                if (TdhGetEventInformation(pEventRecord, 0, NULL, pInfo, &bufferSize) == ERROR_SUCCESS) {
                    ULONGLONG irp = 0;
                    if (GetTdhPropertyPointer(pEventRecord, pInfo, L"Irp", irp) && irp != 0) {
                        PendingFileOp op;
                        bool found = false;
                        {
                            std::lock_guard<std::mutex> lock(s_instance->m_pendingMutex);
                            auto it = s_instance->m_pendingCreates.find(irp);
                            if (it != s_instance->m_pendingCreates.end()) {
                                op = it->second;
                                s_instance->m_pendingCreates.erase(it);
                                found = true;
                            }
                        }

                        if (found) {
                            uint32_t status = 0;
                            GetTdhPropertyUInt32(pEventRecord, pInfo, L"Status", status);

                            EtwEvent ev;
                            ev.pid = op.pid;
                            ev.tid = op.tid;
                            ev.timestamp = op.timestamp;
                            ev.target = op.target;
                            ev.status = status;

                            if (status == 0xC0000022) { // STATUS_ACCESS_DENIED
                                ev.type = EtwEventType::FILE_ACCESS_DENIED;
                                if (s_instance->m_callback) {
                                    s_instance->m_callback(ev);
                                }
                            } else if (status == 0) { // STATUS_SUCCESS
                                ev.type = EtwEventType::FILE_CREATE;
                                if (s_instance->m_callback) {
                                    s_instance->m_callback(ev);
                                }
                            }
                        }
                    }
                }
            }
            return;
        }

        // For all other file events, filter by monitored PIDs
        {
            std::lock_guard<std::mutex> lock(s_instance->m_pidMutex);
            if (s_instance->m_targetPids.empty() || s_instance->m_targetPids.find(pid) == s_instance->m_targetPids.end()) {
                return;
            }
        }

        // Event ID 12 (Create) or 30 (CreateNewFile): register pending IRP
        if (eventId == 12 || eventId == 30) {
            DWORD bufferSize = 0;
            TdhGetEventInformation(pEventRecord, 0, NULL, NULL, &bufferSize);
            if (bufferSize > 0) {
                std::vector<BYTE> infoBuffer(bufferSize);
                auto pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
                if (TdhGetEventInformation(pEventRecord, 0, NULL, pInfo, &bufferSize) == ERROR_SUCCESS) {
                    ULONGLONG irp = 0;
                    std::wstring rawName;
                    GetTdhPropertyPointer(pEventRecord, pInfo, L"Irp", irp);
                    GetTdhPropertyString(pEventRecord, pInfo, L"FileName", rawName);

                    if (irp != 0 && !rawName.empty()) {
                        std::wstring dosPath = util::ResolveNtDevicePath(rawName);
                        std::lock_guard<std::mutex> lock(s_instance->m_pendingMutex);
                        if (s_instance->m_pendingCreates.size() > 5000) {
                            s_instance->m_pendingCreates.clear();
                        }
                        s_instance->m_pendingCreates[irp] = { pid, pEventRecord->EventHeader.ThreadId, dosPath, util::GetCurrentTimeString() };
                    }
                }
            }
            return;
        }

        // Event ID 26 (DeletePath)
        if (eventId == 26) {
            DWORD bufferSize = 0;
            TdhGetEventInformation(pEventRecord, 0, NULL, NULL, &bufferSize);
            if (bufferSize > 0) {
                std::vector<BYTE> infoBuffer(bufferSize);
                auto pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
                if (TdhGetEventInformation(pEventRecord, 0, NULL, pInfo, &bufferSize) == ERROR_SUCCESS) {
                    std::wstring rawPath;
                    if (GetTdhPropertyString(pEventRecord, pInfo, L"FilePath", rawPath)) {
                        EtwEvent ev;
                        ev.pid = pid;
                        ev.tid = pEventRecord->EventHeader.ThreadId;
                        ev.timestamp = util::GetCurrentTimeString();
                        ev.type = EtwEventType::FILE_DELETE;
                        ev.target = util::ResolveNtDevicePath(rawPath);
                        if (s_instance->m_callback) {
                            s_instance->m_callback(ev);
                        }
                    }
                }
            }
            return;
        }

        // Event ID 27 (RenamePath)
        if (eventId == 27) {
            DWORD bufferSize = 0;
            TdhGetEventInformation(pEventRecord, 0, NULL, NULL, &bufferSize);
            if (bufferSize > 0) {
                std::vector<BYTE> infoBuffer(bufferSize);
                auto pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
                if (TdhGetEventInformation(pEventRecord, 0, NULL, pInfo, &bufferSize) == ERROR_SUCCESS) {
                    std::wstring rawPath;
                    if (GetTdhPropertyString(pEventRecord, pInfo, L"FilePath", rawPath)) {
                        EtwEvent ev;
                        ev.pid = pid;
                        ev.tid = pEventRecord->EventHeader.ThreadId;
                        ev.timestamp = util::GetCurrentTimeString();
                        ev.type = EtwEventType::FILE_RENAME;
                        ev.target = util::ResolveNtDevicePath(rawPath);
                        if (s_instance->m_callback) {
                            s_instance->m_callback(ev);
                        }
                    }
                }
            }
            return;
        }

        return;
    }

    // Check if pid is monitored for Network I/O
    {
        std::lock_guard<std::mutex> lock(s_instance->m_pidMutex);
        if (s_instance->m_targetPids.empty() || s_instance->m_targetPids.find(pid) == s_instance->m_targetPids.end()) {
            return;
        }
    }

    // 2. Check Network Events
    if (IsEqualGUID(providerId, KernelNetworkProviderGuid)) {
        EtwEvent ev;
        ev.pid = pid;
        ev.tid = pEventRecord->EventHeader.ThreadId;
        ev.timestamp = util::GetCurrentTimeString();

        UCHAR opcode = pEventRecord->EventHeader.EventDescriptor.Opcode;
        if (opcode == 10 || opcode == 12) {
            ev.type = EtwEventType::TCP_CONNECT;
        } else if (opcode == 13 || opcode == 15) {
            ev.type = EtwEventType::TCP_SEND;
        } else {
            ev.type = EtwEventType::TCP_RECV;
        }

        // TDH property parsing for daddr and dport
        DWORD bufferSize = 0;
        TdhGetEventInformation(pEventRecord, 0, NULL, NULL, &bufferSize);
        if (bufferSize > 0) {
            std::vector<BYTE> infoBuffer(bufferSize);
            auto pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
            if (TdhGetEventInformation(pEventRecord, 0, NULL, pInfo, &bufferSize) == ERROR_SUCCESS) {
                std::string ipStr;
                uint16_t port = 0;

                for (ULONG i = 0; i < pInfo->TopLevelPropertyCount; ++i) {
                    LPWSTR propName = (LPWSTR)((PBYTE)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
                    if (_wcsicmp(propName, L"daddr") == 0 || _wcsicmp(propName, L"RemoteAddress") == 0) {
                        PROPERTY_DATA_DESCRIPTOR desc = { 0 };
                        desc.PropertyName = (ULONGLONG)propName;
                        desc.ArrayIndex = ULONG_MAX;
                        DWORD propSize = 0;
                        TdhGetPropertySize(pEventRecord, 0, NULL, 1, &desc, &propSize);
                        if (propSize == sizeof(IN_ADDR)) {
                            IN_ADDR inAddr;
                            TdhGetProperty(pEventRecord, 0, NULL, 1, &desc, sizeof(inAddr), (PBYTE)&inAddr);
                            ipStr = util::Ipv4ToString(inAddr.S_un.S_addr);
                        }
                    } else if (_wcsicmp(propName, L"dport") == 0 || _wcsicmp(propName, L"RemotePort") == 0) {
                        PROPERTY_DATA_DESCRIPTOR desc = { 0 };
                        desc.PropertyName = (ULONGLONG)propName;
                        desc.ArrayIndex = ULONG_MAX;
                        WORD rawPort = 0;
                        TdhGetProperty(pEventRecord, 0, NULL, 1, &desc, sizeof(rawPort), (PBYTE)&rawPort);
                        port = ntohs(rawPort);
                    }
                }

                if (!ipStr.empty()) {
                    ev.target = util::Utf8ToWide(ipStr + ":" + std::to_string(port));
                    ev.port = port;
                }
            }
        }

        if (ev.target.empty()) {
            ev.target = L"[Unknown Network Flow]";
        }

        if (s_instance->m_callback) {
            s_instance->m_callback(ev);
        }
        return;
    }
}

} // namespace core
} // namespace mcguard
