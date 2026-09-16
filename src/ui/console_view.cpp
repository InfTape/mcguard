#include "console_view.h"
#include "../common.h"
#include "../util/string_util.h"
#include <iostream>
#include <iomanip>
#include <sstream>

namespace mcguard {
namespace ui {

// ANSI escape codes
#define ANSI_RESET       "\033[0m"
#define ANSI_BOLD        "\033[1m"
#define ANSI_RED         "\033[31m"
#define ANSI_GREEN       "\033[32m"
#define ANSI_YELLOW      "\033[33m"
#define ANSI_BLUE        "\033[34m"
#define ANSI_MAGENTA     "\033[35m"
#define ANSI_CYAN        "\033[36m"
#define ANSI_WHITE       "\033[37m"
#define ANSI_BG_RED      "\033[41m\033[37m"
#define ANSI_GRAY        "\033[90m"

ConsoleView::ConsoleView(const std::string& logFilePath) : m_logFilePath(logFilePath) {}

ConsoleView::~ConsoleView() {
    if (m_logStream.is_open()) {
        m_logStream.close();
    }
}

void ConsoleView::Initialize() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        DWORD dwMode = 0;
        if (GetConsoleMode(hOut, &dwMode)) {
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            if (SetConsoleMode(hOut, dwMode)) {
                m_ansiSupported = true;
            }
        }
    }

    // Disable QuickEdit mode on stdin to prevent mouse clicks from freezing the console
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hIn != INVALID_HANDLE_VALUE) {
        DWORD dwInMode = 0;
        if (GetConsoleMode(hIn, &dwInMode)) {
            dwInMode &= ~ENABLE_QUICK_EDIT_MODE;
            dwInMode |= ENABLE_EXTENDED_FLAGS;
            SetConsoleMode(hIn, dwInMode);
        }
    }

    // If relative path, place it in the same directory as the executable
    std::string fullLogPath = m_logFilePath;
    wchar_t exePath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        std::wstring wExe(exePath);
        size_t lastSlash = wExe.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos) {
            std::wstring dir = wExe.substr(0, lastSlash + 1);
            fullLogPath = util::WideToUtf8(dir) + m_logFilePath;
        }
    }

    // Open log file in append mode
    m_logStream.open(fullLogPath, std::ios::out | std::ios::app);
    if (!m_logStream.is_open()) {
        m_logStream.open(m_logFilePath, std::ios::out | std::ios::app);
    }

    std::cout << "\n";
    std::cout << (m_ansiSupported ? ANSI_CYAN ANSI_BOLD : "")
              << "========================================================================================\n"
              << "             MCGuard - Standalone Pure User-Mode Minecraft Sandbox Auditor              \n"
              << "     [WFP ALE Engine: Active] [ETW Kernel I/O: Active] [Native Module Audit: Active]    \n"
              << "========================================================================================\n"
              << (m_ansiSupported ? ANSI_RESET : "");

    // Print table column header
    std::cout << (m_ansiSupported ? ANSI_BOLD : "")
              << TruncateOrPad("TIME", 10) << " "
              << TruncateOrPad("PID", 7) << " "
              << TruncateOrPad("TYPE", 12) << " "
              << TruncateOrPad("TARGET", 38) << " "
              << TruncateOrPad("ACTION", 8) << " "
              << "SOURCE"
              << (m_ansiSupported ? ANSI_RESET : "") << "\n";

    std::cout << std::string(90, '-') << "\n";
    m_headerPrinted = true;
}

std::string ConsoleView::TruncateOrPad(const std::string& str, size_t width, bool alignLeft) {
    if (str.length() == width) return str;
    if (str.length() > width) {
        if (width <= 3) return str.substr(0, width);
        return str.substr(0, width - 3) + "...";
    }
    size_t pad = width - str.length();
    if (alignLeft) {
        return str + std::string(pad, ' ');
    } else {
        return std::string(pad, ' ') + str;
    }
}

std::string ConsoleView::TruncateMiddleOrPad(const std::string& str, size_t width, bool alignLeft) {
    if (str.length() == width) return str;
    if (str.length() > width) {
        if (width <= 5) return str.substr(0, width);
        // Retain 14 chars on left (e.g. drive/user) and the rest on right (filename/parent dir)
        size_t leftLen = (width - 3) * 38 / 100;
        if (leftLen < 4) leftLen = 4;
        size_t rightLen = (width - 3) - leftLen;
        return str.substr(0, leftLen) + "..." + str.substr(str.length() - rightLen);
    }
    size_t pad = width - str.length();
    if (alignLeft) {
        return str + std::string(pad, ' ');
    } else {
        return std::string(pad, ' ') + str;
    }
}

void ConsoleView::DisplayRecord(const core::AuditRecord& record) {
    std::lock_guard<std::mutex> lock(m_renderMutex);

    std::string actionColor = "";
    std::string actionBadge = "";

    switch (record.action) {
        case core::AuditAction::BLOCK:
            actionColor = m_ansiSupported ? ANSI_BG_RED ANSI_BOLD : "";
            actionBadge = " BLOCK ";
            break;
        case core::AuditAction::ALERT:
            actionColor = m_ansiSupported ? ANSI_RED ANSI_BOLD : "";
            actionBadge = " ALERT ";
            break;
        case core::AuditAction::ALLOW:
            actionColor = m_ansiSupported ? ANSI_GREEN ANSI_BOLD : "";
            actionBadge = " ALLOW ";
            break;
        case core::AuditAction::AUDIT:
        default:
            actionColor = m_ansiSupported ? ANSI_GRAY : "";
            actionBadge = " AUDIT ";
            break;
    }

    std::string typeColor = "";
    if (record.type.find("TCP") != std::string::npos) {
        typeColor = m_ansiSupported ? ANSI_CYAN : "";
    } else if (record.type.find("READ") != std::string::npos) {
        typeColor = m_ansiSupported ? ANSI_YELLOW : "";
    } else if (record.type.find("WRITE") != std::string::npos || record.type.find("CREATE") != std::string::npos) {
        typeColor = m_ansiSupported ? ANSI_MAGENTA : "";
    }

    std::string sourceColor = "";
    if (record.source.find("Native") != std::string::npos) {
        sourceColor = m_ansiSupported ? ANSI_RED : "";
    } else if (record.source.find("Minecraft") != std::string::npos) {
        sourceColor = m_ansiSupported ? ANSI_GREEN : "";
    } else {
        sourceColor = m_ansiSupported ? ANSI_YELLOW : "";
    }

    // Format console row
    std::cout << TruncateOrPad(record.timestamp.substr(0, 8), 10) << " "
              << TruncateOrPad(std::to_string(record.pid), 7) << " "
              << typeColor << TruncateOrPad(record.type, 12) << (m_ansiSupported ? ANSI_RESET : "") << " "
              << TruncateMiddleOrPad(record.target, 38) << " "
              << actionColor << TruncateOrPad(actionBadge, 8) << (m_ansiSupported ? ANSI_RESET : "") << " "
              << sourceColor << record.source << (m_ansiSupported ? ANSI_RESET : "") << "\n" << std::flush;

    WriteJsonLog(record);
}

void ConsoleView::WriteJsonLog(const core::AuditRecord& record) {
    if (!m_logStream.is_open()) return;

    std::string actionStr;
    switch (record.action) {
        case core::AuditAction::BLOCK: actionStr = "BLOCK"; break;
        case core::AuditAction::ALERT: actionStr = "ALERT"; break;
        case core::AuditAction::ALLOW: actionStr = "ALLOW"; break;
        default: actionStr = "AUDIT"; break;
    }

    // Escape backslashes for JSON target path
    std::string escapedTarget;
    for (char c : record.target) {
        if (c == '\\') escapedTarget += "\\\\";
        else if (c == '\"') escapedTarget += "\\\"";
        else escapedTarget += c;
    }

    m_logStream << "{"
                << "\"timestamp\":\"" << record.timestamp << "\","
                << "\"pid\":" << record.pid << ","
                << "\"type\":\"" << record.type << "\","
                << "\"target\":\"" << escapedTarget << "\","
                << "\"action\":\"" << actionStr << "\","
                << "\"source\":\"" << record.source << "\","
                << "\"sensitive\":" << (record.isSensitive ? "true" : "false")
                << "}\n";
    m_logStream.flush();
}

void ConsoleView::PrintStatus(const std::string& message) {
    std::lock_guard<std::mutex> lock(m_renderMutex);
    std::cout << (m_ansiSupported ? ANSI_BLUE "[*] " ANSI_RESET : "[*] ") << message << "\n" << std::flush;
}

void ConsoleView::PrintWarning(const std::string& message) {
    std::lock_guard<std::mutex> lock(m_renderMutex);
    std::cout << (m_ansiSupported ? ANSI_YELLOW "[!] " ANSI_RESET : "[!] ") << message << "\n" << std::flush;
}

void ConsoleView::PrintError(const std::string& message) {
    std::lock_guard<std::mutex> lock(m_renderMutex);
    std::cout << (m_ansiSupported ? ANSI_RED "[-] " ANSI_RESET : "[-] ") << message << "\n" << std::flush;
}

void ConsoleView::PrintSuccess(const std::string& message) {
    std::lock_guard<std::mutex> lock(m_renderMutex);
    std::cout << (m_ansiSupported ? ANSI_GREEN "[+] " ANSI_RESET : "[+] ") << message << "\n" << std::flush;
}

} // namespace ui
} // namespace mcguard
