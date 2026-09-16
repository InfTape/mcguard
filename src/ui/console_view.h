#pragma once
#include "../core/correlator.h"
#include <string>
#include <mutex>
#include <fstream>

namespace mcguard {
namespace ui {

class ConsoleView {
public:
    ConsoleView(const std::string& logFilePath = "mcguard_audit.jsonl");
    ~ConsoleView();

    // Enable ANSI console colors and print header
    void Initialize();

    // Render a single audit record into the live console table and JSON log
    void DisplayRecord(const core::AuditRecord& record, bool writeToFile = true);

    // Parse a JSONL line back into an AuditRecord
    static bool ParseJsonRecord(const std::string& line, core::AuditRecord& outRecord);

    // Print status / information banners
    void PrintStatus(const std::string& message);
    void PrintWarning(const std::string& message);
    void PrintError(const std::string& message);
    void PrintSuccess(const std::string& message);
    // Return the resolved absolute path of the audit log
    std::string GetLogFilePath() const { return m_fullLogPath; }

private:
    void WriteJsonLog(const core::AuditRecord& record);
    std::string TruncateOrPad(const std::string& str, size_t width, bool alignLeft = true);
    std::string TruncateMiddleOrPad(const std::string& str, size_t width, bool alignLeft = true);

    std::string m_logFilePath;
    std::string m_fullLogPath;
    std::ofstream m_logStream;
    std::mutex m_renderMutex;
    bool m_ansiSupported = false;
    bool m_headerPrinted = false;
};

} // namespace ui
} // namespace mcguard
