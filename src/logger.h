#pragma once

#include <string>

// Simple file-backed logger for every S7 request/response the app makes.
// Not thread-safe -- SPScomm is single-threaded, so that's fine.
namespace logger {

// Opens a timestamped log file under logDir (created if missing) and writes
// a session header. Safe to call once at startup; a no-op file path means
// Log() calls are silently dropped instead of crashing.
void Init(const std::string &logDir = "logs");

// Appends one line, prefixed with a "YYYY-MM-DD HH:MM:SS.mmm" timestamp,
// and flushes immediately so nothing is lost if the app is killed mid-test.
void Log(const std::string &line);

// Formats a byte buffer as space-separated hex, e.g. "AA 01 3F".
std::string Hex(const unsigned char *data, int len);

// Closes the log file. Optional -- process exit does this too.
void Close();

} // namespace logger
