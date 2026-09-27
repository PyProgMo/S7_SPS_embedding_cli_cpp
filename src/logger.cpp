#include "logger.h"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>

#include <direct.h> // _mkdir (MinGW/Windows)

namespace logger {

namespace {
std::ofstream g_file;
// Guards g_file and the std::localtime static buffer -- Log() is now called
// from both the main thread and the background channel-program thread.
std::mutex g_mutex;

std::string Timestamp(const char *fileNameSafeSeparator = nullptr) {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    std::time_t t = system_clock::to_time_t(now);
    std::tm tmBuf = *std::localtime(&t); // caller must hold g_mutex

    std::ostringstream oss;
    if (fileNameSafeSeparator) {
        oss << std::put_time(&tmBuf, "%Y%m%d_%H%M%S");
    } else {
        oss << std::put_time(&tmBuf, "%Y-%m-%d %H:%M:%S")
            << '.' << std::setfill('0') << std::setw(3) << ms.count();
    }
    return oss.str();
}
} // namespace

void Init(const std::string &logDir) {
    std::lock_guard<std::mutex> lock(g_mutex);

    _mkdir(logDir.c_str()); // ignores EEXIST; failure just means Log() writes go nowhere

    std::string path = logDir + "/spscomm_" + Timestamp("file") + ".log";
    g_file.open(path, std::ios::out | std::ios::app);
    if (g_file.is_open()) {
        g_file << "==== SPScomm traffic log started " << Timestamp() << " ====\n";
        g_file.flush();
        std::printf("Logging S7 traffic to %s\n", path.c_str());
    } else {
        std::fprintf(stderr, "Could not open log file %s -- continuing without logging.\n", path.c_str());
    }
}

void Log(const std::string &line) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_file.is_open()) return;
    g_file << Timestamp() << "  " << line << '\n';
    g_file.flush(); // so a killed/crashed process still leaves a usable log
}

std::string Hex(const unsigned char *data, int len) {
    static const char *kHexDigits = "0123456789ABCDEF";
    std::string out;
    out.reserve(len * 3);
    for (int i = 0; i < len; ++i) {
        if (i) out += ' ';
        out += kHexDigits[(data[i] >> 4) & 0xF];
        out += kHexDigits[data[i] & 0xF];
    }
    return out;
}

void Close() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_file.is_open()) {
        g_file << "==== SPScomm traffic log ended " << Timestamp() << " ====\n";
        g_file.close();
    }
}

} // namespace logger
