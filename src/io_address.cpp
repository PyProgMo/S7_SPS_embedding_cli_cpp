#include "io_address.h"

namespace {
std::string Trim(const std::string &s) {
    size_t begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}
} // namespace

bool ParseIoAddress(const std::string &raw, int &byteIdx, int &bitIdx) {
    std::string s = Trim(raw);
    if (!s.empty() && (s[0] == 'Q' || s[0] == 'q')) {
        s = s.substr(1);
    }
    size_t dot = s.find('.');
    if (dot == std::string::npos) return false;

    try {
        byteIdx = std::stoi(s.substr(0, dot));
        bitIdx = std::stoi(s.substr(dot + 1));
    } catch (...) {
        return false;
    }
    return byteIdx >= 0 && bitIdx >= 0 && bitIdx <= 7;
}
