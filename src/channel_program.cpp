#include "channel_program.h"
#include "io_address.h"

#include <fstream>

namespace {

std::string Trim(const std::string &s) {
    size_t begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

bool ParseBool(const std::string &raw, bool &value) {
    std::string s = Trim(raw);
    if (s == "1" || s == "true" || s == "True" || s == "TRUE") {
        value = true;
        return true;
    }
    if (s == "0" || s == "false" || s == "False" || s == "FALSE") {
        value = false;
        return true;
    }
    return false;
}

} // namespace

bool ParseChannelProgram(const std::string &path, std::vector<ChannelState> &out, std::string &error) {
    std::ifstream file(path);
    if (!file.is_open()) {
        error = "Could not open '" + path + "'";
        return false;
    }

    out.clear();
    std::string line;
    int lineNo = 0;
    while (std::getline(file, line)) {
        ++lineNo;
        std::string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#') continue;

        size_t eq = trimmed.find('=');
        if (eq == std::string::npos) {
            error = "Line " + std::to_string(lineNo) + ": expected '<address>=<value>', got '" +
                    trimmed + "'";
            return false;
        }

        std::string addrPart = Trim(trimmed.substr(0, eq));
        std::string valuePart = Trim(trimmed.substr(eq + 1));

        ChannelState state;
        state.rawAddress = addrPart;
        if (!ParseIoAddress(addrPart, state.byteIdx, state.bitIdx)) {
            error = "Line " + std::to_string(lineNo) + ": invalid address '" + addrPart +
                    "' (expected e.g. Q0.3)";
            return false;
        }
        if (!ParseBool(valuePart, state.value)) {
            error = "Line " + std::to_string(lineNo) + ": invalid value '" + valuePart +
                    "' (expected True/False or 1/0)";
            return false;
        }

        out.push_back(state);
    }

    if (out.empty()) {
        error = "No channel states found in '" + path + "'";
        return false;
    }

    return true;
}
