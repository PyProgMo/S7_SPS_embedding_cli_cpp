#pragma once

#include <string>
#include <vector>

// One desired output state, as parsed from a program file line like
// "Q0.0=True".
struct ChannelState {
    int byteIdx = 0;
    int bitIdx = 0;
    bool value = false;
    std::string rawAddress; // e.g. "Q0.0", kept for logging/printing
};

// Parses a plain-text list of desired output states, one per line:
//   Q0.0=True
//   Q0.1=0
// Blank lines and lines starting with '#' are ignored. Returns false and
// fills `error` with a line-numbered message on the first malformed line,
// or if the file can't be opened, or if it contains no states at all.
bool ParseChannelProgram(const std::string &path, std::vector<ChannelState> &out, std::string &error);
