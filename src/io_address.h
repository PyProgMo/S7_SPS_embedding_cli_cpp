#pragma once

#include <string>

// Parses an address like "Q0.3" (leading 'Q' optional, case-insensitive)
// into a zero-based byte index and bit index (0-7). Returns false on any
// malformed input.
bool ParseIoAddress(const std::string &raw, int &byteIdx, int &bitIdx);
