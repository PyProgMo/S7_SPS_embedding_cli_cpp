#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include "snap7.h"
#include "npcap_dyn.h"   // pulls in pcap.h -> winsock2.h; must come before windows.h
#include "profinet_scan.h"
#include "logger.h"
#include "io_address.h"
#include "channel_program.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN // keep windows.h from dragging in legacy winsock.h
#endif
#include <windows.h> // Sleep()

namespace {

constexpr const char *kDefaultIp = "192.168.0.1";
constexpr int kRack = 0;
constexpr int kSlot = 1; // S7-1200/1500 always use slot 1 (S7-300/400 use slot 2).

// Onboard digital I/O of a CPU 1214C DC/DC/DC: I0.x-I1.x, Q0.x-Q1.x.
// Bump these if expansion I/O modules are attached.
constexpr int kInputBytes = 2;
constexpr int kOutputBytes = 2;

std::string PrintCliError(int rc) {
    char text[1024] = {0};
    Cli_ErrorText(rc, text, sizeof(text));
    return text;
}

std::string Trim(const std::string &s) {
    size_t begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

// Connects to `ip`, replacing any existing connection held in `client`.
// Leaves the connection open on success so later menu actions can reuse it.
bool ConnectToPlc(const std::string &ip, S7Object &client, bool &connected) {
    if (connected) {
        logger::Log("DISCONNECT (reconnecting)");
        Cli_Disconnect(client);
        Cli_Destroy(&client);
        connected = false;
    }

    std::printf("\nConnecting to %s (rack %d, slot %d)...\n", ip.c_str(), kRack, kSlot);
    logger::Log("CONNECT -> ip=" + ip + " rack=" + std::to_string(kRack) +
                " slot=" + std::to_string(kSlot));

    client = Cli_Create();
    if (client == 0) {
        std::fprintf(stderr, "Cli_Create() failed to allocate a client object.\n");
        logger::Log("CONNECT <- Cli_Create() returned a null object");
        return false;
    }

    int rc = Cli_ConnectTo(client, ip.c_str(), kRack, kSlot);
    logger::Log("CONNECT <- rc=" + std::to_string(rc) + " (" + PrintCliError(rc) + ")");
    if (rc != 0) {
        std::fprintf(stderr, "Connection failed: %s\n", PrintCliError(rc).c_str());
        Cli_Destroy(&client);
        return false;
    }

    std::printf("Connected.\n");
    connected = true;

    TS7CpuInfo cpuInfo{};
    logger::Log("GET_CPU_INFO ->");
    rc = Cli_GetCpuInfo(client, &cpuInfo);
    if (rc == 0) {
        std::printf("Module type : %s\n", cpuInfo.ModuleTypeName);
        std::printf("Module name : %s\n", cpuInfo.ModuleName);
        std::printf("Serial no.  : %s\n", cpuInfo.SerialNumber);
        std::printf("AS name     : %s\n", cpuInfo.ASName);
        std::printf("Copyright   : %s\n", cpuInfo.Copyright);
        logger::Log("GET_CPU_INFO <- rc=0 module=" + std::string(cpuInfo.ModuleTypeName) +
                    " serial=" + std::string(cpuInfo.SerialNumber));
    } else {
        std::fprintf(stderr, "Cli_GetCpuInfo() failed: %s\n", PrintCliError(rc).c_str());
        logger::Log("GET_CPU_INFO <- rc=" + std::to_string(rc) + " (" + PrintCliError(rc) + ")");
    }

    TS7OrderCode orderCode{};
    logger::Log("GET_ORDER_CODE ->");
    rc = Cli_GetOrderCode(client, &orderCode);
    if (rc == 0) {
        std::printf("Order code  : %s (V%d.%d.%d)\n",
                    orderCode.Code, orderCode.V1, orderCode.V2, orderCode.V3);
        logger::Log("GET_ORDER_CODE <- rc=0 code=" + std::string(orderCode.Code) +
                    " v=" + std::to_string(orderCode.V1) + "." + std::to_string(orderCode.V2) +
                    "." + std::to_string(orderCode.V3));
    } else {
        std::fprintf(stderr, "Cli_GetOrderCode() failed: %s\n", PrintCliError(rc).c_str());
        logger::Log("GET_ORDER_CODE <- rc=" + std::to_string(rc) + " (" + PrintCliError(rc) + ")");
    }

    return true;
}

// Reads and prints the state of every onboard digital input and output.
void ShowPortStates(S7Object client) {
    unsigned char inputs[kInputBytes] = {0};
    logger::Log("READ -> area=PE start=0 amount=" + std::to_string(kInputBytes));
    int rc = Cli_ReadArea(client, S7AreaPE, 0, 0, kInputBytes, S7WLByte, inputs);
    if (rc != 0) {
        std::fprintf(stderr, "Failed to read inputs: %s\n", PrintCliError(rc).c_str());
        logger::Log("READ <- area=PE rc=" + std::to_string(rc) + " (" + PrintCliError(rc) + ")");
    } else {
        logger::Log("READ <- area=PE rc=0 data=[" + logger::Hex(inputs, kInputBytes) + "]");
        std::printf("\nDigital inputs:\n");
        for (int b = 0; b < kInputBytes; ++b) {
            for (int bit = 0; bit < 8; ++bit) {
                bool state = (inputs[b] >> bit) & 1;
                std::printf("  I%d.%d = %s\n", b, bit, state ? "True" : "False");
            }
        }
    }

    unsigned char outputs[kOutputBytes] = {0};
    logger::Log("READ -> area=PA start=0 amount=" + std::to_string(kOutputBytes));
    rc = Cli_ReadArea(client, S7AreaPA, 0, 0, kOutputBytes, S7WLByte, outputs);
    if (rc != 0) {
        std::fprintf(stderr, "Failed to read outputs: %s\n", PrintCliError(rc).c_str());
        logger::Log("READ <- area=PA rc=" + std::to_string(rc) + " (" + PrintCliError(rc) + ")");
        return;
    }
    logger::Log("READ <- area=PA rc=0 data=[" + logger::Hex(outputs, kOutputBytes) + "]");
    std::printf("\nDigital outputs:\n");
    for (int b = 0; b < kOutputBytes; ++b) {
        for (int bit = 0; bit < 8; ++bit) {
            bool state = (outputs[b] >> bit) & 1;
            std::printf("  Q%d.%d = %s\n", b, bit, state ? "True" : "False");
        }
    }
}

// Repeatedly re-writes a single output bit and immediately reads it back,
// for `durationSec`, tracking what fraction of checks actually held the
// requested value. Snap7 (and the S7 protocol as used here) has no genuine
// "force" telegram -- a single write can only ever compete with, not
// override, a running user program. This quantifies that contention instead
// of guessing at it: a low match rate means something on the CPU is
// actively overwriting the bit faster than we can hold it; a high rate
// means the bit is free and an earlier failure was likely transient.
void HoldAndMonitor(S7Object client, int byteIdx, int bitIdx, bool value, double durationSec) {
    std::printf("\nHolding Q%d.%d = %s for %.1fs, checking for interference"
                " (Ctrl+C to abort)...\n", byteIdx, bitIdx, value ? "True" : "False", durationSec);
    logger::Log("HOLD -> area=PA byte=" + std::to_string(byteIdx) + " bit=" +
                std::to_string(bitIdx) + " value=" + std::string(value ? "True" : "False") +
                " duration_s=" + std::to_string(durationSec));

    const auto start = std::chrono::steady_clock::now();
    auto lastPrint = start;
    long attempts = 0, matches = 0;

    while (true) {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - start).count();
        if (elapsed >= durationSec) break;

        unsigned char byteVal = 0;
        int rc = Cli_ReadArea(client, S7AreaPA, 0, byteIdx, 1, S7WLByte, &byteVal);
        if (rc == 0) {
            unsigned char newByteVal = byteVal;
            if (value) {
                newByteVal |= static_cast<unsigned char>(1 << bitIdx);
            } else {
                newByteVal &= static_cast<unsigned char>(~(1 << bitIdx));
            }
            rc = Cli_WriteArea(client, S7AreaPA, 0, byteIdx, 1, S7WLByte, &newByteVal);
        }

        unsigned char verifyVal = 0;
        int vrc = Cli_ReadArea(client, S7AreaPA, 0, byteIdx, 1, S7WLByte, &verifyVal);
        ++attempts;
        bool matched = (rc == 0) && (vrc == 0) &&
                       (static_cast<bool>((verifyVal >> bitIdx) & 1) == value);
        if (matched) ++matches;

        now = std::chrono::steady_clock::now();
        if (std::chrono::duration<double>(now - lastPrint).count() >= 1.0) {
            double pct = attempts ? 100.0 * matches / attempts : 0.0;
            std::printf("  %.0fs elapsed: %ld/%ld checks matched (%.0f%%)\n",
                        elapsed, matches, attempts, pct);
            logger::Log("HOLD status elapsed_s=" + std::to_string(elapsed) +
                        " attempts=" + std::to_string(attempts) +
                        " matches=" + std::to_string(matches));
            lastPrint = now;
        }

        Sleep(50);
    }

    double pct = attempts ? 100.0 * matches / attempts : 0.0;
    std::printf("\nHold finished: %ld/%ld checks matched the requested value (%.1f%%).\n",
                matches, attempts, pct);
    logger::Log("HOLD <- attempts=" + std::to_string(attempts) + " matches=" +
                std::to_string(matches) + " pct=" + std::to_string(pct));

    if (pct > 95.0) {
        std::printf("This output held reliably -- the earlier mismatch was likely a one-off\n"
                    "race with the CPU's scan cycle rather than active interference.\n");
    } else if (pct < 5.0) {
        std::printf("This output is being overwritten on essentially every scan cycle by\n"
                    "something running on the CPU -- almost certainly the loaded user\n"
                    "program recomputing this whole output byte. A plain S7 write cannot\n"
                    "override that. To actually hold it you'd need TIA Portal's Force/Modify\n"
                    "table (a proprietary telegram snap7 doesn't implement), or to free this\n"
                    "address in the program logic itself.\n");
    } else {
        std::printf("This output is intermittently overwritten -- likely conditional logic in\n"
                    "the running program only drives it part of the time.\n");
    }
}

// Prompts for an output address and a new value, then writes it via a
// read-modify-write on the containing byte so neighbouring bits are untouched.
void SetOutputPort(S7Object client) {
    std::printf("\nEnter output to set, e.g. Q0.3 (blank to cancel): ");
    std::string line;
    if (!std::getline(std::cin, line)) return;
    line = Trim(line);
    if (line.empty()) return;

    int byteIdx = 0, bitIdx = 0;
    if (!ParseIoAddress(line, byteIdx, bitIdx)) {
        std::printf("Invalid address. Use the form Q<byte>.<bit>, e.g. Q0.3.\n");
        return;
    }
    if (byteIdx >= kOutputBytes) {
        std::printf("Byte %d is out of range for this CPU's onboard outputs (Q0-Q%d).\n",
                    byteIdx, kOutputBytes - 1);
        return;
    }

    std::printf("Set Q%d.%d to (1=True, 0=False): ", byteIdx, bitIdx);
    if (!std::getline(std::cin, line)) return;
    line = Trim(line);
    bool value;
    if (line == "1" || line == "true" || line == "True") {
        value = true;
    } else if (line == "0" || line == "false" || line == "False") {
        value = false;
    } else {
        std::printf("Invalid value.\n");
        return;
    }

    unsigned char byteVal = 0;
    logger::Log("WRITE -> read-before area=PA start=" + std::to_string(byteIdx) + " amount=1");
    int rc = Cli_ReadArea(client, S7AreaPA, 0, byteIdx, 1, S7WLByte, &byteVal);
    logger::Log("WRITE <- read-before rc=" + std::to_string(rc) + " (" + PrintCliError(rc) +
                ") data=[" + logger::Hex(&byteVal, 1) + "]");
    if (rc != 0) {
        std::fprintf(stderr, "Failed to read output byte: %s\n", PrintCliError(rc).c_str());
        return;
    }

    unsigned char newByteVal = byteVal;
    if (value) {
        newByteVal |= static_cast<unsigned char>(1 << bitIdx);
    } else {
        newByteVal &= static_cast<unsigned char>(~(1 << bitIdx));
    }

    logger::Log("WRITE -> area=PA start=" + std::to_string(byteIdx) + " bit=" +
                std::to_string(bitIdx) + " value=" + (value ? "True" : "False") +
                " old_byte=[" + logger::Hex(&byteVal, 1) + "] new_byte=[" +
                logger::Hex(&newByteVal, 1) + "]");
    rc = Cli_WriteArea(client, S7AreaPA, 0, byteIdx, 1, S7WLByte, &newByteVal);
    logger::Log("WRITE <- rc=" + std::to_string(rc) + " (" + PrintCliError(rc) + ")");
    if (rc != 0) {
        std::fprintf(stderr, "Failed to write output: %s\n", PrintCliError(rc).c_str());
        return;
    }

    // Read the byte back immediately so a silent revert (e.g. a running
    // program overwriting this output on its own scan cycle, or the CPU's
    // protection level quietly rejecting the write) shows up here instead
    // of only being noticed later.
    unsigned char verifyVal = 0;
    logger::Log("VERIFY -> read-after area=PA start=" + std::to_string(byteIdx) + " amount=1");
    rc = Cli_ReadArea(client, S7AreaPA, 0, byteIdx, 1, S7WLByte, &verifyVal);
    logger::Log("VERIFY <- rc=" + std::to_string(rc) + " (" + PrintCliError(rc) +
                ") data=[" + logger::Hex(&verifyVal, 1) + "]");

    bool actual = (verifyVal >> bitIdx) & 1;
    if (rc == 0 && actual == value) {
        std::printf("Q%d.%d set to %s (confirmed by read-back).\n",
                    byteIdx, bitIdx, value ? "True" : "False");
    } else if (rc != 0) {
        std::fprintf(stderr, "Wrote Q%d.%d but could not verify: %s\n",
                    byteIdx, bitIdx, PrintCliError(rc).c_str());
    } else {
        std::printf("WARNING: wrote Q%d.%d = %s, but it reads back as %s.\n",
                    byteIdx, bitIdx, value ? "True" : "False", actual ? "True" : "False");
        std::printf("Something is reverting it -- likely a running user program driving this\n"
                    "output every scan cycle, or the CPU's protection level rejecting external\n"
                    "writes. Check logs/ for the exact request/response sequence.\n");
        logger::Log("WRITE MISMATCH: requested=" + std::string(value ? "True" : "False") +
                    " actual=" + std::string(actual ? "True" : "False"));

        std::printf("\nHold and monitor this bit to quantify the interference? (y/N): ");
        if (!std::getline(std::cin, line)) return;
        line = Trim(line);
        if (line == "y" || line == "Y") {
            std::printf("Hold duration in seconds [10]: ");
            if (!std::getline(std::cin, line)) return;
            line = Trim(line);
            double durationSec = 10.0;
            if (!line.empty()) {
                try {
                    durationSec = std::stod(line);
                } catch (...) {
                    std::printf("Invalid duration, using 10s.\n");
                }
            }
            HoldAndMonitor(client, byteIdx, bitIdx, value, durationSec);
        }
    }
}

// Applies every channel state from a parsed program file: writes each one,
// then (if holdSeconds > 0) repeatedly re-asserts all of them together while
// tracking how often each one actually holds -- the multi-channel version of
// the same interference check HoldAndMonitor does for a single bit. There is
// still no genuine "force" here (see HoldAndMonitor's comment); this is
// meant to reveal, per channel, which ones are free to set and which are
// being fought by something already running on the CPU.
void RunChannelProgram(S7Object client, const std::vector<ChannelState> &states, double holdSeconds) {
    std::printf("\nApplying %zu channel state(s):\n", states.size());
    logger::Log("PROGRAM -> applying " + std::to_string(states.size()) +
                " channel state(s), hold_s=" + std::to_string(holdSeconds));

    for (const auto &st : states) {
        if (st.byteIdx >= kOutputBytes) {
            std::printf("  %-8s SKIPPED (byte %d out of range for this CPU's outputs Q0-Q%d)\n",
                        st.rawAddress.c_str(), st.byteIdx, kOutputBytes - 1);
            logger::Log("PROGRAM SKIP " + st.rawAddress + " out of range");
            continue;
        }

        unsigned char byteVal = 0;
        int rc = Cli_ReadArea(client, S7AreaPA, 0, st.byteIdx, 1, S7WLByte, &byteVal);
        if (rc != 0) {
            std::printf("  %-8s FAILED to read (%s)\n", st.rawAddress.c_str(), PrintCliError(rc).c_str());
            logger::Log("PROGRAM " + st.rawAddress + " read-before rc=" + std::to_string(rc));
            continue;
        }

        unsigned char newByteVal = byteVal;
        if (st.value) {
            newByteVal |= static_cast<unsigned char>(1 << st.bitIdx);
        } else {
            newByteVal &= static_cast<unsigned char>(~(1 << st.bitIdx));
        }

        rc = Cli_WriteArea(client, S7AreaPA, 0, st.byteIdx, 1, S7WLByte, &newByteVal);
        logger::Log("PROGRAM WRITE " + st.rawAddress + "=" + (st.value ? "True" : "False") +
                    " old=[" + logger::Hex(&byteVal, 1) + "] new=[" + logger::Hex(&newByteVal, 1) +
                    "] rc=" + std::to_string(rc));
        if (rc != 0) {
            std::printf("  %-8s FAILED to write (%s)\n", st.rawAddress.c_str(), PrintCliError(rc).c_str());
            continue;
        }
        std::printf("  %-8s = %-5s written\n", st.rawAddress.c_str(), st.value ? "True" : "False");
    }

    if (holdSeconds <= 0.0) {
        std::printf("\nDone (single pass, no hold). Use option 4 to check the resulting states,\n"
                    "or re-run with a hold duration if a value doesn't stick.\n");
        return;
    }

    std::printf("\nHolding and re-asserting all %zu channel(s) for %.1fs...\n",
                states.size(), holdSeconds);
    logger::Log("PROGRAM HOLD -> " + std::to_string(states.size()) + " channel(s) for " +
                std::to_string(holdSeconds) + "s");

    std::vector<long> matches(states.size(), 0);
    long attempts = 0;
    const auto start = std::chrono::steady_clock::now();
    auto lastPrint = start;

    while (true) {
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - start).count();
        if (elapsed >= holdSeconds) break;

        ++attempts;
        for (size_t i = 0; i < states.size(); ++i) {
            const ChannelState &st = states[i];
            if (st.byteIdx >= kOutputBytes) continue;

            unsigned char byteVal = 0;
            int rc = Cli_ReadArea(client, S7AreaPA, 0, st.byteIdx, 1, S7WLByte, &byteVal);
            if (rc == 0) {
                unsigned char newByteVal = byteVal;
                if (st.value) {
                    newByteVal |= static_cast<unsigned char>(1 << st.bitIdx);
                } else {
                    newByteVal &= static_cast<unsigned char>(~(1 << st.bitIdx));
                }
                rc = Cli_WriteArea(client, S7AreaPA, 0, st.byteIdx, 1, S7WLByte, &newByteVal);
            }

            unsigned char verifyVal = 0;
            int vrc = Cli_ReadArea(client, S7AreaPA, 0, st.byteIdx, 1, S7WLByte, &verifyVal);
            bool matched = (rc == 0) && (vrc == 0) &&
                           (static_cast<bool>((verifyVal >> st.bitIdx) & 1) == st.value);
            if (matched) ++matches[i];
        }

        now = std::chrono::steady_clock::now();
        if (std::chrono::duration<double>(now - lastPrint).count() >= 1.0) {
            std::printf("  %.0fs elapsed, %ld pass(es) so far\n", elapsed, attempts);
            lastPrint = now;
        }

        Sleep(50);
    }

    std::printf("\nHold finished after %ld pass(es):\n", attempts);
    for (size_t i = 0; i < states.size(); ++i) {
        double pct = attempts ? 100.0 * matches[i] / attempts : 0.0;
        std::printf("  %-8s = %-5s held %.1f%% of checks%s\n",
                    states[i].rawAddress.c_str(), states[i].value ? "True" : "False", pct,
                    pct < 50.0 ? "  <-- likely overridden by a running program" : "");
        logger::Log("PROGRAM HOLD RESULT " + states[i].rawAddress + " matches=" +
                    std::to_string(matches[i]) + "/" + std::to_string(attempts));
    }
}

// Prompts for a program file path and hold duration, loads it, and runs it.
void RunProgramFromFile(S7Object client) {
    std::printf("\nProgram file path [program.txt]: ");
    std::string line;
    if (!std::getline(std::cin, line)) return;
    line = Trim(line);
    std::string path = line.empty() ? "program.txt" : line;

    std::vector<ChannelState> states;
    std::string error;
    if (!ParseChannelProgram(path, states, error)) {
        std::printf("Failed to load program: %s\n", error.c_str());
        logger::Log("PROGRAM LOAD FAILED path=" + path + " error=" + error);
        return;
    }

    std::printf("Loaded %zu channel state(s) from %s:\n", states.size(), path.c_str());
    for (const auto &st : states) {
        std::printf("  %s = %s\n", st.rawAddress.c_str(), st.value ? "True" : "False");
    }
    logger::Log("PROGRAM LOAD OK path=" + path + " count=" + std::to_string(states.size()));

    std::printf("\nHold/re-assert duration in seconds (0 = apply once, no hold) [10]: ");
    if (!std::getline(std::cin, line)) return;
    line = Trim(line);
    double holdSeconds = 10.0;
    if (!line.empty()) {
        try {
            holdSeconds = std::stod(line);
        } catch (...) {
            std::printf("Invalid duration, using 10s.\n");
        }
    }

    RunChannelProgram(client, states, holdSeconds);
}

// Runs a PROFINET DCP Identify-All scan (same discovery PRONETA's network
// scan uses) and, if the user picks a result, updates `ip` to its address.
void RunNetworkScan(std::string &ip) {
    NpcapApi api;
    std::string error;
    if (!LoadNpcap(api, error)) {
        std::fprintf(stderr, "\n%s\n", error.c_str());
        return;
    }

    std::vector<ProfinetInterface> ifaces = ListProfinetInterfaces(api);
    if (ifaces.empty()) {
        std::printf("\nNo network interfaces found.\n");
        return;
    }

    std::printf("\nInterfaces:\n");
    for (size_t i = 0; i < ifaces.size(); ++i) {
        const ProfinetInterface &f = ifaces[i];
        std::printf("  %zu) %-20s %-40s %s\n", i + 1,
                    f.friendlyName.empty() ? "(unknown)" : f.friendlyName.c_str(),
                    f.description.c_str(), f.ipv4.c_str());
    }
    std::printf("Use the wired LAN adapter connected to the same switch/Speedport as the\n"
                "PLC -- DCP broadcasts do not cross a Wi-Fi bridge.\n");
    std::printf("Interface number (blank to cancel): ");

    std::string line;
    if (!std::getline(std::cin, line)) return;
    line = Trim(line);
    if (line.empty()) return;

    size_t choice = 0;
    try {
        choice = static_cast<size_t>(std::stoul(line));
    } catch (...) {
        std::printf("Invalid choice.\n");
        return;
    }
    if (choice < 1 || choice > ifaces.size()) {
        std::printf("Invalid choice.\n");
        return;
    }

    const ProfinetInterface &iface = ifaces[choice - 1];
    std::printf("\nSending DCP Identify-All on %s...\n",
                iface.friendlyName.empty() ? iface.pcapName.c_str() : iface.friendlyName.c_str());

    std::vector<ProfinetDevice> devices;
    if (!ScanProfinetDevices(api, iface, 3000, devices, error)) {
        std::fprintf(stderr, "Scan failed: %s\n", error.c_str());
        return;
    }

    if (devices.empty()) {
        std::printf("No PROFINET devices responded.\n");
        return;
    }

    std::printf("\n%zu device(s) found:\n", devices.size());
    for (size_t i = 0; i < devices.size(); ++i) {
        const ProfinetDevice &d = devices[i];
        std::printf("  %zu) %-17s %-15s %-20s %s\n", i + 1, d.mac.c_str(),
                    d.ip.empty() ? "-" : d.ip.c_str(),
                    d.name.empty() ? "-" : d.name.c_str(),
                    d.role.empty() ? "-" : d.role.c_str());
    }

    std::printf("Use device number's IP as the PLC IP (blank to skip): ");
    if (!std::getline(std::cin, line)) return;
    line = Trim(line);
    if (line.empty()) return;

    try {
        choice = static_cast<size_t>(std::stoul(line));
    } catch (...) {
        std::printf("Invalid choice.\n");
        return;
    }
    if (choice < 1 || choice > devices.size() || devices[choice - 1].ip.empty()) {
        std::printf("Invalid choice.\n");
        return;
    }

    ip = devices[choice - 1].ip;
    std::printf("PLC IP set to %s.\n", ip.c_str());
}

void PrintMenu(const std::string &ip, bool connected) {
    std::printf("\n"
                "==== SPScomm ====\n"
                "Current PLC IP : %s\n"
                "Connection     : %s\n"
                "  1) Set PLC IP address\n"
                "  2) Scan / connect\n"
                "  3) Scan network for PROFINET devices\n"
                "  4) Show I/O port states%s\n"
                "  5) Set an output port (True/False)%s\n"
                "  6) Load & run a channel-state program (.txt)%s\n"
                "  0) Exit\n"
                "Choice: ",
                ip.c_str(),
                connected ? "connected" : "not connected",
                connected ? "" : "  (connect first)",
                connected ? "" : "  (connect first)",
                connected ? "" : "  (connect first)");
}

} // namespace

int main(int argc, char *argv[]) {
    logger::Init();

    std::string ip = (argc > 1) ? argv[1] : kDefaultIp;

    S7Object client = 0;
    bool connected = false;

    std::string line;
    while (true) {
        PrintMenu(ip, connected);
        if (!std::getline(std::cin, line)) {
            break; // stdin closed (e.g. EOF)
        }
        line = Trim(line);

        if (line == "1") {
            std::printf("Enter PLC IP address: ");
            if (!std::getline(std::cin, line)) break;
            line = Trim(line);
            if (!line.empty()) {
                ip = line;
            } else {
                std::printf("IP unchanged.\n");
            }
        } else if (line == "2") {
            ConnectToPlc(ip, client, connected);
        } else if (line == "3") {
            RunNetworkScan(ip);
        } else if (line == "4") {
            if (!connected) {
                std::printf("Not connected -- use option 2 first.\n");
            } else {
                ShowPortStates(client);
            }
        } else if (line == "5") {
            if (!connected) {
                std::printf("Not connected -- use option 2 first.\n");
            } else {
                SetOutputPort(client);
            }
        } else if (line == "6") {
            if (!connected) {
                std::printf("Not connected -- use option 2 first.\n");
            } else {
                RunProgramFromFile(client);
            }
        } else if (line == "0" || line == "q" || line == "quit" || line == "exit") {
            break;
        } else {
            std::printf("Invalid choice.\n");
        }
    }

    if (connected) {
        logger::Log("DISCONNECT");
        Cli_Disconnect(client);
        Cli_Destroy(&client);
    }

    logger::Close();
    return 0;
}
