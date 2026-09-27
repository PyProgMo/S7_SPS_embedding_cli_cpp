#include <atomic>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>
#include <thread>
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

std::string CpuStatusText(int status) {
    switch (status) {
        case S7CpuStatusRun: return "RUN";
        case S7CpuStatusStop: return "STOP";
        default: return "UNKNOWN";
    }
}

// Stops the CPU's own resident user program (Cli_PlcStop). This is a real
// CPU-level STOP, distinct from our own external channel-program loop below:
// while stopped, output drivers are disabled entirely, so nothing -- not
// even our external writes -- can drive physical outputs until the CPU is
// started again.
void StopCpu(S7Object client) {
    int status = S7CpuStatusUnknown;
    Cli_GetPlcStatus(client, &status);
    std::printf("\nCurrent CPU status: %s\n", CpuStatusText(status).c_str());
    logger::Log("PLC_STOP -> current_status=" + CpuStatusText(status));

    int rc = Cli_PlcStop(client);
    logger::Log("PLC_STOP <- rc=" + std::to_string(rc) + " (" + PrintCliError(rc) + ")");
    if (rc != 0) {
        std::fprintf(stderr, "Failed to stop CPU: %s\n", PrintCliError(rc).c_str());
        return;
    }

    std::printf("CPU stop requested. This halts whatever user program is currently\n"
                "running on it -- outputs will drop to their configured safe state and\n"
                "cannot be driven externally until the CPU is running again.\n");
}

// Resumes the CPU's own resident user program with a warm (hot) restart,
// which preserves retained data. Use Cli_PlcColdStart instead if you
// specifically need a cold restart -- not exposed here since it resets
// retentive memory and isn't what you want for routine testing.
void StartCpu(S7Object client) {
    int status = S7CpuStatusUnknown;
    Cli_GetPlcStatus(client, &status);
    std::printf("\nCurrent CPU status: %s\n", CpuStatusText(status).c_str());
    logger::Log("PLC_START -> current_status=" + CpuStatusText(status));

    if (status == S7CpuStatusRun) {
        std::printf("CPU is already running.\n");
        return;
    }

    int rc = Cli_PlcHotStart(client);
    logger::Log("PLC_START <- rc=" + std::to_string(rc) + " (" + PrintCliError(rc) + ")");
    if (rc != 0) {
        std::fprintf(stderr, "Hot start failed: %s\n", PrintCliError(rc).c_str());
        return;
    }

    Sleep(500); // give the CPU a moment to come up before checking
    Cli_GetPlcStatus(client, &status);
    std::printf("CPU status after start: %s\n", CpuStatusText(status).c_str());
    logger::Log("PLC_START result status=" + CpuStatusText(status));
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

// Prompts for a program file path, parses it, and stores the result in
// `states`/`path` (replacing whatever was loaded before). Doesn't need a PLC
// connection -- it's just a local file.
void LoadProgramFromFile(std::vector<ChannelState> &states, std::string &path) {
    std::printf("\nProgram file path [program.txt]: ");
    std::string line;
    if (!std::getline(std::cin, line)) return;
    line = Trim(line);
    std::string requestedPath = line.empty() ? "program.txt" : line;

    std::vector<ChannelState> parsed;
    std::string error;
    if (!ParseChannelProgram(requestedPath, parsed, error)) {
        std::printf("Failed to load program: %s\n", error.c_str());
        logger::Log("PROGRAM LOAD FAILED path=" + requestedPath + " error=" + error);
        return;
    }

    states = std::move(parsed);
    path = requestedPath;

    std::printf("Loaded %zu channel state(s) from %s:\n", states.size(), path.c_str());
    for (const auto &st : states) {
        std::printf("  %s = %s\n", st.rawAddress.c_str(), st.value ? "True" : "False");
    }
    logger::Log("PROGRAM LOAD OK path=" + path + " count=" + std::to_string(states.size()));
}

// Runs on a background thread once a program is started. Uses its own S7
// connection (separate from the interactive menu's) so it never contends
// with option 4/5 calls on the shared client. Every ~100ms it re-writes and
// reads back every channel; every ~5s it logs a per-channel hold percentage
// so `logs/` records exactly how much interference each channel saw over
// the whole run, not just a snapshot. Stops as soon as `running` goes false.
void ProgramLoop(std::string ip, std::vector<ChannelState> states, std::atomic<bool> *running) {
    S7Object client = Cli_Create();
    int rc = Cli_ConnectTo(client, ip.c_str(), kRack, kSlot);
    logger::Log("PROGRAM_THREAD connect rc=" + std::to_string(rc) + " (" + PrintCliError(rc) + ")");
    if (rc != 0) {
        Cli_Destroy(&client);
        running->store(false);
        return;
    }

    std::vector<long> matches(states.size(), 0);
    long attempts = 0;
    auto lastLog = std::chrono::steady_clock::now();

    while (running->load()) {
        ++attempts;
        for (size_t i = 0; i < states.size(); ++i) {
            const ChannelState &st = states[i];
            if (st.byteIdx >= kOutputBytes) continue;

            unsigned char byteVal = 0;
            int rrc = Cli_ReadArea(client, S7AreaPA, 0, st.byteIdx, 1, S7WLByte, &byteVal);
            if (rrc == 0) {
                unsigned char newByteVal = byteVal;
                if (st.value) {
                    newByteVal |= static_cast<unsigned char>(1 << st.bitIdx);
                } else {
                    newByteVal &= static_cast<unsigned char>(~(1 << st.bitIdx));
                }
                Cli_WriteArea(client, S7AreaPA, 0, st.byteIdx, 1, S7WLByte, &newByteVal);
            }

            unsigned char verifyVal = 0;
            int vrc = Cli_ReadArea(client, S7AreaPA, 0, st.byteIdx, 1, S7WLByte, &verifyVal);
            bool matched = (vrc == 0) &&
                           (static_cast<bool>((verifyVal >> st.bitIdx) & 1) == st.value);
            if (matched) ++matches[i];
        }

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration<double>(now - lastLog).count() >= 5.0) {
            std::string summary = "PROGRAM_THREAD status attempts=" + std::to_string(attempts);
            for (size_t i = 0; i < states.size(); ++i) {
                double pct = attempts ? 100.0 * matches[i] / attempts : 0.0;
                char buf[64];
                std::snprintf(buf, sizeof(buf), " %s=%.0f%%", states[i].rawAddress.c_str(), pct);
                summary += buf;
            }
            logger::Log(summary);
            lastLog = now;
        }

        Sleep(100);
    }

    logger::Log("PROGRAM_THREAD stopped after " + std::to_string(attempts) + " pass(es)");
    Cli_Disconnect(client);
    Cli_Destroy(&client);
}

// Starts the currently loaded program on its own background connection.
void StartProgram(const std::string &ip, const std::vector<ChannelState> &states,
                   const std::string &path, std::thread &programThread,
                   std::atomic<bool> &programRunning) {
    if (states.empty()) {
        std::printf("\nNo program loaded -- use the load option first.\n");
        return;
    }
    if (programRunning.load()) {
        std::printf("\nA program is already running -- stop it first.\n");
        return;
    }

    std::printf("\nStarting program %s (%zu channel(s)) in the background...\n",
                path.c_str(), states.size());
    logger::Log("PROGRAM START path=" + path + " count=" + std::to_string(states.size()));

    programRunning.store(true);
    programThread = std::thread(ProgramLoop, ip, states, &programRunning);

    std::printf("Running. Use the stop option to end it; check logs/ for the ongoing\n"
                "per-channel hold percentages while it runs.\n");
}

// Stops a running program, if any, and joins its thread.
void StopProgram(std::thread &programThread, std::atomic<bool> &programRunning) {
    if (!programRunning.load() && !programThread.joinable()) {
        std::printf("\nNo program is running.\n");
        return;
    }

    std::printf("\nStopping program...\n");
    programRunning.store(false);
    if (programThread.joinable()) {
        programThread.join();
    }
    std::printf("Stopped.\n");
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

void PrintMenu(const std::string &ip, bool connected, const std::string &programPath,
               bool programRunning) {
    std::printf("\n"
                "==== SPScomm ====\n"
                "Current PLC IP : %s\n"
                "Connection     : %s\n"
                "Loaded program : %s\n"
                "Program status : %s\n"
                "  1) Set PLC IP address\n"
                "  2) Scan / connect\n"
                "  3) Scan network for PROFINET devices\n"
                "  4) Show I/O port states%s\n"
                "  5) Set an output port (True/False)%s\n"
                "  6) Load a channel-state program (.txt)\n"
                "  7) Start loaded program%s\n"
                "  8) Stop running program\n"
                "  9) Stop CPU (halts its own user program)%s\n"
                " 10) Start CPU (resumes its own user program)%s\n"
                "  0) Exit\n"
                "Choice: ",
                ip.c_str(),
                connected ? "connected" : "not connected",
                programPath.empty() ? "(none)" : programPath.c_str(),
                programRunning ? "running" : "stopped",
                connected ? "" : "  (connect first)",
                connected ? "" : "  (connect first)",
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

    std::vector<ChannelState> loadedProgram;
    std::string loadedProgramPath;
    std::thread programThread;
    std::atomic<bool> programRunning{false};

    std::string line;
    while (true) {
        PrintMenu(ip, connected, loadedProgramPath, programRunning.load());
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
            if (programRunning.load()) {
                std::printf("Stopping the running program before reconnecting...\n");
                StopProgram(programThread, programRunning);
            }
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
            LoadProgramFromFile(loadedProgram, loadedProgramPath);
        } else if (line == "7") {
            if (!connected) {
                std::printf("Not connected -- use option 2 first.\n");
            } else {
                StartProgram(ip, loadedProgram, loadedProgramPath, programThread, programRunning);
            }
        } else if (line == "8") {
            StopProgram(programThread, programRunning);
        } else if (line == "9") {
            if (!connected) {
                std::printf("Not connected -- use option 2 first.\n");
            } else {
                StopCpu(client);
            }
        } else if (line == "10") {
            if (!connected) {
                std::printf("Not connected -- use option 2 first.\n");
            } else {
                StartCpu(client);
            }
        } else if (line == "0" || line == "q" || line == "quit" || line == "exit") {
            break;
        } else {
            std::printf("Invalid choice.\n");
        }
    }

    if (programRunning.load() || programThread.joinable()) {
        StopProgram(programThread, programRunning);
    }

    if (connected) {
        logger::Log("DISCONNECT");
        Cli_Disconnect(client);
        Cli_Destroy(&client);
    }

    logger::Close();
    return 0;
}
