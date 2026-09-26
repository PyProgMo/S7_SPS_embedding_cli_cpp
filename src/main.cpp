#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include "snap7.h"
#include "npcap_dyn.h"
#include "profinet_scan.h"

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
        Cli_Disconnect(client);
        Cli_Destroy(&client);
        connected = false;
    }

    std::printf("\nConnecting to %s (rack %d, slot %d)...\n", ip.c_str(), kRack, kSlot);

    client = Cli_Create();
    if (client == 0) {
        std::fprintf(stderr, "Cli_Create() failed to allocate a client object.\n");
        return false;
    }

    int rc = Cli_ConnectTo(client, ip.c_str(), kRack, kSlot);
    if (rc != 0) {
        std::fprintf(stderr, "Connection failed: %s\n", PrintCliError(rc).c_str());
        Cli_Destroy(&client);
        return false;
    }

    std::printf("Connected.\n");
    connected = true;

    TS7CpuInfo cpuInfo{};
    rc = Cli_GetCpuInfo(client, &cpuInfo);
    if (rc == 0) {
        std::printf("Module type : %s\n", cpuInfo.ModuleTypeName);
        std::printf("Module name : %s\n", cpuInfo.ModuleName);
        std::printf("Serial no.  : %s\n", cpuInfo.SerialNumber);
        std::printf("AS name     : %s\n", cpuInfo.ASName);
        std::printf("Copyright   : %s\n", cpuInfo.Copyright);
    } else {
        std::fprintf(stderr, "Cli_GetCpuInfo() failed: %s\n", PrintCliError(rc).c_str());
    }

    TS7OrderCode orderCode{};
    rc = Cli_GetOrderCode(client, &orderCode);
    if (rc == 0) {
        std::printf("Order code  : %s (V%d.%d.%d)\n",
                    orderCode.Code, orderCode.V1, orderCode.V2, orderCode.V3);
    } else {
        std::fprintf(stderr, "Cli_GetOrderCode() failed: %s\n", PrintCliError(rc).c_str());
    }

    return true;
}

// Parses an address like "Q0.3" (the leading 'Q' is optional) into byte/bit.
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

// Reads and prints the state of every onboard digital input and output.
void ShowPortStates(S7Object client) {
    unsigned char inputs[kInputBytes] = {0};
    int rc = Cli_ReadArea(client, S7AreaPE, 0, 0, kInputBytes, S7WLByte, inputs);
    if (rc != 0) {
        std::fprintf(stderr, "Failed to read inputs: %s\n", PrintCliError(rc).c_str());
    } else {
        std::printf("\nDigital inputs:\n");
        for (int b = 0; b < kInputBytes; ++b) {
            for (int bit = 0; bit < 8; ++bit) {
                bool state = (inputs[b] >> bit) & 1;
                std::printf("  I%d.%d = %s\n", b, bit, state ? "True" : "False");
            }
        }
    }

    unsigned char outputs[kOutputBytes] = {0};
    rc = Cli_ReadArea(client, S7AreaPA, 0, 0, kOutputBytes, S7WLByte, outputs);
    if (rc != 0) {
        std::fprintf(stderr, "Failed to read outputs: %s\n", PrintCliError(rc).c_str());
        return;
    }
    std::printf("\nDigital outputs:\n");
    for (int b = 0; b < kOutputBytes; ++b) {
        for (int bit = 0; bit < 8; ++bit) {
            bool state = (outputs[b] >> bit) & 1;
            std::printf("  Q%d.%d = %s\n", b, bit, state ? "True" : "False");
        }
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
    int rc = Cli_ReadArea(client, S7AreaPA, 0, byteIdx, 1, S7WLByte, &byteVal);
    if (rc != 0) {
        std::fprintf(stderr, "Failed to read output byte: %s\n", PrintCliError(rc).c_str());
        return;
    }

    if (value) {
        byteVal |= static_cast<unsigned char>(1 << bitIdx);
    } else {
        byteVal &= static_cast<unsigned char>(~(1 << bitIdx));
    }

    rc = Cli_WriteArea(client, S7AreaPA, 0, byteIdx, 1, S7WLByte, &byteVal);
    if (rc != 0) {
        std::fprintf(stderr, "Failed to write output: %s\n", PrintCliError(rc).c_str());
        return;
    }

    std::printf("Q%d.%d set to %s.\n", byteIdx, bitIdx, value ? "True" : "False");
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
                "  0) Exit\n"
                "Choice: ",
                ip.c_str(),
                connected ? "connected" : "not connected",
                connected ? "" : "  (connect first)",
                connected ? "" : "  (connect first)");
}

} // namespace

int main(int argc, char *argv[]) {
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
        } else if (line == "0" || line == "q" || line == "quit" || line == "exit") {
            break;
        } else {
            std::printf("Invalid choice.\n");
        }
    }

    if (connected) {
        Cli_Disconnect(client);
        Cli_Destroy(&client);
    }

    return 0;
}
