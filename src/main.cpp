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

void ConnectToPlc(const std::string &ip) {
    std::printf("\nConnecting to %s (rack %d, slot %d)...\n", ip.c_str(), kRack, kSlot);

    S7Object client = Cli_Create();
    if (client == 0) {
        std::fprintf(stderr, "Cli_Create() failed to allocate a client object.\n");
        return;
    }

    int rc = Cli_ConnectTo(client, ip.c_str(), kRack, kSlot);
    if (rc != 0) {
        std::fprintf(stderr, "Connection failed: %s\n", PrintCliError(rc).c_str());
        Cli_Destroy(&client);
        return;
    }

    std::printf("Connected.\n");

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

    Cli_Disconnect(client);
    Cli_Destroy(&client);
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

void PrintMenu(const std::string &ip) {
    std::printf("\n"
                "==== SPScomm ====\n"
                "Current PLC IP : %s\n"
                "  1) Set PLC IP address\n"
                "  2) Scan / connect\n"
                "  3) Scan network for PROFINET devices\n"
                "  0) Exit\n"
                "Choice: ",
                ip.c_str());
}

} // namespace

int main(int argc, char *argv[]) {
    std::string ip = (argc > 1) ? argv[1] : kDefaultIp;

    std::string line;
    while (true) {
        PrintMenu(ip);
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
            ConnectToPlc(ip);
        } else if (line == "3") {
            RunNetworkScan(ip);
        } else if (line == "0" || line == "q" || line == "quit" || line == "exit") {
            break;
        } else {
            std::printf("Invalid choice.\n");
        }
    }

    return 0;
}
