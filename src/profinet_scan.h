#pragma once
// PROFINET device discovery via DCP ("Discovery and Configuration Protocol")
// Identify-All -- the same broadcast PRONETA's network scan uses. DCP is a
// raw Ethernet broadcast (EtherType 0x8892, multicast MAC 01:0e:cf:00:00:00),
// so it needs Npcap for raw frame injection/capture (see npcap_dyn.h) and it
// will not cross a Wi-Fi bridge -- run this on the wired LAN adapter.
#include <cstddef>
#include <string>
#include <vector>

#include "npcap_dyn.h"

struct ProfinetInterface {
    std::string pcapName;     // Npcap device name, e.g. \Device\NPF_{GUID}
    std::string friendlyName; // e.g. "Ethernet" (matches ipconfig/ncpa.cpl)
    std::string description;  // e.g. "Realtek PCIe GbE Family Controller"
    std::string ipv4;
    unsigned char mac[6] = {0};
    bool hasMac = false;
};

struct ProfinetDevice {
    std::string mac;
    std::string ip, netmask, gateway;
    std::string name;
    std::string vendorId, deviceId;
    std::string role;
    std::string typeOfStation;
    std::string aliasName;
};

// Enumerates Npcap-visible interfaces, cross-referenced with Windows'
// GetAdaptersAddresses() so each entry carries a human-friendly name, its
// current IPv4 (if any), and the adapter's own MAC (needed as the Ethernet
// source address when sending the DCP request).
std::vector<ProfinetInterface> ListProfinetInterfaces(NpcapApi &api);

// Sends one DCP Identify-All broadcast on `iface` and collects responses for
// `timeoutMs`. Returns false only on a hard failure to open/send (see
// `error`); an empty `out` with a true return just means nothing answered.
bool ScanProfinetDevices(NpcapApi &api, const ProfinetInterface &iface, int timeoutMs,
                          std::vector<ProfinetDevice> &out, std::string &error);

// Decodes a run of concatenated DCP blocks (as carried in an Identify
// Response, starting right after the 10-byte DCP header) into `dev`.
// Exposed (not static) so it can be exercised directly against hand-built
// byte arrays in tests, independent of any live capture.
void ParseDcpBlocks(const unsigned char *data, std::size_t len, ProfinetDevice &dev);
