#include "profinet_scan.h"

#include <cstdio>
#include <cstring>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

namespace {

uint16_t ReadBE16(const unsigned char *p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

std::string MacToString(const unsigned char mac[6]) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

std::string IpToString(const unsigned char *p) {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return buf;
}

std::string WideToUtf8(const wchar_t *wide) {
    if (wide == nullptr) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return "";
    std::string s(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, s.data(), len, nullptr, nullptr);
    return s;
}

} // namespace

void ParseDcpBlocks(const unsigned char *data, std::size_t len, ProfinetDevice &dev) {
    std::size_t offset = 0;
    while (offset + 4 <= len) {
        unsigned char option = data[offset];
        unsigned char suboption = data[offset + 1];
        uint16_t blockLength = ReadBE16(data + offset + 2);
        std::size_t blockStart = offset + 4;

        if (blockStart + blockLength > len) break; // truncated/malformed, stop here

        if (blockLength >= 2) {
            const unsigned char *payload = data + blockStart + 2; // skip block_info
            std::size_t payloadLen = blockLength - 2;

            if (option == 0x02 && suboption == 0x02) { // Name of Station
                dev.name.assign(reinterpret_cast<const char *>(payload), payloadLen);
            } else if (option == 0x01 && suboption == 0x02 && payloadLen >= 12) { // IP Parameter
                dev.ip = IpToString(payload);
                dev.netmask = IpToString(payload + 4);
                dev.gateway = IpToString(payload + 8);
            } else if (option == 0x02 && suboption == 0x03 && payloadLen >= 4) { // Device ID
                char buf[8];
                std::snprintf(buf, sizeof(buf), "0x%02X%02X", payload[0], payload[1]);
                dev.vendorId = buf;
                std::snprintf(buf, sizeof(buf), "0x%02X%02X", payload[2], payload[3]);
                dev.deviceId = buf;
            } else if (option == 0x02 && suboption == 0x04 && payloadLen >= 1) { // Device Role
                switch (payload[0]) {
                    case 0x00: dev.role = "IO Supervisor"; break;
                    case 0x01: dev.role = "IO Device"; break;
                    case 0x02: dev.role = "IO Controller"; break;
                    default: dev.role = "Unknown"; break;
                }
            } else if (option == 0x02 && suboption == 0x06) { // Alias Name
                dev.aliasName.assign(reinterpret_cast<const char *>(payload), payloadLen);
            } else if (option == 0x02 && suboption == 0x01) { // Type of Station
                dev.typeOfStation.assign(reinterpret_cast<const char *>(payload), payloadLen);
            }
        }

        offset += 4 + blockLength + (blockLength % 2);
    }
}

std::vector<ProfinetInterface> ListProfinetInterfaces(NpcapApi &api) {
    std::vector<ProfinetInterface> result;

    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    if (api.findalldevs(&alldevs, errbuf) != 0 || alldevs == nullptr) {
        return result;
    }

    ULONG bufLen = 15000;
    std::vector<unsigned char> buf(bufLen);
    auto *addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG ret = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addresses, &bufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buf.resize(bufLen);
        addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
        ret = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, addresses, &bufLen);
    }

    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        ProfinetInterface iface;
        iface.pcapName = d->name ? d->name : "";
        iface.description = d->description ? d->description : "";

        if (ret == NO_ERROR) {
            for (PIP_ADAPTER_ADDRESSES a = addresses; a != nullptr; a = a->Next) {
                std::string expected = std::string("\\Device\\NPF_") + a->AdapterName;
                if (iface.pcapName != expected) continue;

                iface.friendlyName = WideToUtf8(a->FriendlyName);
                if (a->PhysicalAddressLength == 6) {
                    std::memcpy(iface.mac, a->PhysicalAddress, 6);
                    iface.hasMac = true;
                }
                for (auto *ua = a->FirstUnicastAddress; ua != nullptr; ua = ua->Next) {
                    if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;
                    char ipstr[INET_ADDRSTRLEN] = {0};
                    auto *sin = reinterpret_cast<sockaddr_in *>(ua->Address.lpSockaddr);
                    inet_ntop(AF_INET, &sin->sin_addr, ipstr, sizeof(ipstr));
                    iface.ipv4 = ipstr;
                    break;
                }
                break;
            }
        }

        result.push_back(iface);
    }

    api.freealldevs(alldevs);
    return result;
}

bool ScanProfinetDevices(NpcapApi &api, const ProfinetInterface &iface, int timeoutMs,
                          std::vector<ProfinetDevice> &out, std::string &error) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = api.open_live(iface.pcapName.c_str(), 65536, 1, 200, errbuf);
    if (handle == nullptr) {
        error = std::string("pcap_open_live failed: ") + errbuf;
        return false;
    }

    unsigned char frame[60] = {0};
    const unsigned char dcpMulticast[6] = {0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00};
    std::memcpy(frame, dcpMulticast, 6);
    if (iface.hasMac) {
        std::memcpy(frame + 6, iface.mac, 6);
    }
    frame[12] = 0x88; frame[13] = 0x92; // EtherType: PROFINET

    frame[14] = 0xFE; frame[15] = 0xFE; // ProfinetIO frameID: DCP-Identify-ReqPDU

    frame[16] = 0x05; // service_id: Identify
    frame[17] = 0x00; // service_type: Request
    frame[18] = 0x01; frame[19] = 0x00; frame[20] = 0x00; frame[21] = 0x01; // xid
    frame[22] = 0x00; frame[23] = 0x00; // reserved
    frame[24] = 0x00; frame[25] = 0x04; // dcp_data_length = 4

    frame[26] = 0xFF; // option: All Selector
    frame[27] = 0xFF; // sub_option: ALL Selector
    frame[28] = 0x00; frame[29] = 0x00; // dcp_block_length = 0
    // frame[30..59]: zero padding up to the 60-byte Ethernet minimum.

    if (api.sendpacket(handle, frame, sizeof(frame)) != 0) {
        error = std::string("pcap_sendpacket failed: ") + api.geterr(handle);
        api.close_(handle);
        return false;
    }

    ULONGLONG start = GetTickCount64();
    while (static_cast<ULONGLONG>(GetTickCount64() - start) < static_cast<ULONGLONG>(timeoutMs)) {
        pcap_pkthdr *hdr = nullptr;
        const unsigned char *pkt = nullptr;
        int rc = api.next_ex(handle, &hdr, &pkt);
        if (rc != 1 || pkt == nullptr) continue; // 0 = per-read timeout, -1 = error, -2 = EOF (n/a live)

        if (hdr->caplen < 26) continue;
        if (pkt[12] != 0x88 || pkt[13] != 0x92) continue; // not PROFINET
        if (pkt[14] != 0xFE || pkt[15] != 0xFF) continue; // not DCP-Identify-ResPDU
        if (pkt[17] != 0x01) continue;                    // service_type != Response Success

        uint16_t dcpDataLength = ReadBE16(pkt + 24);
        if (hdr->caplen < 26u + dcpDataLength) continue;  // truncated capture

        ProfinetDevice dev;
        dev.mac = MacToString(pkt + 6); // Ethernet source = the responding device
        ParseDcpBlocks(pkt + 26, dcpDataLength, dev);
        out.push_back(dev);
    }

    api.close_(handle);
    return true;
}
