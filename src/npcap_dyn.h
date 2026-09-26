#pragma once
// Loads wpcap.dll at runtime via LoadLibrary/GetProcAddress instead of
// linking Npcap's import library. This keeps the build independent of
// Npcap's MSVC-format .lib files (which MinGW can't link directly) and
// means only the machine that *runs* a scan needs Npcap installed --
// not the machine that builds SPScomm.exe.
#include <string>

#include <pcap.h>

struct NpcapApi {
    decltype(&pcap_findalldevs) findalldevs = nullptr;
    decltype(&pcap_freealldevs) freealldevs = nullptr;
    decltype(&pcap_open_live) open_live = nullptr;
    decltype(&pcap_close) close_ = nullptr;
    decltype(&pcap_sendpacket) sendpacket = nullptr;
    decltype(&pcap_next_ex) next_ex = nullptr;
    decltype(&pcap_geterr) geterr = nullptr;

    bool loaded = false;
};

// Attempts to load wpcap.dll and resolve the functions we need.
// Returns true on success; on failure, errorOut explains what to install.
bool LoadNpcap(NpcapApi &api, std::string &errorOut);
