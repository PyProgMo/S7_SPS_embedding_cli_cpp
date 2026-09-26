#include "npcap_dyn.h"

#include <windows.h>

namespace {

template <typename Fn>
bool Resolve(HMODULE mod, const char *name, Fn &out) {
    out = reinterpret_cast<Fn>(reinterpret_cast<void *>(GetProcAddress(mod, name)));
    return out != nullptr;
}

} // namespace

bool LoadNpcap(NpcapApi &api, std::string &errorOut) {
    HMODULE mod = LoadLibraryA("wpcap.dll");
    if (mod == nullptr) {
        // Default Npcap install location, in case it wasn't added to PATH.
        mod = LoadLibraryA("C:\\Windows\\System32\\Npcap\\wpcap.dll");
    }
    if (mod == nullptr) {
        errorOut =
            "Could not load wpcap.dll. Npcap does not appear to be installed.\n"
            "Install it from https://npcap.com/#download (the default options are fine)\n"
            "and make sure to run this program as Administrator.";
        return false;
    }

    bool ok = true;
    ok &= Resolve(mod, "pcap_findalldevs", api.findalldevs);
    ok &= Resolve(mod, "pcap_freealldevs", api.freealldevs);
    ok &= Resolve(mod, "pcap_open_live", api.open_live);
    ok &= Resolve(mod, "pcap_close", api.close_);
    ok &= Resolve(mod, "pcap_sendpacket", api.sendpacket);
    ok &= Resolve(mod, "pcap_next_ex", api.next_ex);
    ok &= Resolve(mod, "pcap_geterr", api.geterr);

    if (!ok) {
        errorOut = "wpcap.dll was found but is missing expected functions "
                   "(unexpected/incompatible Npcap version?).";
        return false;
    }

    api.loaded = true;
    return true;
}
