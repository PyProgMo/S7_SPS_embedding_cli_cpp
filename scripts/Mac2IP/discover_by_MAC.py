#!/usr/bin/env python3
"""
Discover a Siemens S7-1200 PLC via PROFINET DCP by its MAC address and, if it
sits in a different IP subnet than this PC, move it into this PC's subnet so it
can be reached over S7comm (TCP port 102).

DCP runs on raw Ethernet (layer 2), so it reaches the PLC even while its IP
address belongs to a completely different subnet -- exactly the situation in
which nothing IP-based (ping, S7comm, SPScomm.exe) can talk to it.

Requirements:
    pip install -r requirements.txt   (pnio-dcp + psutil; python-snap7 for the final S7 check)
    Windows: Npcap installed (check "WinPcap API-compatible mode" during install)
    Run as Administrator (Windows) / root (Linux) if Npcap was installed with
    "Restrict Npcap driver's access to Administrators only".

Usage:
    python discover_by_MAC.py                        discover only: list PROFINET devices and say
                                                     whether the PLC is reachable from this PC
    python discover_by_MAC.py --auto --dry-run       show which address --auto would pick
    python discover_by_MAC.py --auto                 move the PLC into this PC's subnet, picking a
                                                     free address automatically
    python discover_by_MAC.py --new-ip 192.168.2.10  set a specific address instead

    See --help for the remaining options (--mac, --iface-ip, --netmask, --gateway,
    --temporary, --yes, --timeout).
"""

from __future__ import annotations

import argparse
import ctypes
import ipaddress
import re
import socket
import struct
import sys
import time
from dataclasses import dataclass

import psutil
from pnio_dcp import DCP, DcpTimeoutError, ResponseCode

# --- Configuration -------------------------------------------------------
LOCAL_INTERFACE_IP = ""                   # your PC's Ethernet adapter IP; empty = auto-detect the adapter the PLC answers on
TARGET_MAC = "00:1c:06:19:5d:35"          # MAC address of the PLC (from a first discover run); --mac overrides it
DISCOVERY_TIMEOUT = 3.0                   # seconds to collect Identify-All answers per adapter (PLCs answer within ~1.3 s)
# --------------------------------------------------------------------------

S7_PORT = 102
S7_RACK, S7_SLOT = 0, 1                   # S7-1200/1500 always use rack 0, slot 1

DCP_REQUEST_TIMEOUT = 5.0                 # how long to wait for a unicast DCP answer (identify / set)
AUTO_SKIP_TOP = 4                         # --auto leaves the highest 4 addresses (.251-.254 in a /24) alone
AUTO_MAX_PROBES = 32                      # --auto gives up after this many addresses turn out to be in use
VERIFY_TIMEOUT = 30.0                     # how long to wait for the PLC to come up on its new address

# BlockError codes a PROFINET device returns in its answer to a DCP Set request.
DCP_SET_ERRORS = {
    1: "code 01: option not supported",
    2: "code 02: suboption not supported or no data set available",
    3: "code 03: suboption not set",
    4: "code 04: resource error",
    5: "code 05: SET not possible for local reasons",
    6: "code 06: in operation, SET not possible",
    7: "code 07: SET not possible for security reasons",
}

_LOCKED_BY_PROJECT = (
    "On S7-1200/1500 CPUs the usual cause is the TIA Portal setting of the PROFINET interface "
    "(Device configuration -> PROFINET interface -> Ethernet addresses): with \"Set IP address in "
    "the project\" the CPU refuses address changes from any external tool. Switch it to \"IP address "
    "is set directly at the device\", download the hardware configuration once, then retry."
)
DCP_SET_HINTS = {
    3: "The PROFINET spec also uses this answer for an invalid address/netmask/gateway combination, "
       "but this script has already checked those against the spec's rules. " + _LOCKED_BY_PROJECT,
    5: _LOCKED_BY_PROJECT,
    6: "The device won't change its address while \"in operation\" (e.g. running a process with "
       "active PROFINET IO connections). Put the CPU into STOP from TIA Portal, then retry.",
    7: "Change the address from TIA Portal instead, or check the CPU's protection settings.",
}


@dataclass
class LocalInterface:
    name: str          # adapter name as Windows shows it, e.g. "Ethernet"
    ip: str
    netmask: str

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Interface(f"{self.ip}/{self.netmask}").network

    def __str__(self) -> str:
        return f"{self.name} ({self.ip}/{self.network.prefixlen})"


def normalize_mac(text: str) -> str:
    """'00-1C-06-19-5D-35', '001c.0619.5d35' or '001C06195D35' -> '00:1c:06:19:5d:35'
    (the form pnio_dcp expects and reports)."""
    digits = re.sub(r"[:\-.]", "", text.strip()).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", digits):
        raise ValueError(f"Not a MAC address: {text!r}")
    if int(digits[:2], 16) & 1 or digits == "0" * 12:
        # A group (multicast/broadcast) address would make every listening device apply a SET.
        raise ValueError(f"{text!r} is not the MAC address of a single device")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def default_route_ip() -> str | None:
    """IP of the adapter the OS would use to reach the internet, or None without a default route.

    connect() on a UDP socket only performs a route lookup -- no packet is sent.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 1))
            return s.getsockname()[0]
    except OSError:
        return None  # e.g. a PC cabled straight to the PLC, with no router at all


def list_local_interfaces() -> list[LocalInterface]:
    """Up, non-loopback IPv4 addresses on adapters that have a MAC address (pnio_dcp needs one
    as the Ethernet source address), with the default-route address first. An adapter with
    several addresses appears once per address."""
    stats = psutil.net_if_stats()
    found = []
    for name, addresses in psutil.net_if_addrs().items():
        if name not in stats or not stats[name].isup:
            continue
        if not any(a.family == psutil.AF_LINK for a in addresses):
            continue
        for a in addresses:
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                # psutil reports the netmask on Windows and Linux; /24 is only a fallback.
                found.append(LocalInterface(name, a.address, a.netmask or "255.255.255.0"))
    preferred = default_route_ip()
    found.sort(key=lambda iface: iface.ip != preferred)  # stable sort: otherwise keeps the OS order
    return found


def mutually_reachable(iface: LocalInterface, ip: str, netmask: str) -> bool:
    """True if `iface` and a device at ip/netmask each count the other as part of their own
    subnet -- the condition for talking to each other without a router in either direction."""
    try:
        device_net = ipaddress.IPv4Interface(f"{ip}/{netmask}").network
    except ValueError:
        return False
    return ipaddress.IPv4Address(ip) in iface.network and ipaddress.IPv4Address(iface.ip) in device_net


def open_dcp(iface: LocalInterface) -> DCP:
    """Open a raw-Ethernet DCP endpoint on `iface` (raises if Npcap is missing or access is denied)."""
    dcp = DCP(ip=iface.ip)
    dcp.default_timeout = DCP_REQUEST_TIMEOUT
    return dcp


def identify_all(dcp: DCP, timeout: float) -> list:
    """Multicast DCP Identify-All; returns every device that answered within `timeout` seconds."""
    # pnio_dcp's identify_all() listens until `timeout`, but each read inside it can block for
    # dcp.default_timeout (7 s out of the box) on top of that. Shrink the per-read wait while
    # scanning so `timeout` means what it says.
    dcp.default_timeout = 0.5
    try:
        return dcp.identify_all(timeout=timeout)
    finally:
        dcp.default_timeout = DCP_REQUEST_TIMEOUT


def identify(dcp: DCP, mac: str, timeout: float = DCP_REQUEST_TIMEOUT):
    """Unicast DCP Identify of one device; returns its pnio_dcp Device, or None if it didn't answer."""
    dcp.default_timeout = timeout
    try:
        device = dcp.identify(mac)
    except DcpTimeoutError:
        return None
    finally:
        dcp.default_timeout = DCP_REQUEST_TIMEOUT
    # pnio_dcp takes the first answer to its request without checking who sent it.
    return device if device.MAC.lower() == mac else None


def has_ip(device) -> bool:
    return device.IP not in ("", "0.0.0.0")


def print_devices(devices: list, mac: str | None = None) -> None:
    if not devices:
        print("  No PROFINET devices answered here.")
        return
    for d in devices:
        marker = "  <-- target" if mac and d.MAC.lower() == mac else ""
        print(f"  {d.name_of_station or '(no name)':20} MAC={d.MAC}  IP={d.IP if has_ip(d) else '(none)'}  "
              f"Netmask={d.netmask or '-'}  Gateway={d.gateway or '-'}  {d.family}{marker}")


def find_plc(mac: str, interfaces: list[LocalInterface], timeout: float):
    """Scan each adapter (default-route first) until one of them sees the PLC.

    Returns (interface, dcp, plc_device, all_devices_seen_there), or (None, None, None, [])
    if no adapter sees it.
    """
    opened_any = False
    for iface in interfaces:
        try:
            dcp = open_dcp(iface)
        except Exception as exc:  # Npcap missing, access denied, adapter pcap can't open, ...
            print(f"Skipping {iface}: cannot send raw Ethernet frames there ({exc}).")
            continue
        opened_any = True

        print(f"\nScanning {iface} for PROFINET devices...")
        devices = identify_all(dcp, timeout)
        print_devices(devices, mac)
        plc = next((d for d in devices if d.MAC.lower() == mac), None)
        if plc is None:
            # A multicast answer can get lost; ask the PLC directly once before moving on.
            plc = identify(dcp, mac, timeout=2.0)
        if plc is not None:
            return iface, dcp, plc, devices

    if not opened_any:
        print("\nCould not open any adapter for raw Ethernet. Install Npcap (https://npcap.com) and, "
              "if it is restricted to administrators, run this script as Administrator.")
    return None, None, None, []


def arp_owner(ip: str, src_ip: str) -> str | None:
    """Ask the LAN who has `ip` (ARP request sent from the adapter that owns `src_ip`).

    Returns the MAC that answered ("aa:bb:cc:dd:ee:ff"), "" if nobody answered (that takes
    ~3 s), or None if the check isn't available here (non-Windows) or failed.
    Every powered-on device answers ARP for its own address -- even one whose firewall
    drops ping -- so this is a much better "is this address taken?" test than ping.
    """
    if sys.platform != "win32":
        return None

    send_arp = ctypes.WinDLL("iphlpapi").SendARP
    send_arp.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    send_arp.restype = ctypes.c_uint32

    def to_ipaddr(text: str) -> int:
        # IPAddr holds the address bytes in network order; read them as a little-endian
        # integer so they land in memory in that same order.
        return struct.unpack("<I", socket.inet_aton(text))[0]

    mac = (ctypes.c_ubyte * 8)()
    mac_len = ctypes.c_ulong(len(mac))
    rc = send_arp(to_ipaddr(ip), to_ipaddr(src_ip), mac, ctypes.byref(mac_len))
    if rc == 0 and mac_len.value == 6:
        return ":".join(f"{b:02x}" for b in mac[:6])
    if rc in (31, 67):  # ERROR_GEN_FAILURE / ERROR_BAD_NET_NAME: no ARP reply
        return ""
    return None


def pick_free_ip(network: ipaddress.IPv4Network, src_ip: str, taken: set[str]) -> str | None:
    """Highest address in `network` that nobody answers ARP for, or None.

    Searches downward from the top of the subnet (skipping the very last few addresses,
    which routers and repeaters like to use), because home routers usually hand out DHCP
    leases from the lower/middle part -- a static address up there is less likely to
    collide with a future lease.
    """
    first = int(network.network_address) + 1
    last = int(network.broadcast_address) - 1
    if last < first:
        return None  # /31 or /32: no room for another host
    start = last - AUTO_SKIP_TOP if last - first > 4 * AUTO_SKIP_TOP else last

    probes = 0
    for value in range(start, first - 1, -1):
        candidate = str(ipaddress.IPv4Address(value))
        if candidate in taken:
            continue
        owner = arp_owner(candidate, src_ip)
        if owner == "":
            return candidate
        if owner is None:
            print("  The ARP check failed, so free addresses can't be detected -- pass one with --new-ip.")
            return None
        print(f"  {candidate} is in use (answered by {owner}), trying the next one...")
        probes += 1
        if probes >= AUTO_MAX_PROBES:
            print(f"  Gave up after {probes} addresses in use.")
            break
    return None


def parse_netmask(text: str) -> ipaddress.IPv4Address:
    """'255.255.255.0', '24' or '/24' -> IPv4Address('255.255.255.0'). Raises ValueError for
    anything that isn't a proper subnet mask (e.g. the "hostmask" 0.0.0.255)."""
    text = text.strip()
    if text.lstrip("/").isdigit():
        prefix = int(text.lstrip("/"))
        if prefix > 32:
            raise ValueError(f"{text} is not a valid prefix length")
        return ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask
    mask = ipaddress.IPv4Address(text)
    inverted = ~int(mask) & 0xFFFFFFFF
    if inverted & (inverted + 1):  # the one-bits must be contiguous from the left
        raise ValueError(f"{text} is not a valid subnet mask")
    return mask


def parse_ip_config(ip: str, netmask: str, gateway: str) -> tuple[str, str, str]:
    """Check an IP configuration against the PROFINET rules for a device's IP suite (a device
    answers a SET that breaks them with code 03) and return it in canonical spelling.
    Raises ValueError saying what's wrong."""
    address = ipaddress.IPv4Address(ip.strip())
    mask = parse_netmask(netmask)
    router = ipaddress.IPv4Address(gateway.strip())
    network = ipaddress.IPv4Network(f"{address}/{mask}", strict=False)

    if network.prefixlen == 0:
        raise ValueError("netmask 0.0.0.0 would make every address local")
    if network.prefixlen > 30:
        raise ValueError(f"netmask {mask} leaves no room for a device address")
    if any(address in ipaddress.IPv4Network(block) for block in ("0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/3")):
        raise ValueError(f"{address} is not a usable device address")
    if address in (network.network_address, network.broadcast_address):
        raise ValueError(f"{address} is the network or broadcast address of {network}")
    # 0.0.0.0 means "no router". A gateway equal to the device's own address is allowed too:
    # some Siemens devices report that for "no router", so restoring their old config must work.
    if not router.is_unspecified:
        if router not in network:
            raise ValueError(f"gateway {router} is outside the PLC's subnet {network}")
        if router in (network.network_address, network.broadcast_address):
            raise ValueError(f"gateway {router} is the network or broadcast address of {network}")
    return str(address), str(mask), str(router)


def tcp_reachable(ip: str, port: int = S7_PORT, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def s7_status(ip: str) -> str:
    """Open a real S7 connection (rack 0, slot 1) and read the CPU state -- the same first
    step SPScomm.exe and get_plc_info.py take."""
    try:
        from snap7.client import Client
    except ImportError:
        return "skipped (python-snap7 not installed)"

    client = Client()
    try:
        client.connect(ip, S7_RACK, S7_SLOT, S7_PORT)
        return f"OK, CPU state {client.get_cpu_state()}"
    except Exception as exc:  # snap7 raises several S7Error subclasses as well as OSError
        return f"connect failed ({exc})"
    finally:
        try:
            client.disconnect()
        except Exception:
            pass


def confirm(prompt: str) -> bool:
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def report_rejection(code: int | None) -> None:
    print(f"\nThe PLC rejected the change: {DCP_SET_ERRORS.get(code, f'unknown code {code}')}")
    if code in DCP_SET_HINTS:
        print(DCP_SET_HINTS[code])


def set_plc_ip(dcp: DCP, mac: str, ip: str, netmask: str, gateway: str, permanent: bool) -> bool | None:
    """Send the DCP Set request. Returns True if the PLC accepted it, False if it rejected it,
    or None if there was no clear answer (the change may still have been applied).

    Note: if the new IP reverts after a power cycle or a download, the CPU's hardware config
    in TIA Portal most likely has the PROFINET interface set to "Set IP address in the project"
    rather than "IP address is set directly at the device" -- that setting re-applies its own
    configured IP and silently overrides whatever DCP sets here. That's a TIA Portal project
    setting to fix, not something this script can work around.
    """
    try:
        response = dcp.set_ip_address(mac, [ip, netmask, gateway], permanent)
    except DcpTimeoutError:
        print("No answer to the Set request.")
        return None
    except KeyError as exc:
        # pnio_dcp 1.2.0 only knows the codes 0-6 and raises KeyError(code) while logging any
        # other rejection -- e.g. 07, which the PROFINET spec defines for security reasons.
        report_rejection(exc.args[0] if exc.args and isinstance(exc.args[0], int) else None)
        return False

    # set_ip_address() does NOT raise on a rejected request -- it returns a ResponseCode that
    # evaluates to False. Ignoring the return value makes a rejection look identical to success.
    if not isinstance(response, ResponseCode):
        print("The PLC sent an unexpected answer to the Set request.")
        return None
    if not response:
        report_rejection(response.code)
        return False
    return True


def verify_new_address(dcp: DCP, mac: str, iface: LocalInterface | None, ip: str, netmask: str,
                       gateway: str) -> tuple[tuple[str, str, str] | None, bool]:
    """Confirm the change end to end: DCP read-back, then -- if `iface` can reach the new
    address -- ARP, TCP 102 and a real S7 connection.

    Returns (configuration the PLC last reported or None if it never answered, whether every
    check passed).
    """
    deadline = time.monotonic() + VERIFY_TIMEOUT
    print("\nVerifying...")

    # 1. Does the PLC itself report the new configuration -- all of it, not just the IP?
    wanted = (ip, netmask, gateway)
    reported = None
    while time.monotonic() < deadline:
        device = identify(dcp, mac, timeout=2.0)
        if device is not None:
            reported = (device.IP, device.netmask, device.gateway)
            if reported == wanted:
                break
        time.sleep(1.0)
    if reported is None:
        print("  DCP read-back : the PLC did not answer -- could not confirm the change.")
        return None, False
    if reported != wanted:
        print(f"  DCP read-back : the PLC reports IP {reported[0]}  netmask {reported[1]}  "
              f"gateway {reported[2]} -- not the requested configuration.")
        return reported, False
    print(f"  DCP read-back : IP {ip}  netmask {netmask}  gateway {gateway}")

    if iface is None:
        print("  This PC has no address in the PLC's new subnet, so it can't reach it over IP "
              "from here -- skipping the IP checks.")
        return reported, True

    # 2. Does the new address resolve to the PLC -- and not to some other device as well?
    #    (Retries also replace the "unreachable" entry Windows cached if this address was
    #    probed while it was still free.)
    owner = ""
    while owner == "" and time.monotonic() < deadline:
        owner = arp_owner(ip, iface.ip)
        if owner == "":
            time.sleep(0.5)
    if owner is None:
        print("  ARP           : check not available here, skipped")
    elif owner == "":
        print(f"  ARP           : nobody answers for {ip} yet")
    elif owner != mac:
        print(f"  ARP           : {ip} is answered by {owner}, not by the PLC ({mac}) -- another "
              f"device already uses this address! Move the PLC again with --new-ip <free address>.")
        return reported, False
    else:
        print(f"  ARP           : {ip} is at {owner} (the PLC)")

    # 3. Is the S7comm port open?
    while not tcp_reachable(ip):
        if time.monotonic() >= deadline:
            print(f"  TCP {S7_PORT}       : no answer within {VERIFY_TIMEOUT:.0f} s")
            return reported, False
        time.sleep(1.0)
    print(f"  TCP {S7_PORT}       : open")

    # 4. Does a real S7 connection work?
    print(f"  S7 connection : {s7_status(ip)}")

    print(f"\nDone: the PLC is now reachable at {ip}. Use this address in SPScomm.exe "
          f"(menu option 1) or in get_plc_info.py / run_output_test.py.")
    return reported, True


def print_undo(mac: str, plc) -> None:
    """Print the command that puts the PLC back on the configuration it had before."""
    if not has_ip(plc):
        return  # it had no address before; there is nothing to restore
    script = f'"{sys.argv[0]}"' if " " in sys.argv[0] else sys.argv[0]
    print(f"\nTo undo: python {script} --mac {mac} --new-ip {plc.IP} --netmask {plc.netmask} "
          f"--gateway {plc.gateway}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Discover a Siemens PROFINET device by its MAC address and, optionally, move it "
                    "into this PC's IP subnet (or to any other address) via DCP."
    )
    parser.add_argument("--mac", help=f"MAC address of the PLC (default: TARGET_MAC = {TARGET_MAC})")
    parser.add_argument("--iface-ip", metavar="IP", default=LOCAL_INTERFACE_IP or None,
                        help="IP of this PC's adapter to use (default: auto-detect the adapter the "
                             "PLC answers on, trying the default-route adapter first)")
    change = parser.add_mutually_exclusive_group()
    change.add_argument("--auto", action="store_true",
                        help="Move the PLC into this PC's subnet, picking a free address automatically "
                             "(searching down from the top of the subnet, skipping addresses that answer ARP).")
    change.add_argument("--new-ip", metavar="IP", help="Set this exact IP address.")
    parser.add_argument("--netmask",
                        help="Subnet mask to set, e.g. 255.255.255.0 or 24 (default: the netmask of "
                             "this PC's adapter)")
    parser.add_argument("--gateway", default="0.0.0.0",
                        help="Router address to set (default: %(default)s = no router, which is all "
                             "you need to reach the PLC from its own subnet)")
    parser.add_argument("--temporary", action="store_true",
                        help="Don't store the new address permanently. It is lost at the next power "
                             "cycle, and per the PROFINET spec the stored address is cleared as well, "
                             "so the PLC may then come up with no IP address at all.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be set, but change nothing.")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Don't ask for confirmation before changing the PLC.")
    parser.add_argument("--timeout", type=float, default=DISCOVERY_TIMEOUT,
                        help="Seconds to listen for Identify-All answers per adapter (default: %(default)s)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    all_interfaces = list_local_interfaces()
    interfaces = all_interfaces
    if args.iface_ip:
        interfaces = [i for i in all_interfaces if i.ip == args.iface_ip]
        if not interfaces:
            print(f"No active network adapter has the IP {args.iface_ip}.")
            return 1
    if not interfaces:
        print("No active network adapter with an IPv4 address found -- is the Ethernet cable plugged in?")
        return 1

    mac_text = args.mac or TARGET_MAC
    if mac_text.lower() == "xx:xx:xx:xx:xx:xx":
        if args.auto or args.new_ip:
            print("Set TARGET_MAC at the top of this script (or pass --mac) to change a device's address.")
            return 1
        print("Set TARGET_MAC at the top of this script (or pass --mac) -- running discovery only.")
        for iface in interfaces:
            try:
                dcp = open_dcp(iface)
            except Exception as exc:
                print(f"Skipping {iface}: cannot send raw Ethernet frames there ({exc}).")
                continue
            print(f"\nScanning {iface} for PROFINET devices...")
            print_devices(identify_all(dcp, args.timeout))
        return 0

    try:
        mac = normalize_mac(mac_text)
    except ValueError as exc:
        print(exc)
        return 1

    iface, dcp, plc, devices = find_plc(mac, interfaces, args.timeout)
    if plc is None:
        print(f"\nDevice with MAC {mac} was not found -- check the cable/switch, and that this PC's "
              f"adapter is on the same Ethernet segment as the PLC (DCP does not cross routers or Wi-Fi bridges).")
        return 1

    host_net = iface.network
    plc_ip = plc.IP if has_ip(plc) else None
    # Every address this PC has on the adapter the PLC answered on -- with the one the PLC was
    # found through first. Someone may already have added one in the PLC's subnet.
    same_adapter = [iface] + [i for i in all_interfaces if i.name == iface.name and i.ip != iface.ip]

    print(f"\nFound target device: {plc.name_of_station or '(no name)'} at IP={plc_ip or '(none)'} "
          f"via adapter {iface}")
    reachable_via = next((i for i in same_adapter if plc_ip and mutually_reachable(i, plc_ip, plc.netmask)), None)
    if reachable_via is None:
        if plc_ip and ipaddress.IPv4Address(plc_ip) in host_net:
            print(f"Its address is inside this PC's subnet ({host_net}), but its own netmask "
                  f"{plc.netmask} leaves this PC outside the PLC's subnet, so it can't answer.")
        else:
            print(f"It is NOT in this PC's subnet ({host_net}), so it can't be reached over IP from here.")
    else:
        through = "" if reachable_via is iface else f" through this PC's other address {reachable_via.ip}"
        if tcp_reachable(plc_ip):
            print(f"It is reachable from this PC{through} and answers on TCP {S7_PORT}.")
        else:
            print(f"It is in this PC's subnet{through}, but TCP {S7_PORT} does not answer -- check for "
                  f"an address conflict, or whether the CPU is still starting up.")

    if not (args.auto or args.new_ip):
        if reachable_via is None:
            print(f"Re-run with --auto to move it into {host_net} (add --dry-run to preview first).")
        return 0  # discover/identify-only run

    netmask = args.netmask or iface.netmask
    gateway = args.gateway
    if args.auto:
        if reachable_via is iface:
            print("--auto: nothing to change.")
            return 0
        if host_net.is_link_local:
            print(f"This PC's adapter only has a link-local address ({iface.ip}), so there is no real "
                  f"subnet to move the PLC into. Give the adapter a proper IP first, or use --new-ip.")
            return 1
        if plc_ip and ipaddress.IPv4Address(plc_ip) in host_net:
            new_ip = plc_ip  # keep its address, only fix its netmask
        else:
            taken = {iface.ip} | {d.IP for d in devices if has_ip(d)}
            print(f"\nLooking for a free address in {host_net} (ARP check, ~3 s per free address)...")
            new_ip = pick_free_ip(host_net, iface.ip, taken)
            if new_ip is None:
                print("No free address found -- pass one explicitly with --new-ip.")
                return 1
            print(f"  {new_ip} is free.")
    else:
        new_ip = args.new_ip

    try:
        new_ip, netmask, gateway = parse_ip_config(new_ip, netmask, gateway)
    except ValueError as exc:
        print(f"Invalid IP configuration: {exc}")
        return 1

    before = (plc.IP, plc.netmask, plc.gateway)
    if (new_ip, netmask, gateway) == before:
        print("The PLC already has exactly this configuration -- nothing to do.")
        return 0

    if args.new_ip:  # --auto has just ARP-checked its pick (or keeps the PLC's own address)
        owner = arp_owner(new_ip, iface.ip)
        if owner and owner != mac:
            print(f"{new_ip} is already used by another device ({owner}) -- pick a different address.")
            return 1
        if owner is None:
            print(f"(Could not check whether {new_ip} is already in use on this system.)")
    # The PC address that will be able to talk to the PLC afterwards, if any.
    reach_iface = next((i for i in same_adapter if mutually_reachable(i, new_ip, netmask)), None)
    if reach_iface is None:
        print(f"WARNING: with {new_ip}/{netmask} the PLC and this PC ({iface.ip}/{iface.netmask}) are "
              f"not in each other's subnet -- the PLC will still not be reachable over IP from this PC.")

    permanent = not args.temporary
    print("\nPlanned change:")
    print(f"  device  : {plc.name_of_station or '(no name)'} ({plc.family or 'unknown type'}), MAC {mac}")
    print(f"  current : IP {plc_ip or '(none)'}  netmask {plc.netmask or '-'}  gateway {plc.gateway or '-'}")
    print(f"  new     : IP {new_ip}  netmask {netmask}  gateway {gateway}  "
          f"({'permanent' if permanent else 'temporary -- lost at the next power cycle, the PLC may then have no IP at all'})")
    print(f"  adapter : {iface}")
    if plc_ip and new_ip != plc_ip:
        print(f"Anything that talks to the PLC at {plc_ip} today (HMI, TIA Portal, PROFINET IO, other "
              f"scripts) loses the connection -- make sure that's safe if it controls a running process.")

    if args.dry_run:
        print("\n--dry-run: nothing was changed.")
        return 0
    if not args.yes and not confirm("\nApply this change? [y/N] "):
        print("Aborted -- nothing was changed.")
        return 1

    print(f"\nSending DCP Set to {mac}...")
    try:
        accepted = set_plc_ip(dcp, mac, new_ip, netmask, gateway, permanent)
        if accepted is False:
            if plc_ip and reachable_via is None:
                plc_net = ipaddress.IPv4Interface(f"{plc_ip}/{plc.netmask}").network
                print(f"\nAlternative that leaves the PLC untouched: give this PC an additional address "
                      f"in {plc_net} -- then it can be reached at {plc_ip} as it is.")
            return 1
        print("The PLC accepted the new configuration." if accepted
              else "Checking whether it was applied anyway...")
        reported, ok = verify_new_address(dcp, mac, reach_iface, new_ip, netmask, gateway)
    except KeyboardInterrupt:
        print(f"\nInterrupted after the Set request was sent -- the PLC may already be using {new_ip}. "
              f"Run this script without options to see its current address.")
        print_undo(mac, plc)
        return 130

    if reported != before:  # changed (or unknown) -- show how to get back
        print_undo(mac, plc)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
