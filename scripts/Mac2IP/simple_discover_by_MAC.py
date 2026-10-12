#!/usr/bin/env python3
"""
Find PROFINET devices (e.g. an S7-1200) on the local Ethernet via DCP and print
their IP addresses. Read-only: it changes nothing on any device.

Requirements:
    pip install pnio-dcp
    Windows: Npcap installed

Usage:
    python simple_discover_by_MAC.py                      list every device found
    python simple_discover_by_MAC.py 00:1c:06:19:5d:35    show only the device with this MAC
"""

import socket
import sys

from pnio_dcp import DCP

# --- Configuration -------------------------------------------------------
LOCAL_INTERFACE_IP = ""     # your PC's Ethernet adapter IP; empty = the adapter with the default route
DISCOVERY_TIMEOUT = 3       # seconds to wait for answers (devices answer within ~1.3 s)
# --------------------------------------------------------------------------


def default_route_ip():
    """IP of the adapter the PC uses to reach the internet (route lookup only, nothing is sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 1))
        return s.getsockname()[0]


def main():
    target_mac = sys.argv[1].strip().lower().replace("-", ":") if len(sys.argv) > 1 else None

    try:
        local_ip = LOCAL_INTERFACE_IP or default_route_ip()
        dcp = DCP(local_ip)
    except Exception as exc:
        print(f"Cannot open the network adapter: {exc}")
        print("Set LOCAL_INTERFACE_IP at the top of this script, and check that Npcap is installed.")
        sys.exit(1)

    # identify_all() would otherwise wait up to 7 s longer than DISCOVERY_TIMEOUT.
    dcp.default_timeout = 0.5
    print(f"Searching for PROFINET devices via {local_ip}...")
    devices = dcp.identify_all(timeout=DISCOVERY_TIMEOUT)

    if target_mac:
        devices = [d for d in devices if d.MAC.lower() == target_mac]
        if not devices:
            print(f"No device with MAC {target_mac} answered.")
            sys.exit(1)
    elif not devices:
        print("No PROFINET devices answered -- check the cable and the adapter.")
        sys.exit(1)

    print(f"\n{'MAC':19}{'IP':17}{'Netmask':17}Name")
    for d in devices:
        ip = d.IP if d.IP not in ("", "0.0.0.0") else "(none)"
        print(f"{d.MAC:19}{ip:17}{d.netmask or '-':17}{d.name_of_station or '-'}")


if __name__ == "__main__":
    main()
