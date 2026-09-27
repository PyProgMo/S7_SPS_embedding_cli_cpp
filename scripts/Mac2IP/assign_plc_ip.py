#!/usr/bin/env python3
"""
Discover a Siemens S7-1200 PLC via PROFINET DCP by its MAC address,
print its current IP configuration, and (if needed) assign it a new
IP address so it can be reached over the local Ethernet link.

Requirements:
    pip install python-snap7[discovery]
    Windows: Npcap installed (check "WinPcap API-compatible mode" during install)
    Run this script as Administrator (Windows) / root (Linux) — raw socket access
    is required for DCP broadcasts.

Usage:
    1. Fill in TARGET_MAC below (run once with discover-only to find it if unknown).
    2. Fill in LOCAL_INTERFACE_IP with your Ethernet adapter's own IP.
    3. Set NEW_IP_CONFIG to whatever you want the PLC to have.
    4. Run: python assign_plc_ip.py
"""

import sys
import time

from snap7.discovery import discover
from pnio_dcp import DCP, DcpTimeoutError

# --- Configuration -------------------------------------------------------
LOCAL_INTERFACE_IP = "192.168.2.105"        # your PC's Ethernet adapter IP
TARGET_MAC = "00:1c:06:19:5d:35"          # MAC address of the PLC (from a first discover run)
NEW_IP_CONFIG = ["192.168.2.10", "255.255.255.0", "0.0.0.0"]  # [ip, netmask, gateway]
DISCOVERY_TIMEOUT = 5.0
# --------------------------------------------------------------------------


def find_device_by_mac(mac: str, local_ip: str, timeout: float):
    """Broadcast a DCP Identify-All and return the device matching `mac`, or None."""
    try:
        devices = discover(ip=local_ip, timeout=timeout)
    except PermissionError:
        print("Permission denied sending raw frames — re-run this script as Administrator/root.")
        sys.exit(1)
    except Exception as exc:
        print(f"Discovery failed: {exc}")
        sys.exit(1)

    if not devices:
        print("No PROFINET devices found — check link/cable, or try running as Administrator.")
        return None

    print("Devices found on the network:")
    for d in devices:
        marker = "  <-- target" if d.mac.lower() == mac.lower() else ""
        print(f"  {d.name:20} MAC={d.mac}  IP={d.ip or '(none)'}  "
              f"Netmask={d.netmask or '-'}  Gateway={d.gateway or '-'}{marker}")

    return next((d for d in devices if d.mac.lower() == mac.lower()), None)


def assign_ip(mac: str, local_ip: str, ip_config: list):
    """Assign a new IP configuration to the device with the given MAC address."""
    dcp = DCP(ip=local_ip)
    try:
        response = dcp.set_ip_address(mac, ip_config)
    except DcpTimeoutError:
        print(f"Device {mac} did not respond to the set-IP request.")
        sys.exit(1)

    # set_ip_address() does NOT raise on a rejected request -- it returns a
    # ResponseCode that evaluates to False (e.g. "Code 06: In operation, SET
    # not possible" if the CPU is actively running). Ignoring this return
    # value makes a rejection look identical to success.
    if not response:
        print(f"Device rejected the IP change: {response.get_message()}")
        if response.code == 6:
            print("The CPU is currently running (\"in operation\") -- PROFINET devices "
                  "commonly refuse DCP address changes while actively running, as a safety "
                  "measure. Stop the CPU first (e.g. SPScomm's \"Stop CPU\" option, or in "
                  "TIA Portal), retry this, then start it again.")
        elif response.code == 3:
            print("This usually means the CPU's PROFINET interface has \"IP address is set "
                  "in the project\" selected in TIA Portal (Device configuration -> PROFINET "
                  "interface -> Ethernet addresses), which locks out external DCP writes to "
                  "the IP parameter entirely. Switch it to \"IP address is set directly at "
                  "the device\", re-download the hardware config, then retry.")
        sys.exit(1)

    print(f"Requested IP change for {mac} -> {ip_config[0]} "
          f"(netmask {ip_config[1]}, gateway {ip_config[2]})")


def main():
    if TARGET_MAC.lower() == "xx:xx:xx:xx:xx:xx":
        print("Set TARGET_MAC at the top of this script first — running discovery only.\n")
        discover_devices = discover(ip=LOCAL_INTERFACE_IP, timeout=DISCOVERY_TIMEOUT)
        if not discover_devices:
            print("No PROFINET devices found — check link/cable, or try running as Administrator.")
        for d in discover_devices:
            print(f"  {d.name:20} MAC={d.mac}  IP={d.ip or '(none)'}  "
                  f"Netmask={d.netmask or '-'}  Gateway={d.gateway or '-'}")
        return

    device = find_device_by_mac(TARGET_MAC, LOCAL_INTERFACE_IP, DISCOVERY_TIMEOUT)

    if device is None:
        print(f"\nDevice with MAC {TARGET_MAC} was not found on the network.")
        return

    print(f"\nFound target device: {device.name} at IP={device.ip or '(none)'}")

    if device.ip == NEW_IP_CONFIG[0]:
        print("Device already has the desired IP address — nothing to do.")
        return

    print("Assigning new IP configuration...")
    assign_ip(TARGET_MAC, LOCAL_INTERFACE_IP, NEW_IP_CONFIG)

    time.sleep(2)  # give the PLC a moment to apply the new config
    print("\nVerifying new configuration...")
    find_device_by_mac(TARGET_MAC, LOCAL_INTERFACE_IP, DISCOVERY_TIMEOUT)


if __name__ == "__main__":
    main()
