#!/usr/bin/env python3
"""
Discover a Siemens S7-1200 PLC via PROFINET DCP by its MAC address,
print its current IP configuration, and (if requested) permanently
reassign its IP address so it can be reached over the local Ethernet link.

Requirements:
    pip install python-snap7[discovery]
    Windows: Npcap installed (check "WinPcap API-compatible mode" during install)
    Run this script as Administrator (Windows) / root (Linux) — raw socket access
    is required for DCP broadcasts.

Usage:
    1. Fill in TARGET_MAC below (run once with no --new-ip to find it if unknown).
    2. Fill in LOCAL_INTERFACE_IP with your Ethernet adapter's own IP.
    3. Run: python discover_by_MAC.py                       (discover/identify only)
       Or:  python discover_by_MAC.py --new-ip 192.168.2.10  (reassign the IP)
"""

import argparse
import sys
import time

from snap7.discovery import discover
from pnio_dcp import DCP, DcpTimeoutError

# --- Configuration -------------------------------------------------------
LOCAL_INTERFACE_IP = "192.168.2.105"        # your PC's Ethernet adapter IP
TARGET_MAC = "00:1c:06:19:5d:35"          # MAC address of the PLC (from a first discover run)
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


def set_plc_ip(mac_address: str, new_ip: str,
                subnet_mask: str = "255.255.255.0",
                gateway: str = "0.0.0.0",
                permanent: bool = True) -> None:
    """
    Reassign a PROFINET device's IP configuration via DCP, logging a
    before/after record and handling the case where the device doesn't
    respond in time.

    Note: if the new IP reverts after a power cycle, the CPU's hardware
    config in TIA Portal most likely has the PROFINET interface set to
    "IP address set in the project" rather than "IP address set directly
    at the device" -- that setting re-pushes its own configured IP at every
    boot/config-download and silently overrides whatever DCP sets here.
    That's a TIA Portal project setting to fix (re-download hardware config
    after switching it), not something this script can work around.
    """
    dcp = DCP(ip=LOCAL_INTERFACE_IP)

    try:
        before = dcp.identify(mac_address)
        print(f"Current configuration for {mac_address}: "
              f"name={before.name_of_station or '(none)'} IP={before.IP or '(none)'}")
    except DcpTimeoutError:
        print(f"{mac_address} did not respond to identify -- continuing anyway.")

    print(f"Setting {mac_address} -> {new_ip} (netmask {subnet_mask}, gateway {gateway}, "
          f"{'permanent' if permanent else 'temporary'})...")
    try:
        response = dcp.set_ip_address(mac_address, [new_ip, subnet_mask, gateway], permanent)
    except DcpTimeoutError:
        print(f"{mac_address} did not respond to the set-IP request within the timeout.")
        return

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
        return

    time.sleep(2)  # give the device a moment to apply the new configuration

    try:
        confirmed_ip = dcp.get_ip_address(mac_address)
    except DcpTimeoutError:
        print(f"Set request was sent, but {mac_address} did not respond to the "
              f"verification read -- check manually.")
        return

    print(f"Confirmed: {mac_address} is now at {confirmed_ip} (requested {new_ip}).")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Discover a Siemens PROFINET device by MAC and, optionally, "
                    "permanently reassign its IP address."
    )
    parser.add_argument("--new-ip", metavar="IP",
                        help="If given, reassign TARGET_MAC to this IP instead of just "
                             "discovering/identifying it.")
    parser.add_argument("--netmask", default="255.255.255.0",
                        help="Subnet mask to set alongside --new-ip (default: %(default)s)")
    parser.add_argument("--gateway", default="0.0.0.0",
                        help="Gateway to set alongside --new-ip (default: %(default)s)")
    parser.add_argument("--temporary", action="store_true",
                        help="Store --new-ip only until the next power cycle, instead of "
                             "permanently (default: permanent).")
    return parser.parse_args()


def main():
    args = parse_args()

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

    if not args.new_ip:
        return  # discover/identify-only run

    if device.ip == args.new_ip:
        print("Device already has the desired IP address — nothing to do.")
        return

    print("\nAssigning new IP configuration...")
    set_plc_ip(TARGET_MAC, args.new_ip, args.netmask, args.gateway, permanent=not args.temporary)

    print("\nVerifying new configuration...")
    find_device_by_mac(TARGET_MAC, LOCAL_INTERFACE_IP, DISCOVERY_TIMEOUT)


if __name__ == "__main__":
    main()
