#!/usr/bin/env python3
"""Discover PROFINET devices on the local Ethernet segment via DCP Identify-All.

This sends the same broadcast that PRONETA's network scan uses: a PROFINET DCP
"Identify All" request to multicast MAC 01:0e:cf:00:00:00. Every PROFINET
device on the segment answers with its MAC, name of station, current IP, and
device/vendor ID -- useful for finding a PLC's IP when you don't know it yet.

Requirements:
  - Npcap installed (https://npcap.com/#download), with "Support raw 802.11
    traffic" unchecked and "WinPcap API-compatible Mode" checked (default).
  - pip install scapy
  - Run from an elevated (Administrator) terminal -- raw frame injection
    needs it on Windows.
  - Run on the wired LAN interface connected to the same switch/Speedport as
    the PLC. DCP is a raw Ethernet broadcast (EtherType 0x8892); it will not
    cross the router's Wi-Fi bridge.

Usage:
  python profinet_scan.py --list-interfaces
  python profinet_scan.py --iface "Ethernet" [--timeout 3] [-o devices.txt]
"""
import argparse
import sys
from datetime import datetime

try:
    from scapy.all import conf, srp, Ether
except ImportError:
    sys.exit("scapy is required: pip install scapy")

import scapy.contrib.pnio  # noqa: F401  (registers Ether type 0x8892 -> ProfinetIO)
from scapy.contrib.pnio import ProfinetIO
from scapy.contrib.pnio_dcp import (
    ProfinetDCP,
    DCP_IDENTIFY_REQUEST_FRAME_ID,
    DCP_SERVICE_ID_IDENTIFY,
    DCP_REQUEST,
    DCP_DEVICE_ROLES,
    DCPNameOfStationBlock,
    DCPIPBlock,
    DCPDeviceIDBlock,
    DCPDeviceRoleBlock,
    DCPAliasNameBlock,
    DCPManufacturerSpecificBlock,
)

DCP_MULTICAST_MAC = "01:0e:cf:00:00:00"


def _as_text(value):
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def list_interfaces():
    print("Available interfaces:")
    for iface in conf.ifaces.values():
        ip = getattr(iface, "ip", "") or ""
        desc = getattr(iface, "description", "") or ""
        print(f"  {iface.name!r:30} {desc:45} {ip}")


def summarize_blocks(dcp_blocks):
    info = {}
    for block in dcp_blocks:
        if isinstance(block, DCPNameOfStationBlock):
            info["name"] = _as_text(block.name_of_station)
        elif isinstance(block, DCPIPBlock):
            info["ip"] = block.ip
            info["netmask"] = block.netmask
            info["gateway"] = block.gateway
        elif isinstance(block, DCPDeviceIDBlock):
            info["vendor_id"] = f"0x{block.vendor_id:04x}"
            info["device_id"] = f"0x{block.device_id:04x}"
        elif isinstance(block, DCPDeviceRoleBlock):
            info["role"] = DCP_DEVICE_ROLES.get(
                block.device_role_details, str(block.device_role_details)
            )
        elif isinstance(block, DCPAliasNameBlock):
            info["alias"] = _as_text(block.alias_name)
        elif isinstance(block, DCPManufacturerSpecificBlock):
            info["type"] = _as_text(block.device_vendor_value)
    return info


def scan(iface, timeout):
    request = (
        Ether(dst=DCP_MULTICAST_MAC)
        / ProfinetIO(frameID=DCP_IDENTIFY_REQUEST_FRAME_ID)
        / ProfinetDCP(
            service_id=DCP_SERVICE_ID_IDENTIFY,
            service_type=DCP_REQUEST,
            option=255,
            sub_option=255,
            dcp_data_length=4,
        )
    )

    answered, _ = srp(
        request, iface=iface, timeout=timeout, verbose=0, filter="ether proto 0x8892"
    )

    devices = []
    for _, response in answered:
        dcp = response.getlayer(ProfinetDCP)
        if dcp is None or dcp.service_type != 1:
            continue
        info = summarize_blocks(dcp.dcp_blocks)
        info["mac"] = response[Ether].src
        devices.append(info)
    return devices


def main():
    parser = argparse.ArgumentParser(
        description="Discover PROFINET devices via DCP Identify-All (like PRONETA's network scan)."
    )
    parser.add_argument("--iface", help="Interface to scan on (see --list-interfaces)")
    parser.add_argument(
        "--timeout", type=float, default=3.0,
        help="Seconds to wait for responses (default: %(default)s)",
    )
    parser.add_argument(
        "-o", "--output", default="profinet_devices.txt",
        help="Output file path (default: %(default)s)",
    )
    parser.add_argument(
        "--list-interfaces", action="store_true", help="List available interfaces and exit"
    )
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    if not args.iface:
        print("No --iface given.\n")
        list_interfaces()
        print('\nRe-run with --iface "<name>" using the wired LAN adapter '
              "connected to the Speedport (not Wi-Fi).")
        sys.exit(1)

    print(f"Sending DCP Identify-All on {args.iface!r} (timeout={args.timeout}s)...")
    devices = scan(args.iface, args.timeout)

    if not devices:
        print("No PROFINET devices responded.")
    else:
        print(f"{len(devices)} device(s) found:\n")
        for d in devices:
            print(f"  {d['mac']}  {d.get('ip', '-'):15} {d.get('name', '-')}")

    with open(args.output, "w") as f:
        f.write(f"PROFINET DCP scan on interface {args.iface}\n")
        f.write(f"Timestamp: {datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"Devices found: {len(devices)}\n\n")
        for d in devices:
            f.write(f"MAC: {d['mac']}\n")
            f.write(f"  Name of station : {d.get('name', '-')}\n")
            f.write(f"  IP address      : {d.get('ip', '-')}\n")
            f.write(f"  Netmask         : {d.get('netmask', '-')}\n")
            f.write(f"  Gateway         : {d.get('gateway', '-')}\n")
            f.write(f"  Vendor/Device ID: {d.get('vendor_id', '-')}/{d.get('device_id', '-')}\n")
            f.write(f"  Device role     : {d.get('role', '-')}\n")
            f.write(f"  Type of station : {d.get('type', '-')}\n")
            f.write(f"  Alias name      : {d.get('alias', '-')}\n")
            f.write("\n")

    print(f"\nResults written to {args.output}")


if __name__ == "__main__":
    main()
