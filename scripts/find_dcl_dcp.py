#!/usr/bin/env python3
"""
Find the Siemens S7-1200 via PROFINET DCP (layer 2) instead of guessing
IP subnets. This uses the real DCP "Identify All" broadcast -- the same
mechanism PRONETA and TIA Portal's "Accessible devices" use -- so it finds
the PLC by MAC address no matter which subnet its static IP is on.

Install:
    pip install pnio_dcp

Requires Npcap on Windows (you already installed this alongside PRONETA).

Usage:
    python find_plc_dcp.py
"""

from pnio_dcp import DCP

# MAC printed on the CPU 1214C's PROFINET label
TARGET_MAC = "00:1c:06:19:5d:35"

# The IP currently assigned to the NIC you connected the PLC to.
# Check with `ipconfig` and use whatever shows up for that adapter --
# even an auto-assigned 169.254.x.x (APIPA) address is fine here, since
# it's only used as the local socket DCP sends/listens on, not to reach
# the PLC over IP.
LOCAL_IP = "169.254.1.1"  # <-- change this


def normalize(mac: str) -> str:
    return mac.replace("-", ":").lower()


def main() -> None:
    print(f"Sending DCP identify-all broadcast from {LOCAL_IP} ...\n")

    dcp = DCP(LOCAL_IP)
    devices = dcp.identify_all()

    if not devices:
        print("No PROFINET devices responded.")
        print("Check the cable/link light, and that LOCAL_IP above actually")
        print("matches the adapter physically connected to the PLC.")
        return

    print(f"Found {len(devices)} PROFINET device(s):\n")
    target_norm = normalize(TARGET_MAC)

    for device in devices:
        print(device)  # Device's own repr -- shows name/MAC/IP
        mac = getattr(device, "mac", None) or getattr(device, "MAC", None)
        if mac and normalize(str(mac)) == target_norm:
            print("  ^ this one is your PLC (MAC matches)\n")


if __name__ == "__main__":
    main()