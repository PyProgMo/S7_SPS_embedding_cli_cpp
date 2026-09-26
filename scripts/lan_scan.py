#!/usr/bin/env python3
"""
Brute-force LAN scan for a device with a known MAC address.

How it works:
  1. Ping-sweeps every host in each candidate /24 subnet (populates the OS ARP cache).
  2. Reads the ARP table and looks for the target MAC address.
  3. Reports the IP if found.

Usage:
  python find_plc.py

Edit TARGET_MAC and SUBNETS below to match your setup.
"""

import platform
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Optional

# --- Configuration -----------------------------------------------------

# MAC address printed on the CPU 1214C's PROFINET label
TARGET_MAC = "00-1c-06-19-5d-35"

# Subnets to try, in order. Add more if your first guesses miss.
SUBNETS = [
    "192.168.0.",
    "192.168.1.",
    "192.168.2.",
    "10.0.0.",
    "10.0.1.",
]

HOST_RANGE = range(1, 255)   # .1 .. .254
PING_TIMEOUT_MS = 300        # per-host timeout (ms on Windows, s-ish on Linux)
MAX_WORKERS = 64             # concurrent pings

# ------------------------------------------------------------------------

IS_WINDOWS = platform.system().lower() == "windows"


def normalize_mac(mac: str) -> str:
    """Strip separators and lowercase, so '00-1C-06' == '00:1c:06'."""
    return re.sub(r"[^0-9a-f]", "", mac.lower())


def ping(ip: str) -> None:
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def read_arp_table() -> Dict[str, str]:
    """Return {ip: normalized_mac} from the OS ARP cache."""
    out = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout

    if IS_WINDOWS:
        # e.g. "  192.168.1.1           00-1c-06-19-5d-35     dynamic"
        pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})")
    else:
        # e.g. "? (192.168.1.5) at 00:1c:06:19:5d:35 [ether] on eth0"
        pattern = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{17})")

    table = {}
    for ip, mac in pattern.findall(out):
        table[ip] = normalize_mac(mac)
    return table


def scan_subnet(prefix: str, target_norm: str) -> Optional[str]:
    print(f"Scanning {prefix}0/24 ...")
    ips = [f"{prefix}{i}" for i in HOST_RANGE]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = [pool.submit(ping, ip) for ip in ips]
        for _ in as_completed(futures):
            pass  # we only need pings to populate the ARP cache

    table = read_arp_table()
    for ip, mac in table.items():
        if mac == target_norm and ip.startswith(prefix):
            return ip
    return None


def main() -> None:
    target_norm = normalize_mac(TARGET_MAC)
    print(f"Looking for MAC {TARGET_MAC} ...\n")

    for prefix in SUBNETS:
        found = scan_subnet(prefix, target_norm)
        if found:
            print(f"\nFound it! {TARGET_MAC} -> {found}")
            sys.exit(0)

    print("\nNot found in any scanned subnet.")
    print("Add more ranges to SUBNETS, or fall back to PROFINET DCP discovery")
    print("(Siemens PRONETA / TIA Portal 'Accessible devices'), which finds the")
    print("device by MAC regardless of which subnet its static IP is actually on.")


if __name__ == "__main__":
    main()