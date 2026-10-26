#!/usr/bin/env python3
"""
Change the PLC's IP address to 192.168.178.70 (the "main" FRITZ!Box subnet),
in one command.

This is a thin, preset wrapper around scripts/Mac2IP/discover_by_MAC.py -- it
reuses that script's tested engine (device discovery by MAC over PROFINET DCP,
IP-suite validation, the DCP Set request, address-conflict check, end-to-end
verification and the printed "undo" command) and only fixes the target address.
Everything that actually touches the PLC lives there.

HOW THE CHANGE TRAVELS
    The IP is changed over PROFINET DCP, which is raw Ethernet (layer 2). That
    reaches the PLC even when this PC is in a different IP subnet, so you do NOT
    strictly need a 192.168.5.x address on this PC to run it. Giving this PC a
    192.168.5.x address first only helps you ping/verify the PLC beforehand; it
    does not change whether the PLC accepts the DCP write.

IF IT IS REJECTED (code 03 / "suboption not set")
    The CPU's TIA Portal project has the PROFINET interface set to
    "Set IP address in the project", which makes it refuse address changes from
    any external tool -- DCP, PRONETA, Primary Setup Tool alike. There is no
    script workaround. Either:
      * switch it to "IP address is set directly at the device" and download the
        hardware configuration once, then re-run this; or
      * simply set the project's IP to 192.168.178.70 in TIA and download it.

Requirements:
    pip install -r requirements.txt   (pnio-dcp + psutil; python-snap7 for the final S7 check)
    Windows: Npcap installed. Run as Administrator only if Npcap was installed
    restricted to administrators.

Usage:
    python set_plc_ip.py                 move the PLC to 192.168.178.70 (asks first)
    python set_plc_ip.py --dry-run       show the plan, change nothing
    python set_plc_ip.py --yes           don't ask for confirmation
    python set_plc_ip.py --new-ip 192.168.178.50 --mac 00:1c:06:19:5d:35
"""

from __future__ import annotations

import argparse
import os
import sys

# Reuse the audited engine next door (scripts/Mac2IP/discover_by_MAC.py).
_MAC2IP = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "Mac2IP"))
if _MAC2IP not in sys.path:
    sys.path.insert(0, _MAC2IP)
import discover_by_MAC as engine  # noqa: E402

# --- Configuration -------------------------------------------------------
NEW_IP = "192.168.178.70"          # where the PLC should end up
NEW_NETMASK = "255.255.255.0"
NEW_GATEWAY = "0.0.0.0"            # no router needed to reach it from its own subnet
TARGET_MAC = engine.TARGET_MAC     # the PLC, identified by MAC (00:1c:06:19:5d:35)
# --------------------------------------------------------------------------


def parse_args():
    parser = argparse.ArgumentParser(
        description="Move the PLC to 192.168.178.70 via PROFINET DCP (wrapper around "
                    "scripts/Mac2IP/discover_by_MAC.py).")
    parser.add_argument("--new-ip", default=NEW_IP, help=f"Target IP (default: {NEW_IP})")
    parser.add_argument("--mac", default=TARGET_MAC, help=f"PLC MAC address (default: {TARGET_MAC})")
    parser.add_argument("--netmask", default=NEW_NETMASK, help=f"Subnet mask (default: {NEW_NETMASK})")
    parser.add_argument("--gateway", default=NEW_GATEWAY, help=f"Gateway (default: {NEW_GATEWAY})")
    parser.add_argument("--iface-ip", metavar="IP", help="Force which local adapter to send on (default: auto).")
    parser.add_argument("--timeout", type=float, default=engine.DISCOVERY_TIMEOUT,
                        help=f"DCP discovery timeout in seconds (default: {engine.DISCOVERY_TIMEOUT})")
    parser.add_argument("--dry-run", action="store_true", help="Show the plan, change nothing.")
    parser.add_argument("-y", "--yes", action="store_true", help="Don't ask for confirmation.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    print(f"Target: move the PLC ({args.mac}) to {args.new_ip} / {args.netmask}.")
    print("The change is sent over PROFINET DCP (layer 2), so this works from any subnet.")
    print("If the PLC answers 'code 03', its IP is locked by the TIA project -- see this "
          "script's header for the fix.\n")

    # Hand off to the audited engine's --new-ip path (discovery, validation, the DCP
    # Set, conflict check, verification and undo all live and are tested there).
    forwarded = [
        "discover_by_MAC.py",
        "--mac", args.mac,
        "--new-ip", args.new_ip,
        "--netmask", args.netmask,
        "--gateway", args.gateway,
        "--timeout", str(args.timeout),
    ]
    if args.iface_ip:
        forwarded += ["--iface-ip", args.iface_ip]
    if args.dry_run:
        forwarded.append("--dry-run")
    if args.yes:
        forwarded.append("--yes")

    saved_argv = sys.argv
    sys.argv = forwarded
    try:
        return engine.main()
    finally:
        sys.argv = saved_argv


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
