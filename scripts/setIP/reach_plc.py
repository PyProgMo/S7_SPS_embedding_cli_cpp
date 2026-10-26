#!/usr/bin/env python3
"""
Make the fixed-IP PLC reachable from this PC WITHOUT changing the PLC.

Why this exists
    The PLC's IP (192.168.5.70) is fixed by its TIA Portal project and cannot be
    changed from outside -- every DCP Set is refused with "code 03", and the CPU
    has no TIA access and no buttons here. On top of that its gateway is 0.0.0.0,
    so it can ONLY talk to devices inside 192.168.5.0/24; no router can bridge it.

    The way to use such a PLC is therefore to give THIS PC an address in the
    PLC's subnet. The trick is to ADD it as a SECOND address next to the normal
    DHCP address (192.168.178.x) instead of replacing it -- so the internet /
    home-router connection keeps working while the PLC becomes reachable too.
    That is what this script does, persistently (it survives a reboot).

    After this runs, 192.168.5.70 answers ping and S7comm (TCP 102), so
    scripts/plc_info/*, scripts/program_io/* and SPScomm.exe can all talk to it.

Needs Administrator (it changes this PC's IP configuration). It never touches
the PLC. Windows only.

Usage (in an ELEVATED PowerShell / terminal):
    python reach_plc.py                 add 192.168.5.60/24 next to DHCP, then verify
    python reach_plc.py --check         show status only, change nothing
    python reach_plc.py --dry-run       print the exact netsh commands, run nothing
    python reach_plc.py --remove        remove the extra address again
    python reach_plc.py --host-ip 192.168.5.61 --yes
"""

from __future__ import annotations

import argparse
import ctypes
import socket
import subprocess
import sys
import time

# --- Configuration -------------------------------------------------------
HOST_IP = "192.168.5.60"      # the address to give THIS PC in the PLC's subnet (free, != PLC)
PREFIX = 24                   # 255.255.255.0
PLC_IP = "192.168.5.70"       # only used to verify reachability afterwards
# --------------------------------------------------------------------------

MASK = socket.inet_ntoa((0xFFFFFFFF << (32 - PREFIX) & 0xFFFFFFFF).to_bytes(4, "big"))


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def default_route_ip() -> str | None:
    """The local IP this PC uses toward the internet (route lookup only, nothing sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 1))
            return s.getsockname()[0]
    except OSError:
        return None


def detect_adapter() -> str:
    """Friendly name of the adapter carrying the default route (e.g. 'Ethernet')."""
    try:
        import psutil
    except ImportError:
        return "Ethernet"
    want = default_route_ip()
    names = {}
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET:
                names.setdefault(name, a.address)
                if a.address == want:
                    return name
    return next(iter(names), "Ethernet")


def arp_owner(ip: str, src_ip: str | None) -> str | None:
    """MAC that answers ARP for `ip` (''=nobody, None=check unavailable)."""
    if sys.platform != "win32":
        return None
    send_arp = ctypes.WinDLL("iphlpapi").SendARP
    send_arp.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    dst = int.from_bytes(socket.inet_aton(ip), "little")
    src = int.from_bytes(socket.inet_aton(src_ip), "little") if src_ip else 0
    mac = (ctypes.c_ubyte * 8)()
    length = ctypes.c_ulong(8)
    rc = send_arp(dst, src, mac, ctypes.byref(length))
    if rc == 0 and length.value == 6:
        return ":".join(f"{b:02x}" for b in mac[:6])
    if rc in (31, 67):
        return ""
    return None


def tcp_open(ip: str, port: int = 102, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def commands(adapter: str, host_ip: str, remove: bool) -> list[list[str]]:
    if remove:
        return [["netsh", "interface", "ipv4", "delete", "address",
                 f"name={adapter}", f"address={host_ip}"]]
    return [
        # Let a manually-added static address coexist with the DHCP address, so
        # the internet/home-router address and lease are kept.
        ["netsh", "interface", "ipv4", "set", "interface", adapter, "dhcpstaticipcoexistence=enabled"],
        # Add it as a SECONDARY address (no gateway -> the default route stays via DHCP).
        ["netsh", "interface", "ipv4", "add", "address",
         f"name={adapter}", f"address={host_ip}", f"mask={MASK}"],
    ]


def run_netsh(cmd: list[str]) -> tuple[int, str]:
    print("  >", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = (proc.stdout + proc.stderr).strip()
    if out:
        print("   ", out.replace("\n", "\n    "))
    return proc.returncode, out


def show_status(adapter: str, host_ip: str) -> None:
    src = default_route_ip()
    print(f"Adapter      : {adapter}")
    print(f"This PC's IPs : ", end="")
    try:
        import psutil
        ips = [a.address for a in psutil.net_if_addrs().get(adapter, []) if a.family == socket.AF_INET]
        print(", ".join(ips) or "(none)")
        has_host = host_ip in ips
    except ImportError:
        print("(psutil not available)")
        has_host = None
    owner = arp_owner(PLC_IP, src)
    print(f"PLC {PLC_IP} : ARP {'answers ' + owner if owner else 'no answer' if owner == '' else 'unknown'}, "
          f"TCP 102 {'open' if tcp_open(PLC_IP) else 'closed'}")
    if has_host is not None:
        print(f"{host_ip} present on this PC: {'yes' if has_host else 'no'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Give this PC a second IP in the PLC's subnet (kept alongside DHCP) so the "
                    "fixed-IP PLC is reachable. Does not change the PLC.")
    parser.add_argument("--host-ip", default=HOST_IP, help=f"PC address to add (default: {HOST_IP})")
    parser.add_argument("--adapter", help="Network adapter name (default: auto-detect the default-route adapter)")
    parser.add_argument("--remove", action="store_true", help="Remove the extra address again.")
    parser.add_argument("--check", action="store_true", help="Show status only; change nothing.")
    parser.add_argument("--dry-run", action="store_true", help="Print the netsh commands without running them.")
    parser.add_argument("-y", "--yes", action="store_true", help="Don't ask for confirmation.")
    args = parser.parse_args()

    if sys.platform != "win32":
        print("This script configures Windows networking and only runs on Windows.")
        return 1

    adapter = args.adapter or detect_adapter()

    if args.check:
        show_status(adapter, args.host_ip)
        return 0

    if not args.remove:
        owner = arp_owner(args.host_ip, default_route_ip())
        if owner:
            print(f"{args.host_ip} is already used by another device ({owner}) -- choose a free "
                  f"address with --host-ip.")
            return 1

    action = "Remove" if args.remove else "Add"
    print(f"{action} {args.host_ip}/{PREFIX} on adapter '{adapter}'"
          + ("" if args.remove else " (kept alongside the DHCP/internet address)."))
    cmds = commands(adapter, args.host_ip, args.remove)

    if args.dry_run:
        print("\nWould run (in an elevated terminal):")
        for cmd in cmds:
            print("  " + " ".join(cmd))
        return 0

    if not is_admin():
        print("\nThis needs Administrator rights. Open PowerShell as Administrator and run this "
              "script again, or run these commands there directly:")
        for cmd in cmds:
            print("  " + " ".join(cmd))
        return 1

    if not args.yes:
        try:
            if input(f"\nProceed? [y/N] ").strip().lower() not in ("y", "yes"):
                print("Aborted.")
                return 1
        except EOFError:
            print("Aborted.")
            return 1

    print()
    for cmd in cmds:
        rc, out = run_netsh(cmd)
        if rc != 0 and "exist" not in out.lower():  # "already exists" on a repeat add is fine
            print(f"\nCommand failed (exit {rc}). If it is a permissions error, run as Administrator.")
            return 1

    if args.remove:
        print(f"\nRemoved {args.host_ip}. The DHCP/internet address is untouched.")
        return 0

    print("\nVerifying the PLC is now reachable...")
    deadline = time.monotonic() + 10
    while not tcp_open(PLC_IP):
        if time.monotonic() >= deadline:
            print(f"  TCP {PLC_IP}:102 still not answering. Check the cable/switch and that the PLC "
                  f"is powered; re-run with --check.")
            return 1
        time.sleep(1)
    print(f"  {PLC_IP}:102 is open -- the PLC is reachable.")
    print("\nDone. Internet keeps working via the DHCP address; the PLC is reachable at "
          f"{PLC_IP} for get_plc_info.py, program_io/* and SPScomm.exe.")
    print(f"To undo later: python {sys.argv[0]} --remove")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
