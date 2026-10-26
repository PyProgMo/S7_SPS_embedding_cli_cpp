#!/usr/bin/env python3
"""
PLC connectivity & capability diagnostics -- run AFTER you have switched this PC
into the PLC's network (i.e. once this PC has an address in 192.168.5.0/24).

What it does
    Runs a sequence of read-only checks, from the physical layer up to a real
    S7comm session, and then prints -- and saves -- a report that says, in plain
    terms, WHICH of the project's tools you can use right now and which you
    cannot, with the reason for each. It changes nothing on the PLC and nothing
    on this PC; every step is a lookup or a read.

    Layers it checks, bottom to top:
      1. Python + the three libraries the tools need (pnio-dcp, python-snap7, psutil)
      2. Npcap (needed for layer-2 discovery)                         [Windows]
      3. This PC's own IP addresses -- is one of them in the PLC's subnet?
      4. PROFINET DCP: can we see the PLC by its MAC on the wire?      (works cross-subnet)
      5. ARP: does the PLC's IP answer on the local segment?
      6. ICMP ping                                                    (informational)
      7. TCP 102 (S7comm port) open?
      8. S7 session: connect, CPU state, order code, firmware, PDU
      9. Process image: read the I and Q bytes (current channel states)

    From those results it builds a capability matrix for the repo's scripts
    (discovery, get_plc_info, read_states, send_program/blink_test, setIP/*).

Needs nothing but this repo's requirements (pip install -r requirements.txt).
No internet. No Administrator rights, unless Npcap was installed restricted to
administrators (then the DCP step needs an elevated terminal).

Usage:
    python scripts/diagnostics/plc_diagnostics.py
    python scripts/diagnostics/plc_diagnostics.py --ip 192.168.5.70 --mac 00:1c:06:19:5d:35
    python scripts/diagnostics/plc_diagnostics.py --no-ping --out my_report.md
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import ipaddress
import os
import platform
import re
import socket
import struct
import subprocess
import sys

# --- Defaults for this lab's PLC (override on the command line) ----------
PLC_IP = "192.168.5.70"                 # the PLC's fixed IP (locked by its TIA project)
PLC_MAC = "00:1c:06:19:5d:35"           # the PLC, identified on the wire by its MAC
S7_PORT, S7_RACK, S7_SLOT = 102, 0, 1   # S7-1200/1500 always rack 0, slot 1
DCP_DISCOVERY_TIMEOUT = 3.0             # seconds to collect DCP answers per adapter
# --------------------------------------------------------------------------

# Status tags. OK = works; FAIL = a tool depends on this and it is broken;
# WARN = works but with a caveat; SKIP = couldn't test it here; INFO = just a fact.
OK, FAIL, WARN, SKIP, INFO = "OK", "FAIL", "WARN", "SKIP", "INFO"


class Check:
    """One diagnostic step's outcome: a status, a one-line headline, and detail lines."""

    def __init__(self, title: str):
        self.title = title
        self.status = INFO
        self.headline = ""
        self.lines: list[str] = []

    def set(self, status: str, headline: str) -> "Check":
        self.status, self.headline = status, headline
        return self

    def add(self, line: str) -> "Check":
        self.lines.append(line)
        return self


# ---------------------------------------------------------------------------
# Small, dependency-free network helpers (inlined so this script still runs and
# reports even when pnio-dcp / snap7 / psutil are missing or broken).
# ---------------------------------------------------------------------------
def normalize_mac(text: str) -> str:
    digits = re.sub(r"[:\-.]", "", text.strip()).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", digits):
        raise ValueError(f"Not a MAC address: {text!r}")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def default_route_ip() -> str | None:
    """Local IP the OS would use toward the internet (route lookup only; nothing is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 1))
            return s.getsockname()[0]
    except OSError:
        return None


def local_ipv4s() -> list[tuple[str, str, str]]:
    """[(adapter, ip, netmask)] for every up, non-loopback IPv4 address.

    Uses psutil when present; falls back to hostname lookup (no netmasks) otherwise.
    """
    try:
        import psutil
    except ImportError:
        out = []
        seen = set()
        for ip in {default_route_ip(), *_hostname_ips()} - {None}:
            if ip and ip not in seen:
                seen.add(ip)
                out.append(("(unknown)", ip, "255.255.255.0"))  # mask unknown without psutil
        return out

    stats = psutil.net_if_stats()
    found = []
    for name, addrs in psutil.net_if_addrs().items():
        if name not in stats or not stats[name].isup:
            continue
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                found.append((name, a.address, a.netmask or "255.255.255.0"))
    return found


def _hostname_ips() -> set[str]:
    try:
        return {ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")}
    except OSError:
        return set()


def arp_owner(ip: str, src_ip: str | None) -> str | None:
    """MAC that answers ARP for `ip` ('' = nobody answered, None = check unavailable).

    Every powered device answers ARP for its own address, even one whose firewall
    drops ping -- so this is the most reliable "is it there?" test on the segment.
    """
    if sys.platform != "win32":
        return None
    try:
        send_arp = ctypes.WinDLL("iphlpapi").SendARP
    except OSError:
        return None
    send_arp.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    send_arp.restype = ctypes.c_uint32

    def to_ipaddr(text: str) -> int:
        return struct.unpack("<I", socket.inet_aton(text))[0]

    mac = (ctypes.c_ubyte * 8)()
    mac_len = ctypes.c_ulong(len(mac))
    rc = send_arp(to_ipaddr(ip), to_ipaddr(src_ip or "0.0.0.0"), mac, ctypes.byref(mac_len))
    if rc == 0 and mac_len.value == 6:
        return ":".join(f"{b:02x}" for b in mac[:6])
    if rc in (31, 67):  # no ARP reply
        return ""
    return None


def tcp_open(ip: str, port: int = S7_PORT, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def _decode_console(data: bytes) -> str:
    """Decode bytes a Windows console tool printed, trying the likely code pages
    in turn (German consoles use cp850, not UTF-8 or cp1252)."""
    for enc in ("utf-8", "cp850", "cp1252"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("cp1252", errors="replace")


def icmp_ping(ip: str) -> tuple[bool, str]:
    """One ICMP echo. Returns (reachable, first useful output line).

    Decodes the output ourselves with errors='replace': `ping` prints in the
    console's OEM code page (and in the user's language), which the default
    text decoder chokes on -- e.g. German Windows emits bytes cp1252 can't map.
    """
    cmd = (["ping", "-n", "1", "-w", "1500", ip] if sys.platform == "win32"
           else ["ping", "-c", "1", "-W", "2", ip])
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"ping could not run ({exc})"
    text = _decode_console(proc.stdout or b"")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    # Only surface a genuine reply line (it carries "TTL=" in every language);
    # skip ping's localized banner, which adds nothing and varies by OS language.
    line = next((ln for ln in lines if "ttl=" in ln.lower()), "")
    return proc.returncode == 0, line


def in_same_subnet(local_ip: str, local_mask: str, plc_ip: str) -> bool:
    """True if a host at local_ip/local_mask would route to plc_ip directly (no gateway)."""
    try:
        net = ipaddress.IPv4Interface(f"{local_ip}/{local_mask}").network
        return ipaddress.IPv4Address(plc_ip) in net
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------
def check_python() -> Check:
    c = Check("Python & platform")
    c.set(INFO, f"Python {platform.python_version()} on {platform.system()} {platform.release()}")
    c.add(f"Executable : {sys.executable}")
    c.add(f"Machine    : {platform.machine()}")
    return c


def check_dependencies() -> tuple[Check, dict]:
    """Report the three libraries the tools need; record which are importable."""
    c = Check("Required Python libraries")
    present = {}
    wanted = [
        ("pnio_dcp", "pnio-dcp", "layer-2 discovery by MAC (Mac2IP/*)"),
        ("snap7", "python-snap7", "all S7comm tools (plc_info, program_io/*)"),
        ("psutil", "psutil", "listing this PC's network adapters"),
    ]
    missing = []
    for module, pip_name, used_for in wanted:
        try:
            mod = __import__(module)
            ver = getattr(mod, "__version__", "?")
            present[module] = True
            c.add(f"{pip_name:14} {ver:10} present  -> {used_for}")
        except ImportError:
            present[module] = False
            missing.append(pip_name)
            c.add(f"{pip_name:14} {'--':10} MISSING  -> blocks {used_for}")
    if missing:
        c.set(WARN, f"Missing: {', '.join(missing)}  (pip install -r requirements.txt)")
    else:
        c.set(OK, "pnio-dcp, python-snap7 and psutil are all installed")
    return c, present


def check_npcap() -> Check:
    c = Check("Npcap (needed for DCP discovery)")
    if sys.platform != "win32":
        return c.set(SKIP, "not Windows -- Npcap not applicable")
    sysdir = os.environ.get("SystemRoot", r"C:\Windows") + r"\System32"
    dll = os.path.join(sysdir, "wpcap.dll")
    npcap_dir = os.path.join(sysdir, "Npcap", "wpcap.dll")
    if os.path.exists(dll) or os.path.exists(npcap_dir):
        c.set(OK, "Npcap is installed (wpcap.dll found)")
        c.add(f"Found: {dll if os.path.exists(dll) else npcap_dir}")
    else:
        c.set(WARN, "Npcap not detected -- layer-2 discovery (Mac2IP/*) will fail")
        c.add("Install Npcap from https://npcap.com (tick 'WinPcap API-compatible mode').")
    return c


def check_local_network(plc_ip: str) -> tuple[Check, bool, str | None]:
    """List this PC's IPs; decide whether one of them is in the PLC's subnet."""
    c = Check("This PC's network addresses")
    route_ip = default_route_ip()
    addrs = local_ipv4s()
    if not addrs:
        c.set(FAIL, "No usable IPv4 address on this PC")
        return c, False, None
    in_subnet = False
    subnet_ip = None
    for name, ip, mask in addrs:
        tags = []
        if ip == route_ip:
            tags.append("default route / internet")
        if in_same_subnet(ip, mask, plc_ip):
            tags.append(f"SAME SUBNET as PLC {plc_ip}")
            in_subnet = True
            subnet_ip = ip
        suffix = ("  <- " + ", ".join(tags)) if tags else ""
        c.add(f"{name:22} {ip}/{mask}{suffix}")
    if in_subnet:
        c.set(OK, f"This PC has {subnet_ip}, in the PLC's subnet -- S7comm can work")
    else:
        c.set(FAIL, f"No address in the PLC's subnet ({plc_ip}) -- S7comm cannot reach it yet")
        c.add("Fix: give this PC an address in 192.168.5.0/24 (e.g. scripts/setIP/reach_plc.py),")
        c.add("     or set this adapter statically to 192.168.5.60 / 255.255.255.0.")
    return c, in_subnet, subnet_ip


def check_dcp(plc_mac: str, timeout: float) -> tuple[Check, dict | None]:
    """Layer-2 DCP Identify of the PLC by MAC. Works even across IP subnets."""
    c = Check("PROFINET DCP discovery (layer 2, by MAC)")
    try:
        from pnio_dcp import DCP, DcpTimeoutError
    except ImportError:
        return c.set(SKIP, "pnio-dcp not installed"), None

    interfaces = local_ipv4s()
    if not interfaces:
        return c.set(SKIP, "no local adapter to send DCP from"), None

    found = None
    seen_any = False
    errors = []
    for name, ip, _mask in interfaces:
        try:
            dcp = DCP(ip=ip)
            dcp.default_timeout = 0.5  # keep per-read waits short while scanning
            devices = dcp.identify_all(timeout=timeout)
        except Exception as exc:  # Npcap missing/denied, adapter without L2, etc.
            errors.append(f"{name} ({ip}): {type(exc).__name__}: {exc}")
            continue
        for d in devices:
            seen_any = True
            mark = ""
            if d.MAC.lower() == plc_mac:
                mark = "  <-- target PLC"
                found = {"mac": d.MAC, "ip": d.IP, "netmask": d.netmask,
                         "gateway": d.gateway, "name": d.name_of_station, "family": d.family,
                         "via": f"{name} ({ip})"}
            c.add(f"via {name:12} {(d.name_of_station or '(no name)'):18} MAC={d.MAC}  "
                  f"IP={d.IP or '(none)'}  mask={d.netmask or '-'}  gw={d.gateway or '-'}  "
                  f"{d.family}{mark}")

    if found:
        c.set(OK, f"PLC answered DCP: name '{found['name']}', reports IP {found['ip'] or '(none)'}")
    elif seen_any:
        c.set(WARN, f"PROFINET devices answered, but none with MAC {plc_mac}")
        c.add("The PLC may be powered off, on another switch, or have a different MAC (--mac).")
    elif errors:
        c.set(WARN, "DCP could not run on any adapter (Npcap / permissions?)")
        for e in errors:
            c.add(e)
    else:
        c.set(WARN, "No PROFINET device answered DCP on any adapter")
        c.add("Check the cable/switch; try an elevated terminal if Npcap is admin-restricted.")
    return c, found


def check_arp(plc_ip: str, src_ip: str | None, plc_mac: str) -> Check:
    c = Check(f"ARP reachability of {plc_ip}")
    owner = arp_owner(plc_ip, src_ip)
    if owner is None:
        return c.set(SKIP, "ARP check not available here (non-Windows or API error)")
    if owner == "":
        c.set(FAIL, f"{plc_ip} did not answer ARP -- not reachable at layer 3 from this PC")
        c.add("Either this PC is not in the PLC's subnet yet, or the device/cable is down.")
        return c
    c.add(f"{plc_ip} is answered by MAC {owner}")
    if owner.lower() == plc_mac:
        c.set(OK, f"{plc_ip} answers ARP and it is the expected PLC ({plc_mac})")
    else:
        c.set(WARN, f"{plc_ip} answers ARP, but with MAC {owner}, not the PLC's {plc_mac}")
        c.add("Another device may be using the PLC's IP, or the PLC's MAC differs (--mac).")
    return c


def check_ping(plc_ip: str, do_ping: bool) -> Check:
    c = Check(f"ICMP ping {plc_ip}")
    if not do_ping:
        return c.set(SKIP, "skipped (--no-ping)")
    ok, line = icmp_ping(plc_ip)
    if line:
        c.add(line)
    if ok:
        c.set(OK, f"{plc_ip} replies to ping")
    else:
        c.set(INFO, f"{plc_ip} did not reply to ping (many PLCs drop ICMP -- not conclusive)")
    return c


def check_tcp(plc_ip: str) -> tuple[Check, bool]:
    c = Check(f"S7comm port {plc_ip}:{S7_PORT}")
    ok = tcp_open(plc_ip, S7_PORT)
    if ok:
        c.set(OK, f"TCP {S7_PORT} is open -- S7comm tools can connect")
    else:
        c.set(FAIL, f"TCP {S7_PORT} is closed/unreachable -- no S7comm tool can connect")
        c.add("Needs this PC in the PLC's subnet AND the CPU powered on.")
    return c, ok


def _decode(field) -> str:
    raw = bytes(field) if isinstance(field, (bytes, bytearray)) else bytes(field.value)
    return raw.decode("ascii", errors="replace").strip()


def check_s7(plc_ip: str) -> tuple[Check, bool, str | None]:
    """Open a real S7 session and read identity/state. Returns (check, connected, cpu_state)."""
    c = Check("S7 session (identity & CPU state)")
    try:
        from snap7.client import Client
    except ImportError:
        return c.set(SKIP, "python-snap7 not installed"), False, None

    client = Client()
    cpu_state = None
    try:
        client.connect(plc_ip, S7_RACK, S7_SLOT, S7_PORT)
    except Exception as exc:
        c.set(FAIL, f"S7 connect to {plc_ip} failed ({exc})")
        c.add("If TCP 102 was open, something may already hold the connection (e.g. TIA Portal).")
        return c, False, None
    if not client.get_connected():
        return c.set(FAIL, "socket opened but the S7 session did not establish"), False, None

    try:
        try:
            cpu_state = str(client.get_cpu_state())
            c.add(f"CPU state     : {cpu_state}")
        except Exception as exc:
            c.add(f"CPU state     : unavailable ({exc})")
        try:
            info = client.get_cpu_info()
            c.add(f"Module type   : {_decode(info.ModuleTypeName)}")
            c.add(f"Module name   : {_decode(info.ModuleName)}")
            c.add(f"Serial number : {_decode(info.SerialNumber)}")
        except Exception as exc:
            c.add(f"CPU info      : unavailable ({exc})")
        try:
            order = client.get_order_code()
            c.add(f"Order number  : {_decode(order.OrderCode)}")
            c.add(f"Firmware      : V{order.V1}.{order.V2}.{order.V3}")
        except Exception as exc:
            c.add(f"Order code    : unavailable ({exc})")
        try:
            cp = client.get_cp_info()
            c.add(f"Max PDU length: {cp.MaxPduLength}")
            c.add(f"Max connects  : {cp.MaxConnections}")
        except Exception as exc:
            c.add(f"CP info       : unavailable ({exc})")
        c.set(OK, f"S7 session established with {plc_ip}")
    finally:
        try:
            client.disconnect()
        except Exception:
            pass
    return c, True, cpu_state


def check_io(plc_ip: str) -> tuple[Check, bool]:
    """Read the digital input (I) and output (Q) process image. Read-only."""
    c = Check("Process image read (inputs I, outputs Q)")
    try:
        from snap7.client import Client
        from snap7.type import Area
    except ImportError:
        return c.set(SKIP, "python-snap7 not installed"), False

    def fmt(prefix: str, image: bytes) -> str:
        return " ".join(f"{prefix}{byte}.{b}={int(bool(image[byte] & (1 << b)))}"
                        for byte in range(len(image)) for b in range(8))

    client = Client()
    try:
        client.connect(plc_ip, S7_RACK, S7_SLOT, S7_PORT)
        inputs = client.read_area(Area.PE, 0, 0, 2)   # I0, I1
        outputs = client.read_area(Area.PA, 0, 0, 2)   # Q0, Q1
        c.add("Inputs : " + fmt("I", inputs))
        c.add("Outputs: " + fmt("Q", outputs))
        c.set(OK, "Read I0/I1 and Q0/Q1 successfully")
        return c, True
    except Exception as exc:
        c.set(WARN, f"Could not read the process image ({exc})")
        return c, False
    finally:
        try:
            client.disconnect()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Capability matrix: translate the raw checks into "which tool can I use now?"
# ---------------------------------------------------------------------------
def capability_matrix(deps: dict, dcp_found, in_subnet: bool, tcp_ok: bool,
                      s7_ok: bool, io_ok: bool, cpu_state: str | None) -> list[tuple[str, str, str, str]]:
    """Returns rows of (capability, script(s), status, reason)."""
    rows = []
    have_dcp = deps.get("pnio_dcp", False)
    have_snap7 = deps.get("snap7", False)
    running = bool(cpu_state and "run" in cpu_state.lower())

    # Discovery by MAC (layer 2) -- independent of IP subnet.
    if not have_dcp:
        rows.append(("Discover PLC by MAC", "Mac2IP/simple_discover_by_MAC.py, Mac2IP/discover_by_MAC.py",
                     FAIL, "pnio-dcp not installed"))
    elif dcp_found:
        rows.append(("Discover PLC by MAC", "Mac2IP/simple_discover_by_MAC.py, Mac2IP/discover_by_MAC.py",
                     OK, "PLC answered DCP on the wire"))
    else:
        rows.append(("Discover PLC by MAC", "Mac2IP/simple_discover_by_MAC.py, Mac2IP/discover_by_MAC.py",
                     WARN, "library OK, but the PLC did not answer DCP (see that check)"))

    # Read identity.
    rows.append(("Read PLC identity", "plc_info/get_plc_info.py",
                 OK if s7_ok else FAIL,
                 "S7 session works" if s7_ok else
                 ("python-snap7 missing" if not have_snap7 else
                  "no S7 session" + ("" if in_subnet else " -- this PC is not in the PLC's subnet"))))

    # Read I/O states.
    rows.append(("Read I/O states", "program_io/read_states.py",
                 OK if io_ok else (FAIL if have_snap7 else FAIL),
                 "process image read OK" if io_ok else
                 ("python-snap7 missing" if not have_snap7 else "no S7 session / read failed")))

    # Drive outputs.
    if not s7_ok:
        drive_status, drive_reason = FAIL, ("python-snap7 missing" if not have_snap7 else "no S7 session")
    elif running:
        drive_status, drive_reason = OK, "S7 session works and CPU is in RUN (outputs reach terminals)"
    else:
        drive_status, drive_reason = WARN, (f"S7 session works but CPU state is {cpu_state!r}; "
                                            "writes won't reach terminals unless the CPU is in RUN")
    rows.append(("Drive / overwrite outputs", "program_io/send_program.py, program_io/blink_test.py",
                 drive_status, drive_reason))

    # Reach the PLC from this PC (only relevant if not already in subnet).
    rows.append(("Put this PC in the PLC's subnet", "setIP/reach_plc.py",
                 INFO if in_subnet else WARN,
                 "already in the subnet -- not needed now" if in_subnet
                 else "needed: run it in an elevated terminal to add 192.168.5.60"))

    # Change the PLC's IP -- known-locked.
    rows.append(("Change the PLC's IP", "setIP/set_plc_ip.py",
                 FAIL, "PLC IP is locked by its TIA project (DCP code 03) -- not usable here"))
    return rows


def verdict(in_subnet: bool, tcp_ok: bool, s7_ok: bool, dcp_found) -> str:
    if s7_ok and tcp_ok:
        return "READY -- the PLC is fully reachable over S7comm; all read/drive tools can run."
    if in_subnet and not tcp_ok:
        return ("PC is in the subnet but the PLC's S7comm port is not answering -- check the CPU is "
                "powered on and nothing else holds the connection.")
    if not in_subnet and dcp_found:
        return ("The PLC is on the wire (DCP sees it) but this PC has no address in its subnet yet -- "
                "add 192.168.5.60 (setIP/reach_plc.py) and re-run this.")
    if not in_subnet:
        return "This PC is not in the PLC's subnet yet -- put it in 192.168.5.0/24, then re-run this."
    return "Partly reachable -- see the checks above for the blocking step."


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def render(checks: list[Check], rows, bottom_line: str, meta: dict) -> str:
    """Build the full report as Markdown (also fine to read as plain text)."""
    lines = []
    lines.append("# PLC diagnostics report")
    lines.append("")
    lines.append(f"- Generated : {meta['when']}")
    lines.append(f"- PLC target: {meta['plc_ip']}  (MAC {meta['plc_mac']})")
    lines.append(f"- From host : {meta['host']}  ({meta['python']})")
    lines.append("")
    lines.append(f"**Bottom line:** {bottom_line}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Check | Result |")
    lines.append("|---|---|")
    for c in checks:
        lines.append(f"| {c.title} | **{c.status}** -- {c.headline} |")
    lines.append("")

    lines.append("## What you can use right now")
    lines.append("")
    lines.append("| Capability | Script(s) | Status | Reason |")
    lines.append("|---|---|---|---|")
    for cap, script, status, reason in rows:
        lines.append(f"| {cap} | `{script}` | **{status}** | {reason} |")
    lines.append("")

    lines.append("## Detail")
    lines.append("")
    for c in checks:
        lines.append(f"### [{c.status}] {c.title}")
        lines.append(f"{c.headline}")
        if c.lines:
            lines.append("")
            lines.append("```")
            lines.extend(c.lines)
            lines.append("```")
        lines.append("")
    return "\n".join(lines)


def print_console(checks: list[Check], rows, bottom_line: str) -> None:
    width = 74
    print("=" * width)
    print("PLC DIAGNOSTICS")
    print("=" * width)
    for c in checks:
        print(f"[{c.status:4}] {c.title}: {c.headline}")
        for ln in c.lines:
            print(f"        {ln}")
    print("-" * width)
    print("WHAT YOU CAN USE RIGHT NOW")
    print("-" * width)
    for cap, script, status, reason in rows:
        print(f"[{status:4}] {cap}")
        print(f"        {script}")
        print(f"        -> {reason}")
    print("=" * width)
    print(f"BOTTOM LINE: {bottom_line}")
    print("=" * width)


# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only diagnostics of PLC reachability; prints and saves a report. "
                    "Run it once this PC is in the PLC's subnet.")
    parser.add_argument("--ip", default=PLC_IP, help=f"PLC IP (default: {PLC_IP})")
    parser.add_argument("--mac", default=PLC_MAC, help=f"PLC MAC (default: {PLC_MAC})")
    parser.add_argument("--timeout", type=float, default=DCP_DISCOVERY_TIMEOUT,
                        help=f"DCP discovery timeout in seconds (default: {DCP_DISCOVERY_TIMEOUT})")
    parser.add_argument("--no-ping", action="store_true", help="Skip the ICMP ping step.")
    parser.add_argument("--out", help="Where to save the report (default: a timestamped file "
                                       "under scripts/diagnostics/reports/).")
    parser.add_argument("--no-save", action="store_true", help="Print the report but don't save a file.")
    args = parser.parse_args()

    # Don't let a stray non-encodable character (e.g. from a localized `ping`)
    # crash the console output; the saved report is UTF-8 regardless.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass

    try:
        plc_mac = normalize_mac(args.mac)
    except ValueError as exc:
        print(f"Bad --mac: {exc}")
        return 2

    print(f"Running diagnostics against PLC {args.ip} (MAC {plc_mac})...\n")

    checks: list[Check] = []
    checks.append(check_python())
    dep_check, deps = check_dependencies()
    checks.append(dep_check)
    checks.append(check_npcap())

    net_check, in_subnet, subnet_ip = check_local_network(args.ip)
    checks.append(net_check)
    src_ip = subnet_ip or default_route_ip()

    dcp_check, dcp_found = check_dcp(plc_mac, args.timeout)
    checks.append(dcp_check)
    checks.append(check_arp(args.ip, src_ip, plc_mac))
    checks.append(check_ping(args.ip, do_ping=not args.no_ping))

    tcp_check, tcp_ok = check_tcp(args.ip)
    checks.append(tcp_check)

    cpu_state = None
    s7_ok = io_ok = False
    if tcp_ok:
        s7_check, s7_ok, cpu_state = check_s7(args.ip)
        checks.append(s7_check)
        io_check, io_ok = check_io(args.ip)
        checks.append(io_check)
    else:
        skip = Check("S7 session (identity & CPU state)").set(SKIP, "TCP 102 closed -- not attempting S7")
        checks.append(skip)
        checks.append(Check("Process image read (inputs I, outputs Q)").set(SKIP, "TCP 102 closed"))

    rows = capability_matrix(deps, dcp_found, in_subnet, tcp_ok, s7_ok, io_ok, cpu_state)
    bottom_line = verdict(in_subnet, tcp_ok, s7_ok, dcp_found)

    print_console(checks, rows, bottom_line)

    if not args.no_save:
        when = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        meta = {"when": when, "plc_ip": args.ip, "plc_mac": plc_mac,
                "host": socket.gethostname(),
                "python": f"Python {platform.python_version()} on {platform.system()}"}
        report = render(checks, rows, bottom_line, meta)
        if args.out:
            out_path = os.path.abspath(args.out)
        else:
            reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
            os.makedirs(reports_dir, exist_ok=True)
            stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            out_path = os.path.join(reports_dir, f"plc_diagnostics_{stamp}.md")
        try:
            with open(out_path, "w", encoding="utf-8") as handle:
                handle.write(report)
            print(f"\nReport saved to: {out_path}")
        except OSError as exc:
            print(f"\nCould not save the report ({exc}).")

    # Exit code: 0 if the PLC is fully reachable over S7comm, else 1 (handy in scripts).
    return 0 if (s7_ok and tcp_ok) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
