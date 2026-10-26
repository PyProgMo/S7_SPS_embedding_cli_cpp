#!/usr/bin/env python3
"""
Shared helpers for talking to the S7 PLC over S7comm (python-snap7): connect,
read the digital I/O process image, parse a channel-state program file, and
write the output image.

IMPORTANT -- what "sending a program" means here:
    python-snap7 has NO compiler. It cannot replace the ladder/SCL user program
    that TIA Portal downloaded into the CPU; only TIA Portal can do that. What
    these scripts do instead is drive the OUTPUT process image (the Q bytes)
    over S7comm and re-assert it, which is the standard way an external tool
    overrides a PLC's outputs. So "overwrite the program on the PLC" means
    "take over its output channels", not "flash new CPU code".

    Consequences you will see in the read-backs:
      * If the CPU is in STOP, its output drivers are off -- nothing we write
        reaches the physical terminals.
      * If the CPU is in RUN and its own program drives the same Q bits, our
        write and its scan cycle fight each other; the read-back shows who won.
        An output nothing in the program touches is ours to hold freely.

Requirements:
    pip install python-snap7
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

from snap7.client import Client
from snap7.type import Area

# --- Fixed for this CPU (CPU 1214C DC/DC/DC onboard digital I/O) ----------
DEFAULT_IP = "192.168.5.70"   # matches the sibling scripts; override with --ip
RACK, SLOT, TCP_PORT = 0, 1, 102
OUTPUT_BYTES = 2              # Q0.x, Q1.x
INPUT_BYTES = 2              # I0.x, I1.x
# --------------------------------------------------------------------------

# One line of a channel-state program file: Q<byte>.<bit>=<True|False|1|0>
_CHANNEL_RE = re.compile(r"^\s*([Qq])\s*(\d+)\s*\.\s*(\d+)\s*=\s*(\S+)\s*$")
_TRUE = {"1", "true", "on", "high"}
_FALSE = {"0", "false", "off", "low"}


class PlcUnreachable(Exception):
    """The PLC's S7comm port could not be reached (wrong subnet, cable, CPU off)."""


@dataclass(frozen=True)
class Channel:
    byte: int
    bit: int
    value: bool

    @property
    def name(self) -> str:
        return f"Q{self.byte}.{self.bit}"


def parse_channel_program(path: str) -> list[Channel]:
    """Parse a channel-state program file (same format as the project's program.txt).

    Lines look like 'Q0.0=True'; blanks and '#' comments are ignored. Only
    outputs (Q) are writable, so only Q is accepted. Raises ValueError with the
    offending line number on anything malformed or out of range.
    """
    channels: list[Channel] = []
    seen: dict[tuple[int, int], int] = {}
    with open(path, encoding="utf-8") as handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            match = _CHANNEL_RE.match(line)
            if not match:
                raise ValueError(f"{path}:{lineno}: expected 'Q<byte>.<bit>=<True|False>', got {raw.strip()!r}")
            byte, bit = int(match.group(2)), int(match.group(3))
            token = match.group(4).lower()
            if token in _TRUE:
                value = True
            elif token in _FALSE:
                value = False
            else:
                raise ValueError(f"{path}:{lineno}: value must be True/False/1/0, got {match.group(4)!r}")
            if byte >= OUTPUT_BYTES or not 0 <= bit <= 7:
                raise ValueError(f"{path}:{lineno}: Q{byte}.{bit} is outside this CPU's outputs "
                                 f"(Q0.0-Q{OUTPUT_BYTES - 1}.7)")
            if (byte, bit) in seen:
                raise ValueError(f"{path}:{lineno}: Q{byte}.{bit} was already set on line {seen[(byte, bit)]}")
            seen[(byte, bit)] = lineno
            channels.append(Channel(byte, bit, value))
    if not channels:
        raise ValueError(f"{path}: no channels defined")
    return channels


def program_to_output_image(channels: list[Channel]) -> bytearray:
    """Build the full output image (all OUTPUT_BYTES bytes) from a program.

    Channels not listed default to False, so writing this image genuinely
    overwrites the whole output state, not just the bits that were mentioned.
    """
    image = bytearray(OUTPUT_BYTES)
    for ch in channels:
        if ch.value:
            image[ch.byte] |= 1 << ch.bit
    return image


def source_ip_for(dest_ip: str, prefix: int = 24) -> str | None:
    """This PC's own IPv4 address that sits in the same subnet as `dest_ip`, or None.

    Asks the OS which local address it would use to reach `dest_ip` (a UDP route
    lookup -- no packet is sent) and only accepts it when it genuinely shares
    `dest_ip`'s subnet, i.e. the PLC is directly reachable from that address.
    You cannot "pretend" to hold an address the machine doesn't have, so this is
    exactly the address reach_plc.py adds (e.g. 192.168.5.60) when it worked.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((dest_ip, 9))          # route lookup only; nothing is sent
            src = probe.getsockname()[0]
    except OSError:
        return None
    try:
        net = ipaddress.ip_network(f"{dest_ip}/{prefix}", strict=False)
        return src if ipaddress.ip_address(src) in net else None
    except ValueError:
        return None


def connect(ip: str = DEFAULT_IP, *, preflight: bool = True, source_ip: str | None = None) -> Client:
    """Open an S7 connection (rack 0, slot 1) to the PLC, FROM this PC's address in
    the PLC's subnet. Raises PlcUnreachable with actionable guidance otherwise.

    Why the source address matters here:
        The PLC's IP is fixed (locked by its TIA project) and its gateway is
        0.0.0.0, so it only answers devices inside its own subnet (192.168.5.0/24).
        This PC reaches it by holding a SECOND address in that subnet alongside its
        normal/internet address (see scripts/setIP/reach_plc.py). We bind the
        connection's source to that in-subnet address, so the traffic always leaves
        from the PLC's network -- the "behave as if this PC lived in the PLC's
        network" approach -- and so we fail fast, with a clear message, when this PC
        is not in that subnet yet (rather than hanging or sourcing from the wrong
        adapter). snap7 itself then routes the S7 session out the same interface,
        because 192.168.5.70 is directly connected on it.
    """
    src = source_ip or source_ip_for(ip)
    if src is None:
        raise PlcUnreachable(
            f"This PC has no address in the PLC's subnet, so it cannot reach {ip}.\n"
            f"  - Give it one (kept alongside your normal/internet address) with:\n"
            f"      python scripts/setIP/reach_plc.py\n"
            f"  - Check the PLC's current IP (DCP works across subnets, S7comm does not):\n"
            f"      python scripts/Mac2IP/simple_discover_by_MAC.py\n"
            f"  - Or pass the local address to use explicitly: connect(ip, source_ip=...)."
        )
    print(f"  Using this PC's {src} as the source (same subnet as the PLC at {ip}).")

    if preflight:
        try:
            with socket.create_connection((ip, TCP_PORT), timeout=3, source_address=(src, 0)):
                pass
        except OSError as exc:
            raise PlcUnreachable(
                f"This PC is in the PLC's subnet (as {src}) but {ip}:{TCP_PORT} did not answer ({exc}).\n"
                f"  - Is the PLC powered on and on the same switch?\n"
                f"  - Is anything else (e.g. TIA Portal) already holding the S7 connection?"
            ) from exc

    client = Client()
    client.connect(ip, RACK, SLOT, TCP_PORT)
    if not client.get_connected():
        raise PlcUnreachable(f"Reached {ip}:{TCP_PORT} from {src} but the S7 session did not establish.")
    return client


def read_outputs(client: Client) -> bytearray:
    return client.read_area(Area.PA, 0, 0, OUTPUT_BYTES)


def read_inputs(client: Client) -> bytearray:
    return client.read_area(Area.PE, 0, 0, INPUT_BYTES)


def write_outputs(client: Client, image: bytearray) -> None:
    """Overwrite the whole output image in one request."""
    client.write_area(Area.PA, 0, 0, bytearray(image))


def bit(image: bytes, byte: int, bit_index: int) -> bool:
    return bool(image[byte] & (1 << bit_index))


def format_image(prefix: str, image: bytes) -> str:
    """One-line rendering, e.g. 'Q0.0=1 Q0.1=0 ... Q1.7=0'."""
    return " ".join(f"{prefix}{byte}.{b}={int(bit(image, byte, b))}"
                     for byte in range(len(image)) for b in range(8))
