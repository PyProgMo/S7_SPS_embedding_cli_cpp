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


def connect(ip: str = DEFAULT_IP, *, preflight: bool = True) -> Client:
    """Open an S7 connection (rack 0, slot 1). Raises PlcUnreachable with
    actionable guidance if the S7comm port can't even be reached."""
    if preflight:
        try:
            with socket.create_connection((ip, TCP_PORT), timeout=3):
                pass
        except OSError as exc:
            raise PlcUnreachable(
                f"Cannot reach the PLC at {ip}:{TCP_PORT} ({exc}).\n"
                f"  - Is this PC in the same IP subnet as the PLC? Run\n"
                f"      python scripts/Mac2IP/simple_discover_by_MAC.py\n"
                f"    to see the PLC's current IP (DCP works across subnets, S7comm does not).\n"
                f"  - If it is in a different subnet, move it with scripts/Mac2IP/discover_by_MAC.py --auto,\n"
                f"    or give this PC a second IP in the PLC's subnet."
            ) from exc

    client = Client()
    client.connect(ip, RACK, SLOT, TCP_PORT)
    if not client.get_connected():
        raise PlcUnreachable(f"Connected socket to {ip} but the S7 session did not establish.")
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
