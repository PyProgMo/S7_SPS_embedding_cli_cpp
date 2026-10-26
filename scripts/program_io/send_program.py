#!/usr/bin/env python3
"""
Send a channel-state program to the PLC and overwrite its current output state.

Reads a program file (same format as the project's program.txt -- lines like
'Q0.0=True'), connects over S7comm, writes the WHOLE output image (channels not
listed default to False), and -- unless --once -- keeps re-asserting it so the
CPU's own scan cycle can't quietly override it. Each pass reads the outputs back
and reports any bit that doesn't hold.

See plc_io.py for why this drives outputs rather than flashing CPU code, and why
a bit may refuse to hold (CPU in STOP, or its program driving the same output).

SAFETY: this physically energizes the PLC's outputs. Make sure nothing hazardous
is wired to them before running.

Requirements:
    pip install python-snap7

Usage:
    python send_program.py                          hold program.txt until Ctrl+C
    python send_program.py --duration 30            hold it for 30 seconds
    python send_program.py --once                   write it a single time and exit
    python send_program.py --file my_program.txt
    python send_program.py --ip 192.168.2.10 --yes
"""

from __future__ import annotations

import argparse
import os
import sys
import time

import plc_io
from snap7.error import S7Error

# program.txt lives at the repo root, two levels up from this script.
DEFAULT_PROGRAM = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "program.txt"))
REASSERT_INTERVAL = 0.2   # seconds between re-writes while holding
STATUS_INTERVAL = 2.0     # seconds between read-back status lines


def confirm(prompt: str) -> bool:
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def assert_once(client, image: bytearray) -> tuple[bytearray, list[str]]:
    """Write the image, read it back, and return (read-back, list of mismatched channel names)."""
    plc_io.write_outputs(client, image)
    actual = plc_io.read_outputs(client)
    mismatches = [f"Q{byte}.{b}" for byte in range(len(image)) for b in range(8)
                  if plc_io.bit(actual, byte, b) != plc_io.bit(image, byte, b)]
    return actual, mismatches


def main() -> int:
    parser = argparse.ArgumentParser(description="Overwrite the PLC's outputs from a channel-state program file.")
    parser.add_argument("--file", default=DEFAULT_PROGRAM, help="Program file (default: the project's program.txt)")
    parser.add_argument("--ip", default=plc_io.DEFAULT_IP, help=f"PLC IP (default: {plc_io.DEFAULT_IP})")
    parser.add_argument("--duration", type=float, default=0.0,
                        help="Hold for this many seconds (default: 0 = until Ctrl+C). Ignored with --once.")
    parser.add_argument("--once", action="store_true", help="Write the program a single time and exit.")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip the confirmation prompt.")
    args = parser.parse_args()

    try:
        channels = plc_io.parse_channel_program(args.file)
    except (OSError, ValueError) as exc:
        print(f"Could not load program: {exc}")
        return 1
    image = plc_io.program_to_output_image(channels)

    print(f"Program from {args.file}:")
    print("  ", plc_io.format_image("Q", image))
    print("(channels not listed in the file are forced to 0)")

    if not args.yes:
        mode = "write it once" if args.once else (
            f"hold it for {args.duration:.0f}s" if args.duration else "hold it until you press Ctrl+C")
        if not confirm(f"\nThis drives the PLC's physical outputs. Overwrite them and {mode}? [y/N] "):
            print("Aborted -- nothing was sent.")
            return 1

    print(f"\nConnecting to {args.ip} (rack {plc_io.RACK}, slot {plc_io.SLOT})...")
    try:
        client = plc_io.connect(args.ip)
    except plc_io.PlcUnreachable as exc:
        print(exc)
        return 1
    except (S7Error, RuntimeError) as exc:
        print(f"Connection failed: {exc}")
        return 1

    state = client.get_cpu_state()
    print(f"Connected. CPU state: {state}")
    if "run" not in state.lower():
        print("WARNING: the CPU is not in RUN -- its output drivers are off, so these writes will not "
              "reach the physical terminals until it is running.")

    try:
        actual, mismatches = assert_once(client, image)
        print("\nWrote program. Read-back:", plc_io.format_image("Q", actual))
        if mismatches:
            print("  did not hold:", ", ".join(mismatches),
                  "(CPU in STOP, or its own program is driving these outputs)")

        if not args.once:
            deadline = time.monotonic() + args.duration if args.duration else None
            last_status = time.monotonic()
            print("\nHolding (Ctrl+C to stop)..." if deadline is None
                  else f"\nHolding for {args.duration:.0f}s (Ctrl+C to stop)...")
            while deadline is None or time.monotonic() < deadline:
                actual, mismatches = assert_once(client, image)
                if time.monotonic() - last_status >= STATUS_INTERVAL:
                    note = "all holding" if not mismatches else "not holding: " + ", ".join(mismatches)
                    print(f"  {time.strftime('%H:%M:%S')}  {note}")
                    last_status = time.monotonic()
                time.sleep(REASSERT_INTERVAL)
            print("\nDuration elapsed. Outputs left as written.")
    except KeyboardInterrupt:
        print("\nStopped. Outputs left as last written (run read_states.py to check, "
              "or blink_test.py / a program of all-False to clear them).")
    except (S7Error, RuntimeError) as exc:
        print(f"Error while sending: {exc}")
        return 1
    finally:
        client.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
