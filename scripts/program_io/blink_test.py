#!/usr/bin/env python3
"""
Test program: for 10 seconds, hold every output False except Q0.0, which
alternates each second -- on, off, on, off, ... (1 Hz). Every second it reads
the whole output image back and prints it, so the run verifies itself. All
outputs are reset to False on exit (normal end or Ctrl+C).

This drives outputs over S7comm the same way send_program.py does; see plc_io.py
for why a bit might not hold (CPU in STOP, or its own program driving Q0.0).

SAFETY: this physically energizes Q0.0 once per second. Make sure nothing
hazardous is wired to it before running.

Requirements:
    pip install python-snap7

Usage:
    python blink_test.py
    python blink_test.py --duration 10 --period 1.0 --ip 192.168.2.10 --yes
"""

from __future__ import annotations

import argparse
import sys
import time

import plc_io
from snap7.error import S7Error

BLINK_BYTE, BLINK_BIT = 0, 0   # Q0.0
REASSERT_INTERVAL = 0.2        # re-write within each step so a scan cycle can't flip it


def confirm(prompt: str) -> bool:
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def image_for(on: bool) -> bytearray:
    """All outputs False except Q0.0 = `on`."""
    image = bytearray(plc_io.OUTPUT_BYTES)
    if on:
        image[BLINK_BYTE] |= 1 << BLINK_BIT
    return image


def run_blink(client, duration: float, period: float) -> bool:
    """Run the blink pattern, printing a read-back each step. Returns True if every
    step's read-back matched what was written."""
    steps = max(1, round(duration / period))
    all_ok = True
    print(f"\nBlinking Q{BLINK_BYTE}.{BLINK_BIT} for {steps} step(s) of {period:.1f}s "
          f"(all other outputs held False):")
    for step in range(steps):
        want_on = (step % 2 == 0)      # step 0 = on, 1 = off, 2 = on, ...
        image = image_for(want_on)
        step_end = time.monotonic() + period
        while True:
            plc_io.write_outputs(client, image)
            if time.monotonic() >= step_end - REASSERT_INTERVAL:
                break
            time.sleep(REASSERT_INTERVAL)

        actual = plc_io.read_outputs(client)
        got_on = plc_io.bit(actual, BLINK_BYTE, BLINK_BIT)
        ok = (got_on == want_on)
        all_ok = all_ok and ok
        print(f"  t={step * period:4.1f}s  want Q{BLINK_BYTE}.{BLINK_BIT}={int(want_on)}  "
              f"read {plc_io.format_image('Q', actual)}  {'OK' if ok else 'MISMATCH'}")
    return all_ok


def main() -> int:
    parser = argparse.ArgumentParser(description="Blink Q0.0 at 1 Hz for 10 s as a self-verifying PLC output test.")
    parser.add_argument("--ip", default=plc_io.DEFAULT_IP, help=f"PLC IP (default: {plc_io.DEFAULT_IP})")
    parser.add_argument("--duration", type=float, default=10.0, help="Total seconds (default: 10)")
    parser.add_argument("--period", type=float, default=1.0, help="Seconds per on/off step (default: 1)")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip the confirmation prompt.")
    args = parser.parse_args()

    if not args.yes:
        if not confirm(f"This blinks the PLC's physical output Q{BLINK_BYTE}.{BLINK_BIT} for "
                       f"{args.duration:.0f}s. Continue? [y/N] "):
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
        print("WARNING: the CPU is not in RUN -- its output drivers are off, so Q0.0 will not change "
              "physically and every step below will read MISMATCH.")

    ok = False
    try:
        ok = run_blink(client, args.duration, args.period)
        print("\nResult:", "all steps matched -- the output follows the blink pattern." if ok
              else "some steps did not match -- see MISMATCH lines above (likely the CPU's own program "
                   "driving Q0.0, or the CPU not in RUN).")
    except KeyboardInterrupt:
        print("\nInterrupted.")
    except (S7Error, RuntimeError) as exc:
        print(f"Error during blink test: {exc}")
    finally:
        try:
            plc_io.write_outputs(client, bytearray(plc_io.OUTPUT_BYTES))  # reset all outputs to False
            print("Reset all outputs to False.")
        except (S7Error, RuntimeError):
            pass
        client.disconnect()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
