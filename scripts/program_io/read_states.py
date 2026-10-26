#!/usr/bin/env python3
"""
Read and print the current digital I/O state of the PLC -- all inputs (I0.x,
I1.x) and outputs (Q0.x, Q1.x). Read-only: it changes nothing on the PLC.

Use it to verify what send_program.py / blink_test.py actually did.

Requirements:
    pip install python-snap7

Usage:
    python read_states.py                       read once and print
    python read_states.py --watch               poll forever (Ctrl+C to stop)
    python read_states.py --watch --interval 0.5
    python read_states.py --ip 192.168.2.10
"""

from __future__ import annotations

import argparse
import sys
import time

import plc_io
from snap7.error import S7Error


def print_states(client) -> None:
    inputs = plc_io.read_inputs(client)
    outputs = plc_io.read_outputs(client)
    print("Inputs :", plc_io.format_image("I", inputs))
    print("Outputs:", plc_io.format_image("Q", outputs))


def main() -> int:
    parser = argparse.ArgumentParser(description="Read the PLC's digital input/output states.")
    parser.add_argument("--ip", default=plc_io.DEFAULT_IP, help=f"PLC IP (default: {plc_io.DEFAULT_IP})")
    parser.add_argument("--watch", action="store_true", help="Keep polling until Ctrl+C.")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between polls with --watch (default: 1.0)")
    args = parser.parse_args()

    print(f"Connecting to {args.ip} (rack {plc_io.RACK}, slot {plc_io.SLOT})...")
    try:
        client = plc_io.connect(args.ip)
    except plc_io.PlcUnreachable as exc:
        print(exc)
        return 1
    except (S7Error, RuntimeError) as exc:
        print(f"Connection failed: {exc}")
        return 1
    print(f"Connected. CPU state: {client.get_cpu_state()}\n")

    try:
        if not args.watch:
            print_states(client)
        else:
            while True:
                print(time.strftime("%H:%M:%S"), end="  ")
                print_states(client)
                print()
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    except (S7Error, RuntimeError) as exc:
        print(f"Read failed: {exc}")
        return 1
    finally:
        client.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(main())
