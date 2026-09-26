#!/usr/bin/env python3
"""
Set a single PLC output to True, hold it for a fixed duration, then read it
back to confirm it actually stuck.

This does NOT compile or download a ladder/SCL program -- python-snap7 has
no compiler, that only exists inside TIA Portal. Instead this drives the
output directly over S7comm using process-image writes (the standard way
external tools force/test I/O), and re-asserts the bit periodically for the
whole hold so nothing else running on the CPU can silently override it.

SAFETY: this physically energizes the chosen output for the entire hold
duration. Make sure nothing hazardous is wired to it before running.

Requirements:
    pip install python-snap7

Usage:
    1. Fill in PLC_IP / RACK / SLOT / OUTPUT_BYTE / OUTPUT_BIT below.
    2. Run: python run_output_test.py
    3. Ctrl+C at any point safely resets the output before exiting.
"""

import sys
import time
from datetime import datetime, timedelta

from snap7.client import Client
from snap7.error import S7Error
from snap7.type import Area

# --- Configuration -------------------------------------------------------
PLC_IP = "192.168.5.70"
RACK = 0
SLOT = 1
TCP_PORT = 102

OUTPUT_BYTE = 0    # QB0
OUTPUT_BIT = 0     # Q0.0

HOLD_DURATION_SECONDS = 10 * 60   # 10 minutes
REASSERT_INTERVAL_SECONDS = 2      # re-write the bit this often during the hold
STATUS_INTERVAL_SECONDS = 30       # print a progress line this often
RESET_AFTER_HOLD = True            # turn the output back off once the test finishes
# --------------------------------------------------------------------------


def ensure_running(client: Client):
    state = client.get_cpu_state()
    print(f"CPU state: {state}")
    if "run" not in state.lower():
        print("CPU is not running -- attempting a hot start...")
        client.plc_hot_start()
        time.sleep(2)
        state = client.get_cpu_state()
        print(f"CPU state after start attempt: {state}")
        if "run" not in state.lower():
            print("CPU did not enter RUN. Outputs cannot be driven from STOP.")
            print("This CPU likely has no valid program/hardware config loaded yet --")
            print("that one-time setup (even an empty OB1) has to be downloaded from TIA Portal first.")
            sys.exit(1)


def read_bit(client: Client) -> bool:
    data = client.read_area(Area.PA, 0, OUTPUT_BYTE, 1)
    return bool(data[0] & (1 << OUTPUT_BIT))


def set_bit(client: Client, value: bool):
    client.force_bit(Area.PA, OUTPUT_BYTE, OUTPUT_BIT, value)


def main():
    client = Client()
    print(f"Connecting to {PLC_IP} (rack {RACK}, slot {SLOT}, port {TCP_PORT})...")
    try:
        client.connect(PLC_IP, RACK, SLOT, TCP_PORT)
    except (S7Error, RuntimeError) as exc:
        print(f"Connection failed: {exc}")
        sys.exit(1)

    if not client.get_connected():
        print("Connection could not be established.")
        sys.exit(1)
    print("Connected.\n")

    try:
        ensure_running(client)

        print(f"\nSetting Q{OUTPUT_BYTE}.{OUTPUT_BIT} = True, holding for "
              f"{HOLD_DURATION_SECONDS // 60} minute(s)...")
        end_time = datetime.now() + timedelta(seconds=HOLD_DURATION_SECONDS)
        last_status = time.monotonic()

        while datetime.now() < end_time:
            set_bit(client, True)

            if time.monotonic() - last_status >= STATUS_INTERVAL_SECONDS:
                remaining = (end_time - datetime.now()).total_seconds()
                print(f"  Q{OUTPUT_BYTE}.{OUTPUT_BIT} = {read_bit(client)}   "
                      f"({remaining:.0f}s remaining)")
                last_status = time.monotonic()

            time.sleep(REASSERT_INTERVAL_SECONDS)

        final_state = read_bit(client)
        print(f"\nHold complete. Q{OUTPUT_BYTE}.{OUTPUT_BIT} = {final_state}")
        if final_state:
            print("Output confirmed True.")
        else:
            print("WARNING: output reads False -- check wiring/output module, "
                  "or something else on the CPU is overriding it.")

        if RESET_AFTER_HOLD:
            set_bit(client, False)
            print(f"Reset Q{OUTPUT_BYTE}.{OUTPUT_BIT} back to False.")

    except (S7Error, RuntimeError) as exc:
        print(f"Error during test: {exc}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted -- resetting output before exit.")
        try:
            set_bit(client, False)
        except (S7Error, RuntimeError):
            pass
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
