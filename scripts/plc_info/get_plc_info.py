#!/usr/bin/env python3
"""
Connect to a Siemens S7 PLC and print its product/identification details
(order number, firmware version, module name, serial number, CPU state, ...).

Requirements:
    pip install python-snap7

Usage:
    1. Fill in PLC_IP / RACK / SLOT below (see assign_plc_ip.py if the PLC's
       IP isn't set yet, or lan_scanner.py / big_range_scanner.py to find it).
    2. Run: python get_plc_info.py
"""

import sys

from snap7.client import Client
from snap7.error import S7Error

# --- Configuration -------------------------------------------------------
PLC_IP = "192.168.5.70"   # the PLC's IP address
RACK = 0                  # 0 for S7-1200/1500; S7-300/400 CPUs are usually rack 0 too
SLOT = 1                  # 1 for S7-1200/1500; S7-300/400 CPUs are usually slot 2
TCP_PORT = 102            # S7comm port
# --------------------------------------------------------------------------


def decode(field) -> str:
    """Decode a char-array struct field to text.

    ctypes exposes c_char array fields as plain bytes when read from a
    Structure instance (not as an object with a .value attribute), but
    fall back to .value in case a raw ctypes array is passed instead.
    """
    raw = bytes(field) if isinstance(field, (bytes, bytearray)) else bytes(field.value)
    return raw.decode("ascii", errors="replace").strip()


def print_cpu_info(client: Client):
    info = client.get_cpu_info()
    print("CPU identification (SZL 0x001C):")
    print(f"  Module type   : {decode(info.ModuleTypeName)}")
    print(f"  Module name   : {decode(info.ModuleName)}")
    print(f"  Serial number : {decode(info.SerialNumber)}")
    print(f"  AS name       : {decode(info.ASName)}")
    print(f"  Copyright     : {decode(info.Copyright)}")


def print_order_code(client: Client):
    order = client.get_order_code()
    print("\nOrder code / firmware version (SZL 0x0011):")
    print(f"  Order number  : {decode(order.OrderCode)}")
    print(f"  Firmware      : V{order.V1}.{order.V2}.{order.V3}")


def print_cp_info(client: Client):
    cp = client.get_cp_info()
    print("\nCommunication processor info (SZL 0x0131):")
    print(f"  Max PDU length : {cp.MaxPduLength}")
    print(f"  Max connections: {cp.MaxConnections}")
    print(f"  Max MPI rate   : {cp.MaxMpiRate}")
    print(f"  Max bus rate   : {cp.MaxBusRate}")


def print_cpu_state(client: Client):
    state = client.get_cpu_state()
    print(f"\nCPU state       : {state}")


def main():
    client = Client()
    print(f"Connecting to {PLC_IP} (rack {RACK}, slot {SLOT}, port {TCP_PORT})...")
    try:
        client.connect(PLC_IP, RACK, SLOT, TCP_PORT)
    except (S7Error, RuntimeError) as exc:
        print(f"Connection failed: {exc}")
        print("Check the IP/rack/slot, that the PLC is reachable, and that")
        print("nothing else (e.g. TIA Portal) is already using the connection.")
        sys.exit(1)

    if not client.get_connected():
        print("Connection could not be established.")
        sys.exit(1)

    print("Connected.\n")
    try:
        for step in (print_cpu_info, print_order_code, print_cp_info, print_cpu_state):
            try:
                step(client)
            except (S7Error, RuntimeError) as exc:
                print(f"{step.__name__.replace('print_', '').replace('_', ' ')}: "
                      f"not available on this device ({exc})")
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
