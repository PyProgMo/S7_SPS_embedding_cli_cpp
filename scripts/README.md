# PLC helper scripts

Python helpers for talking to the lab's Siemens S7-1200 (CPU 1214C, order
`6ES7 214-1AG31-0XB0`) over PROFINET DCP and S7comm. They complement the C++
`SPScomm` app in [`../src`](../src).

## The one thing to know about this PLC

Its IP is **fixed at `192.168.5.70`** and **cannot be changed** by any tool here:
the TIA project has the PROFINET interface set to *"IP address is set in the
project"*, so every DCP Set-IP is refused with **code 03** (confirmed repeatedly),
and the CPU is access-protected (it even refuses some S7 info functions). Its
gateway is `0.0.0.0`, so it only answers devices **inside `192.168.5.0/24`**.

Therefore we don't move the PLC into our network -- we give **this PC** a second
address in the PLC's subnet and talk to the PLC from there, while keeping the
normal/internet address. That is what `setIP/reach_plc.py` does.

## Typical workflow

```
# 1. (Admin terminal) add 192.168.5.60 to this PC, kept alongside the internet IP
python scripts/setIP/reach_plc.py

# 2. Confirm what's reachable and get a saved report
python scripts/diagnostics/plc_diagnostics.py

# 3. Use the PLC
python scripts/plc_info/get_plc_info.py                       # identity / firmware
python scripts/program_io/read_states.py --watch              # live I and Q states
python scripts/program_io/blink_test.py                       # 10 s Q0.0 on/off test
python scripts/program_io/send_program.py                     # drive outputs from program.txt
```

The S7comm tools bind their socket to this PC's `192.168.5.x` address (see
`program_io/plc_io.py:connect`), so they always talk to the PLC from inside its
subnet and fail fast with guidance if this PC isn't in that subnet yet.

## What's here

| Folder / script | What it does |
|---|---|
| `setIP/reach_plc.py` | Add/remove a secondary `192.168.5.60/24` on this PC (netsh), kept next to DHCP so the internet stays up. Needs an elevated terminal. `--check`, `--dry-run`, `--remove`. |
| `diagnostics/plc_diagnostics.py` | Read-only health check from Python libs up to a live S7 session; prints and saves a report (into `diagnostics/reports/`, gitignored) of what is callable and what isn't. |
| `Mac2IP/simple_discover_by_MAC.py` | Minimal, dependency-light DCP discovery: list PROFINET devices and their IPs by MAC. Works across subnets (layer 2). |
| `plc_info/get_plc_info.py` | Connect over S7comm and print identity (order no., firmware, module, CPU state). |
| `program_io/plc_io.py` | Shared S7comm helpers: source-bound `connect()`, read/write the I/Q process image, parse `program.txt`. Drives outputs -- it does **not** flash CPU code (snap7 has no compiler). |
| `program_io/read_states.py` | Read and optionally `--watch` the input (I) and output (Q) bytes. |
| `program_io/blink_test.py` | Toggle `Q0.0` on/off each second for 10 s, reading back each step; resets outputs on exit. |
| `program_io/send_program.py` | Overwrite the whole output image from a channel file (default `../program.txt`) and hold it. |

## Requirements

```
pip install -r ../requirements.txt     # pnio-dcp, python-snap7, psutil
```
Windows: Npcap installed (for the DCP/discovery scripts). An elevated terminal is
only needed for `reach_plc.py`, or for discovery if Npcap was installed
admin-restricted.
