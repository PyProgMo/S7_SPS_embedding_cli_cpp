#!/usr/bin/env python3
"""Scan a /24 local network with ICMP pings and log the hosts that respond."""
import argparse
import concurrent.futures
import platform
import subprocess
from datetime import datetime


def ping_once(ip: str, timeout_ms: int) -> bool:
    system = platform.system().lower()
    kwargs = {}
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    else:
        timeout_s = max(1, timeout_ms // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000) + 2,
            **kwargs,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def main():
    parser = argparse.ArgumentParser(description="Scan a /24 local network with ICMP pings.")
    parser.add_argument("subnet", nargs="?", default="192.168.2",
                         help="First three octets, e.g. 192.168.2 (default: %(default)s)")
    parser.add_argument("-t", "--timeout", type=int, default=500,
                         help="Per-host ping timeout in ms (default: %(default)s)")
    parser.add_argument("-w", "--workers", type=int, default=64,
                         help="Number of concurrent pings (default: %(default)s)")
    parser.add_argument("-o", "--output", default="scan_results.txt",
                         help="Output file path (default: %(default)s)")
    args = parser.parse_args()

    subnet = args.subnet.strip().rstrip(".")
    hosts = [f"{subnet}.{i}" for i in range(0, 256)]

    print(f"Scanning {subnet}.0/24 ({len(hosts)} hosts, timeout={args.timeout}ms, workers={args.workers})...")

    responded = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(ping_once, ip, args.timeout): ip for ip in hosts}
        done = 0
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            done += 1
            if future.result():
                responded.append(ip)
                print(f"[{done}/{len(hosts)}] {ip} responded")

    responded.sort(key=lambda ip: int(ip.rsplit(".", 1)[1]))

    with open(args.output, "w") as f:
        f.write(f"Ping scan of {subnet}.0/24\n")
        f.write(f"Timestamp: {datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"Responding hosts: {len(responded)}/256\n\n")
        for ip in responded:
            last_octet = int(ip.rsplit(".", 1)[1])
            f.write(f"{last_octet}\t{ip}\n")

    print(f"\nDone. {len(responded)} host(s) responded. Results written to {args.output}")


if __name__ == "__main__":
    main()
