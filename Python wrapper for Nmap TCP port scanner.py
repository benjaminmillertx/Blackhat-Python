#!/usr/bin/env python3
"""
nmap_port_scanner.py

Purpose: Python wrapper for Nmap TCP port scanner

Author: Benjamin Miller
Version: 2.0
Date: 2026

Requirements:
    - Nmap installed and available in PATH
    - python-nmap package

Examples:
    python nmap_port_scanner.py -o 192.168.1.10 -p 22,80,443
    python nmap_port_scanner.py -o 192.168.1.10 -p 1-1024
    python nmap_port_scanner.py -o example.com -p 22,80,443

Only scan systems you own or have explicit permission to test.
"""

import argparse
import shutil
import sys

try:
    import nmap
except ImportError:
    print(
        "[-] python-nmap is not installed.\n"
        "    Install it with: pip install python-nmap"
    )
    sys.exit(1)


def argument_parser():
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Nmap-based TCP port scanner. "
            "Accepts a hostname/IP address and ports to scan."
        )
    )

    parser.add_argument(
        "-o",
        "--host",
        required=True,
        help="Hostname or IP address to scan."
    )

    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        help=(
            "Comma-separated ports or ranges. "
            "Examples: '22,80,443' or '1-1024'."
        )
    )

    parser.add_argument(
        "-T",
        "--timing",
        choices=["T1", "T2", "T3", "T4", "T5"],
        default="T3",
        help="Nmap timing template (default: T3)."
    )

    parser.add_argument(
        "-s",
        "--service-detection",
        action="store_true",
        help="Enable Nmap service/version detection."
    )

    return parser


def validate_ports(port_string):
    """Validate a basic Nmap port specification."""
    if not port_string.strip():
        raise ValueError("Port specification cannot be empty.")

    for item in port_string.split(","):
        item = item.strip()

        if not item:
            continue

        if "-" in item:
            parts = item.split("-", 1)

            if len(parts) != 2:
                raise ValueError(f"Invalid port range: {item}")

            try:
                start = int(parts[0])
                end = int(parts[1])
            except ValueError:
                raise ValueError(f"Invalid port range: {item}")

            if not (1 <= start <= 65535):
                raise ValueError(f"Invalid port: {start}")

            if not (1 <= end <= 65535):
                raise ValueError(f"Invalid port: {end}")

        else:
            try:
                port = int(item)
            except ValueError:
                raise ValueError(f"Invalid port: {item}")

            if not 1 <= port <= 65535:
                raise ValueError(f"Invalid port: {port}")


def nmap_scan(host, ports, timing, service_detection):
    """Run one Nmap scan against all requested ports."""
    scanner = nmap.PortScanner()

    arguments = f"-{timing}"

    if service_detection:
        arguments += " -sV"

    try:
        scanner.scan(
            hosts=host,
            ports=ports,
            arguments=arguments
        )

    except nmap.PortScannerError as error:
        raise RuntimeError(f"Nmap error: {error}") from error

    if host not in scanner.all_hosts():
        return []

    if "tcp" not in scanner[host]:
        return []

    results = []

    for port in sorted(scanner[host]["tcp"]):
        information = scanner[host]["tcp"][port]

        state = information.get("state", "unknown")
        service = information.get("name", "unknown")
        product = information.get("product", "")
        version = information.get("version", "")

        results.append(
            {
                "port": port,
                "state": state,
                "service": service,
                "product": product,
                "version": version,
            }
        )

    return results


def print_results(host, results):
    """Display scan results in a readable format."""
    print()
    print("=" * 70)
    print("                 BENJAMIN MILLER")
    print("                   NMAP SCANNER")
    print("=" * 70)
    print(f"Target: {host}")
    print("-" * 70)

    if not results:
        print("[-] No TCP ports were returned by Nmap.")
        print("=" * 70)
        return

    print(
        f"{'PORT':<10}"
        f"{'STATE':<12}"
        f"{'SERVICE':<18}"
        f"VERSION"
    )
    print("-" * 70)

    for result in results:
        version = " ".join(
            part
            for part in (
                result["product"],
                result["version"],
            )
            if part
        )

        print(
            f"{result['port']:<10}"
            f"{result['state']:<12}"
            f"{result['service']:<18}"
            f"{version}"
        )

    print("-" * 70)

    open_ports = [
        result for result in results
        if result["state"] == "open"
    ]

    print(f"[+] Open TCP ports: {len(open_ports)}")
    print("=" * 70)


def main():
    """Program entry point."""
    parser = argument_parser()
    args = parser.parse_args()

    # Check that the Nmap executable exists.
    if shutil.which("nmap") is None:
        print(
            "[-] Nmap executable was not found in PATH.\n"
            "    Install Nmap and make sure 'nmap' is available "
            "from the command line."
        )
        sys.exit(1)

    try:
        validate_ports(args.ports)

    except ValueError as error:
        parser.error(str(error))

    print()
    print("[*] Starting Nmap scan...")
    print(f"[*] Target : {args.host}")
    print(f"[*] Ports  : {args.ports}")
    print(f"[*] Timing : {args.timing}")

    if args.service_detection:
        print("[*] Service detection: enabled")
    else:
        print("[*] Service detection: disabled")

    try:
        results = nmap_scan(
            host=args.host,
            ports=args.ports,
            timing=args.timing,
            service_detection=args.service_detection,
        )

    except RuntimeError as error:
        print(f"[-] {error}")
        sys.exit(1)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted.")
        sys.exit(130)

    print_results(args.host, results)


if __name__ == "__main__":
    main()

Improvements over the original

    One Nmap scan instead of starting Nmap once per port. This is the biggest improvement.
    -o and -p are now required.
    Validates individual ports and ranges.
    Detects whether the Nmap executable is actually installed.
    Handles a missing python-nmap module cleanly.
    Handles Nmap errors without a traceback dump.
    Supports Nmap timing templates such as T3 and T4.
    Optional service/version detection with -s.
    Displays port, state, service, product, and version.
    Correctly handles hosts where Nmap returns no TCP results.
    Handles Ctrl+C.
    Uses modern Python formatting and documentation.
    Keeps the Benjamin Miller attribution throughout.

Example commands

Basic scan:

python nmap_port_scanner.py -o 192.168.1.10 -p 22,80,443

Port range:

python nmap_port_scanner.py -o 192.168.1.10 -p 1-1024

With service/version detection:

python nmap_port_scanner.py -o 192.168.1.10 -p 22,80,443 -s

Faster timing:

python nmap_port_scanner.py -o 192.168.1.10 -p 1-1024 -T4 -s

The -s option is particularly useful if your goal is to turn this from a simple port-state wrapper into something that also reports what Nmap believes is running on an open port.

Use it only against systems you own or are explicitly authorized to assess.
