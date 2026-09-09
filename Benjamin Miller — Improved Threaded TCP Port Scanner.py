#!/usr/bin/env python3
"""
python_port_scanner_threaded.py

Purpose: Python-based threaded TCP port scanner

Author: Benjamin Miller
Version: 1.0
Date: 2026

Usage:
    python python_port_scanner_threaded.py -o 192.168.1.10 -p 22,80,443
    python python_port_scanner_threaded.py -o 192.168.1.10 -p 1-1024

Only scan systems you own or have explicit permission to test.
"""

import argparse
import socket
import threading
from queue import Queue


DEFAULT_TIMEOUT = 1.0


def connection_scan(target_ip, target_port, timeout=DEFAULT_TIMEOUT):
    """Attempt a TCP connection to a specified port.

    Returns True if the port accepts a TCP connection.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn_socket:
            conn_socket.settimeout(timeout)

            result = conn_socket.connect_ex((target_ip, target_port))

            if result == 0:
                print(f"[+] {target_port}/tcp OPEN")
                return True

    except OSError:
        pass

    return False


def worker(target_ip, queue, timeout, open_ports):
    """Process ports from the queue."""
    while True:
        try:
            port = queue.get_nowait()
        except Exception:
            return

        try:
            if connection_scan(target_ip, port, timeout):
                open_ports.append(port)
        finally:
            queue.task_done()


def parse_ports(port_string):
    """Parse comma-separated ports and port ranges.

    Examples:
        22,80,443
        1-1024
        22,80,8000-8080
    """
    ports = set()

    for item in port_string.split(","):
        item = item.strip()

        if not item:
            continue

        try:
            if "-" in item:
                start, end = map(int, item.split("-", 1))

                if start > end:
                    start, end = end, start

                ports.update(range(start, end + 1))
            else:
                ports.add(int(item))

        except ValueError:
            raise ValueError(f"Invalid port: {item}")

    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(
                f"Invalid port {port}. "
                "Ports must be between 1 and 65535."
            )

    return sorted(ports)


def port_scan(target, port_string, threads=50, timeout=DEFAULT_TIMEOUT):
    """Resolve the target and scan the requested ports."""
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] Cannot resolve {target}: Unknown host")
        return

    try:
        target_name = socket.gethostbyaddr(target_ip)[0]
    except OSError:
        target_name = target_ip

    try:
        ports = parse_ports(port_string)
    except ValueError as error:
        print(f"[-] {error}")
        return

    if not ports:
        print("[-] No valid ports were supplied.")
        return

    print()
    print("=" * 50)
    print("       BENJAMIN MILLER")
    print("       THREADED TCP PORT SCANNER")
    print("=" * 50)
    print(f"[*] Target : {target_name}")
    print(f"[*] IP     : {target_ip}")
    print(f"[*] Ports  : {len(ports)}")
    print(f"[*] Threads: {threads}")
    print("-" * 50)

    queue = Queue()

    for port in ports:
        queue.put(port)

    open_ports = []
    thread_list = []

    thread_count = min(threads, len(ports))

    for _ in range(thread_count):
        thread = threading.Thread(
            target=worker,
            args=(target_ip, queue, timeout, open_ports),
            daemon=True
        )

        thread.start()
        thread_list.append(thread)

    queue.join()

    for thread in thread_list:
        thread.join()

    open_ports.sort()

    print("-" * 50)

    if open_ports:
        print(f"[+] {len(open_ports)} open port(s) found:")

        for port in open_ports:
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"

            print(f"    {port}/tcp  {service}")
    else:
        print("[-] No open TCP ports found.")

    print("=" * 50)


def argument_parser():
    """Create and return the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Threaded TCP port scanner. "
            "Accepts a hostname/IP address and ports to scan."
        )
    )

    parser.add_argument(
        "-o",
        "--host",
        required=True,
        help="Hostname or IPv4 address to scan."
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
        "-t",
        "--threads",
        type=int,
        default=50,
        help="Number of scanning threads (default: 50)."
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="Connection timeout in seconds (default: 1.0)."
    )

    return parser


def main():
    """Program entry point."""
    parser = argument_parser()
    args = parser.parse_args()

    if args.threads <= 0:
        parser.error("Thread count must be greater than zero.")

    if args.timeout <= 0:
        parser.error("Timeout must be greater than zero.")

    port_scan(
        target=args.host,
        port_string=args.ports,
        threads=args.threads,
        timeout=args.timeout
    )


if __name__ == "__main__":
    main()

Example

python python_port_scanner_threaded.py -o 192.168.1.10 -p 22,80,443

Or scan a range:

python python_port_scanner_threaded.py -o 192.168.1.10 -p 1-1024 -t 100

The biggest fixes from your original are:

    connection_scan() now receives the resolved IP rather than accidentally using the hostname.
    Sockets are safely closed with with socket.socket(...).
    Connections have a timeout, so scans don't hang.
    Threads actually process a shared queue of ports.
    -o and -p are properly required.
    Invalid port numbers are rejected.
    Supports both individual ports and ranges.
    Reports common TCP service names.
    Results are sorted and summarized.
    Removed the unnecessary Banner_query transmission.

Only use the scanner against systems you own or have explicit authorization to test.
