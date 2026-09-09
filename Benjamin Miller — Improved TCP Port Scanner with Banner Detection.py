#!/usr/bin/env python3
"""
python_port_scanner_banner.py

Purpose: Threaded TCP port scanner with basic banner detection

Author: Benjamin Miller
Version: 2.0
Date: 2026

Usage:
    python python_port_scanner_banner.py -o 192.168.1.10 -p 22,80,443
    python python_port_scanner_banner.py -o example.com -p 1-1024
    python python_port_scanner_banner.py -o 192.168.1.10 -p 22,80,443 -t 50

Only scan systems you own or have explicit permission to test.
"""

import argparse
import socket
import threading
from queue import Queue, Empty


DEFAULT_TIMEOUT = 2.0
DEFAULT_THREADS = 50
BANNER_SIZE = 256

print_lock = threading.Lock()


def parse_ports(port_string):
    """Convert ports and ranges into a sorted list of unique ports."""
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
            raise ValueError(f"Invalid port specification: {item}")

    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(
                f"Invalid port {port}. "
                "Valid TCP ports are 1-65535."
            )

    return sorted(ports)


def resolve_target(target):
    """Resolve a hostname or IPv4 address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as error:
        raise ValueError(
            f"Unable to resolve host '{target}'."
        ) from error


def clean_banner(data):
    """Convert raw banner bytes into readable text."""
    if not data:
        return None

    text = data.decode("utf-8", errors="replace")

    # Keep output on a single line.
    text = text.replace("\r", " ")
    text = text.replace("\n", " ")

    # Remove excessive whitespace.
    return " ".join(text.split())


def grab_banner(sock):
    """Attempt to read a banner from an already-open connection.

    Some services send a banner immediately. Others wait for input.
    We first attempt a passive read so that we do not send arbitrary
    protocol data to the service.
    """
    try:
        data = sock.recv(BANNER_SIZE)
        return clean_banner(data)

    except socket.timeout:
        return None

    except OSError:
        return None


def scan_port(target_ip, port, timeout):
    """Scan one TCP port and attempt basic banner detection."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            result = sock.connect_ex((target_ip, port))

            if result != 0:
                return None

            banner = grab_banner(sock)

            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"

            return {
                "port": port,
                "service": service,
                "banner": banner,
            }

    except OSError:
        return None


def worker(target_ip, queue, timeout, results):
    """Worker thread that processes ports from the queue."""
    while True:
        try:
            port = queue.get_nowait()
        except Empty:
            return

        try:
            result = scan_port(target_ip, port, timeout)

            if result:
                results.append(result)

                with print_lock:
                    print(
                        f"[+] {result['port']}/tcp OPEN "
                        f"({result['service']})"
                    )

                    if result["banner"]:
                        print(
                            f"    Banner: {result['banner']}"
                        )
                    else:
                        print("    Banner: unavailable")

        finally:
            queue.task_done()


def scan_ports(target_ip, ports, timeout, thread_count):
    """Scan all requested ports using worker threads."""
    port_queue = Queue()
    results = []

    for port in ports:
        port_queue.put(port)

    thread_count = min(thread_count, len(ports))

    threads = []

    for _ in range(thread_count):
        thread = threading.Thread(
            target=worker,
            args=(
                target_ip,
                port_queue,
                timeout,
                results,
            ),
            daemon=True,
        )

        thread.start()
        threads.append(thread)

    port_queue.join()

    for thread in threads:
        thread.join()

    return sorted(results, key=lambda result: result["port"])


def argument_parser():
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Threaded TCP port scanner with basic "
            "banner detection."
        )
    )

    parser.add_argument(
        "-o",
        "--host",
        required=True,
        help="Hostname or IPv4 address to scan.",
    )

    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        help=(
            "Ports to scan. Examples: "
            "'22,80,443' or '1-1024'."
        ),
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=(
            f"Number of worker threads "
            f"(default: {DEFAULT_THREADS})."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=(
            f"Socket timeout in seconds "
            f"(default: {DEFAULT_TIMEOUT})."
        ),
    )

    return parser


def main():
    """Program entry point."""
    parser = argument_parser()
    args = parser.parse_args()

    if args.threads < 1:
        parser.error("Thread count must be at least 1.")

    if args.timeout <= 0:
        parser.error("Timeout must be greater than 0.")

    try:
        target_ip = resolve_target(args.host)
        ports = parse_ports(args.ports)

    except ValueError as error:
        parser.error(str(error))

    if not ports:
        parser.error("No valid ports were specified.")

    try:
        reverse_name = socket.gethostbyaddr(target_ip)[0]
    except OSError:
        reverse_name = target_ip

    print()
    print("=" * 60)
    print("          BENJAMIN MILLER")
    print("       TCP BANNER PORT SCANNER")
    print("=" * 60)
    print(f"Target       : {args.host}")
    print(f"IP Address   : {target_ip}")
    print(f"Reverse DNS  : {reverse_name}")
    print(f"Ports        : {len(ports)}")
    print(f"Threads      : {args.threads}")
    print(f"Timeout      : {args.timeout}s")
    print("-" * 60)

    try:
        results = scan_ports(
            target_ip=target_ip,
            ports=ports,
            timeout=args.timeout,
            thread_count=args.threads,
        )

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted.")
        return

    print("-" * 60)

    if results:
        print(f"[+] {len(results)} open TCP port(s) found.")

        print()
        print("PORT       SERVICE       BANNER")
        print("-" * 60)

        for result in results:
            port = result["port"]
            service = result["service"]
            banner = result["banner"] or "unavailable"

            print(
                f"{port:<10} "
                f"{service:<13} "
                f"{banner}"
            )

    else:
        print("[-] No open TCP ports found.")

    print("=" * 60)


if __name__ == "__main__":
    main()

What makes this version better

    Actually uses threading effectively with a worker queue.
    Doesn't send Banner_query\r\n blindly. Different TCP services speak different protocols, so sending arbitrary data can produce misleading results.
    Attempts passive banner detection by reading data the service sends after connection.
    Uses connect_ex() rather than relying on exceptions for normal closed-port detection.
    Uses with socket.socket(...), guaranteeing sockets are closed.
    Has configurable timeouts so an unresponsive port doesn't stall the scan.
    Supports ranges, such as 1-1024, in addition to 22,80,443.
    Validates ports from 1–65535.
    Handles DNS/reverse-DNS failures cleanly.
    Synchronizes threaded output so results don't get mangled together.
    Identifies common services such as ssh, http, and https when Python's service database knows them.
    Produces a clean final table containing port, service, and banner.

For example:

python python_port_scanner_banner.py -o 192.168.1.10 -p 22,80,443

For a larger authorized scan:

python python_port_scanner_banner.py -o 192.168.1.10 -p 1-1024 -t 100 --timeout 1

One important limitation: banner detection is not service identification. A service may not send anything until it receives a protocol-specific request, and some services intentionally don't disclose a banner. This version therefore reports unavailable rather than pretending that a missing banner means the service isn't there.
