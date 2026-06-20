#!/usr/bin/env python3
"""
port-scan.py - dependency-free threaded TCP port scanner
================================================================================
A pure-Python (standard library only) TCP connect scanner intended as a fallback
when nmap is not available on the box you are working from. It supports:

  * Scanning a port range (e.g. 1-1024) OR a built-in common-ports list.
  * Concurrent scanning via a thread pool (configurable worker count).
  * Per-connection timeout.
  * Best-effort banner grabbing on open ports.
  * Clean human-readable output, plus optional JSON output to stdout/file.

--------------------------------------------------------------------------------
AUTHORIZED USE ONLY: Scan only hosts you own or are explicitly permitted to test
(CTF/lab targets, HTB/picoCTF machines, etc.). Unauthorized scanning may be
illegal in your jurisdiction.
--------------------------------------------------------------------------------

USAGE EXAMPLES:
  # Scan the common ports on a host:
  python3 port-scan.py 10.10.10.5 --common

  # Scan a full range with 500 workers and a 0.5s timeout:
  python3 port-scan.py target.htb -p 1-65535 -w 500 -t 0.5

  # Scan specific ports, grab banners, write JSON to a file:
  python3 port-scan.py 192.168.56.101 -p 22,80,443,8080 --banner -o results.json

  # Emit JSON to stdout (pipe into jq):
  python3 port-scan.py 10.10.10.5 --common --json | jq .
"""

import argparse
import concurrent.futures
import json
import socket
import sys
from datetime import datetime

# A practical "common ports" list (well-known + frequent CTF services).
COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 990, 993,
    995, 1080, 1099, 1433, 1521, 1723, 2049, 2121, 2375, 3000, 3128, 3306,
    3389, 3690, 4444, 5000, 5432, 5555, 5900, 5985, 5986, 6000, 6379, 6667,
    7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 10000, 11211,
    27017, 50000,
]


def parse_ports(spec: str) -> list[int]:
    """
    Parse a port specification string into a sorted, de-duplicated list of ints.

    Accepts comma-separated values and dash ranges, e.g.:
        "22,80,443"        -> [22, 80, 443]
        "1-1024"           -> [1, 2, ..., 1024]
        "22,80,8000-8010"  -> mix of both
    """
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, end_s = chunk.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))
    # Keep only valid TCP port numbers.
    return sorted(p for p in ports if 1 <= p <= 65535)


def grab_banner(sock: socket.socket, timeout: float) -> str:
    """
    Best-effort banner read from an already-connected socket.
    Many services (FTP, SSH, SMTP) send a greeting immediately; for those that
    don't we send a tiny generic probe and read whatever comes back.
    Returns a cleaned single-line banner, or "" if nothing was received.
    """
    try:
        sock.settimeout(timeout)
        try:
            data = sock.recv(1024)
        except socket.timeout:
            data = b""
        if not data:
            # Nudge HTTP-like services into responding.
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(1024)
            except (socket.timeout, OSError):
                data = b""
        return data.decode("utf-8", errors="replace").strip().splitlines()[0] if data else ""
    except OSError:
        return ""


def scan_port(host: str, port: int, timeout: float, banner: bool) -> dict | None:
    """
    Attempt a TCP connect to host:port.
    Returns a result dict if the port is OPEN, otherwise None.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) == 0:
            result = {"port": port, "state": "open", "service": guess_service(port)}
            if banner:
                result["banner"] = grab_banner(sock, timeout)
            return result
        return None
    except OSError:
        return None
    finally:
        sock.close()


def guess_service(port: int) -> str:
    """Map a port to its IANA service name when the OS database knows it."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def resolve(host: str) -> str:
    """Resolve a hostname to an IPv4 address (exit cleanly if it fails)."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        sys.exit(f"[-] Could not resolve host '{host}': {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Dependency-free threaded TCP port scanner (nmap fallback).",
        epilog="Authorized targets only.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("host", help="Target hostname or IP address.")

    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports to scan: comma list and/or ranges, e.g. '22,80,8000-8100'.",
    )
    port_group.add_argument(
        "--common", action="store_true",
        help="Scan a built-in list of common/CTF ports instead of --ports.",
    )

    parser.add_argument("-w", "--workers", type=int, default=200,
                        help="Number of concurrent worker threads.")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="Per-connection timeout in seconds.")
    parser.add_argument("--banner", action="store_true",
                        help="Attempt a banner grab on each open port.")
    parser.add_argument("--json", action="store_true",
                        help="Print results as JSON to stdout.")
    parser.add_argument("-o", "--output",
                        help="Write JSON results to this file.")
    args = parser.parse_args()

    ip = resolve(args.host)
    ports = COMMON_PORTS if args.common else parse_ports(args.ports)
    if not ports:
        sys.exit("[-] No valid ports to scan.")

    if not args.json:
        print(f"[*] Scanning {args.host} ({ip}) - {len(ports)} ports, "
              f"{args.workers} workers, {args.timeout}s timeout")
        print(f"[*] Started at {datetime.now().isoformat(timespec='seconds')}")

    open_results: list[dict] = []
    # ThreadPoolExecutor is ideal here: connect() is I/O-bound, so the GIL is
    # released while waiting and we get real concurrency.
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(scan_port, ip, port, args.timeout, args.banner): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_results.append(res)
                if not args.json:
                    line = f"[+] {res['port']:>5}/tcp  open  {res['service']}"
                    if args.banner and res.get("banner"):
                        line += f"  | {res['banner']}"
                    print(line)

    open_results.sort(key=lambda r: r["port"])

    summary = {
        "target": args.host,
        "ip": ip,
        "scanned": len(ports),
        "open": open_results,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
        if not args.json:
            print(f"[*] JSON results written to {args.output}")

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[*] Done. {len(open_results)} open port(s) found.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[-] Interrupted by user.")
