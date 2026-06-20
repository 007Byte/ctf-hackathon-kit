#!/usr/bin/env python3
"""
host-discovery.py  --  Live-host discovery for a home-network security audit.

============================================================================
AUTHORIZED NETWORKS ONLY.
This tool is part of a home-network security-audit suite. Use it ONLY on
networks you own or are explicitly authorized to test. Unauthorized scanning
of networks may be illegal in your jurisdiction. You are responsible for how
you use it.
============================================================================

What it does
------------
Discovers live hosts on a subnet using only the Python standard library by
default (no admin/root required):
  * TCP-connect "ping" to a handful of common ports (liveness without ICMP).
  * ICMP echo via the OS `ping` command (OS-aware flags).
  * Reads the system ARP table (`arp -a`) to harvest MAC addresses.
Optionally, if `scapy` is installed AND you pass --scapy, it performs a fast,
reliable layer-2 ARP scan (this DOES require admin/root + raw-socket rights).

For every live host it reports: IP, MAC, MAC-vendor (small built-in OUI map),
hostname (reverse DNS, best effort), and state.

Cross-platform: works on Windows and Linux (and macOS best-effort).

Output: human-readable summary to stdout, plus an optional shared-schema JSON
file via --json for an orchestrator to aggregate.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import platform
import re
import socket
import subprocess
import sys

# --------------------------------------------------------------------------
# Built-in OUI prefix -> vendor map (small, common-vendor subset).
# A full IEEE OUI file can be dropped in as `oui.txt` (see load_oui_file()).
# Keys are the first 3 octets, uppercase, no separators (e.g. "FCFBFB").
# --------------------------------------------------------------------------
BUILTIN_OUI = {
    # Apple
    "F0989D": "Apple", "A4B197": "Apple", "3C0754": "Apple", "AC87A3": "Apple",
    "F0DBF8": "Apple", "D0817A": "Apple",
    # Samsung
    "FCFBFB": "Samsung", "5CF8A1": "Samsung", "8425DB": "Samsung", "0023D6": "Samsung",
    # Cisco / Cisco-Linksys
    "00000C": "Cisco", "001A2F": "Cisco", "F02765": "Cisco", "00059A": "Cisco",
    "68BDAB": "Cisco",
    # TP-Link
    "50C7BF": "TP-Link", "A42BB0": "TP-Link", "C46E1F": "TP-Link", "EC086B": "TP-Link",
    # Netgear
    "00146C": "Netgear", "20E52A": "Netgear", "A040A0": "Netgear", "9C3DCF": "Netgear",
    # Amazon (Echo / Fire / Kindle)
    "FC65DE": "Amazon", "44650D": "Amazon", "68374A": "Amazon", "087190": "Amazon",
    # Google / Nest
    "F4F5D8": "Google", "F88FCA": "Google", "3C5AB4": "Google", "001A11": "Google",
    # Raspberry Pi Foundation
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "28CDC1": "Raspberry Pi",
    # Intel
    "001B21": "Intel", "3C970E": "Intel", "A0A8CD": "Intel", "8086F2": "Intel",
    # Microsoft
    "0017FA": "Microsoft", "7C1E52": "Microsoft", "C83F26": "Microsoft",
    # Espressif (ESP8266/ESP32 IoT)
    "240AC4": "Espressif", "A020A6": "Espressif", "84F3EB": "Espressif",
    # Ubiquiti
    "0418D6": "Ubiquiti", "44D9E7": "Ubiquiti", "788A20": "Ubiquiti",
    # D-Link
    "1CBDB9": "D-Link", "B8A386": "D-Link", "C8BE19": "D-Link",
    # ASUS / ASUSTek
    "1C872C": "ASUSTek", "AC220B": "ASUSTek", "2C56DC": "ASUSTek",
    # Sonos
    "5CAAFD": "Sonos", "B8E937": "Sonos",
    # Roku
    "B0A737": "Roku", "CC6DA0": "Roku",
    # Philips Hue (Signify)
    "001788": "Philips Hue",
    # Xiaomi
    "78110E": "Xiaomi", "F8A45F": "Xiaomi",
    # Huawei
    "00E0FC": "Huawei", "48435A": "Huawei",
    # HP / Hewlett Packard
    "001B78": "HP", "3C52A1": "HP",
    # Dell
    "B083FE": "Dell", "001422": "Dell",
    # Realtek (common NIC chipset)
    "525400": "QEMU/KVM (virtual)", "0800271": "VirtualBox",
    "000C29": "VMware", "005056": "VMware",
}

# Common ports to TCP-"ping" for liveness when ICMP is filtered.
TCP_PING_PORTS = [80, 443, 22, 445, 139, 135, 3389, 53, 8080, 23, 21, 5357, 62078]


def load_oui_file(path):
    """Optionally merge a full OUI file into the lookup map.

    Accepts simple "PREFIX<whitespace>Vendor" lines, where PREFIX may be
    formatted as AA:BB:CC, AA-BB-CC, AABBCC, or the IEEE 'AABBCC<TAB>...'
    style. Lines that don't parse are ignored.
    """
    merged = dict(BUILTIN_OUI)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Split on first run of whitespace.
                parts = re.split(r"\s+", line, maxsplit=1)
                if len(parts) != 2:
                    continue
                prefix = re.sub(r"[^0-9A-Fa-f]", "", parts[0]).upper()
                if len(prefix) >= 6:
                    merged[prefix[:6]] = parts[1].strip()
    except OSError as exc:
        print(f"[!] Could not read OUI file {path}: {exc}", file=sys.stderr)
    return merged


def normalize_mac(mac):
    """Return a canonical lowercase colon-separated MAC, or '' if invalid."""
    if not mac:
        return ""
    hexonly = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(hexonly) != 12:
        return ""
    hexonly = hexonly.lower()
    return ":".join(hexonly[i:i + 2] for i in range(0, 12, 2))


def vendor_for_mac(mac, oui_map):
    """Look up the vendor from the first 3 octets of a MAC."""
    if not mac:
        return ""
    prefix = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()[:6]
    return oui_map.get(prefix, "")


# --------------------------------------------------------------------------
# Local subnet auto-detection
# --------------------------------------------------------------------------
def get_primary_ip():
    """Best-effort local IP by opening a UDP socket to a public IP.

    No packets are actually sent for UDP connect(); this just makes the OS
    pick the outbound interface so we can read its address.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def detect_local_cidr():
    """Auto-detect the local subnet as a CIDR string.

    Tries to read the netmask from `ipconfig` (Windows) or `ip addr` /
    `ifconfig` (Linux/mac). Falls back to assuming a /24 around the
    primary IP if the mask can't be determined.
    """
    primary = get_primary_ip()
    if not primary:
        return None

    system = platform.system().lower()
    mask = None
    try:
        if system == "windows":
            out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                 timeout=10).stdout
            # Find the IPv4 line matching primary, then the subnet mask line.
            lines = out.splitlines()
            for idx, line in enumerate(lines):
                if primary in line and "IPv4" in line:
                    for follow in lines[idx:idx + 4]:
                        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", follow)
                        if "Subnet Mask" in follow and m:
                            mask = m.group(1)
                            break
                    break
        else:
            # Try `ip addr`; output like "inet 192.168.1.5/24 ..."
            out = subprocess.run(["ip", "-o", "-f", "inet", "addr", "show"],
                                 capture_output=True, text=True, timeout=10).stdout
            for line in out.splitlines():
                m = re.search(rf"inet\s+{re.escape(primary)}/(\d+)", line)
                if m:
                    return f"{primary}/{m.group(1)}"
    except (OSError, subprocess.SubprocessError):
        mask = None

    try:
        if mask:
            net = ipaddress.ip_network(f"{primary}/{mask}", strict=False)
            return str(net)
    except ValueError:
        pass

    # Fallback: assume a /24.
    net = ipaddress.ip_network(f"{primary}/24", strict=False)
    return str(net)


# --------------------------------------------------------------------------
# Liveness probes
# --------------------------------------------------------------------------
def tcp_ping(ip, ports, timeout):
    """Return True if any of the given TCP ports accepts a connection."""
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    return True
        except OSError:
            continue
    return False


def icmp_ping(ip, timeout):
    """ICMP echo via the OS `ping` binary (OS-aware flags). No root needed."""
    system = platform.system().lower()
    if system == "windows":
        # -n 1 one echo, -w timeout in milliseconds.
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        # -c 1 one echo, -W timeout in whole seconds (min 1).
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout + 3)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def probe_host(ip, ports, timeout, use_icmp):
    """Return ip if the host appears up, else None."""
    if tcp_ping(ip, ports, timeout):
        return ip
    if use_icmp and icmp_ping(ip, timeout):
        return ip
    return None


# --------------------------------------------------------------------------
# ARP table reading (no root required)
# --------------------------------------------------------------------------
def read_arp_table():
    """Parse the system ARP table into {ip: mac} (canonical MACs).

    Handles Windows (`arp -a`, dash-separated MACs) and Linux/mac
    (`arp -a` or `ip neigh`, colon-separated MACs).
    """
    result = {}
    system = platform.system().lower()
    commands = []
    if system == "windows":
        commands = [["arp", "-a"]]
    else:
        commands = [["ip", "neigh"], ["arp", "-a"], ["arp", "-n"]]

    text = ""
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0 and proc.stdout.strip():
                text = proc.stdout
                break
        except (OSError, subprocess.SubprocessError):
            continue

    # Generic regex: capture an IPv4 and a nearby MAC (either separator).
    mac_re = re.compile(r"([0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(\2[0-9A-Fa-f]{2}){4})")
    for line in text.splitlines():
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        mac_match = mac_re.search(line)
        if ip_match and mac_match:
            mac = normalize_mac(mac_match.group(1))
            if mac and mac != "00:00:00:00:00:00" and not mac.startswith("ff:ff:ff"):
                result[ip_match.group(1)] = mac
    return result


# --------------------------------------------------------------------------
# Optional scapy ARP scan (requires admin/root + scapy installed)
# --------------------------------------------------------------------------
def scapy_arp_scan(cidr, timeout):
    """Layer-2 ARP scan using scapy. Returns {ip: mac} or None on failure."""
    try:
        from scapy.all import ARP, Ether, srp  # noqa: import inside func by design
    except ImportError:
        print("[!] scapy not installed. Install with: pip install scapy",
              file=sys.stderr)
        return None
    try:
        # Broadcast an ARP who-has for the whole range and collect replies.
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        answered, _ = srp(packet, timeout=timeout, verbose=0)
        found = {}
        for _sent, received in answered:
            found[received.psrc] = normalize_mac(received.hwsrc)
        return found
    except PermissionError:
        print("[!] scapy ARP scan needs admin/root (raw sockets). "
              "Falling back to stdlib methods.", file=sys.stderr)
        return None
    except Exception as exc:  # scapy raises a variety of low-level errors
        print(f"[!] scapy ARP scan failed ({exc}). Falling back.", file=sys.stderr)
        return None


# --------------------------------------------------------------------------
# Hostname resolution (best effort)
# --------------------------------------------------------------------------
def resolve_hostname(ip):
    """Reverse-DNS lookup; returns '' if it fails. (NetBIOS not attempted to
    avoid heavy/blocking dependencies; reverse DNS covers most home setups.)"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


# --------------------------------------------------------------------------
# Main orchestration
# --------------------------------------------------------------------------
def discover(cidr, args, oui_map):
    """Run discovery against a CIDR and return a list of host dicts."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        print(f"[!] Invalid target {cidr}: {exc}", file=sys.stderr)
        sys.exit(2)

    hosts_iter = list(network.hosts()) if network.num_addresses > 2 else [network.network_address]
    targets = [str(h) for h in hosts_iter]
    print(f"[*] Target: {cidr}  ({len(targets)} addresses)")
    print(f"[*] Threads: {args.threads}  TCP-ping timeout: {args.timeout}s  "
          f"ICMP: {'on' if not args.no_icmp else 'off'}")

    live = set()

    # Optional scapy fast path first (populates both liveness + MAC).
    scapy_macs = {}
    if args.scapy:
        print("[*] Attempting scapy ARP scan (needs admin/root)...")
        sres = scapy_arp_scan(cidr, args.timeout + 1)
        if sres:
            scapy_macs = sres
            live.update(sres.keys())
            print(f"[+] scapy found {len(sres)} host(s) via ARP.")

    # Stdlib probing (always run unless scapy already covered everything; it
    # is cheap and catches hosts that ignore ARP-from-us or are off-segment).
    print("[*] Probing for live hosts (TCP-connect + ICMP)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(probe_host, ip, TCP_PING_PORTS, args.timeout,
                        not args.no_icmp): ip
            for ip in targets
        }
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                live.add(res)

    # Harvest MACs from the ARP table (probing populated it).
    arp_macs = read_arp_table()
    # ARP entries for live hosts that probing missed are also "up".
    for ip in arp_macs:
        if ipaddress.ip_address(ip) in network:
            live.add(ip)

    print(f"[+] {len(live)} live host(s) found. Resolving details...")

    # Resolve hostname + vendor per live host (threaded reverse DNS).
    hosts = []
    sorted_live = sorted(live, key=lambda x: tuple(int(o) for o in x.split(".")))
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        name_futures = {pool.submit(resolve_hostname, ip): ip for ip in sorted_live}
        names = {}
        for fut in concurrent.futures.as_completed(name_futures):
            names[name_futures[fut]] = fut.result()

    for ip in sorted_live:
        mac = scapy_macs.get(ip) or arp_macs.get(ip, "")
        hosts.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor_for_mac(mac, oui_map),
            "hostname": names.get(ip, ""),
            "state": "up",
        })
    return hosts


def print_summary(cidr, hosts):
    """Pretty human-readable table to stdout."""
    print("\n" + "=" * 78)
    print(f"HOST DISCOVERY SUMMARY  --  {cidr}")
    print("=" * 78)
    if not hosts:
        print("No live hosts found.")
        return
    header = f"{'IP':<16}{'MAC':<19}{'VENDOR':<16}{'HOSTNAME'}"
    print(header)
    print("-" * 78)
    for h in hosts:
        print(f"{h['ip']:<16}{h['mac'] or '-':<19}"
              f"{(h['vendor'] or '-')[:15]:<16}{h['hostname'] or '-'}")
    print("-" * 78)
    print(f"Total live hosts: {len(hosts)}")


def main():
    parser = argparse.ArgumentParser(
        description="Discover live hosts on a subnet (AUTHORIZED NETWORKS ONLY).",
        epilog="Example: python host-discovery.py 192.168.1.0/24 --json hosts.json")
    parser.add_argument("target", nargs="?",
                        help="CIDR or IP range to scan (e.g. 192.168.1.0/24). "
                             "If omitted, the local subnet is auto-detected.")
    parser.add_argument("--threads", type=int, default=100,
                        help="Concurrent probe threads (default: 100).")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Per-probe timeout in seconds (default: 0.5).")
    parser.add_argument("--no-icmp", action="store_true",
                        help="Skip ICMP ping (TCP-connect probes only).")
    parser.add_argument("--scapy", action="store_true",
                        help="Use scapy ARP scan if available (needs admin/root).")
    parser.add_argument("--oui-file",
                        help="Path to a full OUI file to merge with the built-in map.")
    parser.add_argument("--json", dest="json_out",
                        help="Write results to this JSON file (shared schema).")
    args = parser.parse_args()

    print("=" * 78)
    print("AUTHORIZED NETWORKS ONLY -- scan only networks you own/are authorized "
          "to test.")
    print("=" * 78)

    oui_map = load_oui_file(args.oui_file) if args.oui_file else dict(BUILTIN_OUI)

    cidr = args.target or detect_local_cidr()
    if not cidr:
        print("[!] Could not auto-detect local subnet. Please pass a target CIDR.",
              file=sys.stderr)
        sys.exit(2)

    hosts = discover(cidr, args, oui_map)
    print_summary(cidr, hosts)

    output = {
        "tool": "host-discovery",
        "target": cidr,
        "hosts": hosts,
        "findings": [],
    }
    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(output, fh, indent=2)
            print(f"\n[+] JSON written to {args.json_out}")
        except OSError as exc:
            print(f"[!] Could not write JSON: {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
