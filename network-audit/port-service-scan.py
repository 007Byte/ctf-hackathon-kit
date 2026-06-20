#!/usr/bin/env python3
"""
port-service-scan.py  --  Threaded TCP port + service scanner for a home-network
                          security audit.

============================================================================
AUTHORIZED NETWORKS ONLY.
This tool is part of a home-network security-audit suite. Use it ONLY on
networks/hosts you own or are explicitly authorized to test. Unauthorized
port scanning may be illegal in your jurisdiction. You are responsible for
how you use it.
============================================================================

What it does
------------
Performs threaded TCP-connect scans (no admin/root, no raw packets) against
one or more hosts. Accepts a single IP, a comma-separated list, a CIDR, or
hosts loaded from a prior host-discovery JSON file (--from-json).

For each open port it grabs a banner (best effort) and identifies the likely
service from the port number and/or banner. It then generates security
"findings" with severities for risky exposed services (Telnet, FTP, SMB,
databases, RDP, UPnP, unencrypted HTTP admin, etc.).

Cross-platform: pure standard library, works on Windows and Linux.

Output: human-readable summary to stdout, plus an optional shared-schema JSON
file via --json for an orchestrator to aggregate.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import socket
import ssl
import sys

# --------------------------------------------------------------------------
# Default port set (~100 common TCP ports across services).
# --------------------------------------------------------------------------
DEFAULT_PORTS = [
    20, 21, 22, 23, 25, 37, 53, 67, 69, 79, 80, 81, 88, 102, 110, 111, 113,
    119, 123, 135, 137, 138, 139, 143, 161, 179, 389, 427, 443, 445, 465,
    500, 514, 515, 520, 523, 548, 554, 587, 623, 631, 636, 873, 902, 989,
    990, 993, 995, 1080, 1099, 1194, 1433, 1434, 1521, 1701, 1723, 1883,
    1900, 2049, 2082, 2083, 2222, 2375, 2376, 3000, 3128, 3260, 3306, 3389,
    3478, 4444, 4500, 4567, 5000, 5060, 5432, 5555, 5601, 5672, 5800, 5900,
    5985, 5986, 6000, 6379, 6667, 7000, 7070, 8000, 8008, 8080, 8081, 8082,
    8088, 8123, 8443, 8554, 8888, 9000, 9090, 9100, 9200, 10000, 11211,
    27017, 32400, 49152,
]

# Top-N candidate list (used by --top N). Ordered by rough prevalence.
TOP_PORTS = [
    80, 443, 22, 445, 139, 135, 3389, 53, 21, 23, 25, 110, 143, 993, 995,
    8080, 8443, 3306, 5432, 1433, 5900, 3000, 8000, 8888, 161, 5000, 6379,
    27017, 11211, 9200, 1900, 5357, 49152, 62078, 548, 631, 515, 9100,
    554, 1883, 8009, 5060, 5985, 2049, 111, 873, 389, 636, 88, 5601,
]

# port -> (service-name, severity, title, detail, recommendation)
# severity in: info|low|medium|high|critical
RISKY_SERVICES = {
    23: ("telnet", "high", "Telnet exposed (cleartext admin)",
         "Telnet transmits credentials and commands in cleartext and is "
         "trivially sniffable on the LAN.",
         "Disable Telnet; use SSH (port 22) instead."),
    21: ("ftp", "medium", "FTP exposed (often cleartext)",
         "Plain FTP sends credentials and data unencrypted. Anonymous FTP "
         "may also be enabled.",
         "Disable FTP or replace with SFTP/FTPS; verify anonymous access is off."),
    2375: ("docker-api", "critical", "Unauthenticated Docker API exposed",
           "Docker daemon TCP socket without TLS allows full container/host "
           "takeover by anyone who can reach the port.",
           "Bind Docker to localhost only or enable mutual-TLS (2376)."),
    3389: ("rdp", "medium", "RDP exposed",
           "Remote Desktop is a frequent brute-force and exploit target when "
           "reachable on the network.",
           "Restrict RDP to VPN/allow-listed IPs; enable NLA and strong passwords."),
    445: ("smb", "medium", "SMB file sharing exposed",
          "SMB exposes file shares and has a history of wormable vulnerabilities "
          "(e.g. EternalBlue).",
          "Limit SMB to trusted hosts; ensure SMBv1 is disabled and patches applied."),
    139: ("netbios-ssn", "medium", "NetBIOS/SMB session service exposed",
          "Legacy NetBIOS session service often accompanies SMBv1 and leaks "
          "host information.",
          "Disable NetBIOS over TCP/IP if not required; disable SMBv1."),
    1900: ("upnp", "low", "UPnP/SSDP exposed",
           "UPnP can allow devices to auto-open firewall/router ports and leaks "
           "device details.",
           "Disable UPnP on the router unless a specific device requires it."),
    1433: ("mssql", "high", "Microsoft SQL Server exposed",
           "Database ports should not be reachable from the general LAN; common "
           "target for brute force and data theft.",
           "Bind to localhost/trusted subnet only; firewall the port."),
    3306: ("mysql", "high", "MySQL/MariaDB exposed",
           "Open database port reachable on the network risks unauthorized "
           "access and data exfiltration.",
           "Bind to localhost only; require strong auth; firewall the port."),
    5432: ("postgresql", "high", "PostgreSQL exposed",
           "Open database port reachable on the network risks unauthorized access.",
           "Restrict listen_addresses to localhost/trusted hosts; firewall it."),
    27017: ("mongodb", "high", "MongoDB exposed",
            "MongoDB has historically shipped with no auth; exposure risks full "
            "data disclosure.",
            "Enable authentication and bind to localhost/trusted subnet only."),
    6379: ("redis", "high", "Redis exposed",
           "Redis often has no auth by default and can be abused for RCE if "
           "reachable on the network.",
           "Bind to localhost, set requirepass, and enable protected-mode."),
    9200: ("elasticsearch", "high", "Elasticsearch exposed",
           "Open Elasticsearch frequently exposes all indexed data without auth.",
           "Enable security/auth and restrict to localhost/trusted hosts."),
    11211: ("memcached", "high", "Memcached exposed",
            "Open memcached can leak cached data and be abused for DDoS "
            "amplification.",
            "Bind to localhost; disable UDP; firewall the port."),
    5900: ("vnc", "high", "VNC exposed",
           "VNC remote control is often weakly authenticated and unencrypted.",
           "Tunnel VNC over SSH/VPN; require strong auth; restrict access."),
    2049: ("nfs", "medium", "NFS exposed",
           "NFS exports may allow unauthorized file access if host/export rules "
           "are loose.",
           "Restrict exports to specific hosts; consider Kerberos (sec=krb5)."),
    161: ("snmp", "medium", "SNMP exposed",
          "SNMP with default community strings (public/private) leaks device "
          "config and may allow changes.",
          "Disable SNMP if unused; use SNMPv3 with auth; change community strings."),
    25: ("smtp", "low", "SMTP exposed",
         "Open SMTP may be probed for relay abuse.",
         "Ensure the server is not an open relay; restrict to trusted senders."),
    3000: ("dev-http", "low", "Development HTTP service exposed",
           "Dev servers (e.g. Node/Grafana) often lack hardening and may expose "
           "debug endpoints.",
           "Do not expose dev services on the LAN; bind to localhost."),
    5984: ("couchdb", "high", "CouchDB exposed",
           "CouchDB has had unauthenticated-admin issues; exposure risks data loss.",
           "Enable admin auth and restrict bind address."),
}

# Generic well-known port -> service name (for non-risky identification).
PORT_SERVICE = {
    20: "ftp-data", 22: "ssh", 25: "smtp", 37: "time", 53: "domain",
    67: "dhcp", 69: "tftp", 79: "finger", 80: "http", 81: "http-alt",
    88: "kerberos", 102: "iso-tsap", 110: "pop3", 111: "rpcbind",
    113: "ident", 119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 143: "imap", 179: "bgp", 389: "ldap", 427: "svrloc",
    443: "https", 465: "smtps", 500: "isakmp", 514: "syslog", 515: "printer",
    520: "rip", 548: "afp", 554: "rtsp", 587: "submission", 623: "ipmi",
    631: "ipp", 636: "ldaps", 873: "rsync", 902: "vmware", 989: "ftps-data",
    990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks", 1099: "rmi",
    1194: "openvpn", 1521: "oracle", 1701: "l2tp", 1723: "pptp", 1883: "mqtt",
    2222: "ssh-alt", 3128: "squid", 3260: "iscsi", 3478: "stun",
    4444: "metasploit?", 5000: "upnp/http", 5060: "sip", 5357: "wsdapi",
    5555: "adb/freeciv", 5601: "kibana", 5672: "amqp", 5800: "vnc-http",
    5985: "winrm-http", 5986: "winrm-https", 6000: "x11", 6667: "irc",
    7000: "http-alt", 7070: "realserver", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8082: "http-alt", 8088: "http-alt",
    8123: "homeassistant", 8443: "https-alt", 8554: "rtsp-alt",
    8888: "http-alt", 9000: "http-alt", 9090: "http-alt", 9100: "jetdirect",
    10000: "webmin", 32400: "plex", 49152: "upnp", 62078: "iphone-sync",
}

# Ports where an unencrypted HTTP admin interface is plausible -> low finding.
HTTP_ADMIN_PORTS = {80, 81, 8080, 8000, 8008, 8081, 8082, 8088, 8888, 9000,
                    10000, 8123, 9090}


def grab_banner(ip, port, timeout):
    """Best-effort banner grab. Sends a light probe for HTTP-ish ports."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) != 0:
                return None  # not actually open
            # For HTTP-ish ports, nudge the server to respond.
            if port in (80, 81, 8080, 8000, 8008, 8081, 8082, 8088, 8888,
                        9000, 3000, 10000, 8123):
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: scan\r\n\r\n")
                except OSError:
                    pass
            try:
                data = sock.recv(256)
            except (socket.timeout, OSError):
                return ""  # open but silent
            return data.decode("latin-1", "replace").strip()
    except OSError:
        return None


def scan_port(ip, port, timeout):
    """Return (port, banner) if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                # Connected: try a quick banner on a fresh connection.
                banner = grab_banner(ip, port, timeout)
                return (port, banner if banner is not None else "")
    except OSError:
        return None
    return None


def identify_service(port, banner):
    """Pick a service name from banner hints, else the port map."""
    b = (banner or "").lower()
    if "ssh-" in b:
        return "ssh"
    if "http/" in b or "server:" in b:
        return PORT_SERVICE.get(port, "http")
    if "smtp" in b or b.startswith("220") and "ftp" not in b and "smtp" in b:
        return "smtp"
    if "ftp" in b or b.startswith("220") and "ftp" in b:
        return "ftp"
    if "mysql" in b:
        return "mysql"
    if "redis" in b or "-err" in b:
        return "redis"
    return PORT_SERVICE.get(port, f"tcp/{port}")


def is_smb_v1_suspect(port, banner):
    """Heuristic: SMB on 139/445 -- flag SMBv1 risk (banner rarely reveals
    version over a plain connect, so we raise an informational SMBv1 check)."""
    return port in (139, 445)


def build_findings(ip, open_ports):
    """Produce schema-shaped findings for a host's open ports."""
    findings = []
    for port, banner in open_ports:
        if port in RISKY_SERVICES:
            svc, sev, title, detail, rec = RISKY_SERVICES[port]
            extra = f" Banner: {banner[:120]}" if banner else ""
            findings.append({
                "host": ip, "port": port, "service": svc, "severity": sev,
                "title": title, "detail": detail + extra, "recommendation": rec,
            })
            # SMB ports: add an explicit SMBv1 check note.
            if port in (139, 445):
                findings.append({
                    "host": ip, "port": port, "service": svc, "severity": "high",
                    "title": "Verify SMBv1 is disabled",
                    "detail": "SMB service reachable; SMBv1 (if enabled) is "
                              "wormable (EternalBlue). A plain TCP connect cannot "
                              "confirm the dialect, so verify manually.",
                    "recommendation": "On Windows: disable the SMB1 feature; "
                                      "confirm via Get-SmbServerConfiguration.",
                })
        elif port in HTTP_ADMIN_PORTS:
            # Unencrypted HTTP admin interface -> low finding.
            svc = identify_service(port, banner)
            findings.append({
                "host": ip, "port": port, "service": svc, "severity": "low",
                "title": "Unencrypted HTTP service exposed",
                "detail": "An HTTP (non-TLS) service is reachable; if it serves "
                          "an admin/login UI, credentials travel in cleartext."
                          + (f" Banner: {banner[:120]}" if banner else ""),
                "recommendation": "Use HTTPS/TLS for any admin interface; restrict "
                                  "access to trusted hosts.",
            })
    return findings


def expand_targets(args):
    """Resolve the requested targets into a flat list of IP strings."""
    targets = []
    if args.from_json:
        try:
            with open(args.from_json, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for host in data.get("hosts", []):
                if host.get("ip"):
                    targets.append(host["ip"])
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            print(f"[!] Could not read --from-json {args.from_json}: {exc}",
                  file=sys.stderr)
            sys.exit(2)
    if args.target:
        for chunk in args.target.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "/" in chunk:
                try:
                    net = ipaddress.ip_network(chunk, strict=False)
                    hosts = (net.hosts() if net.num_addresses > 2
                             else [net.network_address])
                    targets.extend(str(h) for h in hosts)
                except ValueError as exc:
                    print(f"[!] Invalid CIDR {chunk}: {exc}", file=sys.stderr)
                    sys.exit(2)
            else:
                targets.append(chunk)
    # De-duplicate, preserve order.
    seen, ordered = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            ordered.append(t)
    return ordered


def resolve_ports(args):
    """Determine the port list from --ports / --top / --full / default."""
    if args.full:
        return list(range(1, 65536))
    if args.ports:
        ports = set()
        for token in args.ports.split(","):
            token = token.strip()
            if "-" in token:
                lo, hi = token.split("-", 1)
                ports.update(range(int(lo), int(hi) + 1))
            elif token:
                ports.add(int(token))
        return sorted(ports)
    if args.top:
        return TOP_PORTS[:args.top]
    return DEFAULT_PORTS


def scan_host(ip, ports, timeout, threads):
    """Scan all ports of one host; return sorted list of (port, banner)."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(scan_port, ip, p, timeout) for p in ports]
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(res)
    return sorted(open_ports)


def main():
    parser = argparse.ArgumentParser(
        description="Threaded TCP port + service scanner (AUTHORIZED NETWORKS "
                    "ONLY).",
        epilog="Example: python port-service-scan.py 192.168.1.10 --json scan.json")
    parser.add_argument("target", nargs="?",
                        help="IP, comma-list, or CIDR to scan "
                             "(e.g. 192.168.1.10 or 192.168.1.0/24).")
    parser.add_argument("--from-json",
                        help="Load hosts to scan from a host-discovery JSON file.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--ports",
                       help="Explicit ports/ranges, e.g. '22,80,443,8000-8100'.")
    group.add_argument("--top", type=int, metavar="N",
                       help="Scan the top N common ports.")
    group.add_argument("--full", action="store_true",
                       help="Scan all 65535 TCP ports (slow).")
    parser.add_argument("--timeout", type=float, default=0.7,
                        help="Per-port connect timeout in seconds (default: 0.7).")
    parser.add_argument("--threads", type=int, default=200,
                        help="Concurrent threads per host (default: 200).")
    parser.add_argument("--json", dest="json_out",
                        help="Write results to this JSON file (shared schema).")
    args = parser.parse_args()

    print("=" * 78)
    print("AUTHORIZED NETWORKS ONLY -- scan only hosts you own/are authorized "
          "to test.")
    print("=" * 78)

    if not args.target and not args.from_json:
        parser.error("provide a target or --from-json")

    targets = expand_targets(args)
    ports = resolve_ports(args)
    if not targets:
        print("[!] No targets to scan.", file=sys.stderr)
        sys.exit(2)

    print(f"[*] Scanning {len(targets)} host(s) across {len(ports)} port(s) "
          f"each. Timeout {args.timeout}s, {args.threads} threads/host.\n")

    all_hosts, all_findings = [], []
    for ip in targets:
        open_ports = scan_host(ip, ports, args.timeout, args.threads)
        state = "up" if open_ports else "unknown"
        all_hosts.append({
            "ip": ip, "mac": "", "vendor": "", "hostname": "", "state": state,
        })
        if not open_ports:
            print(f"[-] {ip}: no open ports in the scanned set.")
            continue
        print(f"[+] {ip}: {len(open_ports)} open port(s)")
        for port, banner in open_ports:
            svc = identify_service(port, banner)
            shown = f"  ({banner[:60]})" if banner else ""
            print(f"      {port:>5}/tcp  {svc:<14}{shown}")
        host_findings = build_findings(ip, open_ports)
        all_findings.extend(host_findings)

    # Findings summary.
    print("\n" + "=" * 78)
    print("FINDINGS")
    print("=" * 78)
    if not all_findings:
        print("No risky exposed services detected in the scanned ports.")
    else:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(all_findings, key=lambda x: order.get(x["severity"], 5)):
            print(f"[{f['severity'].upper():<8}] {f['host']}:{f['port']} "
                  f"{f['title']}")
            print(f"           {f['detail']}")
            print(f"           -> {f['recommendation']}")

    target_label = args.target or f"from-json:{args.from_json}"
    output = {
        "tool": "port-service-scan",
        "target": target_label,
        "hosts": all_hosts,
        "findings": all_findings,
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
