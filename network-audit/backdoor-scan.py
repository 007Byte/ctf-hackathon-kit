#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  backdoor-scan.py  --  Backdoor / suspicious-service indicator scanner
#  Part of the Home-Network Security Audit suite.
#
#  ***************************************************************************
#  *  AUTHORIZED NETWORKS ONLY.                                            *
#  *  Scanning hosts you do not own may be ILLEGAL. Run this ONLY against  *
#  *  equipment you own or are explicitly authorized in writing to test.   *
#  ***************************************************************************
#
#  Purpose: Scan hosts on YOUR OWN network for INDICATORS of backdoors,
#  RATs/trojans, and exposed remote-admin services, so a defender can
#  investigate. These are INDICATORS, NOT PROOF -- legitimate software can
#  reuse any port, and attackers can change ports. Treat every hit as a
#  lead to verify, not a confirmed compromise.
#
#  Checks performed:
#    * Known RAT / backdoor / trojan default ports (curated, cited list).
#    * Unexpected open Telnet (23) -- cleartext remote admin.
#    * Android ADB (5555) exposed -- remote shell with no auth by default.
#    * VNC (5900/5901) -- flagged; unauthenticated VNC is high severity.
#    * Banner vs. port mismatch (e.g. a shell-like banner on a high port,
#      or an SSH/HTTP banner on an unexpected port).
#    * Metasploit / meterpreter handler signatures (default 4444, etc.).
#
#  Modes:
#    * --from-json : reuse a prior port-service-scan.json (shared schema) and
#      analyze the already-discovered open ports (no new connections unless
#      --grab-banners is set).
#    * direct scan : connect-scan a host/range over the curated port list.
#
#  Cross-platform: pure Python 3 standard library. Works on Windows & Linux.
# =============================================================================

import argparse
import ipaddress
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

TOOL_NAME = "backdoor-scan"

# ---------------------------------------------------------------------------
# Curated known-bad / suspicious port catalog.
#
# Sources (consulted June 2026):
#   * Back Orifice -> 31337 ; NetBus -> 12345/12346
#     https://en.wikipedia.org/wiki/NetBus , https://www.irchelp.org/security/netbus
#   * SubSeven/Sub7 -> 27374 ; Bifrost -> 81
#     https://en.wikipedia.org/wiki/Bifrost_(Trojan_horse)
#   * Metasploit/meterpreter default handler -> 4444 (and 4445)
#   * Gary Kessler "Bad" TCP/UDP Ports list
#     https://www.garykessler.net/library/bad_ports.html
#   * General trojan port tables (chebucto, trendmicro glossary)
#
# Each entry: severity + a short, accurate explanation. "1337"/"31337" and
# "4444" are classic attacker conventions ("leet"); legitimate use is rare on
# a home LAN, hence we flag them -- but always as INDICATORS to investigate.
# ---------------------------------------------------------------------------
SUSPICIOUS_PORTS = {
    81:    ("medium",   "Bifrost trojan default / alt-HTTP", "Bifrost RAT default port; also used as an alternate HTTP port. Verify what is listening."),
    1080:  ("medium",   "Open SOCKS proxy", "Open SOCKS proxies are abused for C2 relay and traffic laundering; an exposed one on a LAN is suspicious."),
    1337:  ("high",     "'leet' backdoor port", "Port 1337 is a hacker-culture convention frequently used by backdoors/bind shells."),
    2222:  ("low",      "Alt-SSH / some RATs", "Common alternate SSH port; also used by some malware. Confirm it is your own SSH."),
    3127:  ("high",     "MyDoom backdoor", "MyDoom worm backdoor listener."),
    3389:  ("medium",   "RDP exposed", "Remote Desktop exposed on the LAN; if reachable from WAN this is a major risk. Ensure NLA and strong creds."),
    4444:  ("high",     "Metasploit/Meterpreter default handler", "TCP 4444 is the default Metasploit reverse/bind shell handler port. Strong indicator of a payload listener."),
    4445:  ("high",     "Metasploit alt handler", "Common secondary Metasploit handler port."),
    4899:  ("medium",   "Radmin remote admin", "Radmin remote-administration tool; legitimate but should not be unexpected/exposed."),
    5400:  ("high",     "Back Construction / Blade Runner", "Known trojan listener port."),
    5555:  ("high",     "Android ADB / various RATs", "Android Debug Bridge listens here; if open it grants an UNAUTHENTICATED remote shell to the device. Also used by some RATs."),
    5800:  ("medium",   "VNC over HTTP (Java viewer)", "VNC web interface; verify it is authenticated."),
    5900:  ("high",     "VNC remote desktop", "VNC remote desktop. UNAUTHENTICATED or weakly-authenticated VNC gives full GUI control. Investigate auth."),
    5901:  ("high",     "VNC display :1", "Secondary VNC display; same risk as 5900."),
    6000:  ("medium",   "X11 server exposed", "An exposed X11 server can leak keystrokes/screen and allow input injection."),
    6667:  ("high",     "IRC -- common botnet C2", "IRC is heavily used for botnet command-and-control. Unexpected IRC on a host is a strong C2 indicator."),
    6668:  ("high",     "IRC -- common botnet C2", "Alternate IRC C2 port."),
    6669:  ("high",     "IRC -- common botnet C2", "Alternate IRC C2 port."),
    6697:  ("medium",   "IRC over TLS", "Encrypted IRC; can also be used for botnet C2."),
    7000:  ("medium",   "IRC range / various trojans", "Upper IRC range; also used by assorted trojans."),
    9001:  ("medium",   "Tor ORPort / Supydog trojan", "Default Tor relay ORPort; also a known trojan port. Investigate which it is."),
    9999:  ("medium",   "Common bind-shell / misc backdoors", "Frequently chosen for ad-hoc bind shells and several backdoors."),
    12345: ("high",     "NetBus trojan", "NetBus remote-control trojan default port."),
    12346: ("high",     "NetBus trojan (alt)", "NetBus secondary default port."),
    16660: ("high",     "Stacheldraht DDoS agent", "Stacheldraht distributed-DoS handler/agent port."),
    20034: ("high",     "NetBus 2 Pro", "NetBus 2.0 Pro trojan port."),
    27374: ("high",     "SubSeven / Sub7 trojan", "SubSeven (Sub7) RAT default port -- classic Windows backdoor."),
    27665: ("high",     "Trinoo DDoS master", "Trinoo distributed-DoS master control port."),
    31337: ("critical", "Back Orifice ('eleet') backdoor", "Port 31337 is the iconic Back Orifice backdoor port and a hacker-culture marker. Highly suspicious."),
    31338: ("high",     "Back Orifice / DeepBO", "Back Orifice variant / DeepBO port."),
    54320: ("high",     "Back Orifice 2000", "BO2K trojan port."),
    54321: ("high",     "Back Orifice 2000 / SchoolBus", "BO2K / SchoolBus trojan port."),
    65000: ("medium",   "Devil / misc backdoors", "Used by the 'Devil' trojan and other backdoors."),
}

# Ports where cleartext or remote-admin services warrant a specific note even
# though they are "normal" services. Handled separately from the trojan list.
REMOTE_ADMIN_NOTES = {
    23:   ("medium", "Telnet (cleartext remote admin)",
           "Telnet sends credentials and sessions in CLEARTEXT and is a top "
           "target for IoT botnets (e.g. Mirai). It should almost never be "
           "open on a home network.",
           "Disable Telnet and use SSH instead. If a device only offers "
           "Telnet, restrict it to the LAN and change default credentials."),
}

# Banner keyword -> what it implies, for banner/port mismatch detection.
SHELL_BANNER_TOKENS = ["microsoft windows", "command prompt", "/bin/sh",
                       "bash", "$ ", "# ", "meterpreter", "msf", "shell"]


# ---------------------------------------------------------------------------
# Report schema helpers
# ---------------------------------------------------------------------------
def new_report(target):
    return {
        "tool": TOOL_NAME,
        "target": target,
        "generated": datetime.now(timezone.utc).isoformat(),
        "hosts": [],
        "findings": [],
    }


def add_host(report, ip):
    for h in report["hosts"]:
        if h["ip"] == ip:
            return
    report["hosts"].append(
        {"ip": ip, "mac": "", "vendor": "", "hostname": "", "state": "up"}
    )


def add_finding(report, host, port, service, severity, title, detail, recommendation):
    report["findings"].append(
        {
            "host": host,
            "port": port,
            "service": service,
            "severity": severity,
            "title": title,
            "detail": detail,
            "recommendation": recommendation,
        }
    )


# ---------------------------------------------------------------------------
# Networking helpers
# ---------------------------------------------------------------------------
def tcp_connect(ip, port, timeout):
    """Return True if a TCP connect to (ip, port) succeeds."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def grab_banner(ip, port, timeout):
    """Best-effort banner grab. Returns a decoded string (may be empty)."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        # For HTTP-ish ports, nudge the server to talk.
        if port in (80, 81, 8080, 8443, 443):
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            except Exception:
                pass
        data = b""
        try:
            data = s.recv(256)
        except Exception:
            pass
        s.close()
        return data.decode("latin-1", errors="replace").strip()
    except Exception:
        return ""


def expand_targets(target):
    """Expand a single IP or CIDR (e.g. 192.168.1.0/24) into a list of IPs.

    A bare hostname is returned as-is (resolved by the socket layer later).
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses == 1:
            return [str(net.network_address)]
        return [str(h) for h in net.hosts()]
    except ValueError:
        return [target]


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def analyze_open_port(report, ip, port, service, banner, args):
    """Apply all indicator rules to a single open port."""
    svc = (service or "").lower()

    # 1) Known trojan / backdoor / RAT port.
    if port in SUSPICIOUS_PORTS:
        sev, title, detail = SUSPICIOUS_PORTS[port]
        rec = ("INVESTIGATE: identify the process bound to this port "
               "(e.g. `netstat -anob` on Windows, `ss -tlnp`/`lsof -i` on "
               "Linux). If you did not intentionally run this service, treat "
               "the host as potentially compromised: isolate it, scan for "
               "malware, and review startup items.")
        if port == 5555:
            rec = ("If this is an Android device, DISABLE 'USB/Wireless "
                   "debugging' (ADB). Open ADB grants an unauthenticated "
                   "remote shell. " + rec)
        if port in (5900, 5901):
            rec = ("Ensure VNC requires a strong password (or disable it). "
                   "Never expose VNC to the WAN. " + rec)
        add_finding(report, ip, port, svc or "unknown", sev,
                    "Suspicious port open: %d (%s)" % (port, title),
                    "%s This is an INDICATOR, not proof." % detail, rec)

    # 2) Remote-admin / cleartext service notes (e.g. Telnet).
    if port in REMOTE_ADMIN_NOTES:
        sev, title, detail, rec = REMOTE_ADMIN_NOTES[port]
        add_finding(report, ip, port, svc or "telnet", sev, title, detail, rec)

    # 3) Banner vs. port mismatch + shell signatures.
    if banner:
        low = banner.lower()
        # Shell-like banner anywhere is a strong indicator of a bind shell.
        for tok in SHELL_BANNER_TOKENS:
            if tok in low:
                add_finding(
                    report, ip, port, svc or "unknown", "high",
                    "Shell-like banner on port %d" % port,
                    "The banner on %s:%d contains '%s', which looks like an "
                    "interactive shell or Metasploit/meterpreter handler rather "
                    "than a normal service. Banner snippet: %r"
                    % (ip, port, tok, banner[:120]),
                    "Investigate immediately -- a listening shell is a strong "
                    "backdoor indicator. Identify and terminate the process.",
                )
                break
        # SSH banner on a non-22 port (could be legit alt-SSH, but note it).
        if low.startswith("ssh-") and port not in (22, 2222):
            add_finding(
                report, ip, port, "ssh", "low",
                "SSH banner on unexpected port %d" % port,
                "An SSH service is answering on port %d (banner %r). This may "
                "be legitimate alternate SSH or a relocated service."
                % (port, banner[:80]),
                "Confirm you intentionally run SSH on this port.",
            )
        # HTTP banner on a classic trojan port.
        if ("http" in low or "server:" in low) and port in (1337, 4444, 31337):
            add_finding(
                report, ip, port, "http", "high",
                "HTTP service on classic backdoor port %d" % port,
                "An HTTP-like service responds on a port commonly used by "
                "backdoors. Banner %r." % banner[:80],
                "Identify the web service; backdoors often expose an HTTP C2 "
                "panel on these ports.",
            )


def scan_host_direct(ip, ports, args):
    """Connect-scan a host over the given ports; return list of open (port,banner)."""
    open_ports = []

    def check(p):
        if tcp_connect(ip, p, args.timeout):
            banner = grab_banner(ip, p, args.timeout) if args.grab_banners else ""
            return (p, banner)
        return None

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(check, p): p for p in ports}
        for fut in as_completed(futures):
            res = fut.result()
            if res is not None:
                open_ports.append(res)
    open_ports.sort()
    return open_ports


# ---------------------------------------------------------------------------
# From-JSON ingestion
# ---------------------------------------------------------------------------
def analyze_from_json(report, path, args):
    """Analyze open ports recorded in a prior scan JSON (shared schema)."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Carry over host records.
    for h in data.get("hosts", []):
        ip = h.get("ip")
        if ip:
            add_host(report, ip)
            # preserve known metadata
            for rec in report["hosts"]:
                if rec["ip"] == ip:
                    rec["mac"] = h.get("mac", "") or rec["mac"]
                    rec["vendor"] = h.get("vendor", "") or rec["vendor"]
                    rec["hostname"] = h.get("hostname", "") or rec["hostname"]

    # The shared schema records open services as findings with host/port/service.
    analyzed = 0
    for fnd in data.get("findings", []):
        ip = fnd.get("host")
        port = fnd.get("port")
        service = fnd.get("service", "")
        if not ip or not port:
            continue
        add_host(report, ip)
        banner = fnd.get("detail", "") if args.grab_banners else ""
        # Optionally re-grab a live banner for richer mismatch detection.
        if args.grab_banners:
            live = grab_banner(ip, port, args.timeout)
            if live:
                banner = live
        analyze_open_port(report, ip, port, service, banner, args)
        analyzed += 1

    print("[*] Analyzed %d open service(s) from %s" % (analyzed, path))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_summary(report):
    print("\n" + "=" * 70)
    print("SUMMARY -- %s" % TOOL_NAME)
    print("=" * 70)
    print("Target : %s" % report["target"])
    print("Hosts  : %d" % len(report["hosts"]))
    sev_order = ["critical", "high", "medium", "low", "info"]
    counts = {s: 0 for s in sev_order}
    for f in report["findings"]:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    print("Findings by severity: " +
          ", ".join("%s=%d" % (s, counts.get(s, 0)) for s in sev_order))
    print("-" * 70)
    if not report["findings"]:
        print("No suspicious indicators found on the scanned ports.")
    for sev in sev_order:
        for f in report["findings"]:
            if f["severity"] == sev:
                print("[%s] %s:%s  %s" % (sev.upper(), f["host"], f["port"],
                                          f["title"]))
                print("    %s" % f["detail"])
                print("    -> %s" % f["recommendation"])
    print("-" * 70)
    print("NOTE: These are INDICATORS to investigate, NOT proof of compromise.")
    print("Legitimate software may reuse these ports; attackers may relocate.")
    print("=" * 70)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description="Scan hosts for backdoor / RAT / suspicious-service "
                    "INDICATORS. AUTHORIZED NETWORKS ONLY.",
        epilog="Examples:\n"
               "  python backdoor-scan.py 192.168.1.10 --grab-banners\n"
               "  python backdoor-scan.py 192.168.1.0/24 --json out.json\n"
               "  python backdoor-scan.py --from-json port-service-scan.json --grab-banners\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?",
                   help="IP, hostname, or CIDR (e.g. 192.168.1.0/24) to scan.")
    p.add_argument("--from-json", dest="from_json",
                   help="Analyze open ports from a prior scan JSON (shared schema).")
    p.add_argument("--json", dest="json_out",
                   help="Write results to this JSON file (shared schema).")
    p.add_argument("--ports", default=None,
                   help="Comma-separated extra ports to add to the curated list "
                        "(e.g. 8081,9000). The curated suspicious/admin ports are "
                        "always included for a direct scan.")
    p.add_argument("--grab-banners", action="store_true", dest="grab_banners",
                   help="Grab service banners for banner/port mismatch detection "
                        "(makes one extra connection per open port).")
    p.add_argument("--timeout", type=float, default=2.0,
                   help="Per-connection timeout in seconds (default: 2.0).")
    p.add_argument("--workers", type=int, default=50,
                   help="Concurrent connect-scan workers (default: 50).")
    return p


def main():
    args = build_parser().parse_args()

    print("=" * 70)
    print(" backdoor-scan  --  AUTHORIZED NETWORKS ONLY")
    print(" Scanning hosts you do not own may be ILLEGAL. Findings are")
    print(" INDICATORS to investigate, NOT proof of compromise.")
    print("=" * 70)

    if not args.target and not args.from_json:
        print("[ERROR] Provide a target to scan or --from-json.")
        sys.exit(2)

    label = args.from_json if args.from_json else args.target
    report = new_report(label)

    if args.from_json:
        analyze_from_json(report, args.from_json, args)

    if args.target:
        # Build the port list: curated suspicious + remote-admin + user extras.
        ports = sorted(set(SUSPICIOUS_PORTS.keys())
                       | set(REMOTE_ADMIN_NOTES.keys()))
        if args.ports:
            try:
                ports = sorted(set(ports)
                               | {int(x) for x in args.ports.split(",") if x.strip()})
            except ValueError:
                print("[ERROR] --ports must be comma-separated integers.")
                sys.exit(2)

        ips = expand_targets(args.target)
        print("[*] Direct scan: %d host(s) x %d port(s) (timeout %.1fs, %d workers)"
              % (len(ips), len(ports), args.timeout, args.workers))
        if args.grab_banners:
            print("[*] Banner grabbing enabled.")

        for ip in ips:
            open_ports = scan_host_direct(ip, ports, args)
            if open_ports:
                add_host(report, ip)
                print("  [%s] open suspicious/admin ports: %s"
                      % (ip, ", ".join(str(p) for p, _ in open_ports)))
                for port, banner in open_ports:
                    analyze_open_port(report, ip, port, "", banner, args)

    print_summary(report)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print("\n[+] JSON written to %s" % args.json_out)


if __name__ == "__main__":
    main()
