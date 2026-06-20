#!/usr/bin/env python3
"""
pcap-analyzer.py - Comprehensive PCAP triage tool for CTF / lab work.

AUTHORIZED USE ONLY: This tool is intended for analysing packet captures from
CTF challenges, your own lab traffic, or captures you are explicitly authorised
to inspect. Do not use it against traffic you have no permission to handle.

Subcommands:
    summary   Protocol/port breakdown, packet counts, timespan, top talkers
    dns       List all DNS queries and responses
    http      Extract HTTP requests (method/host/uri/UA) and responses
    creds     Hunt cleartext credentials (Basic auth, FTP, Telnet, POST, mail)
    streams   Reassemble and dump a chosen TCP stream
    flags     Search payloads for flag patterns (+ a base64-decode pass)

Pure scapy + stdlib. Runs on Linux/Kali and Windows (Python is cross-platform).

Examples:
    python3 pcap-analyzer.py summary capture.pcap
    python3 pcap-analyzer.py dns capture.pcap
    python3 pcap-analyzer.py http capture.pcap
    python3 pcap-analyzer.py creds capture.pcap
    python3 pcap-analyzer.py streams capture.pcap --list
    python3 pcap-analyzer.py streams capture.pcap --index 3
    python3 pcap-analyzer.py flags capture.pcap --regex 'MYCTF\\{[^}]+\\}'
"""

import sys
import os
import argparse
import base64
import re
import binascii
from collections import defaultdict, Counter

# ---------------------------------------------------------------------------
# Graceful scapy import
# ---------------------------------------------------------------------------
try:
    # Silence scapy's noisy IPv6 / runtime warnings on import.
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import (
        rdpcap, Packet, Raw,
        Ether, IP, IPv6, TCP, UDP, ARP, ICMP,
        DNS, DNSQR, DNSRR,
    )
    # HTTP layers are optional depending on scapy version.
    try:
        from scapy.layers.http import HTTPRequest, HTTPResponse, HTTP
        HAVE_HTTP_LAYER = True
    except Exception:
        HAVE_HTTP_LAYER = False
except ImportError:
    sys.stderr.write(
        "[!] scapy is not installed.\n"
        "    Install it with:  pip install scapy\n"
        "    (On Kali it is usually preinstalled; otherwise: sudo apt install python3-scapy)\n"
    )
    sys.exit(2)


# ---------------------------------------------------------------------------
# Colour helpers (degrade gracefully when not a TTY or on dumb terminals)
# ---------------------------------------------------------------------------
class C:
    """ANSI colour codes; blanked out when stdout is not a TTY."""
    enabled = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"

    RESET = "\033[0m" if enabled else ""
    BOLD = "\033[1m" if enabled else ""
    RED = "\033[31m" if enabled else ""
    GREEN = "\033[32m" if enabled else ""
    YELLOW = "\033[33m" if enabled else ""
    BLUE = "\033[34m" if enabled else ""
    MAGENTA = "\033[35m" if enabled else ""
    CYAN = "\033[36m" if enabled else ""


def hdr(text):
    """Print a section header."""
    print(f"\n{C.BOLD}{C.CYAN}=== {text} ==={C.RESET}")


def info(text):
    print(f"{C.GREEN}{text}{C.RESET}")


def warn(text):
    print(f"{C.YELLOW}[!] {text}{C.RESET}")


def hit(text):
    print(f"{C.RED}{C.BOLD}{text}{C.RESET}")


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def load_pcap(path):
    """Load a pcap/pcapng file, returning a PacketList. Exits on failure."""
    if not os.path.isfile(path):
        sys.stderr.write(f"[!] File not found: {path}\n")
        sys.exit(1)
    try:
        # rdpcap transparently handles .pcap and .pcapng.
        packets = rdpcap(path)
    except Exception as exc:
        sys.stderr.write(f"[!] Failed to read pcap '{path}': {exc}\n")
        sys.exit(1)
    if len(packets) == 0:
        warn("Capture loaded but contains 0 packets.")
    return packets


def safe_decode(data):
    """Decode bytes to a printable-ish string without throwing."""
    if isinstance(data, str):
        return data
    return data.decode("utf-8", errors="replace")


def get_l3(pkt):
    """Return (src, dst) IP-ish addresses for a packet, or (None, None)."""
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    if pkt.haslayer(ARP):
        return pkt[ARP].psrc, pkt[ARP].pdst
    return None, None


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------
def cmd_summary(packets, args):
    hdr("Capture Summary")
    total = len(packets)
    print(f"Total packets : {C.BOLD}{total}{C.RESET}")

    # Capture timespan (packet.time is a float/EDecimal epoch timestamp).
    if total:
        times = [float(p.time) for p in packets]
        start, end = min(times), max(times)
        from datetime import datetime, timezone
        s = datetime.fromtimestamp(start, tz=timezone.utc)
        e = datetime.fromtimestamp(end, tz=timezone.utc)
        print(f"First packet  : {s.isoformat()}")
        print(f"Last packet   : {e.isoformat()}")
        print(f"Duration      : {end - start:.3f} s")

    proto_counter = Counter()
    l4_port_counter = Counter()         # (proto, port) -> count
    talkers_bytes = defaultdict(int)    # (src,dst) -> bytes
    talkers_pkts = defaultdict(int)     # (src,dst) -> packets
    total_bytes = 0

    for pkt in packets:
        total_bytes += len(pkt)

        # Highest-level protocol name we can name.
        if pkt.haslayer(DNS):
            proto_counter["DNS"] += 1
        elif HAVE_HTTP_LAYER and pkt.haslayer(HTTP):
            proto_counter["HTTP"] += 1
        elif pkt.haslayer(TCP):
            proto_counter["TCP"] += 1
        elif pkt.haslayer(UDP):
            proto_counter["UDP"] += 1
        elif pkt.haslayer(ICMP):
            proto_counter["ICMP"] += 1
        elif pkt.haslayer(ARP):
            proto_counter["ARP"] += 1
        elif pkt.haslayer(IPv6):
            proto_counter["IPv6-other"] += 1
        elif pkt.haslayer(IP):
            proto_counter["IP-other"] += 1
        else:
            proto_counter["other"] += 1

        # Port accounting (use dst port as the "service" heuristic).
        if pkt.haslayer(TCP):
            l4_port_counter[("TCP", int(pkt[TCP].dport))] += 1
        elif pkt.haslayer(UDP):
            l4_port_counter[("UDP", int(pkt[UDP].dport))] += 1

        # Talkers.
        src, dst = get_l3(pkt)
        if src and dst:
            key = (src, dst)
            talkers_bytes[key] += len(pkt)
            talkers_pkts[key] += 1

    print(f"Total bytes   : {total_bytes}")

    hdr("Protocol breakdown")
    for proto, cnt in proto_counter.most_common():
        pct = (cnt / total * 100) if total else 0
        print(f"  {proto:<12} {cnt:>8}  ({pct:5.1f}%)")

    hdr("Top destination ports")
    for (proto, port), cnt in l4_port_counter.most_common(15):
        svc = WELL_KNOWN_PORTS.get(port, "")
        svc = f" [{svc}]" if svc else ""
        print(f"  {proto}/{port:<6} {cnt:>8}{svc}")

    hdr("Top talkers (by bytes)")
    top = sorted(talkers_bytes.items(), key=lambda kv: kv[1], reverse=True)[:15]
    for (src, dst), nbytes in top:
        print(f"  {src:>22} -> {dst:<22} {nbytes:>10} bytes  "
              f"({talkers_pkts[(src, dst)]} pkts)")


WELL_KNOWN_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 123: "ntp", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 587: "smtp-sub", 993: "imaps",
    995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
    5060: "sip", 5432: "postgres", 6379: "redis", 8080: "http-alt",
    8443: "https-alt",
}


# ---------------------------------------------------------------------------
# dns
# ---------------------------------------------------------------------------
def cmd_dns(packets, args):
    hdr("DNS Queries & Responses")
    q_count = r_count = 0
    for pkt in packets:
        if not pkt.haslayer(DNS):
            continue
        dns = pkt[DNS]
        src, dst = get_l3(pkt)

        # Query (qr == 0) records.
        if dns.qr == 0 and dns.qdcount > 0 and pkt.haslayer(DNSQR):
            q_count += 1
            qname = safe_decode(pkt[DNSQR].qname).rstrip(".")
            qtype = qtype_name(pkt[DNSQR].qtype)
            print(f"{C.BLUE}[Q]{C.RESET} {src} -> {dst}  "
                  f"{C.BOLD}{qname}{C.RESET} ({qtype})")

        # Response (qr == 1) records.
        if dns.qr == 1 and dns.ancount > 0:
            r_count += 1
            # Walk the answer record chain.
            ans = dns.an
            answers = []
            for _ in range(dns.ancount):
                if ans is None:
                    break
                rrname = safe_decode(ans.rrname).rstrip(".")
                rtype = qtype_name(ans.type)
                rdata = ans.rdata
                if isinstance(rdata, bytes):
                    rdata = safe_decode(rdata)
                answers.append(f"{rrname} {rtype} -> {rdata}")
                ans = ans.payload if ans.payload and isinstance(ans.payload, DNSRR) else None
            for a in answers:
                print(f"{C.GREEN}[R]{C.RESET} {src} -> {dst}  {a}")

    print()
    info(f"{q_count} queries, {r_count} response packets with answers.")


# Minimal DNS type-code -> name map (covers the common CTF cases).
_DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 257: "CAA",
}


def qtype_name(code):
    try:
        return _DNS_TYPES.get(int(code), str(code))
    except Exception:
        return str(code)


# ---------------------------------------------------------------------------
# http
# ---------------------------------------------------------------------------
def _http_field(layer, name):
    """Fetch an HTTP header field from a scapy HTTP layer, decoded."""
    val = getattr(layer, name, None)
    if val is None:
        return None
    return safe_decode(val)


def cmd_http(packets, args):
    hdr("HTTP Traffic")
    if not HAVE_HTTP_LAYER:
        warn("scapy HTTP layer unavailable; falling back to raw payload parsing.")
        _http_raw_fallback(packets)
        return

    req_count = resp_count = 0
    for pkt in packets:
        src, dst = get_l3(pkt)

        if pkt.haslayer(HTTPRequest):
            req_count += 1
            r = pkt[HTTPRequest]
            method = _http_field(r, "Method") or "?"
            host = _http_field(r, "Host") or ""
            path = _http_field(r, "Path") or ""
            ua = _http_field(r, "User_Agent") or ""
            print(f"{C.BLUE}[REQ]{C.RESET} {src} -> {dst}  "
                  f"{C.BOLD}{method}{C.RESET} http://{host}{path}")
            if ua:
                print(f"        UA: {ua}")
            # Show body if present (e.g. POST data).
            if pkt.haslayer(Raw):
                body = safe_decode(pkt[Raw].load).strip()
                if body:
                    print(f"        BODY: {body[:300]}")

        if pkt.haslayer(HTTPResponse):
            resp_count += 1
            r = pkt[HTTPResponse]
            status = _http_field(r, "Status_Code") or "?"
            reason = _http_field(r, "Reason_Phrase") or ""
            ctype = _http_field(r, "Content_Type") or ""
            print(f"{C.GREEN}[RES]{C.RESET} {src} -> {dst}  "
                  f"{status} {reason}  {ctype}")

    print()
    info(f"{req_count} requests, {resp_count} responses.")


def _http_raw_fallback(packets):
    """Crude HTTP request/response detection from raw TCP payloads."""
    req_re = re.compile(rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ")
    for pkt in packets:
        if not pkt.haslayer(Raw):
            continue
        data = bytes(pkt[Raw].load)
        src, dst = get_l3(pkt)
        if req_re.match(data):
            line = safe_decode(data.split(b"\r\n", 1)[0])
            print(f"{C.BLUE}[REQ]{C.RESET} {src} -> {dst}  {line}")
        elif data.startswith(b"HTTP/"):
            line = safe_decode(data.split(b"\r\n", 1)[0])
            print(f"{C.GREEN}[RES]{C.RESET} {src} -> {dst}  {line}")


# ---------------------------------------------------------------------------
# creds
# ---------------------------------------------------------------------------
def cmd_creds(packets, args):
    hdr("Cleartext Credential Hunt")
    found = 0

    # Pre-compiled patterns for POST form / generic key=value credentials.
    form_re = re.compile(
        rb"(?i)\b(user(name)?|usr|login|email|passw(or)?d?|pass|pwd|pin)\b\s*=\s*([^\s&\"']+)"
    )

    for pkt in packets:
        if not pkt.haslayer(Raw):
            continue
        data = bytes(pkt[Raw].load)
        src, dst = get_l3(pkt)
        loc = f"{src} -> {dst}"

        # --- HTTP Basic auth ---
        m = re.search(rb"(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", data)
        if m:
            try:
                decoded = base64.b64decode(m.group(1)).decode("utf-8", "replace")
                hit(f"[HTTP Basic] {loc}  {decoded}")
                found += 1
            except Exception:
                pass

        # --- FTP USER / PASS ---
        for proto_re, label in (
            (rb"(?i)^USER\s+(.+)", "FTP USER"),
            (rb"(?i)^PASS\s+(.+)", "FTP PASS"),
        ):
            fm = re.search(proto_re, data)
            if fm:
                hit(f"[{label}] {loc}  {safe_decode(fm.group(1)).strip()}")
                found += 1

        # --- Mail AUTH (IMAP / POP3 / SMTP) ---
        # SMTP AUTH LOGIN / PLAIN often base64-encodes the credential lines.
        for am in re.finditer(rb"(?i)\bAUTH\s+(LOGIN|PLAIN|CRAM-MD5)\b", data):
            hit(f"[MAIL AUTH] {loc}  {safe_decode(am.group(0)).strip()}")
            found += 1
        # POP3 USER/PASS commands.
        for proto_re, label in (
            (rb"(?im)^USER\s+(.+)$", "POP3/IMAP USER"),
            (rb"(?im)^PASS\s+(.+)$", "POP3 PASS"),
        ):
            # Avoid double-counting FTP lines handled above by checking port.
            if pkt.haslayer(TCP) and int(pkt[TCP].dport) in (110, 143, 993, 995):
                pm = re.search(proto_re, data)
                if pm:
                    hit(f"[{label}] {loc}  {safe_decode(pm.group(1)).strip()}")
                    found += 1

        # --- Telnet (port 23) typed characters ---
        if pkt.haslayer(TCP) and 23 in (int(pkt[TCP].sport), int(pkt[TCP].dport)):
            text = safe_decode(data).strip()
            # Telnet often sends one char per packet; show non-trivial chunks.
            if text and all(31 < ord(c) < 127 or c in "\r\n\t" for c in text) and len(text) > 1:
                print(f"{C.MAGENTA}[Telnet]{C.RESET} {loc}  {text!r}")

        # --- POST form params with credential keywords ---
        # Only inspect what looks like HTTP request bodies / query strings.
        if b"=" in data and (b"POST " in data or b"GET " in data or b"&" in data):
            for fm in form_re.finditer(data):
                key = safe_decode(fm.group(1))
                val = safe_decode(fm.group(5))
                hit(f"[Form param] {loc}  {key}={val}")
                found += 1

    print()
    if found:
        info(f"{found} potential credential artefact(s) found.")
    else:
        warn("No cleartext credentials matched. (They may be encrypted or encoded.)")


# ---------------------------------------------------------------------------
# streams
# ---------------------------------------------------------------------------
def _stream_key(pkt):
    """Canonical bidirectional TCP stream key (sorted endpoint tuple)."""
    if not pkt.haslayer(TCP):
        return None
    src, dst = get_l3(pkt)
    if src is None:
        return None
    a = (src, int(pkt[TCP].sport))
    b = (dst, int(pkt[TCP].dport))
    return tuple(sorted((a, b)))


def _build_streams(packets):
    """Group TCP packets into streams. Returns ordered list of (key, [pkts])."""
    streams = {}
    order = []
    for pkt in packets:
        key = _stream_key(pkt)
        if key is None:
            continue
        if key not in streams:
            streams[key] = []
            order.append(key)
        streams[key].append(pkt)
    return [(k, streams[k]) for k in order]


def cmd_streams(packets, args):
    streams = _build_streams(packets)
    if not streams:
        warn("No TCP streams found.")
        return

    if args.list or (args.index is None and not args.filter):
        hdr("TCP Streams")
        for idx, (key, pkts) in enumerate(streams):
            (ip_a, port_a), (ip_b, port_b) = key
            nbytes = sum(len(p[Raw].load) for p in pkts if p.haslayer(Raw))
            print(f"  [{idx:>3}] {ip_a}:{port_a} <-> {ip_b}:{port_b}  "
                  f"{len(pkts)} pkts, {nbytes} payload bytes")
        print()
        info("Re-run with --index N to dump a stream.")
        return

    # Select a stream by index or by simple substring filter on endpoints.
    selected = None
    if args.index is not None:
        if 0 <= args.index < len(streams):
            selected = streams[args.index]
        else:
            warn(f"Index {args.index} out of range (0..{len(streams) - 1}).")
            return
    elif args.filter:
        for key, pkts in streams:
            (ip_a, port_a), (ip_b, port_b) = key
            label = f"{ip_a}:{port_a} {ip_b}:{port_b}"
            if args.filter in label:
                selected = (key, pkts)
                break
        if selected is None:
            warn(f"No stream matched filter '{args.filter}'.")
            return

    key, pkts = selected
    (ip_a, port_a), (ip_b, port_b) = key
    hdr(f"Stream {ip_a}:{port_a} <-> {ip_b}:{port_b}")

    # Reassemble payloads in capture order, tagging direction by client (ip_a).
    for pkt in pkts:
        if not pkt.haslayer(Raw):
            continue
        src, _ = get_l3(pkt)
        data = bytes(pkt[Raw].load)
        if args.hexdump:
            print(f"{C.YELLOW}--- {src} ({len(data)} bytes) ---{C.RESET}")
            print(_hexdump(data))
        else:
            colour = C.BLUE if src == ip_a else C.GREEN
            text = data.decode("utf-8", "replace")
            sys.stdout.write(f"{colour}{text}{C.RESET}")
    print()


def _hexdump(data, width=16):
    """Classic offset / hex / ascii hexdump."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart:<{width * 3}}  {asciipart}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# flags
# ---------------------------------------------------------------------------
DEFAULT_FLAG_PATTERNS = [
    r"flag\{[^}]*\}",
    r"picoCTF\{[^}]*\}",
    r"CTF\{[^}]*\}",
    r"HTB\{[^}]*\}",
    r"FLAG\{[^}]*\}",
]


def cmd_flags(packets, args):
    hdr("Flag Hunt")
    patterns = list(DEFAULT_FLAG_PATTERNS)
    if args.regex:
        patterns.append(args.regex)
    compiled = [re.compile(p.encode(), re.IGNORECASE) for p in patterns]

    found = 0
    seen = set()  # de-duplicate identical hits

    def scan(blob, where, note=""):
        nonlocal found
        for rx in compiled:
            for m in rx.finditer(blob):
                token = m.group(0)
                key = (token, note)
                if key in seen:
                    continue
                seen.add(key)
                found += 1
                tag = f" ({note})" if note else ""
                hit(f"[FLAG]{tag} {where}  {safe_decode(token)}")

    for i, pkt in enumerate(packets):
        if not pkt.haslayer(Raw):
            continue
        data = bytes(pkt[Raw].load)
        src, dst = get_l3(pkt)
        where = f"pkt#{i} {src}->{dst}"

        # 1) Direct payload scan.
        scan(data, where)

        # 2) base64-decode pass: find base64-looking tokens and decode them,
        #    then re-scan the decoded bytes for flags.
        for bm in re.finditer(rb"[A-Za-z0-9+/]{16,}={0,2}", data):
            token = bm.group(0)
            try:
                decoded = base64.b64decode(token, validate=False)
            except (binascii.Error, ValueError):
                continue
            # Only bother if decoded looks at least partly printable.
            if not decoded:
                continue
            printable = sum(1 for b in decoded if 9 <= b <= 126)
            if printable / max(len(decoded), 1) > 0.6:
                scan(decoded, where, note="base64-decoded")

    print()
    if found:
        info(f"{found} flag-like token(s) found.")
    else:
        warn("No flags matched. Try a custom --regex, or inspect streams manually.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description="PCAP triage tool for CTF / authorised lab traffic.",
        epilog="Authorised CTF/lab use only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True)

    def add_pcap_arg(sp):
        sp.add_argument("pcap", help="Path to the .pcap / .pcapng file")

    sp = sub.add_parser("summary", help="Protocol/port breakdown + top talkers")
    add_pcap_arg(sp)
    sp.set_defaults(func=cmd_summary)

    sp = sub.add_parser("dns", help="List DNS queries and responses")
    add_pcap_arg(sp)
    sp.set_defaults(func=cmd_dns)

    sp = sub.add_parser("http", help="Extract HTTP requests/responses")
    add_pcap_arg(sp)
    sp.set_defaults(func=cmd_http)

    sp = sub.add_parser("creds", help="Hunt cleartext credentials")
    add_pcap_arg(sp)
    sp.set_defaults(func=cmd_creds)

    sp = sub.add_parser("streams", help="List or dump TCP streams")
    add_pcap_arg(sp)
    sp.add_argument("--list", action="store_true", help="List all TCP streams")
    sp.add_argument("--index", type=int, help="Dump stream by index")
    sp.add_argument("--filter", help="Dump first stream whose endpoints contain this substring")
    sp.add_argument("--hexdump", action="store_true", help="Hexdump instead of ASCII")
    sp.set_defaults(func=cmd_streams)

    sp = sub.add_parser("flags", help="Search payloads for flag patterns")
    add_pcap_arg(sp)
    sp.add_argument("--regex", help="Additional custom flag regex (e.g. 'MY\\{[^}]+\\}')")
    sp.set_defaults(func=cmd_flags)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    packets = load_pcap(args.pcap)
    try:
        args.func(packets, args)
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] Interrupted.\n")
        return 130
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        sys.stderr.write(f"[!] Error while running '{args.command}': {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
