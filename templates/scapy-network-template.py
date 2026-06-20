#!/usr/bin/env python3
"""
scapy-network-template.py  --  Scapy networking starter (sniff / pcap / craft)
==============================================================================
Covers the three things you actually do in network CTFs:
  1. Live sniffing with a BPF filter + per-packet callback
  2. Offline pcap analysis (rdpcap) -- pull out DNS, HTTP, and creds
  3. Crafting and sending packets
  4. A stub for parsing a custom/proprietary protocol

USAGE
-----
    sudo python scapy-network-template.py sniff  [iface] [bpf-filter]
    python      scapy-network-template.py pcap   capture.pcap
    sudo python scapy-network-template.py send

NOTE: live sniffing and raw send() need root/admin (run with sudo on Linux,
or an elevated shell + Npcap on Windows). Reading a pcap does NOT.

INSTALL:  pip install scapy
"""

import sys
from scapy.all import (
    sniff, rdpcap, wrpcap, send, sr1,
    Ether, IP, TCP, UDP, ICMP, Raw,
)
# HTTP layers live in a contrib module; load them so haslayer(HTTPRequest) works.
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR


# ============================================================================
# 1) LIVE SNIFFING
# ============================================================================
def on_packet(pkt):
    """Callback invoked for every captured packet (the `prn` of sniff())."""
    # Cheap one-line summary per packet:
    if IP in pkt:
        proto = pkt.sprintf("%IP.proto%")
        print(f"{pkt[IP].src:>15} -> {pkt[IP].dst:<15}  {proto}  len={len(pkt)}")

    # Route into the specialized parsers below.
    parse_dns(pkt)
    parse_http(pkt)
    hunt_credentials(pkt)


def do_sniff(iface=None, bpf="", count=0):
    """
    Capture live traffic.
      iface : interface name (None = scapy's default)
      bpf   : Berkeley Packet Filter string, applied in-kernel (fast).
              examples: "tcp port 80", "udp port 53", "host 10.0.0.5", "icmp"
      count : number of packets (0 = run until Ctrl-C)
    `store=False` keeps memory flat for long captures.
    """
    print(f"[*] sniffing on {iface or 'default'} filter={bpf!r} (Ctrl-C to stop)")
    sniff(iface=iface, filter=bpf or None, prn=on_packet, store=False, count=count)


# ============================================================================
# 2) OFFLINE PCAP ANALYSIS
# ============================================================================
def do_pcap(path):
    """Load a pcap and run every packet through the analyzers."""
    print(f"[*] reading {path}")
    packets = rdpcap(path)          # loads the whole capture into memory
    print(f"[*] {len(packets)} packets\n")
    for pkt in packets:
        parse_dns(pkt)
        parse_http(pkt)
        hunt_credentials(pkt)


def parse_dns(pkt):
    """Print DNS queries (qr==0) and answers (qr==1)."""
    if not pkt.haslayer(DNS):
        return
    dns = pkt[DNS]
    if dns.qr == 0 and dns.qd is not None:          # query
        qname = dns.qd.qname.decode(errors="replace").rstrip(".")
        print(f"[DNS  Q] {qname}")
    elif dns.qr == 1:                                # response
        for i in range(dns.ancount):
            rr = dns.an[i]
            name = rr.rrname.decode(errors="replace").rstrip(".")
            print(f"[DNS  A] {name} -> {rr.rdata}")


def parse_http(pkt):
    """Print HTTP request lines and any response status."""
    if pkt.haslayer(HTTPRequest):
        http = pkt[HTTPRequest]
        host = http.Host.decode(errors="replace") if http.Host else ""
        path = http.Path.decode(errors="replace") if http.Path else ""
        method = http.Method.decode(errors="replace") if http.Method else ""
        print(f"[HTTP  ] {method} {host}{path}")
        # POST bodies (often hold login form data) ride in the Raw layer:
        if pkt.haslayer(Raw):
            body = pkt[Raw].load
            if body:
                print(f"         body: {body[:200]!r}")
    elif pkt.haslayer(HTTPResponse):
        http = pkt[HTTPResponse]
        code = http.Status_Code.decode(errors="replace") if http.Status_Code else "?"
        print(f"[HTTP <-] {code}")


# Substrings that frequently flag plaintext credentials in TCP payloads.
CRED_MARKERS = [b"user", b"pass", b"login", b"USER ", b"PASS ",
                b"Authorization:", b"pwd", b"token", b"api_key", b"flag{"]

def hunt_credentials(pkt):
    """
    Scan TCP payloads for plaintext credential markers. Catches FTP USER/PASS,
    HTTP Basic auth, login form bodies, leaked tokens, and stray flags.
    """
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return
    load = pkt[Raw].load
    low = load.lower()
    if any(m.lower() in low for m in CRED_MARKERS):
        src = pkt[IP].src if IP in pkt else "?"
        dst = pkt[IP].dst if IP in pkt else "?"
        print(f"[CRED?] {src} -> {dst}: {load[:200]!r}")


# ============================================================================
# 3) CRAFTING & SENDING PACKETS
# ============================================================================
def do_send():
    """Examples of building packets with the / layering operator and sending."""
    target = "10.10.10.10"

    # ICMP ping. sr1() sends one packet and returns the first reply.
    ping = IP(dst=target) / ICMP()
    reply = sr1(ping, timeout=2, verbose=False)
    if reply:
        print(f"[+] {target} replied (ttl={reply.ttl})")
    else:
        print(f"[-] no reply from {target}")

    # Raw TCP SYN to a port (layer-3 send; the kernel doesn't know about it).
    syn = IP(dst=target) / TCP(dport=80, flags="S")
    sr1(syn, timeout=2, verbose=False)

    # A custom UDP payload (e.g. poking a service / sending an exploit string).
    pkt = IP(dst=target) / UDP(dport=9999) / Raw(load=b"PAYLOAD_HERE")
    send(pkt, verbose=False)

    # Save crafted packets for later replay / inspection in Wireshark:
    # wrpcap("crafted.pcap", [ping, syn, pkt])


# ============================================================================
# 4) CUSTOM PROTOCOL PARSING  --  fill in for proprietary formats
# ============================================================================
def parse_custom(pkt):
    """
    Template for decoding a custom protocol carried over TCP/UDP. Pull the raw
    bytes and slice the fields per the spec / your reverse engineering.
    """
    if not pkt.haslayer(Raw):
        return
    data = pkt[Raw].load

    # Example: imaginary header  [1B type][2B length][N payload]
    if len(data) < 3:
        return
    msg_type = data[0]
    length = int.from_bytes(data[1:3], "big")
    payload = data[3:3 + length]
    print(f"[CUSTOM] type={msg_type} len={length} payload={payload!r}")

    # For complex formats, define a proper Scapy layer instead:
    #   from scapy.packet import Packet
    #   from scapy.fields import ByteField, ShortField, StrLenField
    #   class MyProto(Packet):
    #       fields_desc = [ByteField("type", 0), ShortField("length", 0),
    #                      StrLenField("payload", "", length_from=lambda p: p.length)]
    #   bind_layers(TCP, MyProto, dport=9999)


# ============================================================================
# CLI
# ============================================================================
def usage():
    print(__doc__)
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
    mode = sys.argv[1]

    if mode == "sniff":
        iface = sys.argv[2] if len(sys.argv) > 2 else None
        bpf   = sys.argv[3] if len(sys.argv) > 3 else ""
        do_sniff(iface, bpf)
    elif mode == "pcap":
        if len(sys.argv) < 3:
            usage()
        do_pcap(sys.argv[2])
    elif mode == "send":
        do_send()
    else:
        usage()
