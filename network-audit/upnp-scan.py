#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
upnp-scan.py  --  Home-Network Security Audit Suite
====================================================

AUTHORIZED USE ONLY.  Run this tool ONLY on a network that YOU own or are
explicitly authorized to assess.  This is a DEFENSIVE tool to help a defender
inventory UPnP devices on their OWN LAN and spot risky configurations.

What it does
------------
* Sends an SSDP M-SEARCH multicast (239.255.255.250:1900) over a UDP socket
  (standard library only) to discover UPnP devices.
* Parses SSDP responses for each device's LOCATION (device-description URL),
  ST/USN, and SERVER header.
* Fetches and parses each device-description XML, extracting:
      friendlyName, manufacturer, modelName, deviceType
* ENUMERATES the UPnP services each device exposes (serviceType list).
* Flags exposure of the Internet Gateway Device (IGD) port-mapping services
  (WANIPConnection / WANPPPConnection / Layer3Forwarding) -- a classic
  home-network risk, since UPnP port forwarding lets any LAN program open the
  firewall to the Internet without user awareness.

Output
------
Prints a human-readable summary and (with --json <file>) writes the shared
suite JSON schema:

    {
      "tool": "...", "target": "...",
      "hosts":    [{"ip","mac","vendor","hostname","state"}],
      "findings": [{"host","port","service","severity","title","detail","recommendation"}]
    }

Dependencies
------------
Standard library only.  Uses `requests` for fetching device XML if installed,
otherwise falls back to `urllib`.  UPnP discovery uses raw UDP sockets.

Notes
-----
UPnP/SSDP discovery is UDP and best-effort: some networks/devices reply slowly,
not at all, or only to specific search targets.  The tool handles timeouts and
no-reply situations gracefully.
"""

import argparse
import json
import os
import re
import socket
import struct
import sys
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

# Optional HTTP backend for fetching device description XML.
try:
    import requests  # type: ignore
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    _HAVE_REQUESTS = False
    import urllib.request
    import urllib.error

# SSDP multicast group + port (reserved by the UPnP spec).
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

# Search targets to probe. ssdp:all is the broadest; we also explicitly ask
# for IGD device/service types so IGD-only responders are captured.
SEARCH_TARGETS = [
    "ssdp:all",
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
]

# Service types that represent IGD/port-mapping capability -- the risky ones.
IGD_PORTMAP_SERVICES = (
    "wanipconnection",
    "wanpppconnection",
)
LAYER3_SERVICE = "layer3forwarding"


# ---------------------------------------------------------------------------
# Result accumulator (shared JSON schema)
# ---------------------------------------------------------------------------
class AuditResult:
    def __init__(self, tool, target):
        self.tool = tool
        self.target = target
        self.hosts = []
        self.findings = []

    def add_host(self, ip, mac="", vendor="", hostname="", state="up"):
        # Avoid duplicate host entries for the same IP.
        for h in self.hosts:
            if h["ip"] == ip:
                # Enrich existing entry where we now have better data.
                if vendor and not h["vendor"]:
                    h["vendor"] = vendor
                if hostname and not h["hostname"]:
                    h["hostname"] = hostname
                return
        self.hosts.append({
            "ip": ip, "mac": mac, "vendor": vendor,
            "hostname": hostname, "state": state,
        })

    def add_finding(self, host, port, service, severity, title, detail, recommendation):
        self.findings.append({
            "host": host, "port": port, "service": service,
            "severity": severity, "title": title,
            "detail": detail, "recommendation": recommendation,
        })

    def to_dict(self):
        return {
            "tool": self.tool, "target": self.target,
            "hosts": self.hosts, "findings": self.findings,
        }


# ---------------------------------------------------------------------------
# SSDP discovery (raw UDP)
# ---------------------------------------------------------------------------
def build_msearch(st, mx):
    """Construct an SSDP M-SEARCH request for a given Search Target."""
    # NOTE: header order is flexible, but CRLF line endings + trailing blank
    # line are required by the HTTPU framing SSDP uses.
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: %s:%d\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: %d\r\n"
        "ST: %s\r\n"
        "USER-AGENT: home-audit/1.0 UPnP/1.1 upnp-scan/1.0\r\n"
        "\r\n" % (SSDP_ADDR, SSDP_PORT, mx, st)
    ).encode("ascii")


def discover(timeout, mx, bind_ip=""):
    """
    Send M-SEARCH for each search target and collect raw replies.

    Returns dict keyed by device IP ->
        {"location": set(), "server": str, "st": set(), "usn": set(),
         "raw_addr": (ip, port)}
    """
    devices = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Set multicast TTL so the request can reach the local segment.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL,
                    struct.pack("b", 2))
    if bind_ip:
        try:
            sock.bind((bind_ip, 0))
            # Choose the outgoing multicast interface explicitly.
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(bind_ip))
        except Exception as e:
            print("[!] Could not bind to %s (%s); using default interface."
                  % (bind_ip, e))
    sock.settimeout(timeout)

    # Send each M-SEARCH a couple of times (UDP is lossy).
    for st in SEARCH_TARGETS:
        msg = build_msearch(st, mx)
        for _ in range(2):
            try:
                sock.sendto(msg, (SSDP_ADDR, SSDP_PORT))
            except Exception as e:
                print("[!] Failed to send M-SEARCH (%s): %s" % (st, e))

    # Collect responses until the socket times out.
    print("[*] Listening for SSDP responses (%.1fs)..." % timeout)
    while True:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            break
        except Exception:
            break
        ip = addr[0]
        parsed = parse_ssdp_response(data)
        if not parsed:
            continue
        entry = devices.setdefault(ip, {
            "location": set(), "server": "", "st": set(),
            "usn": set(), "raw_addr": addr,
        })
        if parsed.get("location"):
            entry["location"].add(parsed["location"])
        if parsed.get("server") and not entry["server"]:
            entry["server"] = parsed["server"]
        if parsed.get("st"):
            entry["st"].add(parsed["st"])
        if parsed.get("usn"):
            entry["usn"].add(parsed["usn"])

    sock.close()
    return devices


def parse_ssdp_response(data):
    """Parse an SSDP HTTP-over-UDP response into a header dict (lowercased)."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    # First line is a status/response line; remaining lines are headers.
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {
        "location": headers.get("location", ""),
        "server": headers.get("server", ""),
        "st": headers.get("st", "") or headers.get("nt", ""),
        "usn": headers.get("usn", ""),
    }


# ---------------------------------------------------------------------------
# Device-description XML fetch + parse
# ---------------------------------------------------------------------------
def http_get_text(url, timeout=6.0):
    """Fetch a URL and return its text body, or None."""
    if _HAVE_REQUESTS:
        try:
            r = requests.get(url, timeout=timeout)
            return r.text
        except Exception:
            return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "upnp-scan/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(200000).decode("utf-8", errors="replace")
    except Exception:
        return None


def _localname(tag):
    """Strip XML namespace from a tag, e.g. '{urn:..}device' -> 'device'."""
    return tag.split("}")[-1] if "}" in tag else tag


def parse_device_description(xml_text):
    """
    Parse a UPnP device-description XML.

    Returns dict with friendlyName, manufacturer, modelName, deviceType,
    and a flat list of all serviceType strings found (across nested devices).
    """
    info = {
        "friendlyName": "", "manufacturer": "", "modelName": "",
        "deviceType": "", "services": [], "device_types": [],
    }
    if not xml_text:
        return info
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return info

    # Find the first <device> element (root device) for the top-level fields.
    first_device = None
    for el in root.iter():
        if _localname(el.tag) == "device":
            first_device = el
            break

    if first_device is not None:
        for child in first_device:
            name = _localname(child.tag)
            if name == "friendlyName":
                info["friendlyName"] = (child.text or "").strip()
            elif name == "manufacturer":
                info["manufacturer"] = (child.text or "").strip()
            elif name == "modelName":
                info["modelName"] = (child.text or "").strip()
            elif name == "deviceType":
                info["deviceType"] = (child.text or "").strip()

    # Enumerate ALL serviceType and deviceType strings anywhere in the doc
    # (devices nest sub-devices; IGD services live in WAN sub-devices).
    for el in root.iter():
        name = _localname(el.tag)
        if name == "serviceType" and el.text:
            info["services"].append(el.text.strip())
        elif name == "deviceType" and el.text:
            info["device_types"].append(el.text.strip())

    # De-duplicate while preserving order.
    info["services"] = list(dict.fromkeys(info["services"]))
    info["device_types"] = list(dict.fromkeys(info["device_types"]))
    return info


def _host_port_from_url(url):
    """Extract (host, port) from an http URL for finding metadata."""
    m = re.match(r"https?://([^/:]+)(?::(\d+))?", url, re.I)
    if not m:
        return ("", 0)
    host = m.group(1)
    port = int(m.group(2)) if m.group(2) else 80
    return (host, port)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def analyze(devices, result, http_timeout):
    if not devices:
        print("[!] No UPnP/SSDP devices responded.")
        result.add_finding(
            host=result.target, port=SSDP_PORT, service="ssdp", severity="info",
            title="No UPnP devices discovered",
            detail="No device replied to the SSDP M-SEARCH within the timeout. "
                   "This may mean UPnP is disabled (good) or that replies were "
                   "blocked/slow. UPnP discovery is best-effort over UDP.",
            recommendation="If you expect UPnP devices, increase --timeout/--mx "
                           "or re-run. Note that UPnP being OFF is generally "
                           "desirable for security.")
        return

    print("[+] %d UPnP host(s) responded.\n" % len(devices))

    for ip, entry in sorted(devices.items()):
        locations = sorted(entry["location"])
        server = entry["server"]
        # Resolve a hostname best-effort.
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = ""

        # Aggregate parsed device info across all advertised LOCATIONs.
        friendly = manufacturer = model = devtype = ""
        all_services = []
        all_device_types = list(entry["st"])

        if not locations:
            # Device responded but advertised no LOCATION URL.
            result.add_host(ip=ip, vendor=server.split()[0] if server else "",
                            hostname=hostname, state="up")
            result.add_finding(
                host=ip, port=SSDP_PORT, service="ssdp", severity="info",
                title="UPnP device with no device-description URL",
                detail="Device responded to SSDP (SERVER: %s) but advertised no "
                       "LOCATION; service enumeration not possible." % (server or "?"),
                recommendation="Identify the device on your LAN and confirm it is "
                               "expected. Disable UPnP if not needed.")
            continue

        for loc in locations:
            print("[*] Fetching device description: %s" % loc)
            xml_text = http_get_text(loc, timeout=http_timeout)
            info = parse_device_description(xml_text)
            friendly = friendly or info["friendlyName"]
            manufacturer = manufacturer or info["manufacturer"]
            model = model or info["modelName"]
            devtype = devtype or info["deviceType"]
            all_services.extend(info["services"])
            all_device_types.extend(info["device_types"])

        all_services = list(dict.fromkeys(all_services))
        all_device_types = list(dict.fromkeys(all_device_types))

        vendor = manufacturer or (server.split()[0] if server else "")
        result.add_host(ip=ip, vendor=vendor,
                        hostname=hostname or friendly, state="up")

        # Pretty print device.
        print("    IP:           %s" % ip)
        print("    friendlyName: %s" % (friendly or "-"))
        print("    manufacturer: %s" % (manufacturer or "-"))
        print("    modelName:    %s" % (model or "-"))
        print("    deviceType:   %s" % (devtype or "-"))
        print("    SERVER:       %s" % (server or "-"))
        print("    services (%d):" % len(all_services))
        for s in all_services:
            print("        - %s" % s)
        print("")

        # Informational finding: device + enumerated services.
        loc_host, loc_port = _host_port_from_url(locations[0])
        svc_summary = (", ".join(all_services) if all_services
                       else "(no services enumerated)")
        result.add_finding(
            host=ip, port=loc_port or SSDP_PORT, service="upnp", severity="info",
            title="UPnP device discovered: %s" % (friendly or model or ip),
            detail="manufacturer=%s; model=%s; deviceType=%s; server=%s; "
                   "services=[%s]; location=%s" % (
                       manufacturer or "?", model or "?", devtype or "?",
                       server or "?", svc_summary, "; ".join(locations)),
            recommendation="Confirm this device is one you own and recognize. "
                           "Unknown UPnP devices on your LAN warrant "
                           "investigation.")

        # Risk analysis: IGD port-mapping / WAN connection services.
        lower_services = [s.lower() for s in all_services]
        lower_devtypes = [d.lower() for d in all_device_types]

        igd_services = [s for s in all_services
                        if any(k in s.lower() for k in IGD_PORTMAP_SERVICES)]
        is_igd_device = any("internetgatewaydevice" in d for d in lower_devtypes)
        has_layer3 = any(LAYER3_SERVICE in s for s in lower_services)

        if igd_services:
            result.add_finding(
                host=ip, port=loc_port or SSDP_PORT, service="upnp-igd",
                severity="high",
                title="UPnP IGD port-mapping service exposed",
                detail="This device exposes WAN connection / port-mapping "
                       "service(s): %s. Internet Gateway Device (IGD) port "
                       "mapping lets ANY program on the LAN open inbound ports "
                       "through the router's firewall to the Internet, with no "
                       "user prompt. Malware and worms abuse this to expose "
                       "internal devices and to build botnets."
                       % ", ".join(igd_services),
                recommendation="Disable UPnP / IGD port-mapping on the router "
                               "unless a specific application requires it. If "
                               "needed, configure explicit, minimal static port "
                               "forwards instead. Audit existing UPnP port maps.")
        elif is_igd_device:
            # IGD device advertised but port-map service not directly seen.
            result.add_finding(
                host=ip, port=loc_port or SSDP_PORT, service="upnp-igd",
                severity="medium",
                title="UPnP Internet Gateway Device (IGD) advertised",
                detail="Device advertises an InternetGatewayDevice type, which "
                       "typically provides UPnP port-mapping (WANIPConnection / "
                       "WANPPPConnection). Even if the port-map service was not "
                       "directly enumerated, IGD support means LAN programs may "
                       "be able to open firewall ports automatically.",
                recommendation="Verify whether UPnP port forwarding is enabled on "
                               "the router and disable it if not explicitly "
                               "required.")

        if has_layer3:
            result.add_finding(
                host=ip, port=loc_port or SSDP_PORT, service="upnp-igd",
                severity="low",
                title="UPnP Layer3Forwarding service exposed",
                detail="The device exposes the Layer3Forwarding UPnP service, "
                       "associated with IGD routing/connection control.",
                recommendation="Confirm UPnP control of routing is intended; "
                               "disable UPnP if not required.")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_summary(result):
    print("=" * 70)
    print("UPNP SCAN SUMMARY  --  target: %s" % result.target)
    print("=" * 70)

    print("\nHosts (%d):" % len(result.hosts))
    for h in result.hosts:
        print("  %-15s  vendor=%s  hostname=%s" % (
            h["ip"], h["vendor"] or "-", h["hostname"] or "-"))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(result.findings, key=lambda f: order.get(f["severity"], 9))

    print("\nFindings (%d):" % len(findings))
    if not findings:
        print("  (none)")
    for f in findings:
        loc = f["host"]
        if f["port"]:
            loc += ":%d" % f["port"]
        print("  [%-8s] %s  (%s)" % (f["severity"].upper(), f["title"], loc))
        print("            %s" % f["detail"])
        print("            -> %s" % f["recommendation"])

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("\nSeverity counts: " + (
        ", ".join("%s=%d" % (k, counts[k]) for k in
                  ["critical", "high", "medium", "low", "info"]
                  if k in counts) or "none"))
    print("=" * 70)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Discover & audit UPnP/SSDP devices on your OWN LAN "
                    "(AUTHORIZED USE ONLY).",
        epilog="Defensive tool. Do not run against networks you don't control.")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="Seconds to listen for SSDP replies (default 5.0).")
    parser.add_argument("--mx", type=int, default=2,
                        help="SSDP MX value: max response delay seconds (default 2).")
    parser.add_argument("--bind", default="",
                        help="Local interface IP to send from (default: OS chooses).")
    parser.add_argument("--http-timeout", type=float, default=6.0,
                        help="Device-description XML fetch timeout (default 6.0).")
    parser.add_argument("--json", dest="json_out", metavar="FILE",
                        help="Write results to FILE in the suite JSON schema.")
    args = parser.parse_args()

    print("=" * 70)
    print(" upnp-scan.py  --  AUTHORIZED USE ONLY")
    print(" Scan only networks you own or are permitted to assess.")
    print("=" * 70)

    if _HAVE_REQUESTS:
        try:
            import urllib3  # type: ignore
            urllib3.disable_warnings()
        except Exception:
            pass

    result = AuditResult(tool="upnp-scan", target="%s:%d" % (SSDP_ADDR, SSDP_PORT))

    try:
        devices = discover(timeout=args.timeout, mx=args.mx, bind_ip=args.bind)
    except Exception as e:
        print("[!] SSDP discovery failed: %s" % e)
        devices = {}

    analyze(devices, result, http_timeout=args.http_timeout)
    print_summary(result)

    if args.json_out:
        try:
            payload = result.to_dict()
            payload["_generated"] = datetime.now(timezone.utc).isoformat()
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            print("\n[+] JSON written to %s" % os.path.abspath(args.json_out))
        except Exception as e:
            print("[!] Failed to write JSON: %s" % e)
            sys.exit(1)


if __name__ == "__main__":
    main()
