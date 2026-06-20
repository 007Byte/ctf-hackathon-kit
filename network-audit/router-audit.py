#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
router-audit.py  --  Home-Network Security Audit Suite
=======================================================

AUTHORIZED USE ONLY.  Run this tool ONLY against a router / gateway that YOU
own or are explicitly authorized to assess.  Scanning networks or devices you
do not control may be illegal.  This is a DEFENSIVE tool for a defender to
audit their OWN home router.

What it does
------------
* Auto-detects the default gateway IP (cross-platform):
    - Windows: parses `ipconfig` / `route print`
    - Linux:   parses `ip route` (falls back to `route -n` / `netstat -rn`)
    - Allows manual override with --gateway
* Checks whether the gateway is reachable.
* Scans common router admin ports (80, 443, 8080, 8443, 23, 22).
* Fetches the admin page over HTTP and HTTPS and reports:
    - Server header / router model fingerprint
    - Whether admin is served over plaintext HTTP (finding)
    - Missing security headers (HSTS, X-Frame-Options, CSP, X-Content-Type-Options)
    - Basic TLS certificate info if HTTPS is available
    - Whether Telnet (23) / SSH (22) admin is exposed
    - Presence of an HTML login form
* References default-credential risk (suggests running a weak-creds checker --
  this tool does NOT brute force).
* Reports the configured/handed-out DNS server(s) and notes known-bad indicators.

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
Standard library only.  Uses `requests` if installed, otherwise falls back to
`urllib`.  No third-party package is required.
"""

import argparse
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Optional HTTP backend: prefer `requests`, fall back to stdlib urllib.
# ---------------------------------------------------------------------------
try:
    import requests  # type: ignore
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover - environment dependent
    _HAVE_REQUESTS = False
    import urllib.request
    import urllib.error

# Ports commonly used for router administration.
ADMIN_PORTS = {
    80:   "http",
    443:  "https",
    8080: "http-alt",
    8443: "https-alt",
    23:   "telnet",
    22:   "ssh",
}

# Security headers we expect a hardened web admin to set, with guidance.
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS (Strict-Transport-Security) forces HTTPS and blocks SSL-strip MITM.",
    "x-frame-options":           "X-Frame-Options prevents the admin UI being framed (clickjacking).",
    "content-security-policy":   "Content-Security-Policy restricts script/content sources (mitigates XSS).",
    "x-content-type-options":    "X-Content-Type-Options: nosniff stops MIME-type sniffing attacks.",
}

# A small list of DNS servers that are well-known and generally considered
# legitimate.  Anything that is NOT private (RFC1918) and NOT in this list is
# merely *noted* for the operator to verify -- we do not assert maliciousness.
KNOWN_GOOD_PUBLIC_DNS = {
    "8.8.8.8", "8.8.4.4",            # Google
    "1.1.1.1", "1.0.0.1",            # Cloudflare
    "9.9.9.9", "149.112.112.112",    # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "94.140.14.14", "94.140.15.15",  # AdGuard
}


# ---------------------------------------------------------------------------
# Result accumulator following the shared JSON schema.
# ---------------------------------------------------------------------------
class AuditResult:
    """Collects hosts + findings and serializes to the shared schema."""

    def __init__(self, tool, target):
        self.tool = tool
        self.target = target
        self.hosts = []
        self.findings = []

    def add_host(self, ip, mac="", vendor="", hostname="", state="up"):
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
            "tool": self.tool,
            "target": self.target,
            "hosts": self.hosts,
            "findings": self.findings,
        }


# ---------------------------------------------------------------------------
# Gateway / DNS auto-detection (cross-platform)
# ---------------------------------------------------------------------------
def _run(cmd):
    """Run a command and return stdout as text (best-effort, never raises)."""
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10,
        )
        return (out.stdout or "") + (out.stderr or "")
    except Exception:
        return ""


def detect_gateway_and_dns():
    """
    Return (gateway_ip_or_None, [dns_servers]).

    Cross-platform: Windows parses `ipconfig /all`, Linux parses `ip route`
    + `/etc/resolv.conf` (with fallbacks).
    """
    system = platform.system().lower()
    if system == "windows":
        return _detect_windows()
    return _detect_unix()


def _detect_windows():
    gateway = None
    dns = []
    text = _run(["ipconfig", "/all"])

    # `ipconfig /all` lines look like:
    #    Default Gateway . . . . . . . . . : 192.168.1.1
    #    DNS Servers . . . . . . . . . . . : 192.168.1.1
    #                                         8.8.8.8
    lines = text.splitlines()
    for i, line in enumerate(lines):
        low = line.lower()
        if "default gateway" in low:
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            if m and not gateway:
                gateway = m.group(1)
        if "dns servers" in low:
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            if m:
                dns.append(m.group(1))
            # Continuation lines (indented IPs with no label).
            j = i + 1
            while j < len(lines):
                cont = lines[j]
                if ":" in cont:  # next labeled field -> stop
                    break
                m2 = re.search(r"^\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$", cont)
                if m2:
                    dns.append(m2.group(1))
                    j += 1
                else:
                    break

    # Fallback: parse `route print` for the 0.0.0.0 default route.
    if not gateway:
        rp = _run(["route", "print", "0.0.0.0"])
        m = re.search(
            r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})", rp)
        if m:
            gateway = m.group(1)

    # De-duplicate DNS while preserving order.
    dns = list(dict.fromkeys(dns))
    return gateway, dns


def _detect_unix():
    gateway = None
    dns = []

    # `ip route` default line:  default via 192.168.1.1 dev eth0 ...
    text = _run(["ip", "route"])
    m = re.search(r"default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})", text)
    if m:
        gateway = m.group(1)

    # Fallbacks for systems without iproute2.
    if not gateway:
        text = _run(["route", "-n"])
        m = re.search(
            r"^0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})", text, re.MULTILINE)
        if m:
            gateway = m.group(1)
    if not gateway:
        text = _run(["netstat", "-rn"])
        m = re.search(
            r"^(?:0\.0\.0\.0|default)\s+(\d{1,3}(?:\.\d{1,3}){3})",
            text, re.MULTILINE)
        if m:
            gateway = m.group(1)

    # DNS servers from resolv.conf (and systemd-resolved if present).
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                mm = re.match(r"\s*nameserver\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
                if mm:
                    dns.append(mm.group(1))
    except Exception:
        pass

    if not dns:
        rs = _run(["resolvectl", "status"])
        for mm in re.finditer(r"DNS Servers?:\s*([\d.\s]+)", rs):
            for ipm in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})", mm.group(1)):
                dns.append(ipm.group(1))

    dns = list(dict.fromkeys(dns))
    return gateway, dns


# ---------------------------------------------------------------------------
# Networking helpers
# ---------------------------------------------------------------------------
def is_reachable(ip, port=80, timeout=2.0):
    """TCP-connect test to decide if a port appears open / host reachable."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def scan_ports(ip, ports, timeout=1.5):
    """Return the subset of `ports` that accept a TCP connection."""
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except Exception:
            continue
    return open_ports


def http_get(url, timeout=6.0):
    """
    Fetch a URL. Returns dict {status, headers(lowercased), body, final_url}
    or None on failure. TLS verification is disabled on purpose: home routers
    almost always present self-signed certs and we WANT to inspect them.
    """
    if _HAVE_REQUESTS:
        try:
            resp = requests.get(
                url, timeout=timeout, verify=False, allow_redirects=True)
            return {
                "status": resp.status_code,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body": resp.text[:20000],
                "final_url": resp.url,
            }
        except Exception:
            return None
    # ---- urllib fallback ----
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "router-audit/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read(20000)
            return {
                "status": r.status,
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "body": raw.decode("utf-8", errors="replace"),
                "final_url": r.geturl(),
            }
    except urllib.error.HTTPError as e:  # still has headers/body we can use
        try:
            return {
                "status": e.code,
                "headers": {k.lower(): v for k, v in e.headers.items()},
                "body": (e.read(20000) or b"").decode("utf-8", errors="replace"),
                "final_url": url,
            }
        except Exception:
            return None
    except Exception:
        return None


def get_tls_cert(ip, port, timeout=6.0):
    """Return basic TLS certificate info for ip:port, or None."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()        # parsed dict (may be sparse)
                der = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()
        info = {
            "tls_version": version,
            "cipher": cipher[0] if cipher else None,
            "subject": _flatten_name(cert.get("subject")) if cert else "",
            "issuer": _flatten_name(cert.get("issuer")) if cert else "",
            "notBefore": cert.get("notBefore") if cert else "",
            "notAfter": cert.get("notAfter") if cert else "",
            "der_len": len(der) if der else 0,
        }
        return info
    except Exception:
        return None


def _flatten_name(rdn_seq):
    """Flatten the nested ssl cert subject/issuer structure into a string."""
    if not rdn_seq:
        return ""
    parts = []
    for rdn in rdn_seq:
        for k, v in rdn:
            parts.append("%s=%s" % (k, v))
    return ", ".join(parts)


def fingerprint_router(headers, body):
    """Best-effort vendor/model fingerprint from headers + page content."""
    hints = []
    server = headers.get("server", "")
    if server:
        hints.append("Server: %s" % server)
    www_auth = headers.get("www-authenticate", "")
    if www_auth:
        hints.append("WWW-Authenticate: %s" % www_auth)

    # Look for common vendor markers in the page <title> / body.
    vendors = [
        "netgear", "linksys", "tp-link", "tplink", "asus", "d-link", "dlink",
        "huawei", "zyxel", "ubiquiti", "unifi", "mikrotik", "fritz",
        "xfinity", "arris", "technicolor", "sagemcom", "openwrt", "ddwrt",
        "dd-wrt", "cisco", "tenda", "belkin", "actiontec",
    ]
    low_body = (body or "").lower()
    found = sorted({v for v in vendors if v in low_body or v in server.lower()})
    if found:
        hints.append("Vendor markers: %s" % ", ".join(found))

    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
        if title:
            hints.append("Title: %s" % title)

    return "; ".join(hints) if hints else "unknown", found, title


def has_login_form(body):
    """Heuristic detection of an HTML login form."""
    if not body:
        return False
    low = body.lower()
    if 'type="password"' in low or "type='password'" in low:
        return True
    if "<form" in low and ("login" in low or "password" in low or "passwd" in low):
        return True
    return False


# ---------------------------------------------------------------------------
# Core audit logic
# ---------------------------------------------------------------------------
def audit_router(gateway, dns_servers, result, port_timeout, http_timeout):
    print("[*] Target gateway: %s" % gateway)

    # 1) Reachability ------------------------------------------------------
    reachable = any(is_reachable(gateway, p, timeout=port_timeout)
                    for p in (80, 443, 8080, 8443, 23, 22, 53))
    # Even if no admin port is open, try a generic connect on 80.
    hostname = ""
    try:
        hostname = socket.gethostbyaddr(gateway)[0]
    except Exception:
        hostname = ""

    result.add_host(ip=gateway, hostname=hostname,
                    state="up" if reachable else "down")

    if not reachable:
        result.add_finding(
            host=gateway, port=0, service="gateway", severity="info",
            title="Gateway did not respond on common admin ports",
            detail=("No TCP connection succeeded on 22/23/53/80/443/8080/8443. "
                    "The router may block these from clients, or the detected "
                    "gateway IP may be wrong."),
            recommendation="Verify the gateway IP (--gateway) and that you are "
                           "on the LAN side of the router.")
        print("[!] Gateway not reachable on common admin ports.")
    else:
        print("[+] Gateway is reachable.")

    # 2) Port scan ---------------------------------------------------------
    open_ports = scan_ports(gateway, list(ADMIN_PORTS.keys()), timeout=port_timeout)
    print("[*] Open admin ports: %s" %
          (", ".join(str(p) for p in open_ports) if open_ports else "none"))

    http_open = [p for p in open_ports if ADMIN_PORTS[p].startswith("http")
                 and "https" not in ADMIN_PORTS[p]]
    https_open = [p for p in open_ports if "https" in ADMIN_PORTS[p]]

    # 3) Telnet exposure (port 23) ----------------------------------------
    if 23 in open_ports:
        result.add_finding(
            host=gateway, port=23, service="telnet", severity="high",
            title="Telnet administration is exposed",
            detail="Port 23/tcp (Telnet) is open on the router. Telnet sends "
                   "credentials and all session data in cleartext and is a "
                   "frequent target of IoT/router botnets (e.g. Mirai).",
            recommendation="Disable Telnet on the router. Use HTTPS web admin or "
                           "SSH instead. If remote management is not needed, "
                           "disable it entirely.")

    # 4) SSH exposure (port 22) -------------------------------------------
    if 22 in open_ports:
        result.add_finding(
            host=gateway, port=22, service="ssh", severity="low",
            title="SSH administration is exposed on the LAN",
            detail="Port 22/tcp (SSH) is open. SSH itself is encrypted, but an "
                   "exposed admin service still widens the attack surface and "
                   "may be reachable from the WAN if remote management is on.",
            recommendation="Confirm SSH is intentional, uses key-based auth and "
                           "strong credentials, and is NOT exposed to the "
                           "Internet/WAN. Run a weak-credentials check.")

    # 5) HTTP / HTTPS admin fetches ---------------------------------------
    fingerprint = "unknown"
    vendor_markers = []
    title = ""

    # Plaintext HTTP admin is a finding regardless of fetch success.
    if http_open:
        for p in http_open:
            scheme = "http"
            url = "%s://%s%s/" % (scheme, gateway, "" if p in (80,) else ":%d" % p)
            print("[*] Fetching %s" % url)
            resp = http_get(url, timeout=http_timeout)
            if resp:
                fp, markers, ttl = fingerprint_router(resp["headers"], resp["body"])
                if fp != "unknown":
                    fingerprint = fp
                    vendor_markers = markers
                    title = ttl
                _evaluate_http_response(result, gateway, p, scheme, resp)
            else:
                result.add_finding(
                    host=gateway, port=p, service="http", severity="info",
                    title="HTTP admin port open but page fetch failed",
                    detail="Port %d/tcp accepted a connection but the admin page "
                           "could not be retrieved." % p,
                    recommendation="Open the admin page manually to confirm its "
                                   "configuration.")

            # Plaintext-HTTP admin finding (the connection itself is the issue).
            result.add_finding(
                host=gateway, port=p, service="http", severity="medium",
                title="Router admin reachable over plaintext HTTP",
                detail="The administration interface is served over unencrypted "
                       "HTTP on port %d. Credentials and session cookies can be "
                       "sniffed on the LAN (e.g. by a compromised device or rogue "
                       "Wi-Fi client)." % p,
                recommendation="Enable HTTPS for the admin UI and redirect HTTP to "
                               "HTTPS. Disable plaintext HTTP admin if possible.")

    if https_open:
        for p in https_open:
            scheme = "https"
            url = "%s://%s:%d/" % (scheme, gateway, p) if p != 443 \
                else "https://%s/" % gateway
            print("[*] Fetching %s" % url)
            resp = http_get(url, timeout=http_timeout)
            if resp:
                fp, markers, ttl = fingerprint_router(resp["headers"], resp["body"])
                if fp != "unknown" and fingerprint == "unknown":
                    fingerprint = fp
                    vendor_markers = markers
                    title = ttl
                _evaluate_http_response(result, gateway, p, scheme, resp)

            # TLS certificate basics.
            cert = get_tls_cert(gateway, p, timeout=http_timeout)
            if cert:
                detail = ("TLS %s, cipher %s. Subject: %s. Issuer: %s. "
                          "Valid: %s -> %s." % (
                              cert.get("tls_version"), cert.get("cipher"),
                              cert.get("subject") or "(empty)",
                              cert.get("issuer") or "(empty)",
                              cert.get("notBefore") or "?",
                              cert.get("notAfter") or "?"))
                self_signed = (cert.get("subject") and
                               cert.get("subject") == cert.get("issuer"))
                sev = "low" if self_signed else "info"
                result.add_finding(
                    host=gateway, port=p, service="https", severity=sev,
                    title="HTTPS admin TLS certificate inspected"
                          + (" (self-signed)" if self_signed else ""),
                    detail=detail,
                    recommendation="Self-signed certificates are normal for home "
                                   "routers but train users to ignore TLS warnings. "
                                   "Ensure the cert is current and the key size is "
                                   "adequate (>=2048-bit RSA / ECC).")

    # 6) Login form / default-credentials advisory -----------------------
    # If we saw a login form anywhere, advise running a weak-creds check.
    login_seen = any(f["title"].startswith("Login form")
                     for f in result.findings)
    if login_seen or open_ports:
        result.add_finding(
            host=gateway, port=0, service="admin", severity="info",
            title="Default-credentials risk advisory",
            detail="A router admin interface appears to be present. Many home "
                   "routers ship with well-known default credentials "
                   "(admin/admin, admin/password, etc.). This tool does NOT "
                   "attempt any login or brute force.",
            recommendation="Run the suite's weak-creds-check tool (authorized, "
                           "rate-limited) to confirm credentials have been "
                           "changed from the vendor default.")

    # 7) Fingerprint summary finding --------------------------------------
    if fingerprint != "unknown":
        result.add_finding(
            host=gateway, port=0, service="admin", severity="info",
            title="Router fingerprint",
            detail=fingerprint,
            recommendation="Use the model identity to check vendor advisories and "
                           "ensure firmware is up to date.")
        # Record vendor on the host entry too.
        if result.hosts and vendor_markers:
            result.hosts[0]["vendor"] = ", ".join(vendor_markers)

    # 8) DNS check --------------------------------------------------------
    _evaluate_dns(result, gateway, dns_servers)


def _evaluate_http_response(result, gateway, port, scheme, resp):
    """Inspect a fetched admin page for security headers and a login form."""
    headers = resp["headers"]
    body = resp["body"]
    service = scheme  # 'http' or 'https'

    # Missing security headers.
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    if missing:
        # HSTS only meaningfully applies to HTTPS; note that nuance.
        readable = []
        for h in missing:
            readable.append("%s (%s)" % (h, SECURITY_HEADERS[h]))
        result.add_finding(
            host=gateway, port=port, service=service, severity="low",
            title="Missing HTTP security headers on admin UI",
            detail="The admin response is missing: " + "; ".join(readable),
            recommendation="Configure the router's web server to send these "
                           "headers. X-Content-Type-Options: nosniff and "
                           "X-Frame-Options: DENY are easy wins; add CSP and "
                           "(for HTTPS) HSTS.")

    # Login form presence.
    if has_login_form(body):
        result.add_finding(
            host=gateway, port=port, service=service, severity="info",
            title="Login form detected on admin UI",
            detail="The admin page presents an HTML login form on %s port %d."
                   % (scheme, port),
            recommendation="Ensure strong, non-default credentials are set and "
                           "account lockout / rate-limiting is enabled.")


def _evaluate_dns(result, gateway, dns_servers):
    """Report the DNS servers the gateway/host is configured to use."""
    if not dns_servers:
        result.add_finding(
            host=gateway, port=53, service="dns", severity="info",
            title="Could not determine configured DNS server(s)",
            detail="No DNS servers were parsed from the system configuration.",
            recommendation="Manually verify the DNS settings handed out by the "
                           "router (DHCP) and the router's upstream resolvers.")
        return

    print("[*] Configured DNS server(s): %s" % ", ".join(dns_servers))
    result.add_finding(
        host=gateway, port=53, service="dns", severity="info",
        title="Configured DNS server(s)",
        detail="The host is using DNS server(s): " + ", ".join(dns_servers),
        recommendation="Confirm these are resolvers you trust (your router, ISP, "
                       "or a reputable public resolver). Unexpected public DNS "
                       "servers can indicate DNS hijacking / malware.")

    # Flag any non-private, non-well-known public resolver for manual review.
    for d in dns_servers:
        if _is_private(d):
            continue
        if d not in KNOWN_GOOD_PUBLIC_DNS:
            result.add_finding(
                host=gateway, port=53, service="dns", severity="medium",
                title="Unrecognized public DNS server in use",
                detail="DNS server %s is a public (non-RFC1918) address that is "
                       "not in the list of common, well-known resolvers. This is "
                       "not proof of compromise, but router DNS hijacking is a "
                       "common attack: malware changes the router's DNS to "
                       "redirect victims." % d,
                recommendation="Verify you intentionally configured %s. If not, "
                               "reset the router's DNS settings, change the admin "
                               "password, and check for unauthorized firmware/"
                               "config changes." % d)


def _is_private(ip):
    """RFC1918 / loopback / link-local check."""
    try:
        octets = [int(x) for x in ip.split(".")]
    except Exception:
        return False
    if len(octets) != 4:
        return False
    a, b = octets[0], octets[1]
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    if a == 169 and b == 254:
        return True
    return False


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_summary(result):
    print("\n" + "=" * 70)
    print("ROUTER AUDIT SUMMARY  --  target: %s" % result.target)
    print("=" * 70)

    print("\nHosts:")
    for h in result.hosts:
        print("  %-15s  state=%s  hostname=%s  vendor=%s" % (
            h["ip"], h["state"], h["hostname"] or "-", h["vendor"] or "-"))

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
    print("\nSeverity counts: " +
          ", ".join("%s=%d" % (k, counts[k]) for k in
                    ["critical", "high", "medium", "low", "info"]
                    if k in counts) or "none")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Audit your OWN home router/gateway (AUTHORIZED USE ONLY).",
        epilog="Defensive tool. Do not run against networks you don't control.")
    parser.add_argument("-g", "--gateway",
                        help="Gateway IP to audit (default: auto-detect).")
    parser.add_argument("--dns", nargs="*", default=None,
                        help="Override DNS server(s) to report (default: auto-detect).")
    parser.add_argument("--json", dest="json_out", metavar="FILE",
                        help="Write results to FILE in the suite JSON schema.")
    parser.add_argument("--port-timeout", type=float, default=1.5,
                        help="Per-port TCP connect timeout in seconds (default 1.5).")
    parser.add_argument("--http-timeout", type=float, default=6.0,
                        help="HTTP(S) fetch timeout in seconds (default 6.0).")
    parser.add_argument("--no-verify-warning", action="store_true",
                        help="Suppress the TLS InsecureRequestWarning (requests).")
    args = parser.parse_args()

    print("=" * 70)
    print(" router-audit.py  --  AUTHORIZED USE ONLY")
    print(" Audit only routers/networks you own or are permitted to assess.")
    print("=" * 70)

    # Silence requests' insecure-TLS warning (we disable verify on purpose).
    if _HAVE_REQUESTS:
        try:
            import urllib3  # type: ignore
            urllib3.disable_warnings()
        except Exception:
            pass

    # Detect gateway / DNS unless overridden.
    auto_gw, auto_dns = (None, [])
    if args.gateway is None or args.dns is None:
        auto_gw, auto_dns = detect_gateway_and_dns()

    gateway = args.gateway or auto_gw
    dns_servers = args.dns if args.dns is not None else auto_dns

    if not gateway:
        print("[!] Could not auto-detect the default gateway. "
              "Specify it with --gateway <ip>.")
        sys.exit(2)

    result = AuditResult(tool="router-audit", target=gateway)
    audit_router(gateway, dns_servers, result,
                 port_timeout=args.port_timeout,
                 http_timeout=args.http_timeout)

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
