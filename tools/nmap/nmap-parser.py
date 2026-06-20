#!/usr/bin/env python3
"""
nmap-parser.py — Parse Nmap XML (-oX) output into clean, pipeable summaries.

Part of the CTF/hackathon Nmap toolkit. Pure standard library (xml.etree).

AUTHORIZED TARGETS ONLY. Only scan/parse results for systems you have explicit
written permission to test. Unauthorized scanning is illegal.

Nmap XML structure reference (nmap.org/book/output-formats-xml-output.html):
  <nmaprun>
    <host>
      <status state="up"/>
      <address addr="10.0.0.1" addrtype="ipv4"/>
      <hostnames><hostname name="foo" type="PTR"/></hostnames>
      <ports>
        <port protocol="tcp" portid="80">
          <state state="open"/>
          <service name="http" product="Apache httpd" version="2.4.41"
                   extrainfo="..." tunnel="ssl"/>
          <script id="http-title" output="..."/>
        </port>
      </ports>
      <os><osmatch name="Linux 5.x" accuracy="95"/></os>
    </host>
  </nmaprun>

Usage examples:
  ./nmap-parser.py scan.xml
  ./nmap-parser.py scan.xml --format markdown
  ./nmap-parser.py *.xml --format json > parsed.json
  ./nmap-parser.py scan.xml --grep
  ./nmap-parser.py scan.xml --targets http        # hosts with http open
  ./nmap-parser.py scan.xml --targets smb --grep  # combine for ip:port lines
"""

import argparse
import csv
import io
import json
import sys
import xml.etree.ElementTree as ET


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
class Port:
    """A single discovered port and its (best-effort) service details."""

    def __init__(self, portid, protocol, state, service):
        self.portid = portid            # str, e.g. "80"
        self.protocol = protocol        # str, e.g. "tcp"
        self.state = state              # str, e.g. "open"
        self.service = service          # str service name, e.g. "http"
        self.product = ""               # e.g. "Apache httpd"
        self.version = ""               # e.g. "2.4.41"
        self.extrainfo = ""             # e.g. "(Ubuntu)"
        self.tunnel = ""                # e.g. "ssl" (https etc.)
        self.scripts = {}               # {script_id: output}

    @property
    def port_int(self):
        """Numeric port for sorting; falls back to 0 on malformed data."""
        try:
            return int(self.portid)
        except (TypeError, ValueError):
            return 0

    @property
    def version_str(self):
        """Combined product + version + extrainfo, trimmed."""
        parts = [p for p in (self.product, self.version, self.extrainfo) if p]
        return " ".join(parts).strip()

    @property
    def service_label(self):
        """Service name, annotated with ssl/tls tunnel when present."""
        if self.tunnel and self.tunnel.lower() in ("ssl", "tls"):
            # e.g. http over ssl -> "ssl/http"
            return "ssl/" + (self.service or "unknown")
        return self.service or "unknown"


class Host:
    """A scanned host with its address, names, OS guess, and ports."""

    def __init__(self):
        self.ip = ""                    # primary IPv4/IPv6 address
        self.mac = ""                   # MAC if present
        self.vendor = ""                # MAC vendor if present
        self.hostnames = []             # list of resolved names
        self.state = "unknown"          # up / down
        self.os_guess = ""              # best OS match name
        self.os_accuracy = ""           # accuracy % as str
        self.ports = []                 # list[Port]

    @property
    def display_name(self):
        """IP plus first hostname (if any) for human-readable output."""
        if self.hostnames:
            return "%s (%s)" % (self.ip, self.hostnames[0])
        return self.ip or "unknown"

    @property
    def os_label(self):
        if self.os_guess and self.os_accuracy:
            return "%s (%s%%)" % (self.os_guess, self.os_accuracy)
        return self.os_guess or "unknown"

    def open_ports(self):
        """Only ports in an 'open' (or 'open|filtered') state."""
        return [p for p in self.ports if p.state and p.state.startswith("open")]


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def _text(elem, attr, default=""):
    """Safely fetch an attribute from a possibly-None element."""
    if elem is None:
        return default
    return elem.get(attr, default)


def parse_host(host_elem):
    """Convert a <host> element into a Host object, tolerating missing fields."""
    host = Host()

    # --- status (up/down) ---
    status = host_elem.find("status")
    host.state = _text(status, "state", "unknown")

    # --- addresses: prefer ipv4/ipv6 as primary, capture mac separately ---
    for addr in host_elem.findall("address"):
        addrtype = addr.get("addrtype", "")
        if addrtype in ("ipv4", "ipv6"):
            # First IP wins as the primary display address.
            if not host.ip:
                host.ip = addr.get("addr", "")
        elif addrtype == "mac":
            host.mac = addr.get("addr", "")
            host.vendor = addr.get("vendor", "")

    # --- hostnames ---
    hn_container = host_elem.find("hostnames")
    if hn_container is not None:
        for hn in hn_container.findall("hostname"):
            name = hn.get("name", "")
            if name:
                host.hostnames.append(name)

    # --- OS detection (best match by accuracy) ---
    os_elem = host_elem.find("os")
    if os_elem is not None:
        best = None
        for match in os_elem.findall("osmatch"):
            try:
                acc = int(match.get("accuracy", "0"))
            except ValueError:
                acc = 0
            if best is None or acc > best[0]:
                best = (acc, match.get("name", ""))
        if best is not None:
            host.os_accuracy = str(best[0])
            host.os_guess = best[1]

    # --- ports ---
    ports_container = host_elem.find("ports")
    if ports_container is not None:
        for port_elem in ports_container.findall("port"):
            state_elem = port_elem.find("state")
            svc_elem = port_elem.find("service")

            port = Port(
                portid=port_elem.get("portid", ""),
                protocol=port_elem.get("protocol", ""),
                state=_text(state_elem, "state", "unknown"),
                service=_text(svc_elem, "name", ""),
            )
            port.product = _text(svc_elem, "product", "")
            port.version = _text(svc_elem, "version", "")
            port.extrainfo = _text(svc_elem, "extrainfo", "")
            port.tunnel = _text(svc_elem, "tunnel", "")

            # NSE script output attached to this port
            for script in port_elem.findall("script"):
                sid = script.get("id", "")
                if sid:
                    port.scripts[sid] = script.get("output", "")

            host.ports.append(port)

    # Sort ports numerically for stable, readable output.
    host.ports.sort(key=lambda p: (p.protocol, p.port_int))
    return host


def parse_files(paths):
    """Parse one or more nmap XML files into a flat list of Host objects."""
    hosts = []
    for path in paths:
        try:
            tree = ET.parse(path)
        except ET.ParseError as exc:
            print("[!] Skipping %s: malformed XML (%s)" % (path, exc),
                  file=sys.stderr)
            continue
        except (OSError, IOError) as exc:
            print("[!] Skipping %s: cannot read (%s)" % (path, exc),
                  file=sys.stderr)
            continue

        root = tree.getroot()
        for host_elem in root.findall("host"):
            hosts.append(parse_host(host_elem))
    return hosts


# --------------------------------------------------------------------------- #
# Output renderers
# --------------------------------------------------------------------------- #
def _ascii_table(headers, rows):
    """Render a simple fixed-width ASCII table."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt(cells):
        return "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(cells))

    out = [fmt(headers), "  ".join("-" * w for w in widths)]
    for row in rows:
        out.append(fmt(row))
    return "\n".join(out)


def render_table(hosts):
    """Human-readable per-host summary plus an open-ports table."""
    blocks = []
    for host in hosts:
        header = "=" * 70
        info = [
            header,
            "Host:  %s" % host.display_name,
            "State: %s" % host.state,
            "OS:    %s" % host.os_label,
        ]
        if host.mac:
            mac_line = "MAC:   %s" % host.mac
            if host.vendor:
                mac_line += " (%s)" % host.vendor
            info.append(mac_line)
        blocks.append("\n".join(info))

        open_ports = host.open_ports()
        if not open_ports:
            blocks.append("  (no open ports found)")
            continue

        rows = [
            (p.portid, p.protocol, p.state, p.service_label,
             p.version_str or "-")
            for p in open_ports
        ]
        table = _ascii_table(
            ["PORT", "PROTO", "STATE", "SERVICE", "VERSION"], rows
        )
        # Indent the table under the host block.
        blocks.append("\n".join("  " + line for line in table.splitlines()))

    if not blocks:
        return "No hosts found in input."
    return "\n\n".join(blocks)


def render_markdown(hosts):
    """Markdown suitable for pasting into CTF notes."""
    out = []
    for host in hosts:
        out.append("## %s" % host.display_name)
        out.append("")
        out.append("- **State:** %s" % host.state)
        out.append("- **OS:** %s" % host.os_label)
        if host.mac:
            mac = host.mac + (" (%s)" % host.vendor if host.vendor else "")
            out.append("- **MAC:** %s" % mac)
        out.append("")

        open_ports = host.open_ports()
        if not open_ports:
            out.append("_No open ports found._")
            out.append("")
            continue

        out.append("| Port | Proto | State | Service | Version |")
        out.append("|------|-------|-------|---------|---------|")
        for p in open_ports:
            # Escape pipe chars so they don't break the markdown table.
            ver = (p.version_str or "-").replace("|", "\\|")
            svc = p.service_label.replace("|", "\\|")
            out.append("| %s | %s | %s | %s | %s |" % (
                p.portid, p.protocol, p.state, svc, ver))
        out.append("")

    if not out:
        return "No hosts found in input."
    return "\n".join(out)


def render_csv(hosts):
    """Flat CSV: one row per open port."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "ip", "hostname", "state", "os", "port", "protocol",
        "port_state", "service", "product", "version", "extrainfo",
    ])
    for host in hosts:
        hostname = host.hostnames[0] if host.hostnames else ""
        for p in host.open_ports():
            writer.writerow([
                host.ip, hostname, host.state, host.os_guess,
                p.portid, p.protocol, p.state, p.service_label,
                p.product, p.version, p.extrainfo,
            ])
    return buf.getvalue().rstrip("\n")


def render_json(hosts):
    """Structured JSON for programmatic consumption."""
    data = []
    for host in hosts:
        data.append({
            "ip": host.ip,
            "hostnames": host.hostnames,
            "state": host.state,
            "mac": host.mac,
            "vendor": host.vendor,
            "os": {"guess": host.os_guess, "accuracy": host.os_accuracy},
            "ports": [
                {
                    "port": p.portid,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service_label,
                    "product": p.product,
                    "version": p.version,
                    "extrainfo": p.extrainfo,
                    "tunnel": p.tunnel,
                    "scripts": p.scripts,
                }
                for p in host.ports
            ],
        })
    return json.dumps(data, indent=2)


def render_grep(hosts):
    """One `ip:port service` line per open port — easy to pipe/awk."""
    lines = []
    for host in hosts:
        for p in host.open_ports():
            lines.append("%s:%s %s" % (host.ip, p.portid, p.service_label))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# --targets mode
# --------------------------------------------------------------------------- #
def filter_targets(hosts, service):
    """
    Return hosts that have an open port whose service matches `service`.

    Matching is case-insensitive and substring-based so that "http" also
    matches "https"/"ssl/http", and "smb" matches "microsoft-ds"/"netbios-ssn"
    via the alias table below.
    """
    needle = service.lower().strip()

    # Common service aliases so high-level names match nmap's port labels.
    aliases = {
        "smb": ["smb", "microsoft-ds", "netbios-ssn", "netbios"],
        "http": ["http", "http-proxy", "http-alt"],
        "https": ["https", "ssl/http"],
        "ftp": ["ftp", "ftp-data"],
        "ssh": ["ssh"],
        "rdp": ["rdp", "ms-wbt-server"],
        "dns": ["dns", "domain"],
        "mysql": ["mysql"],
        "mssql": ["mssql", "ms-sql-s", "ms-sql"],
        "ldap": ["ldap", "ldapssl"],
        "winrm": ["winrm", "wsman"],
    }
    candidates = aliases.get(needle, [needle])

    matched = []
    for host in hosts:
        hit_ports = []
        for p in host.open_ports():
            label = (p.service_label or "").lower()
            name = (p.service or "").lower()
            if any(c in label or c in name for c in candidates):
                hit_ports.append(p)
        if hit_ports:
            matched.append((host, hit_ports))
    return matched


def render_targets(matched, service, grep):
    """Render --targets results, either as ip lines or ip:port lines."""
    if not matched:
        return ""  # nothing matched; stay quiet so pipes get empty input

    lines = []
    if grep:
        # ip:port service — one per matching port
        for host, ports in matched:
            for p in ports:
                lines.append("%s:%s %s" % (host.ip, p.portid, p.service_label))
    else:
        # Just the host IPs (deduplicated, order-preserving) for piping.
        seen = set()
        for host, _ports in matched:
            if host.ip and host.ip not in seen:
                seen.add(host.ip)
                lines.append(host.ip)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_parser():
    parser = argparse.ArgumentParser(
        description="Parse Nmap XML (-oX) output into clean summaries. "
                    "AUTHORIZED TARGETS ONLY.",
        epilog="Examples:\n"
               "  %(prog)s scan.xml --format markdown\n"
               "  %(prog)s *.xml --grep\n"
               "  %(prog)s scan.xml --targets http\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "xml", nargs="+", metavar="XML",
        help="one or more nmap XML files (-oX output)")
    parser.add_argument(
        "--format", choices=["table", "markdown", "csv", "json"],
        default="table",
        help="output format (default: table)")
    parser.add_argument(
        "--grep", action="store_true",
        help="print only `ip:port service` lines")
    parser.add_argument(
        "--targets", metavar="SERVICE",
        help="print hosts that have SERVICE open (e.g. http, smb, ftp). "
             "Combine with --grep for ip:port lines.")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    hosts = parse_files(args.xml)

    # --targets takes precedence: it's a filter+pipe mode.
    if args.targets:
        matched = filter_targets(hosts, args.targets)
        out = render_targets(matched, args.targets, args.grep)
        if out:
            print(out)
        return 0

    # --grep is a quick flat view that ignores --format.
    if args.grep:
        out = render_grep(hosts)
        if out:
            print(out)
        return 0

    renderers = {
        "table": render_table,
        "markdown": render_markdown,
        "csv": render_csv,
        "json": render_json,
    }
    print(renderers[args.format](hosts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
