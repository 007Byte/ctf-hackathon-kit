#!/usr/bin/env python3
"""
audit.py  --  Home-Network Security Audit ORCHESTRATOR

  +------------------------------------------------------------------+
  |  AUTHORIZED NETWORKS ONLY.  Run this only against a network you   |
  |  own or have explicit written permission to test. Port scanning,  |
  |  credential testing, and service probing of networks you do not   |
  |  control may be illegal in your jurisdiction.                     |
  +------------------------------------------------------------------+

Runs the suite's Python tools in sequence, feeding each stage's output into
the next, then aggregates every tool's shared-schema JSON into ONE HTML
report (plus a combined JSON).

Pipeline:
    host-discovery  ->  port-service-scan  ->  backdoor-scan
                                            ->  weak-creds-check  (opt-in)
    router-audit  (gateway)                 (run in parallel-ish, sequential here)
    upnp-scan     (SSDP)

Examples:
    python audit.py                         # auto-detect subnet, full audit
    python audit.py 192.168.1.0/24          # explicit subnet
    python audit.py --quick                 # top-20 ports, faster
    python audit.py --check-creds           # ALSO test default creds (intrusive!)
    python audit.py -o myrun                # write results to ./myrun/

The credential test is OFF by default because it actively attempts logins.
Add --check-creds to enable it (it still rate-limits and caps attempts).
"""

import argparse
import datetime
import html
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable or "python3"

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLOR = {
    "critical": "#b00020", "high": "#d93025", "medium": "#f29900",
    "low": "#1a73e8", "info": "#5f6368",
}


def banner():
    print("=" * 68)
    print("  HOME-NETWORK SECURITY AUDIT  --  authorized networks only")
    print("=" * 68)


def run_tool(script, args, json_out, label):
    """Run a suite tool as a subprocess; return parsed JSON dict or None."""
    path = os.path.join(HERE, script)
    if not os.path.exists(path):
        print(f"[!] {label}: {script} not found, skipping.")
        return None
    cmd = [PY, path] + args + ["--json", json_out]
    print(f"\n[>] {label}")
    print(f"    $ {' '.join(cmd)}")
    try:
        # Stream tool output live; tools also write their JSON file.
        subprocess.run(cmd, cwd=HERE, check=False)
    except KeyboardInterrupt:
        print(f"[!] {label} interrupted by user.")
    except Exception as e:  # noqa: BLE001
        print(f"[!] {label} failed to launch: {e}")
        return None
    if os.path.exists(json_out):
        try:
            with open(json_out, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as e:  # noqa: BLE001
            print(f"[!] {label}: could not read JSON ({e}).")
    return None


def merge(results):
    """Merge per-tool results into combined hosts + findings."""
    hosts = {}
    findings = []
    for res in results:
        if not res:
            continue
        for h in res.get("hosts", []) or []:
            ip = h.get("ip")
            if not ip:
                continue
            cur = hosts.setdefault(ip, {"ip": ip, "mac": "", "vendor": "",
                                        "hostname": "", "state": "up"})
            for k in ("mac", "vendor", "hostname", "state"):
                if h.get(k) and not cur.get(k):
                    cur[k] = h[k]
        for f in res.get("findings", []) or []:
            f = dict(f)
            f["_tool"] = res.get("tool", "")
            findings.append(f)
    # De-duplicate findings on (host, port, title)
    seen = set()
    deduped = []
    for f in findings:
        key = (f.get("host", ""), f.get("port", 0), f.get("title", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    deduped.sort(key=lambda x: (SEV_ORDER.get(str(x.get("severity", "info")).lower(), 9),
                                str(x.get("host", "")), x.get("port", 0) or 0))
    return list(hosts.values()), deduped


def severity_counts(findings):
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        s = str(f.get("severity", "info")).lower()
        if s in counts:
            counts[s] += 1
    return counts


def write_text_report(path, target, hosts, findings):
    counts = severity_counts(findings)
    lines = []
    lines.append("HOME-NETWORK SECURITY AUDIT REPORT")
    lines.append("=" * 60)
    lines.append(f"Target : {target}")
    lines.append(f"Hosts  : {len(hosts)} live")
    lines.append("Findings: " + ", ".join(
        f"{s}={counts[s]}" for s in SEV_ORDER if counts[s]))
    lines.append("")
    lines.append("-- LIVE HOSTS " + "-" * 46)
    for h in sorted(hosts, key=lambda x: x.get("ip", "")):
        lines.append(f"  {h.get('ip',''):<16} {h.get('hostname',''):<22} "
                     f"{h.get('mac',''):<18} {h.get('vendor','')}")
    lines.append("")
    lines.append("-- FINDINGS (by severity) " + "-" * 34)
    for f in findings:
        sev = str(f.get("severity", "info")).upper()
        loc = f.get("host", "")
        if f.get("port"):
            loc += f":{f['port']}"
        lines.append(f"  [{sev}] {loc}  {f.get('title','')}")
        if f.get("detail"):
            lines.append(f"        {f['detail']}")
        if f.get("recommendation"):
            lines.append(f"        -> {f['recommendation']}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def write_html_report(path, target, hosts, findings, when):
    counts = severity_counts(findings)
    def esc(x):
        return html.escape(str(x if x is not None else ""))

    chips = "".join(
        f'<span class="chip" style="background:{SEV_COLOR[s]}">{s.upper()}: {counts[s]}</span>'
        for s in SEV_ORDER if counts[s]
    ) or '<span class="chip" style="background:#1e8e3e">No findings</span>'

    host_rows = "".join(
        f"<tr><td>{esc(h.get('ip'))}</td><td>{esc(h.get('hostname'))}</td>"
        f"<td>{esc(h.get('mac'))}</td><td>{esc(h.get('vendor'))}</td></tr>"
        for h in sorted(hosts, key=lambda x: x.get("ip", ""))
    ) or '<tr><td colspan="4">No live hosts recorded.</td></tr>'

    finding_rows = ""
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        color = SEV_COLOR.get(sev, "#5f6368")
        loc = esc(f.get("host", ""))
        if f.get("port"):
            loc += f":{esc(f['port'])}"
        finding_rows += (
            f'<tr><td><span class="sev" style="background:{color}">{sev.upper()}</span></td>'
            f"<td>{loc}</td><td><b>{esc(f.get('title'))}</b><br>"
            f"<span class='detail'>{esc(f.get('detail'))}</span>"
            + (f"<br><span class='rec'>&#10148; {esc(f.get('recommendation'))}</span>"
               if f.get("recommendation") else "")
            + f"</td><td class='tool'>{esc(f.get('_tool'))}</td></tr>"
        )
    if not finding_rows:
        finding_rows = '<tr><td colspan="4">No findings — nothing flagged.</td></tr>'

    doc = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Audit Report</title><style>
body{{font-family:-apple-system,"Segoe UI",Roboto,Arial,sans-serif;margin:0;background:#f5f6f8;color:#202124}}
header{{background:#1a2733;color:#fff;padding:20px 28px}}
header h1{{margin:0;font-size:22px}} .meta{{color:#9fb3c8;font-size:13px;margin-top:6px}}
.wrap{{max-width:1100px;margin:0 auto;padding:20px 28px}}
.chip,.sev{{color:#fff;border-radius:12px;padding:3px 10px;font-size:12px;font-weight:600;margin-right:6px;display:inline-block}}
.sev{{border-radius:4px;font-size:11px;padding:2px 7px}}
.card{{background:#fff;border-radius:10px;padding:16px 20px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.12)}}
h2{{font-size:15px;color:#1a2733;border-bottom:2px solid #e0e3e7;padding-bottom:6px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
td,th{{text-align:left;padding:7px 9px;border-bottom:1px solid #eceef1;vertical-align:top}}
th{{background:#f0f2f5;font-size:12px}} .detail{{color:#444}} .rec{{color:#1e7e34}}
.tool{{color:#888;font-size:11px}}
.warn{{background:#fff4e5;border:1px solid #f0c36d;border-radius:8px;padding:10px 14px;font-size:13px;margin:16px 0}}
footer{{text-align:center;color:#888;font-size:12px;padding:20px}}
</style></head><body>
<header><h1>&#128737; Home-Network Security Audit</h1>
<div class="meta">Target: {esc(target)} &nbsp;|&nbsp; Generated: {esc(when)} &nbsp;|&nbsp; {len(hosts)} live hosts &nbsp;|&nbsp; {len(findings)} findings</div></header>
<div class="wrap">
<div class="warn">&#9888; For authorized networks only. This report lists <b>indicators</b> to review — verify before acting. Severities are heuristic.</div>
<div class="card"><h2>Summary</h2>{chips}</div>
<div class="card"><h2>Findings</h2>
<table><tr><th>Severity</th><th>Location</th><th>Detail</th><th>Source</th></tr>{finding_rows}</table></div>
<div class="card"><h2>Live Hosts</h2>
<table><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th></tr>{host_rows}</table></div>
</div>
<footer>Generated by audit.py — CTF/Hackathon network-audit suite. Authorized use only.</footer>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


def main():
    ap = argparse.ArgumentParser(
        description="Orchestrate the home-network security audit suite.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="AUTHORIZED NETWORKS ONLY. Scan only networks you own or may test.")
    ap.add_argument("target", nargs="?",
                    help="CIDR/subnet to audit (default: auto-detect local subnet).")
    ap.add_argument("-o", "--output", default="audit-results",
                    help="Output directory (default: ./audit-results).")
    ap.add_argument("--quick", action="store_true",
                    help="Faster: scan top 20 ports only.")
    ap.add_argument("--check-creds", action="store_true",
                    help="ALSO run the default-credential test (intrusive; off by default).")
    ap.add_argument("--skip-discovery", action="store_true",
                    help="Skip host discovery (requires --target be a single host/list).")
    ap.add_argument("--skip-router", action="store_true", help="Skip the router/gateway audit.")
    ap.add_argument("--skip-upnp", action="store_true", help="Skip UPnP/SSDP discovery.")
    ap.add_argument("--skip-backdoor", action="store_true", help="Skip the backdoor/suspicious-port scan.")
    args = ap.parse_args()

    banner()
    when = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    outdir = os.path.abspath(args.output)
    os.makedirs(outdir, exist_ok=True)
    print(f"[i] Output directory: {outdir}")
    if not args.check_creds:
        print("[i] Credential testing is OFF (add --check-creds to enable).")

    def jp(name):
        return os.path.join(outdir, name)

    results = []
    target = args.target or "auto-detected local subnet"

    # 1. Host discovery
    hosts_json = jp("host-discovery.json")
    if not args.skip_discovery:
        disc_args = [args.target] if args.target else []
        results.append(run_tool("host-discovery.py", disc_args, hosts_json, "Host discovery"))

    # 2. Port + service scan
    ports_json = jp("port-service-scan.json")
    ps_args = []
    if not args.skip_discovery and os.path.exists(hosts_json):
        ps_args = ["--from-json", hosts_json]
    elif args.target:
        ps_args = [args.target]
    if args.quick:
        ps_args += ["--top", "20"]
    results.append(run_tool("port-service-scan.py", ps_args, ports_json, "Port & service scan"))

    # 3. Backdoor / suspicious-service scan (reuse port-scan output)
    if not args.skip_backdoor:
        bd_args = ["--from-json", ports_json] if os.path.exists(ports_json) else \
                  ([args.target] if args.target else [])
        results.append(run_tool("backdoor-scan.py", bd_args, jp("backdoor-scan.json"),
                                "Backdoor / suspicious-service scan"))

    # 4. Default-credential test (opt-in)
    if args.check_creds and os.path.exists(ports_json):
        results.append(run_tool("weak-creds-check.py", ["--from-json", ports_json],
                                jp("weak-creds-check.json"), "Default-credential test"))
    elif args.check_creds:
        print("[!] --check-creds requested but no port-scan JSON; skipping credential test.")

    # 5. Router / gateway audit
    if not args.skip_router:
        results.append(run_tool("router-audit.py", [], jp("router-audit.json"),
                                "Router / gateway audit"))

    # 6. UPnP / SSDP discovery
    if not args.skip_upnp:
        results.append(run_tool("upnp-scan.py", [], jp("upnp-scan.json"), "UPnP / SSDP discovery"))

    # Aggregate
    hosts, findings = merge(results)
    combined = {
        "target": target, "generated": when,
        "hosts": hosts, "findings": findings,
        "summary": severity_counts(findings),
    }
    with open(jp("combined.json"), "w", encoding="utf-8") as fh:
        json.dump(combined, fh, indent=2)
    write_text_report(jp("report.txt"), target, hosts, findings)
    html_path = jp("report.html")
    write_html_report(html_path, target, hosts, findings, when)

    counts = severity_counts(findings)
    print("\n" + "=" * 68)
    print(f"  AUDIT COMPLETE — {len(hosts)} hosts, {len(findings)} findings")
    print("  " + ", ".join(f"{s}={counts[s]}" for s in SEV_ORDER if counts[s]) or "  no findings")
    print(f"  HTML report : {html_path}")
    print(f"  Text report : {jp('report.txt')}")
    print(f"  Combined JSON: {jp('combined.json')}")
    print("=" * 68)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        sys.exit(130)
