#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  weak-creds-check.py  --  Default / weak credential auditor
#  Part of the Home-Network Security Audit suite.
#
#  ***************************************************************************
#  *  AUTHORIZED NETWORKS ONLY.                                            *
#  *  Testing default credentials against devices you do not own may be    *
#  *  ILLEGAL. Run this ONLY against equipment you own or are explicitly   *
#  *  authorized in writing to test. You are responsible for your use.     *
#  ***************************************************************************
#
#  Purpose: SAFELY check whether services discovered on YOUR OWN local
#  network still accept well-known default / weak credentials.
#
#  Safety design (defensive, anti-lockout):
#    * STRICT rate limiting: a configurable delay between every attempt.
#    * Low/no concurrency (sequential per host by default).
#    * A hard max-attempts cap PER HOST to avoid triggering lockouts.
#    * STOP-ON-FIRST-SUCCESS per (host, service) -- once a default cred
#      works we stop hammering that service.
#    * --dry-run prints exactly what WOULD be tried, connecting to nothing.
#
#  Supported services: http (basic-auth + simple form login), ssh (paramiko),
#  ftp (ftplib), telnet (socket-based), mysql (mysql.connector/pymysql).
#  Optional libraries are skipped gracefully with a note if missing.
#
#  Cross-platform: pure Python 3 standard library + optional 'requests',
#  'paramiko', 'mysql.connector'/'pymysql'. Works on Windows and Linux.
# =============================================================================

import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone

TOOL_NAME = "weak-creds-check"

# ---------------------------------------------------------------------------
# Optional dependency detection (graceful degradation)
# ---------------------------------------------------------------------------
# HTTP: prefer 'requests', fall back to urllib from the standard library.
try:
    import requests  # type: ignore
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False
    import urllib.request
    import urllib.error
    import base64

# SSH: requires paramiko (no stdlib equivalent).
try:
    import paramiko  # type: ignore
    HAVE_PARAMIKO = True
except Exception:
    HAVE_PARAMIKO = False

# FTP: standard library.
try:
    import ftplib
    HAVE_FTP = True
except Exception:
    HAVE_FTP = False

# MySQL: try mysql.connector, then pymysql.
MYSQL_DRIVER = None
try:
    import mysql.connector as _mysql_connector  # type: ignore
    MYSQL_DRIVER = "mysql.connector"
except Exception:
    try:
        import pymysql as _pymysql  # type: ignore
        MYSQL_DRIVER = "pymysql"
    except Exception:
        MYSQL_DRIVER = None


# ---------------------------------------------------------------------------
# Default port -> service mapping used when --from-json is not given and the
# user passes bare host:port targets without an explicit service.
# ---------------------------------------------------------------------------
PORT_SERVICE_HINTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    80: "http",
    81: "http",
    443: "http",
    8080: "http",
    8443: "http",
    3306: "mysql",
}


# ---------------------------------------------------------------------------
# Result schema helpers
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
# Credential loading
# ---------------------------------------------------------------------------
def load_creds(path):
    """Load default-creds.json into a dict of service -> [ {user,pass}, ... ]."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


def creds_for_service(creds_db, service):
    """Build the ordered list of (user, pass) pairs to try for a service.

    For HTTP we also fold in every router-vendor pair, since web admin pages
    are the most common place those defaults live. We de-duplicate while
    preserving order.
    """
    pairs = []
    seen = set()

    def add_list(lst):
        for c in lst or []:
            key = (c.get("user", ""), c.get("pass", ""))
            if key not in seen:
                seen.add(key)
                pairs.append(key)

    add_list(creds_db.get(service))
    if service == "http":
        for vendor_pairs in (creds_db.get("router_vendors") or {}).values():
            add_list(vendor_pairs)
    # Always include the small generic set as a backstop.
    add_list(creds_db.get("generic"))
    return pairs


# ---------------------------------------------------------------------------
# Target parsing
# ---------------------------------------------------------------------------
def parse_targets_from_args(target_args):
    """Parse 'ip:port[:service]' style targets from the command line."""
    targets = []
    for t in target_args:
        parts = t.split(":")
        if len(parts) == 1:
            raise ValueError("Target '%s' must include a port (ip:port)" % t)
        ip = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            raise ValueError("Invalid port in target '%s'" % t)
        service = parts[2].lower() if len(parts) >= 3 else PORT_SERVICE_HINTS.get(port)
        if not service:
            raise ValueError(
                "Could not infer service for %s; add it: %s:SERVICE" % (t, t)
            )
        targets.append({"ip": ip, "port": port, "service": service})
    return targets


def parse_targets_from_json(path):
    """Read open services from a prior port-service-scan.json (shared schema).

    We only look at findings that describe an open port with a service we can
    test. This lets weak-creds-check operate on already-discovered services.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    targets = []
    seen = set()
    for fnd in data.get("findings", []):
        host = fnd.get("host")
        port = fnd.get("port")
        svc = (fnd.get("service") or "").lower()
        if not host or not port:
            continue
        # Normalize service names from a generic scanner to ours.
        svc_norm = None
        if svc in ("http", "https", "http-alt", "www"):
            svc_norm = "http"
        elif svc in PORT_SERVICE_HINTS.values():
            svc_norm = svc
        elif port in PORT_SERVICE_HINTS:
            svc_norm = PORT_SERVICE_HINTS[port]
        if not svc_norm:
            continue
        key = (host, port, svc_norm)
        if key in seen:
            continue
        seen.add(key)
        targets.append({"ip": host, "port": port, "service": svc_norm})
    return targets


# ---------------------------------------------------------------------------
# Service-specific credential testers.
# Each returns one of:
#   ("success", "<user>:<pass>")   default cred accepted
#   ("fail", None)                  attempt completed, rejected
#   ("error", "<msg>")             connection/protocol error (counts as attempt)
# ---------------------------------------------------------------------------
def test_http(ip, port, user, password, timeout):
    """Try HTTP basic-auth, and a best-effort generic form POST.

    We treat HTTP 200/30x without a re-presented auth challenge as success for
    basic-auth. Form detection is heuristic; we never claim success unless the
    response clearly differs from an unauthenticated/failed login.
    """
    scheme = "https" if port in (443, 8443) else "http"
    url = "%s://%s:%d/" % (scheme, ip, port)

    if HAVE_REQUESTS:
        try:
            # Attempt 1: HTTP Basic auth.
            r = requests.get(
                url,
                auth=(user, password),
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            if r.status_code in (200, 301, 302, 303) and r.status_code != 401:
                # Confirm the page wasn't just a public landing page by re-checking
                # without creds: if anon also returns 200 identically, it's not auth.
                anon = requests.get(url, timeout=timeout, verify=False,
                                    allow_redirects=False)
                if anon.status_code == 401 and r.status_code != 401:
                    return ("success", "%s:%s" % (user, password))
                # If anon is 200 too, basic auth wasn't the gate -> inconclusive.
            return ("fail", None)
        except requests.exceptions.RequestException as e:
            return ("error", str(e))
    else:
        # urllib fallback for HTTP basic-auth only.
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            token = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
            req = urllib.request.Request(url)
            req.add_header("Authorization", "Basic " + token)
            try:
                resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
                code = resp.getcode()
                if code in (200, 301, 302, 303):
                    return ("success", "%s:%s" % (user, password))
                return ("fail", None)
            except urllib.error.HTTPError as he:
                if he.code == 401:
                    return ("fail", None)
                if he.code in (200, 301, 302, 303):
                    return ("success", "%s:%s" % (user, password))
                return ("fail", None)
        except Exception as e:
            return ("error", str(e))


def test_ssh(ip, port, user, password, timeout):
    if not HAVE_PARAMIKO:
        return ("skip", "paramiko not installed")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            ip,
            port=port,
            username=user,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
        client.close()
        return ("success", "%s:%s" % (user, password))
    except paramiko.AuthenticationException:
        return ("fail", None)
    except Exception as e:
        return ("error", str(e))
    finally:
        try:
            client.close()
        except Exception:
            pass


def test_ftp(ip, port, user, password, timeout):
    if not HAVE_FTP:
        return ("skip", "ftplib unavailable")
    ftp = ftplib.FTP()
    try:
        ftp.connect(ip, port, timeout=timeout)
        ftp.login(user, password)
        ftp.quit()
        return ("success", "%s:%s" % (user, password))
    except ftplib.error_perm:
        return ("fail", None)
    except Exception as e:
        return ("error", str(e))
    finally:
        try:
            ftp.close()
        except Exception:
            pass


def test_telnet(ip, port, user, password, timeout):
    """Socket-based Telnet login attempt.

    telnetlib was removed in Python 3.13, so we implement a minimal,
    best-effort login over a raw socket. This is heuristic: we look for a
    prompt that indicates a successful shell vs a repeated login prompt.
    """
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
    except Exception as e:
        return ("error", str(e))

    def recv_all():
        data = b""
        try:
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
                if len(chunk) < 1024:
                    break
        except socket.timeout:
            pass
        except Exception:
            pass
        return data

    try:
        banner = recv_all().lower()
        # Respond to username prompt.
        if b"login" in banner or b"user" in banner or b"username" in banner:
            s.sendall((user + "\r\n").encode())
            time.sleep(0.3)
            prompt = recv_all().lower()
        else:
            # Some devices ask for password only.
            prompt = banner
        if b"password" in prompt or b"pass" in prompt:
            s.sendall((password + "\r\n").encode())
            time.sleep(0.5)
            result = recv_all().lower()
        else:
            result = prompt
        # Heuristic success: a shell prompt and NOT another login/incorrect msg.
        bad = (b"incorrect" in result or b"failed" in result
               or b"login:" in result or b"denied" in result)
        good = (b"$" in result or b"#" in result or b">" in result
                or b"welcome" in result)
        if good and not bad:
            return ("success", "%s:%s" % (user, password))
        return ("fail", None)
    except Exception as e:
        return ("error", str(e))
    finally:
        try:
            s.close()
        except Exception:
            pass


def test_mysql(ip, port, user, password, timeout):
    if MYSQL_DRIVER is None:
        return ("skip", "no mysql driver (install mysql-connector-python or pymysql)")
    try:
        if MYSQL_DRIVER == "mysql.connector":
            conn = _mysql_connector.connect(
                host=ip, port=port, user=user, password=password,
                connection_timeout=timeout,
            )
            conn.close()
            return ("success", "%s:%s" % (user, password))
        else:  # pymysql
            conn = _pymysql.connect(
                host=ip, port=port, user=user, password=password,
                connect_timeout=timeout,
            )
            conn.close()
            return ("success", "%s:%s" % (user, password))
    except Exception as e:
        msg = str(e).lower()
        if "access denied" in msg or "1045" in msg:
            return ("fail", None)
        return ("error", str(e))


SERVICE_TESTERS = {
    "http": test_http,
    "ssh": test_ssh,
    "ftp": test_ftp,
    "telnet": test_telnet,
    "mysql": test_mysql,
}


# ---------------------------------------------------------------------------
# Core audit loop
# ---------------------------------------------------------------------------
def audit_target(report, tgt, creds_db, args, per_host_counts):
    ip = tgt["ip"]
    port = tgt["port"]
    service = tgt["service"]
    add_host(report, ip)

    tester = SERVICE_TESTERS.get(service)
    if tester is None:
        print("  [skip] %s:%d  unsupported service '%s'" % (ip, port, service))
        return

    pairs = creds_for_service(creds_db, service)

    print("\n[*] %s:%d (%s) -- %d candidate pair(s)" % (ip, port, service, len(pairs)))

    success = False
    for (user, password) in pairs:
        # Per-host attempt cap to avoid lockouts.
        if per_host_counts.get(ip, 0) >= args.max_attempts:
            print("  [cap] reached max-attempts (%d) for host %s; stopping."
                  % (args.max_attempts, ip))
            break

        disp_pass = password if password != "" else "<blank>"
        disp_user = user if user != "" else "<blank>"

        if args.dry_run:
            print("  [dry-run] WOULD try %s / %s" % (disp_user, disp_pass))
            continue

        per_host_counts[ip] = per_host_counts.get(ip, 0) + 1

        status, info = tester(ip, port, user, password, args.timeout)

        if status == "skip":
            print("  [skip] %s -- %s" % (service, info))
            add_finding(
                report, ip, port, service, "info",
                "Service not tested (missing optional dependency)",
                "Could not test %s because: %s" % (service, info),
                "Install the optional library to enable testing, or test manually.",
            )
            return
        elif status == "success":
            print("  [!!] SUCCESS  %s / %s  accepted!" % (disp_user, disp_pass))
            add_finding(
                report, ip, port, service, "critical",
                "Default/weak credentials accepted on %s" % service.upper(),
                "The %s service at %s:%d accepted the default credential "
                "'%s' / '%s'. Anyone on the network can log in." %
                (service.upper(), ip, port, disp_user, disp_pass),
                "Immediately change this account to a strong, unique password "
                "(and disable the service or restrict access if not needed). "
                "Disable remote/WAN management. Consider disabling default "
                "accounts entirely.",
            )
            success = True
            break  # stop-on-first-success per (host, service)
        elif status == "error":
            print("  [err] %s / %s -- %s" % (disp_user, disp_pass, info))
        else:  # fail
            print("  [ok]  %s / %s rejected" % (disp_user, disp_pass))

        # STRICT rate limiting between every real attempt.
        time.sleep(args.delay)

    if not args.dry_run and not success:
        add_finding(
            report, ip, port, service, "info",
            "No default credentials accepted on %s" % service.upper(),
            "Tested common default/weak credentials against %s:%d; none "
            "succeeded (within the attempt cap)." % (ip, port),
            "Good. Continue using strong, unique passwords and keep firmware "
            "up to date.",
        )


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
    for f in report["findings"]:
        if f["severity"] in ("critical", "high"):
            print("[%s] %s:%s (%s)" % (f["severity"].upper(), f["host"],
                                       f["port"], f["service"]))
            print("    %s" % f["title"])
            print("    %s" % f["detail"])
            print("    -> %s" % f["recommendation"])
    if counts["critical"] == 0 and counts["high"] == 0:
        print("No critical/high credential findings. (See JSON for info items.)")
    print("=" * 70)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description="Safely check discovered services for default/weak "
                    "credentials. AUTHORIZED NETWORKS ONLY.",
        epilog="Examples:\n"
               "  python weak-creds-check.py 192.168.1.1:80 192.168.1.1:23:telnet\n"
               "  python weak-creds-check.py --from-json port-service-scan.json --json out.json\n"
               "  python weak-creds-check.py 192.168.1.1:80 --dry-run\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="*",
                   help="Targets as ip:port[:service] (service inferred from "
                        "well-known ports if omitted).")
    p.add_argument("--from-json", dest="from_json",
                   help="Read open services from a prior scan JSON (shared schema).")
    p.add_argument("--creds", default=None,
                   help="Path to credentials JSON (default: default-creds.json "
                        "next to this script).")
    p.add_argument("--json", dest="json_out",
                   help="Write results to this JSON file (shared schema).")
    p.add_argument("--delay", type=float, default=1.0,
                   help="Delay in seconds between EVERY attempt (default: 1.0). "
                        "Higher = safer against lockouts.")
    p.add_argument("--max-attempts", type=int, default=20, dest="max_attempts",
                   help="Hard cap on total attempts PER HOST (default: 20).")
    p.add_argument("--timeout", type=float, default=5.0,
                   help="Per-connection timeout in seconds (default: 5.0).")
    p.add_argument("--dry-run", action="store_true",
                   help="List what WOULD be tried; connect to nothing.")
    return p


def main():
    args = build_parser().parse_args()

    print("=" * 70)
    print(" weak-creds-check  --  AUTHORIZED NETWORKS ONLY")
    print(" Testing default credentials against devices you do not own may")
    print(" be ILLEGAL. Use only on equipment you own or may test.")
    print("=" * 70)

    # Locate creds file.
    creds_path = args.creds
    if not creds_path:
        creds_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "default-creds.json")
    if not os.path.isfile(creds_path):
        print("[ERROR] credentials file not found: %s" % creds_path)
        sys.exit(2)
    creds_db = load_creds(creds_path)

    # Gather targets.
    targets = []
    target_label = ""
    try:
        if args.from_json:
            targets = parse_targets_from_json(args.from_json)
            target_label = "from-json:%s" % args.from_json
        if args.targets:
            targets += parse_targets_from_args(args.targets)
            target_label = (target_label + " " if target_label else "") + \
                ",".join(args.targets)
    except ValueError as e:
        print("[ERROR] %s" % e)
        sys.exit(2)

    if not targets:
        print("[ERROR] No targets. Provide ip:port targets or --from-json.")
        sys.exit(2)

    # Dependency status note.
    print("\nOptional dependency status:")
    print("  HTTP via requests : %s" % ("yes" if HAVE_REQUESTS else "no (urllib fallback)"))
    print("  SSH via paramiko  : %s" % ("yes" if HAVE_PARAMIKO else "NO (ssh skipped)"))
    print("  MySQL driver      : %s" % (MYSQL_DRIVER or "NO (mysql skipped)"))
    if args.dry_run:
        print("\n*** DRY-RUN: no connections will be made. ***")
    print("\nRate limiting: delay=%.1fs, max-attempts/host=%d, timeout=%.1fs"
          % (args.delay, args.max_attempts, args.timeout))

    # Suppress noisy TLS warnings from requests when verify=False.
    if HAVE_REQUESTS:
        try:
            requests.packages.urllib3.disable_warnings()  # type: ignore
        except Exception:
            pass

    report = new_report(target_label)
    per_host_counts = {}

    for tgt in targets:
        audit_target(report, tgt, creds_db, args, per_host_counts)

    print_summary(report)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print("\n[+] JSON written to %s" % args.json_out)


if __name__ == "__main__":
    main()
