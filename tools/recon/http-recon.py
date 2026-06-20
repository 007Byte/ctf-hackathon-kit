#!/usr/bin/env python3
"""
http-recon.py - Deep HTTP(S) reconnaissance tool

Part of the CY5770 Hackathon recon toolkit. This is the Python counterpart to
the existing bash web-enum.sh (which focuses on dir/vhost fuzzing). This tool
focuses on *fingerprinting and content analysis* of a single URL:

  * status code + full redirect chain
  * all response headers, flagging MISSING security headers
  * detected server / technology (from headers + simple body fingerprints for
    common CMS / frameworks: WordPress, Joomla, Drupal, Laravel, Django, etc.)
  * <title> and HTML comments
  * links and forms (method + action + input fields)
  * probe for interesting files/paths (robots.txt, sitemap.xml, .git/HEAD,
    .env, /admin, /api, common backup files)
  * cookies and their security flags (HttpOnly / Secure / SameSite)
  * any CTF-style flag patterns found in responses

Uses 'requests' if available, gracefully falls back to urllib otherwise.

AUTHORIZED TARGETS ONLY. Only run this against systems you own or have explicit
written permission to test. Unauthorized scanning is illegal.

USAGE:
  ./http-recon.py <url> [options]

EXAMPLES:
  ./http-recon.py http://10.10.10.5/
  ./http-recon.py https://target.htb/ --timeout 15 --json out.json
  ./http-recon.py http://10.10.10.5:8080/ --proxy http://127.0.0.1:8080 -k
"""

import argparse
import json
import re
import sys
import ssl
from urllib.parse import urljoin, urlparse

# ---------------------------------------------------------------------------
# HTTP backend: prefer requests, fall back to urllib.
# ---------------------------------------------------------------------------
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)       # type: ignore
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False
    import urllib.request
    import urllib.error
    import http.cookiejar

# ANSI colors (auto-disabled when not a TTY)
_TTY = sys.stdout.isatty()
def _c(code):
    return code if _TTY else ""
RESET, RED, GRN, YEL, BLU, CYN, BOLD = (
    _c("\033[0m"), _c("\033[31m"), _c("\033[32m"), _c("\033[33m"),
    _c("\033[34m"), _c("\033[36m"), _c("\033[1m"),
)

def log(m):   print(f"{BLU}[*]{RESET} {m}")
def ok(m):    print(f"{GRN}[+]{RESET} {m}")
def warn(m):  print(f"{YEL}[!]{RESET} {m}")
def err(m):   print(f"{RED}[-]{RESET} {m}", file=sys.stderr)
def section(m):
    print(f"\n{BOLD}{CYN}===== {m} ====={RESET}")

# Security headers we expect to see on a well-configured site.
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Interesting paths to probe (sensitive files / common endpoints).
INTERESTING_PATHS = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config", ".env",
    ".env.bak", "admin", "administrator", "login", "api", "api/", "phpinfo.php",
    "server-status", "wp-login.php", ".htaccess", "config.php",
    "backup.zip", "backup.tar.gz", "db.sql", "dump.sql", "config.php.bak",
    "index.php.bak", ".DS_Store", "web.config",
]

# Body fingerprints for common CMS / frameworks (regex -> tech name).
TECH_FINGERPRINTS = [
    (r"wp-content|wp-includes|/wp-json/", "WordPress"),
    (r"Joomla!|/media/jui/|com_content", "Joomla"),
    (r"Drupal\.settings|sites/default/files|/sites/all/", "Drupal"),
    (r"laravel_session|csrf-token|Laravel", "Laravel (PHP)"),
    (r"csrfmiddlewaretoken|__admin__|Django", "Django (Python)"),
    (r"X-Powered-By: Express|__NEXT_DATA__", "Node/Express or Next.js"),
    (r"name=\"generator\" content=\"Magento", "Magento"),
    (r"/typo3/|TYPO3", "TYPO3"),
    (r"jsessionid|/struts/|Apache Tomcat", "Java / Tomcat"),
    (r"phpMyAdmin|pma_", "phpMyAdmin"),
    (r"react|data-reactroot", "React"),
    (r"ng-version|angular", "Angular"),
    (r"vue(\.runtime)?(\.min)?\.js|data-v-", "Vue.js"),
]

# CTF flag patterns to surface automatically.
FLAG_PATTERNS = [
    r"flag\{[^}]{1,200}\}",
    r"FLAG\{[^}]{1,200}\}",
    r"CTF\{[^}]{1,200}\}",
    r"HTB\{[^}]{1,200}\}",
    r"[A-Za-z0-9_]+\{[A-Za-z0-9_\-!@#$%^&*]{4,}\}",
]


def make_request(url, method, args, allow_redirects=True):
    """Perform an HTTP request and return a normalized dict.

    Returns: {status, headers(dict), body(str), url(final), history(list),
              cookies(list of dict), error(str|None)}
    """
    headers = {"User-Agent": args.user_agent}
    if HAVE_REQUESTS:
        proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        try:
            r = requests.request(
                method, url, headers=headers, timeout=args.timeout,
                verify=not args.insecure, allow_redirects=allow_redirects,
                proxies=proxies,
            )
            cookies = [
                {
                    "name": c.name, "value": c.value,
                    "secure": c.secure,
                    "httponly": bool(c._rest.get("HttpOnly") or c._rest.get("httponly")),
                    "samesite": c._rest.get("SameSite") or c._rest.get("samesite") or "",
                }
                for c in r.cookies
            ]
            return {
                "status": r.status_code,
                "headers": dict(r.headers),
                "body": r.text if method != "HEAD" else "",
                "url": r.url,
                "history": [h.url for h in r.history],
                "cookies": cookies,
                "error": None,
            }
        except Exception as e:
            return {"status": None, "headers": {}, "body": "", "url": url,
                    "history": [], "cookies": [], "error": str(e)}
    else:
        # urllib fallback
        ctx = ssl.create_default_context()
        if args.insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        cj = http.cookiejar.CookieJar()
        handlers = [urllib.request.HTTPSHandler(context=ctx),
                    urllib.request.HTTPCookieProcessor(cj)]
        if args.proxy:
            handlers.append(urllib.request.ProxyHandler(
                {"http": args.proxy, "https": args.proxy}))
        if not allow_redirects:
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):
                    return None
            handlers.append(_NoRedirect())
        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, headers=headers, method=method)
        try:
            resp = opener.open(req, timeout=args.timeout)
            raw = resp.read() if method != "HEAD" else b""
            cookies = [
                {"name": c.name, "value": c.value, "secure": bool(c.secure),
                 "httponly": bool(c.has_nonstandard_attr("HttpOnly")),
                 "samesite": ""}
                for c in cj
            ]
            return {
                "status": resp.status,
                "headers": dict(resp.headers.items()),
                "body": raw.decode("utf-8", errors="replace"),
                "url": resp.geturl(),
                "history": [],
                "cookies": cookies,
                "error": None,
            }
        except urllib.error.HTTPError as e:
            return {"status": e.code, "headers": dict(e.headers.items()),
                    "body": e.read().decode("utf-8", errors="replace"),
                    "url": url, "history": [], "cookies": [], "error": None}
        except Exception as e:
            return {"status": None, "headers": {}, "body": "", "url": url,
                    "history": [], "cookies": [], "error": str(e)}


def analyze_headers(headers, report):
    """Print headers and flag missing security headers."""
    section("Response headers")
    for k, v in headers.items():
        print(f"  {BOLD}{k}{RESET}: {v}")
    report["headers"] = dict(headers)

    # Case-insensitive presence check.
    lower = {k.lower(): v for k, v in headers.items()}
    missing = [h for h in SECURITY_HEADERS if h.lower() not in lower]
    report["missing_security_headers"] = missing
    if missing:
        warn("Missing security headers:")
        for h in missing:
            print(f"    {YEL}- {h}{RESET}")
    else:
        ok("All checked security headers present.")

    # Surface server / X-Powered-By directly.
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        if h.lower() in lower:
            ok(f"{h}: {lower[h.lower()]}")
            report.setdefault("server_tech", []).append(f"{h}: {lower[h.lower()]}")


def detect_tech(headers, body, report):
    """Fingerprint CMS / frameworks from headers + body."""
    section("Technology fingerprinting")
    found = []
    haystack = body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
    for pattern, name in TECH_FINGERPRINTS:
        if re.search(pattern, haystack, re.IGNORECASE):
            found.append(name)
    found = sorted(set(found))
    report["detected_tech"] = found
    if found:
        for t in found:
            ok(f"Detected: {t}")
    else:
        log("No common CMS/framework fingerprints matched.")


def parse_html(body, base_url, report):
    """Extract title, comments, links, and forms from the HTML body."""
    section("HTML content analysis")

    # Title
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    title = m.group(1).strip() if m else ""
    report["title"] = title
    print(f"  {BOLD}Title:{RESET} {title or '(none)'}")

    # HTML comments (often leak dev notes / creds / hints)
    comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
    comments = [c.strip() for c in comments if c.strip()]
    report["comments"] = comments
    if comments:
        warn(f"{len(comments)} HTML comment(s) found:")
        for c in comments[:25]:
            preview = (c[:200] + "...") if len(c) > 200 else c
            print(f"    {YEL}#{RESET} {preview}")
    else:
        log("No HTML comments found.")

    # Links
    links = re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE)
    links = sorted(set(urljoin(base_url, l) for l in links))
    report["links"] = links
    if links:
        log(f"{len(links)} link(s) found (showing up to 40):")
        for l in links[:40]:
            print(f"    -> {l}")

    # Forms with methods, actions, inputs
    forms = []
    for fm in re.finditer(r"<form\b(.*?)</form>", body, re.IGNORECASE | re.DOTALL):
        block = fm.group(0)
        attrs = fm.group(1)
        method = re.search(r'method=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        action = re.search(r'action=["\']?([^"\'\s>]+)', attrs, re.IGNORECASE)
        inputs = []
        for inp in re.finditer(r"<input\b([^>]*)>", block, re.IGNORECASE):
            iattr = inp.group(1)
            iname = re.search(r'name=["\']?([^"\'\s>]+)', iattr, re.IGNORECASE)
            itype = re.search(r'type=["\']?([^"\'\s>]+)', iattr, re.IGNORECASE)
            inputs.append({
                "name": iname.group(1) if iname else "",
                "type": itype.group(1) if itype else "text",
            })
        forms.append({
            "method": (method.group(1).upper() if method else "GET"),
            "action": urljoin(base_url, action.group(1)) if action else base_url,
            "inputs": inputs,
        })
    report["forms"] = forms
    if forms:
        warn(f"{len(forms)} form(s) found:")
        for f in forms:
            print(f"    {BOLD}[{f['method']}]{RESET} {f['action']}")
            for i in f["inputs"]:
                print(f"        input name='{i['name']}' type='{i['type']}'")
    else:
        log("No forms found.")


def analyze_cookies(cookies, report):
    """Report cookies and their security flags."""
    section("Cookies")
    report["cookies"] = cookies
    if not cookies:
        log("No cookies set.")
        return
    for c in cookies:
        flags = []
        if not c.get("httponly"):
            flags.append(f"{YEL}missing HttpOnly{RESET}")
        if not c.get("secure"):
            flags.append(f"{YEL}missing Secure{RESET}")
        if not c.get("samesite"):
            flags.append(f"{YEL}missing SameSite{RESET}")
        flagstr = (" [" + ", ".join(flags) + "]") if flags else f" [{GRN}all flags set{RESET}]"
        print(f"  {c['name']}={c.get('value','')[:40]}{flagstr}")


def find_flags(text, report, source):
    """Search text for CTF-style flag patterns."""
    hits = set()
    for pat in FLAG_PATTERNS:
        for m in re.findall(pat, text):
            hits.add(m)
    if hits:
        for h in hits:
            ok(f"POSSIBLE FLAG in {source}: {h}")
        report.setdefault("flags", []).extend(sorted(hits))


def probe_paths(base_url, args, report):
    """Probe a list of interesting paths and report accessible ones."""
    section("Interesting file / path probe")
    results = []
    for path in INTERESTING_PATHS:
        url = urljoin(base_url, path)
        r = make_request(url, "GET", args, allow_redirects=False)
        status = r["status"]
        if status is None:
            continue
        clen = r["headers"].get("Content-Length") or len(r["body"])
        entry = {"path": path, "url": url, "status": status, "length": clen}
        results.append(entry)
        # 200/401/403 are all interesting (exists / protected).
        if status in (200, 401, 403, 301, 302):
            color = GRN if status == 200 else YEL
            print(f"  {color}[{status}]{RESET} {url}  (len={clen})")
            # Look for flags in the body of accessible probes.
            if status == 200 and r["body"]:
                find_flags(r["body"], report, url)
            # Special note for exposed .git / .env.
            if status == 200 and path in (".git/HEAD", ".git/config"):
                warn("    -> Exposed .git directory! Try git-dumper to reconstruct source.")
            if status == 200 and path in (".env", ".env.bak"):
                warn("    -> Exposed .env file! Likely contains secrets/credentials.")
    report["probed_paths"] = results


def main():
    p = argparse.ArgumentParser(
        description="Deep HTTP(S) recon: headers, tech, forms, cookies, flags.",
        epilog="AUTHORIZED TARGETS ONLY.",
    )
    p.add_argument("url", help="Target URL (e.g. http://10.10.10.5/)")
    p.add_argument("--timeout", type=float, default=10.0, help="Request timeout seconds (default 10)")
    p.add_argument("--user-agent", default="http-recon/1.0 (+CY5770-toolkit)",
                   help="Custom User-Agent header")
    p.add_argument("--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080 (Burp/ZAP)")
    p.add_argument("-k", "--insecure", action="store_true",
                   help="Do not verify TLS certificates")
    p.add_argument("--no-probe", action="store_true",
                   help="Skip the interesting-file probing stage")
    p.add_argument("--json", metavar="FILE", help="Write full report as JSON to FILE")
    args = p.parse_args()

    # Normalize URL (add scheme if omitted).
    if not re.match(r"^https?://", args.url, re.IGNORECASE):
        args.url = "http://" + args.url
        warn(f"No scheme supplied - assuming {args.url}")

    parsed = urlparse(args.url)
    base_url = f"{parsed.scheme}://{parsed.netloc}/"

    section(f"HTTP RECON :: {args.url}")
    warn("AUTHORIZED TARGETS ONLY. Confirm you are permitted to test this host.")
    log(f"Backend: {'requests' if HAVE_REQUESTS else 'urllib (fallback)'}")
    if args.proxy:
        log(f"Using proxy: {args.proxy}")

    report = {"target": args.url}

    # Main fetch (follow redirects).
    r = make_request(args.url, "GET", args, allow_redirects=True)
    if r["error"]:
        err(f"Request failed: {r['error']}")
        sys.exit(2)

    section("Status & redirects")
    ok(f"Final status: {r['status']}")
    report["status"] = r["status"]
    report["final_url"] = r["url"]
    if r["history"]:
        log("Redirect chain:")
        for h in r["history"]:
            print(f"    -> {h}")
        print(f"    => {r['url']}")
        report["redirect_chain"] = r["history"] + [r["url"]]
    else:
        log("No redirects.")

    analyze_headers(r["headers"], report)
    detect_tech(r["headers"], r["body"], report)
    parse_html(r["body"], base_url, report)
    analyze_cookies(r["cookies"], report)

    # Flags in the main body.
    section("Flag pattern scan (main page)")
    before = len(report.get("flags", []))
    find_flags(r["body"], report, args.url)
    if len(report.get("flags", [])) == before:
        log("No flag patterns in main page body.")

    if not args.no_probe:
        probe_paths(base_url, args, report)

    # Final flag summary.
    if report.get("flags"):
        section("FLAG SUMMARY")
        for f in sorted(set(report["flags"])):
            ok(f)

    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
            ok(f"JSON report written to {args.json}")
        except Exception as e:
            err(f"Failed to write JSON: {e}")

    print()
    log("Recon complete. For dir/vhost fuzzing use the bash web-enum.sh tool.")
    log("Reminder: stay within authorized scope.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        err("Interrupted by user.")
        sys.exit(130)
