#!/usr/bin/env python3
"""
subdomain-enum.py - subdomain enumeration via brute-force + crt.sh
================================================================================
Discovers subdomains of a target domain using two complementary techniques:

  1. ACTIVE  brute force: resolve <word>.<domain> concurrently from a wordlist.
  2. PASSIVE crt.sh:      query the Certificate Transparency log JSON API for
                          subdomains that appear in issued certificates.

Results are merged, de-duplicated, and (by default) filtered down to names that
actually resolve in DNS. Output can be plain text or JSON.

--------------------------------------------------------------------------------
AUTHORIZED USE ONLY: Enumerate only domains you own or are explicitly authorized
to assess (CTF/lab scope, bug-bounty programs that permit it, etc.).
--------------------------------------------------------------------------------

DEPENDENCIES:
  requests   (pip install requests)   - used for the crt.sh HTTP query.
             If 'requests' is missing the script falls back to urllib so the
             crt.sh step still works with only the standard library.

USAGE EXAMPLES:
  # Brute-force with a wordlist plus crt.sh, print live subdomains:
  python3 subdomain-enum.py example.com -w subdomains.txt

  # crt.sh only (no wordlist), keep unresolved names too, JSON output:
  python3 subdomain-enum.py example.com --no-bruteforce --keep-unresolved --json

  # Tune concurrency and DNS timeout:
  python3 subdomain-enum.py example.com -w big.txt -c 100 --timeout 3 -o subs.txt
"""

import argparse
import concurrent.futures
import json
import socket
import sys
from datetime import datetime

# crt.sh is queried over HTTP. Prefer 'requests'; fall back to urllib so the
# script remains usable on a minimal Python install.
try:
    import requests  # type: ignore
    _HAVE_REQUESTS = True
except ImportError:
    _HAVE_REQUESTS = False
    import urllib.request
    import urllib.error


def load_wordlist(path: str) -> list[str]:
    """Read a wordlist file, skipping blanks and comment lines."""
    words: list[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                w = line.strip()
                if w and not w.startswith("#"):
                    words.append(w)
    except OSError as exc:
        sys.exit(f"[-] Could not read wordlist '{path}': {exc}")
    return words


def resolve_name(name: str, timeout: float) -> tuple[str, str | None]:
    """
    Resolve a single hostname to an IPv4 address.
    Returns (name, ip) where ip is None if resolution failed.
    """
    socket.setdefaulttimeout(timeout)
    try:
        return name, socket.gethostbyname(name)
    except (socket.gaierror, socket.timeout, OSError):
        return name, None


def query_crtsh(domain: str, timeout: float) -> set[str]:
    """
    Query crt.sh Certificate Transparency logs for subdomains of `domain`.
    Endpoint: https://crt.sh/?q=%.<domain>&output=json
    The 'name_value' field may contain multiple newline-separated names and
    wildcard entries (*.foo.com) which we normalize.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    found: set[str] = set()
    raw = ""
    try:
        if _HAVE_REQUESTS:
            resp = requests.get(url, timeout=timeout,
                                headers={"User-Agent": "subdomain-enum/1.0"})
            resp.raise_for_status()
            raw = resp.text
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "subdomain-enum/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
                raw = r.read().decode("utf-8", errors="replace")
    except Exception as exc:  # broad on purpose: network/JSON issues are non-fatal
        print(f"[!] crt.sh query failed: {exc}", file=sys.stderr)
        return found

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        print("[!] crt.sh returned non-JSON data - skipping passive results.",
              file=sys.stderr)
        return found

    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.splitlines():
            name = name.strip().lstrip("*.").lower()
            # Keep only names that belong to the target domain.
            if name and (name == domain or name.endswith("." + domain)):
                found.add(name)
    return found


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Subdomain enumeration via DNS brute force + crt.sh CT logs.",
        epilog="Authorized targets only.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("domain", help="Base domain, e.g. example.com")
    parser.add_argument("-w", "--wordlist",
                        help="Wordlist for brute force (one label per line).")
    parser.add_argument("--no-bruteforce", action="store_true",
                        help="Skip DNS brute force; use crt.sh only.")
    parser.add_argument("--no-crtsh", action="store_true",
                        help="Skip crt.sh; use brute force only.")
    parser.add_argument("-c", "--concurrency", type=int, default=50,
                        help="Concurrent DNS resolution workers.")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="DNS / HTTP timeout in seconds.")
    parser.add_argument("--keep-unresolved", action="store_true",
                        help="Also include candidate names that do not resolve.")
    parser.add_argument("--json", action="store_true",
                        help="Emit results as JSON.")
    parser.add_argument("-o", "--output",
                        help="Write the final subdomain list to this file.")
    args = parser.parse_args()

    domain = args.domain.strip().lstrip(".").lower()
    candidates: set[str] = set()

    # --- passive: crt.sh ---
    if not args.no_crtsh:
        if not args.json:
            print(f"[*] Querying crt.sh for *.{domain} ...")
        crt = query_crtsh(domain, args.timeout)
        if not args.json:
            print(f"[+] crt.sh returned {len(crt)} unique name(s).")
        candidates |= crt

    # --- active: brute force ---
    if not args.no_bruteforce:
        if not args.wordlist:
            print("[!] No --wordlist provided; skipping brute force. "
                  "(Use --no-bruteforce to silence this.)", file=sys.stderr)
        else:
            words = load_wordlist(args.wordlist)
            if not args.json:
                print(f"[*] Brute forcing {len(words)} candidate label(s)...")
            candidates |= {f"{w}.{domain}" for w in words}

    if not candidates:
        sys.exit("[-] No candidate subdomains gathered. Nothing to do.")

    # --- resolve all candidates concurrently ---
    if not args.json:
        print(f"[*] Resolving {len(candidates)} unique candidate(s) "
              f"with {args.concurrency} workers...")

    live: dict[str, str] = {}     # name -> ip
    unresolved: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [pool.submit(resolve_name, name, args.timeout) for name in candidates]
        for fut in concurrent.futures.as_completed(futures):
            name, ip = fut.result()
            if ip:
                live[name] = ip
                if not args.json:
                    print(f"[+] {name}  ->  {ip}")
            else:
                unresolved.append(name)

    # --- build the final, sorted output set ---
    results = [{"name": n, "ip": live[n]} for n in sorted(live)]
    if args.keep_unresolved:
        results += [{"name": n, "ip": None} for n in sorted(unresolved)]

    summary = {
        "domain": domain,
        "candidates": len(candidates),
        "live": len(live),
        "results": results,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            for r in results:
                fh.write(r["name"] + "\n")
        if not args.json:
            print(f"[*] Wrote {len(results)} name(s) to {args.output}")

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[*] Done. {len(live)} live subdomain(s) found "
              f"out of {len(candidates)} candidate(s).")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[-] Interrupted by user.")
