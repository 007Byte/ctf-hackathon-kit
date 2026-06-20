#!/usr/bin/env python3
"""
r2-auto.py - radare2 / r2pipe automation for CTF & RE triage
============================================================================
AUTHORIZED / EDUCATIONAL USE ONLY.
    For use on CTF challenges, hackathons, and binaries you own or are
    explicitly authorized to analyze. Do not use against software you do not
    have permission to inspect.
============================================================================

What it does
------------
  * Opens a binary with r2pipe and runs full analysis (aaa).
  * Pretty-prints:
      - function list           (aflj)
      - imports                 (iij)
      - strings                 (izzj)
      - dangerous call sites    (system/exec*/gets/strcpy/sprintf/scanf/
                                 popen/memcpy) with the calling function+addr
      - likely win/backdoor functions (win/secret/admin/flag/shell/...)
  * Locates main and prints its decompilation (pdg from r2ghidra, else pdc,
    else plain disassembly pdf @ main).
  * Optional JSON dump of all collected data (--json out.json).

Degrades gracefully: if r2pipe (the Python module) or the radare2 binary are
not installed, it prints a clear install hint and exits cleanly.

Target runtime: Kali / Linux. Authored on a Windows host.

Usage
-----
    ./r2-auto.py <binary> [--json out.json] [--no-decompile] [--max-strings N]
"""

import argparse
import json
import shutil
import sys

# ---------------------------------------------------------------------------
# Graceful dependency handling
# ---------------------------------------------------------------------------
def fail(msg, code=1):
    """Print an error to stderr and exit."""
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(code)


def check_dependencies():
    """Ensure both the r2 binary and the r2pipe python module are available."""
    if shutil.which("radare2") is None and shutil.which("r2") is None:
        fail(
            "radare2 binary not found on PATH.\n"
            "    Install it with:  sudo apt install radare2\n"
            "    or from source:   https://github.com/radareorg/radare2"
        )
    try:
        import r2pipe  # noqa: F401
    except ImportError:
        fail(
            "Python module 'r2pipe' not found.\n"
            "    Install it with:  pip install r2pipe\n"
            "    (or: python3 -m pip install --user r2pipe)"
        )


# ---------------------------------------------------------------------------
# ANSI colour helpers (auto-disabled when not a TTY)
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty()


def _c(text, code):
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def bold(t):   return _c(t, "1")
def red(t):    return _c(t, "31")
def green(t):  return _c(t, "32")
def yellow(t): return _c(t, "33")
def blue(t):   return _c(t, "34")
def cyan(t):   return _c(t, "36")


def section(title):
    print("\n" + bold(blue(f"==[ {title} ]==")))


# Dangerous functions worth flagging at every call site.
DANGEROUS = [
    "system", "execve", "execl", "execlp", "execvp", "execv", "exec",
    "gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf",
    "popen", "memcpy", "fgets", "read", "fscanf",
]

# Substrings hinting at win/backdoor functions.
WIN_HINTS = ["win", "secret", "admin", "flag", "shell", "backdoor",
             "give_shell", "get_flag", "pwn", "magic", "hidden", "cheat"]


# ---------------------------------------------------------------------------
# r2 helpers
# ---------------------------------------------------------------------------
def r2_cmdj(r2, cmd, default=None):
    """Run an r2 command expecting JSON; return parsed obj or `default`."""
    try:
        out = r2.cmd(cmd)
        if not out or not out.strip():
            return default if default is not None else []
        return json.loads(out)
    except (json.JSONDecodeError, Exception):
        return default if default is not None else []


def r2_cmd(r2, cmd):
    """Run an r2 command expecting plain text."""
    try:
        return r2.cmd(cmd) or ""
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Analysis stages
# ---------------------------------------------------------------------------
def get_functions(r2):
    """Return list of dicts from aflj (function list)."""
    funcs = r2_cmdj(r2, "aflj", [])
    return funcs if isinstance(funcs, list) else []


def print_functions(funcs):
    section(f"Functions ({len(funcs)})")
    if not funcs:
        print("  (none found - binary may be stripped or not yet analyzed)")
        return
    # Sort by address for stable output.
    for f in sorted(funcs, key=lambda x: x.get("offset", 0)):
        name = f.get("name", "?")
        addr = f.get("offset", 0)
        size = f.get("size", 0)
        nargs = f.get("nargs", f.get("nbbs", ""))
        line = f"  {addr:#010x}  size={size:<5}  {name}"
        if any(h in name.lower() for h in WIN_HINTS):
            print("  " + cyan(f"[*] {addr:#010x}  size={size:<5}  {name}  <-- interesting"))
        else:
            print(line)


def get_imports(r2):
    imports = r2_cmdj(r2, "iij", [])
    if not imports:
        imports = r2_cmdj(r2, "iEj", [])  # fallback symbol form
    return imports if isinstance(imports, list) else []


def print_imports(imports):
    section(f"Imports ({len(imports)})")
    if not imports:
        print("  (no imports reported)")
        return
    for imp in imports:
        name = imp.get("name", "?")
        plt = imp.get("plt", 0)
        typ = imp.get("type", "")
        marker = ""
        base = name.split("@")[0].split(".")[-1] if name else ""
        if base in DANGEROUS:
            marker = red("  <-- DANGEROUS")
        print(f"  {plt:#010x}  {typ:<6}  {name}{marker}")


def get_strings(r2, limit):
    strs = r2_cmdj(r2, "izzj", [])
    # r2 may wrap the list in {"strings":[...]} on some versions
    if isinstance(strs, dict):
        strs = strs.get("strings", [])
    if not isinstance(strs, list):
        strs = []
    return strs[:limit] if limit and limit > 0 else strs


def print_strings(strs, limit):
    section(f"Strings (showing up to {limit})")
    if not strs:
        print("  (no strings found)")
        return
    keywords = ("flag", "pass", "secret", "admin", "/bin/sh", "http",
                "key", "token", "%n", "%x")
    for s in strs:
        text = s.get("string", "")
        vaddr = s.get("vaddr", 0)
        low = text.lower()
        if any(k in low for k in keywords):
            print("  " + cyan(f"[*] {vaddr:#010x}  {text!r}"))
        else:
            print(f"      {vaddr:#010x}  {text!r}")


def scan_dangerous_calls(r2, funcs):
    """
    Walk every function's disassembly (pdfj) and record call sites that
    reference a dangerous function. Returns a list of finding dicts.
    """
    findings = []
    for f in funcs:
        faddr = f.get("offset", 0)
        fname = f.get("name", "?")
        dis = r2_cmdj(r2, f"pdfj @ {faddr}", {})
        if not isinstance(dis, dict):
            continue
        for op in dis.get("ops", []):
            disasm = op.get("disasm", "") or ""
            opcode = op.get("type", "")
            # Look at call instructions and any opcode mentioning a danger fn.
            for d in DANGEROUS:
                # match e.g. "call sym.imp.system" or "...; system"
                if (f"sym.imp.{d}" in disasm
                        or f"sym.{d}" in disasm
                        or disasm.endswith(d)
                        or f" {d}" in disasm) and (opcode == "call" or "call" in disasm):
                    findings.append({
                        "callee": d,
                        "caller": fname,
                        "caller_addr": faddr,
                        "site": op.get("offset", 0),
                        "disasm": disasm.strip(),
                    })
                    break
    return findings


def print_dangerous(findings):
    section(f"Dangerous call sites ({len(findings)})")
    if not findings:
        print("  (none detected)")
        return
    for f in findings:
        print("  " + red(
            f"{f['site']:#010x}  {f['callee']:<10}"
            f"  in {f['caller']} ({f['caller_addr']:#x})"))
        print(f"               {f['disasm']}")


def find_win_functions(funcs):
    hits = []
    for f in funcs:
        name = f.get("name", "")
        if any(h in name.lower() for h in WIN_HINTS):
            hits.append({"name": name, "addr": f.get("offset", 0)})
    return hits


def print_win_functions(hits):
    section(f"Possible win / backdoor functions ({len(hits)})")
    if not hits:
        print("  (none matched the heuristic names)")
        return
    for h in hits:
        print("  " + cyan(f"[*] {h['addr']:#010x}  {h['name']}"))


def decompile_main(r2, funcs):
    """
    Try to find main and produce the best available representation:
      1. pdg  (r2ghidra decompiler plugin)
      2. pdc  (radare2 built-in pseudo-decompiler)
      3. pdf  (plain disassembly)
    """
    section("main() analysis")

    # Locate main: prefer sym.main / main, else entry's first call target.
    main_addr = None
    for f in funcs:
        if f.get("name") in ("sym.main", "main", "dbg.main", "sym.imp.main"):
            main_addr = f.get("offset")
            break
    if main_addr is None:
        # ask r2 to seek to main; many binaries have it via 's main'
        r2_cmd(r2, "s main")
        try:
            main_addr = int(r2.cmd("s").strip(), 16)
        except Exception:
            main_addr = None

    if main_addr is None or main_addr == 0:
        print("  (could not locate main; try entry0 with: pdf @ entry0)")
        return {"addr": None, "method": None, "code": ""}

    print(f"  main located at {main_addr:#x}\n")

    # 1) r2ghidra pdg
    pdg = r2_cmd(r2, f"pdg @ {main_addr}")
    if pdg.strip() and "Cannot" not in pdg and "command not found" not in pdg.lower():
        print(green("  [decompiled with r2ghidra: pdg]"))
        print(pdg)
        return {"addr": main_addr, "method": "pdg", "code": pdg}

    # 2) built-in pseudo-decompiler pdc
    pdc = r2_cmd(r2, f"pdc @ {main_addr}")
    if pdc.strip() and "command not found" not in pdc.lower():
        print(yellow("  [pseudo-decompiled with built-in: pdc]"))
        print(pdc)
        return {"addr": main_addr, "method": "pdc", "code": pdc}

    # 3) raw disassembly
    pdf = r2_cmd(r2, f"pdf @ {main_addr}")
    print(yellow("  [no decompiler available - showing disassembly: pdf]"))
    print(pdf)
    return {"addr": main_addr, "method": "pdf", "code": pdf}


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="radare2/r2pipe automation for CTF & RE triage "
                    "(authorized/educational use only).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("binary", help="path to the binary to analyze")
    parser.add_argument("--json", metavar="FILE",
                        help="dump all collected data to FILE as JSON")
    parser.add_argument("--no-decompile", action="store_true",
                        help="skip the main() decompilation stage")
    parser.add_argument("--max-strings", type=int, default=80,
                        help="max number of strings to print")
    parser.add_argument("--flags", default="-2",
                        help="extra flags passed to r2pipe.open (default quiets r2)")
    args = parser.parse_args()

    check_dependencies()
    import r2pipe  # safe now

    import os
    if not os.path.isfile(args.binary):
        fail(f"file not found: {args.binary}")

    print(bold("#" * 70))
    print(bold(f"#  r2-auto.py  ::  {args.binary}"))
    print(bold("#" * 70))

    # Open with flags to keep r2 quiet ('-2' silences stderr from r2 core).
    try:
        r2 = r2pipe.open(args.binary, flags=[args.flags] if args.flags else [])
    except Exception as e:
        fail(f"failed to open binary with r2pipe: {e}")

    try:
        print("\n[*] Running full analysis (aaa) - this can take a moment...")
        r2_cmd(r2, "aaa")

        funcs = get_functions(r2)
        imports = get_imports(r2)
        strs = get_strings(r2, args.max_strings)
        win_fns = find_win_functions(funcs)
        dangerous = scan_dangerous_calls(r2, funcs)

        print_functions(funcs)
        print_imports(imports)
        print_strings(strs, args.max_strings)
        print_dangerous(dangerous)
        print_win_functions(win_fns)

        main_info = {"addr": None, "method": None, "code": ""}
        if not args.no_decompile:
            main_info = decompile_main(r2, funcs)

        if args.json:
            data = {
                "binary": args.binary,
                "functions": funcs,
                "imports": imports,
                "strings": strs,
                "dangerous_calls": dangerous,
                "win_functions": win_fns,
                "main": main_info,
            }
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, default=str)
            print("\n" + green(f"[+] JSON written to {args.json}"))

        print("\n" + green(bold("[+] r2-auto analysis complete.")))
    finally:
        try:
            r2.quit()
        except Exception:
            pass


if __name__ == "__main__":
    main()
