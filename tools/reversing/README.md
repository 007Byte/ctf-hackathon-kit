# Reverse Engineering Toolkit (CTF / Hackathon)

A small set of custom RE helpers for triaging and decompiling binaries during
CTF challenges and hackathons.

> **AUTHORIZED / EDUCATIONAL USE ONLY.** These tools are for CTF challenges,
> hackathons, and binaries you own or are explicitly authorized to analyze.
> Do not use them against software you do not have permission to inspect.

Host: Windows 11 (authoring). Runtime target: **Kali / Linux**.

---

## Contents

| File | What it does |
|------|--------------|
| `bin-triage.sh` | One-shot static triage: file/size/checksec/arch/libs/symbols/strings/packer + next steps. |
| `r2-auto.py` | r2pipe automation: `aaa`, functions, imports, strings, dangerous calls, win-func detection, `main` decompilation, optional JSON. |
| `ghidra-decompile.sh` | Headless Ghidra wrapper: import + analyze + export all functions to C. |
| `DecompileToC.java` | Ghidra post-script used by the wrapper to dump decompiled C. |
| `README.md` | This document. |

---

## Prerequisites

Install on the Linux/Kali box where you run the tools:

```bash
# Core binutils + helpers used by bin-triage.sh
sudo apt install binutils file checksec upx-ucl

# radare2 (for r2-auto.py)
sudo apt install radare2
# Python binding:
pip install r2pipe
# (optional, much better decompilation in r2-auto.py)
r2pm -ci r2ghidra

# Ghidra (for ghidra-decompile.sh / DecompileToC.java) + a JDK
sudo apt install openjdk-17-jdk
# Download Ghidra and set GHIDRA_HOME:
#   https://github.com/NationalSecurityAgency/ghidra/releases
export GHIDRA_HOME=/opt/ghidra_11.1_PUBLIC
```

Make the scripts executable (and fix line endings if copied from Windows):

```bash
# Strip any CR characters introduced by editing on Windows, then chmod:
sed -i 's/\r$//' bin-triage.sh ghidra-decompile.sh
chmod +x bin-triage.sh ghidra-decompile.sh r2-auto.py
```

---

## Usage

### 1. `bin-triage.sh`

```bash
./bin-triage.sh ./challenge
```

Prints file type, size, hashes, architecture/endianness, security mitigations
(via `checksec`, or a `readelf`-based fallback for RELRO/Canary/NX/PIE/Fortify
when `checksec` is missing), dynamic libraries, flagged symbols, grouped
interesting strings (flags, credentials, `/bin/sh`, URLs, format strings,
hardcoded paths), packer hints (UPX markers, low printable-byte density), and a
suggested-next-steps section. Every external tool is probed and skipped
gracefully if absent.

### 2. `r2-auto.py`

```bash
./r2-auto.py ./challenge                 # full run to stdout
./r2-auto.py ./challenge --json out.json # also dump structured JSON
./r2-auto.py ./challenge --no-decompile  # skip main() decompilation
./r2-auto.py ./challenge --max-strings 200
```

Runs `aaa`, then lists functions, imports, strings, dangerous call sites
(`system`, `exec*`, `gets`, `strcpy`, `sprintf`, `scanf`, `popen`, `memcpy`,
...) with the calling function and address, highlights likely win/backdoor
functions (`win`, `secret`, `admin`, `flag`, `shell`, ...), and decompiles
`main` using r2ghidra (`pdg`) when available, falling back to the built-in
pseudo-decompiler (`pdc`) and finally raw disassembly (`pdf`). If `r2pipe` or
`radare2` is missing it prints an install hint and exits cleanly.

### 3. `ghidra-decompile.sh` + `DecompileToC.java`

```bash
export GHIDRA_HOME=/opt/ghidra_11.1_PUBLIC   # or rely on auto-detect
./ghidra-decompile.sh ./challenge ./decompiled
# -> ./decompiled/challenge.decompiled.c
```

Creates a temporary Ghidra project, imports and auto-analyzes the binary, then
runs `DecompileToC.java` as a `-postScript` to write the decompiled C for every
function to `<output-dir>/<binary>.decompiled.c`. The temp project is deleted
afterward. `analyzeHeadless` is auto-located from `GHIDRA_HOME`, the `PATH`, or
common install paths; a clear error with a download pointer is shown if Ghidra
is not found.

`DecompileToC.java` can also be run from the Ghidra GUI Script Manager
(category **CTF.Reversing**); it then writes next to the binary or to your home
directory if no argument is given.

---

## RE Challenge Workflow

A practical order of operations for an unknown binary:

1. **Triage (static, fast).**
   ```bash
   ./bin-triage.sh ./challenge
   ```
   Learn the arch, mitigations (NX/PIE/RELRO/Canary), libraries, and whether
   it's packed. If UPX-packed: `upx -d -o challenge.unpacked challenge`.

2. **Strings & low-hanging fruit.**
   ```bash
   strings -a ./challenge | grep -iE 'flag|pass|/bin/sh|http'
   ```
   The triage script already groups these, but a manual pass often reveals
   hardcoded flags or format-string bugs (`%n`, `%x`).

3. **Automated radare2 pass.**
   ```bash
   ./r2-auto.py ./challenge --json r2.json
   ```
   Identify dangerous calls and any `win`/`secret`/`flag` functions, and read
   the `main` decompilation.

4. **Full decompilation (Ghidra).**
   ```bash
   ./ghidra-decompile.sh ./challenge ./decompiled
   less ./decompiled/challenge.decompiled.c
   ```
   Read the C for the interesting functions found in steps 2-3.

5. **Dynamic analysis (gdb / pwndbg / GEF).**
   ```bash
   gdb -q ./challenge
   # pwndbg/GEF: break main ; run ; info functions ; vmmap ; checksec
   strace -f ./challenge      # syscalls
   ltrace -f ./challenge      # library calls
   ```
   Confirm hypotheses, find offsets, and watch the program at runtime.

6. **Exploit / solve.**
   Use the mitigation profile from step 1 to choose a technique (ret2win,
   ret2libc, format string, etc.). Build the harness with `pwntools`:
   ```python
   from pwn import *
   io = process("./challenge")   # or remote(host, port)
   # ...
   ```

---

## Notes & troubleshooting

- **CRLF line endings**: if a `.sh` fails with `bad interpreter` or syntax
  errors after copying from Windows, run `sed -i 's/\r$//' *.sh`.
- **r2ghidra not installed**: `r2-auto.py` still works, falling back to `pdc`
  then `pdf`. Install with `r2pm -ci r2ghidra` for real decompilation.
- **Ghidra analysis is slow**: tune the timeout with
  `GHIDRA_ANALYZE_TIMEOUT=1200 ./ghidra-decompile.sh ...`.
