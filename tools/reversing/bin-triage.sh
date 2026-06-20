#!/usr/bin/env bash
#
# bin-triage.sh - One-shot binary triage for CTF / RE challenges
# ----------------------------------------------------------------------------
# AUTHORIZED / EDUCATIONAL USE ONLY.
#   This tool is intended for CTF challenges, hackathons, and analysis of
#   binaries you own or are explicitly authorized to inspect. Do not use it
#   against software you do not have permission to analyze.
# ----------------------------------------------------------------------------
#
# USAGE:
#   ./bin-triage.sh <path-to-binary>
#
# WHAT IT DOES:
#   * file type, size
#   * checksec (RELRO / Canary / NX / PIE / Fortify) with a readelf fallback
#   * architecture + endianness
#   * dynamic libraries (ldd / readelf -d)
#   * symbols (nm / readelf -s) with interesting ones flagged
#   * interesting strings (flags, passwords, /bin/sh, urls, format strings ...)
#   * packer detection (UPX, high-entropy hint)
#   * suggested next steps (ghidra / r2 / gdb)
#
# Designed to degrade gracefully: every external tool is probed first, and a
# fallback or a clear "missing" note is printed if it is not installed.
#
# Target runtime: Kali / Linux (bash). Authored on a Windows host.
# ----------------------------------------------------------------------------

set -u  # treat unset variables as errors (we intentionally do NOT set -e so a
        # single failing optional tool does not abort the whole triage).

# ---------------------------------------------------------------------------
# Pretty-printing helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    C_RESET="\033[0m"; C_BOLD="\033[1m"; C_RED="\033[31m"
    C_GREEN="\033[32m"; C_YELLOW="\033[33m"; C_BLUE="\033[34m"; C_CYAN="\033[36m"
else
    C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi

section() { printf "\n${C_BOLD}${C_BLUE}==[ %s ]==${C_RESET}\n" "$1"; }
info()    { printf "  %s\n" "$1"; }
good()    { printf "  ${C_GREEN}%s${C_RESET}\n" "$1"; }
warn()    { printf "  ${C_YELLOW}%s${C_RESET}\n" "$1"; }
bad()     { printf "  ${C_RED}%s${C_RESET}\n" "$1"; }
flag()    { printf "  ${C_CYAN}[*] %s${C_RESET}\n" "$1"; }

# has <tool> -> returns 0 if tool is on PATH
has() { command -v "$1" >/dev/null 2>&1; }

missing_note() { warn "[-] '$1' not found - skipping (install: $2)"; }

# ---------------------------------------------------------------------------
# Argument handling / usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
bin-triage.sh - one-shot binary triage for RE/CTF

Usage:
  $0 <path-to-binary>

Example:
  $0 ./challenge

AUTHORIZED / EDUCATIONAL USE ONLY.
EOF
}

if [ "$#" -ne 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
    exit 1
fi

BIN="$1"

if [ ! -f "$BIN" ]; then
    bad "[!] File not found: $BIN"
    exit 1
fi
if [ ! -r "$BIN" ]; then
    bad "[!] File not readable: $BIN"
    exit 1
fi

printf "${C_BOLD}######################################################################${C_RESET}\n"
printf "${C_BOLD}#  Binary Triage: %s\n" "$BIN"
printf "${C_BOLD}#  $(date)\n"
printf "${C_BOLD}######################################################################${C_RESET}\n"

# ---------------------------------------------------------------------------
# 1. file type + size
# ---------------------------------------------------------------------------
section "File type & size"
if has file; then
    FILE_OUT="$(file -b "$BIN")"
    info "Type : $FILE_OUT"
else
    FILE_OUT=""
    missing_note "file" "apt install file"
fi

# size in bytes, human readable if possible
SIZE_BYTES="$(wc -c < "$BIN" 2>/dev/null | tr -d ' ')"
if has numfmt && [ -n "${SIZE_BYTES:-}" ]; then
    HUMAN="$(numfmt --to=iec "$SIZE_BYTES" 2>/dev/null)"
    info "Size : ${SIZE_BYTES} bytes (${HUMAN})"
else
    info "Size : ${SIZE_BYTES:-unknown} bytes"
fi

# md5/sha256 for reference / sharing
if has sha256sum; then info "SHA256: $(sha256sum "$BIN" | awk '{print $1}')"; fi
if has md5sum;    then info "MD5   : $(md5sum    "$BIN" | awk '{print $1}')"; fi

# ---------------------------------------------------------------------------
# 2. architecture / endianness  (from file output + readelf)
# ---------------------------------------------------------------------------
section "Architecture & endianness"
if has readelf && readelf -h "$BIN" >/dev/null 2>&1; then
    readelf -h "$BIN" 2>/dev/null | grep -Ei "Class|Data|Machine|Type:|Entry point" | sed 's/^/  /'
elif [ -n "$FILE_OUT" ]; then
    info "(from file) $FILE_OUT"
else
    warn "[-] Cannot determine architecture (no readelf, no file)."
fi

# ---------------------------------------------------------------------------
# 3. checksec / hardening
# ---------------------------------------------------------------------------
section "Security mitigations (checksec)"
if has checksec; then
    # Newer checksec uses --file=, older uses --file ; try both.
    if ! checksec --file="$BIN" 2>/dev/null; then
        checksec --file "$BIN" 2>/dev/null || warn "[-] checksec ran but produced no output."
    fi
else
    missing_note "checksec" "apt install checksec"
    warn "[-] Falling back to manual readelf-based mitigation checks:"
    if has readelf && readelf -h "$BIN" >/dev/null 2>&1; then

        # ---- NX: look for GNU_STACK program header w/o execute bit ----
        STACK_LINE="$(readelf -lW "$BIN" 2>/dev/null | grep -i GNU_STACK)"
        if [ -z "$STACK_LINE" ]; then
            warn "  NX     : Unknown (no GNU_STACK header)"
        elif echo "$STACK_LINE" | grep -qE 'RWE|RW E| E '; then
            bad  "  NX     : DISABLED (stack executable)"
        else
            good "  NX     : Enabled"
        fi

        # ---- PIE: ET_DYN type + presence of dynamic ----
        ETYPE="$(readelf -h "$BIN" 2>/dev/null | awk -F: '/Type:/ {print $2}')"
        if echo "$ETYPE" | grep -qi "DYN"; then
            # DYN could be a shared lib; check for an interpreter to confirm PIE exe
            if readelf -lW "$BIN" 2>/dev/null | grep -qi INTERP; then
                good "  PIE    : Enabled (PIE executable)"
            else
                warn "  PIE    : DYN object (shared library or PIE)"
            fi
        elif echo "$ETYPE" | grep -qi "EXEC"; then
            bad  "  PIE    : DISABLED (no PIE)"
        else
            warn "  PIE    : Unknown ($ETYPE)"
        fi

        # ---- RELRO: GNU_RELRO segment + BIND_NOW flag ----
        if readelf -lW "$BIN" 2>/dev/null | grep -qi GNU_RELRO; then
            if readelf -dW "$BIN" 2>/dev/null | grep -qiE 'BIND_NOW|FLAGS_1.*NOW'; then
                good "  RELRO  : Full RELRO"
            else
                warn "  RELRO  : Partial RELRO"
            fi
        else
            bad  "  RELRO  : No RELRO"
        fi

        # ---- Stack canary: __stack_chk_fail symbol ----
        if readelf -sW "$BIN" 2>/dev/null | grep -q "__stack_chk_fail"; then
            good "  Canary : Found (__stack_chk_fail present)"
        else
            bad  "  Canary : Not found"
        fi

        # ---- FORTIFY: *_chk symbols ----
        if readelf -sW "$BIN" 2>/dev/null | grep -qE '__\w+_chk'; then
            good "  Fortify: Some fortified functions present"
        else
            warn "  Fortify: No fortified (*_chk) functions detected"
        fi
    else
        bad "[!] readelf unavailable too - cannot assess mitigations."
    fi
fi

# ---------------------------------------------------------------------------
# 4. dynamic libraries
# ---------------------------------------------------------------------------
section "Dynamic libraries / dependencies"
if has readelf && readelf -dW "$BIN" 2>/dev/null | grep -qi NEEDED; then
    info "NEEDED entries (readelf -d):"
    readelf -dW "$BIN" 2>/dev/null | grep -i 'NEEDED\|RUNPATH\|RPATH\|SONAME' | sed 's/^/    /'
else
    info "(no dynamic NEEDED entries - possibly static binary)"
fi
# ldd can resolve full paths but RUNS the loader; only attempt on native arch.
if has ldd; then
    info ""
    info "ldd resolution (note: may invoke the dynamic loader):"
    ldd "$BIN" 2>/dev/null | sed 's/^/    /' || warn "    [-] ldd failed (static or non-native arch)"
else
    missing_note "ldd" "part of libc-bin"
fi

# ---------------------------------------------------------------------------
# 5. symbols  (flag interesting ones)
# ---------------------------------------------------------------------------
section "Symbols (interesting ones flagged)"
INTERESTING_SYMS="main|win|secret|admin|flag|backdoor|shell|system|exec|gets|strcpy|sprintf|scanf|popen|memcpy|read|getenv|setuid|debug"

SYM_SRC=""
if has nm; then
    SYM_SRC="$(nm -C "$BIN" 2>/dev/null)"
    if [ -z "$SYM_SRC" ]; then
        # try dynamic symbols for stripped binaries
        SYM_SRC="$(nm -D -C "$BIN" 2>/dev/null)"
    fi
fi
if [ -z "$SYM_SRC" ] && has readelf; then
    SYM_SRC="$(readelf -sW "$BIN" 2>/dev/null | awk '{print $8}')"
fi

if [ -n "$SYM_SRC" ]; then
    HITS="$(printf '%s\n' "$SYM_SRC" | grep -aiE "\b(${INTERESTING_SYMS})\b" | sort -u)"
    if [ -n "$HITS" ]; then
        printf '%s\n' "$HITS" | while IFS= read -r line; do flag "$line"; done
    else
        info "(no high-value symbols matched; binary may be stripped)"
    fi
    TOTAL_SYMS="$(printf '%s\n' "$SYM_SRC" | grep -c . )"
    info "(total symbol lines seen: $TOTAL_SYMS)"
else
    warn "[-] No symbols recovered (stripped binary, or nm/readelf missing)."
fi

# ---------------------------------------------------------------------------
# 6. interesting strings
# ---------------------------------------------------------------------------
section "Interesting strings"
if has strings; then
    ALLSTR="$(strings -a -n 4 "$BIN" 2>/dev/null)"

    show_str_group() {
        # $1 = label, $2 = grep -E pattern
        local label="$1" pat="$2" out
        out="$(printf '%s\n' "$ALLSTR" | grep -aiE "$pat" | sort -u | head -n 25)"
        if [ -n "$out" ]; then
            printf "  ${C_BOLD}%s:${C_RESET}\n" "$label"
            printf '%s\n' "$out" | sed 's/^/      /'
        fi
    }

    show_str_group "Flag-like"        'flag\{|ctf\{|flag|the_flag'
    show_str_group "Credentials"      'pass(word|wd|phrase)?|secret|admin|login|user(name)?|cred|token|api[_-]?key'
    show_str_group "Shell / commands" '/bin/sh|/bin/bash|/bin/dash|/usr/bin|system\(|sh -c|cmd\.exe'
    show_str_group "URLs / network"   'https?://|ftp://|[0-9]{1,3}(\.[0-9]{1,3}){3}|\.onion'
    show_str_group "Format strings"   '%[0-9.\-]*[diouxXeEfgGscpn]|%n|%x'
    show_str_group "Hardcoded paths"  '/(etc|tmp|home|root|var|opt|dev)/[A-Za-z0-9._/-]+'
    show_str_group "Build/compiler"   'GCC:|clang|rustc|go1\.|__libc_start_main'

    info ""
    info "(showing up to 25 per group; run 'strings -a $BIN' for the full list)"
else
    missing_note "strings" "apt install binutils"
fi

# ---------------------------------------------------------------------------
# 7. packer / entropy detection
# ---------------------------------------------------------------------------
section "Packer / obfuscation hints"
PACKED="no"

# UPX detection via embedded marker strings
if has strings; then
    if strings -a "$BIN" 2>/dev/null | grep -qiE 'UPX!|UPX0|UPX1|\$Info: This file is packed'; then
        bad "[!] UPX markers found - binary is likely UPX packed."
        PACKED="yes"
        if has upx; then
            info "    Verifying with 'upx -t':"
            upx -t "$BIN" 2>&1 | sed 's/^/      /'
            info "    Unpack with: upx -d -o ${BIN}.unpacked \"$BIN\""
        else
            missing_note "upx" "apt install upx-ucl"
            info "    Install upx and run: upx -d \"$BIN\""
        fi
    fi
fi

# Crude entropy hint: ratio of unique bytes / printable density.
# A very low printable-string density in a large binary suggests packing.
if has strings && [ -n "${SIZE_BYTES:-}" ] && [ "${SIZE_BYTES:-0}" -gt 2048 ]; then
    PRINTABLE_BYTES="$(strings -a -n 1 "$BIN" 2>/dev/null | wc -c | tr -d ' ')"
    if [ -n "$PRINTABLE_BYTES" ] && [ "$SIZE_BYTES" -gt 0 ]; then
        # percent = printable*100/size
        PCT=$(( PRINTABLE_BYTES * 100 / SIZE_BYTES ))
        info "Printable-byte density: ${PCT}% of file"
        if [ "$PCT" -lt 25 ] && [ "$PACKED" = "no" ]; then
            warn "[!] Low printable density (<25%) - possible packing/encryption/high entropy."
            PACKED="maybe"
        fi
    fi
fi

if [ "$PACKED" = "no" ]; then
    good "[+] No obvious packer signature detected."
fi

# ---------------------------------------------------------------------------
# 8. suggested next steps
# ---------------------------------------------------------------------------
section "Suggested next steps"
cat <<EOF
  Static analysis:
    * Decompile in Ghidra (GUI) or headless:
        ./ghidra-decompile.sh "$BIN" ./out
    * radare2 automated pass:
        ./r2-auto.py "$BIN"
        r2 -A "$BIN"           # then: afl ; iz ; pdf @ main ; VV
    * Full strings dump:
        strings -a "$BIN" | less

  Dynamic analysis:
    * Run under gdb + pwndbg/GEF:
        gdb -q "$BIN"          # then: break main ; run ; info functions
    * Trace syscalls / library calls:
        strace -f "$BIN"
        ltrace -f "$BIN"

  Exploitation prep (if it's a pwn challenge):
    * Note the mitigations above (NX/PIE/RELRO/Canary) to pick a technique.
    * Build a harness with pwntools:  from pwn import *
EOF

printf "\n${C_GREEN}${C_BOLD}[+] Triage complete.${C_RESET}\n"
